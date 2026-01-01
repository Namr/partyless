mod data;
mod metrics;
mod routes;

use crate::{
    metrics::{MetricsConnection, init_metrics},
    routes::*,
};

use std::{fs::read_to_string, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use chrono::Utc;
use clap::Parser;
use ramhorns::{Content, Template};
use rusqlite::Connection;
use tokio::{net::TcpListener, signal, sync::Mutex};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use uuid::Uuid;

const CLEANUP_PERIOD: Duration = Duration::from_secs(5 * 60 * 60);
const CLEANUP_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);
const BCRYPT_COST: u32 = 12;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to user data SQLite DB file
    #[arg(short, long, default_value = "partyless.db")]
    db_file: String,

    /// Path to metrics SQLite DB file
    #[arg(short, long, default_value = "partyless_metrics.db")]
    metrics_db_file: String,

    /// Path to SQLite DB file
    #[arg(long, default_value = "static")]
    static_pages: String,

    /// Path to SQLite DB file
    #[arg(long, default_value = "templates")]
    templates: String,
}

#[derive(Clone)]
struct RouteState {
    db: Arc<Mutex<Connection>>,
    metrics: Arc<Mutex<MetricsConnection>>,
    event_template: Arc<Template<'static>>,
    guest_edit_template: Arc<Template<'static>>,
    event_edit_template: Arc<Template<'static>>,
}

// error handling
struct AppError(anyhow::Error);
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        error!("Route failed with error: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("<p class=\"error\">Request Failed. Error: {:#}</p>", self.0),
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("tower_http=warn"))?,
        )
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let args = Args::parse();
    let db = Arc::new(Mutex::new(Connection::open(args.db_file)?));
    let metrics = Arc::new(Mutex::new(
        init_metrics(&args.metrics_db_file).with_context(|| "Failed to init metrics.")?,
    ));

    // templates
    let event_template = Arc::new(
        Template::new(
            read_to_string("templates/event.mustache")
                .context("failed to read event mustache template")?,
        )
        .context("failed to instantiate mustache template")?,
    );
    let guest_edit_template = Arc::new(
        Template::new(
            read_to_string("templates/guest_edit.mustache")
                .context("failed to read guest edit mustache template")?,
        )
        .context("failed to instantiate mustache template")?,
    );
    let event_edit_template = Arc::new(
        Template::new(
            read_to_string("templates/event_edit.mustache")
                .context("failed to read event edit mustache template")?,
        )
        .context("failed to instantiate mustache template")?,
    );

    tokio::spawn(clean_database(db.clone()));
    let mut route_state = RouteState {
        db,
        event_template,
        guest_edit_template,
        event_edit_template,
        metrics,
    };

    init_db_schema(&mut route_state).await?;

    let app = Router::new()
        .fallback_service(
            ServeDir::new(args.static_pages).fallback(ServeFile::new("static/404.html")),
        )
        .route("/event", get(get_event).post(post_event).put(put_event))
        .route("/rsvp", post(post_rsvp).put(put_rsvp))
        // (note: amoussa) these are POSTs because otherwise
        // HTMX will send the password as a query param :/
        .route("/event/delete", post(delete_event))
        .route("/rsvp/delete", post(delete_rsvp))
        .route("/auth_guest", post(post_auth_guest))
        .route("/auth_event", post(post_auth_event))
        .layer(TraceLayer::new_for_http())
        .with_state(route_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    info!("server started on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/*
 * Checks the existance of each table in the DB, and if it does not exist, creates it
 */
async fn init_db_schema(route_state: &mut RouteState) -> Result<()> {
    let db = route_state.db.lock().await;
    if let Err(rusqlite::Error::QueryReturnedNoRows) = db.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'",
        (),
        |row| row.get::<usize, String>(0),
    ) {
        info!("creating events table!");
        db.execute(
            "CREATE TABLE events (
            uuid BLOB PRIMARY KEY,
            event_name  TEXT NOT NULL,
            host_name TEXT NOT NULL,
            address TEXT NOT NULL,
            description TEXT NOT NULL,
            time INTEGER NOT NULL,
            password BLOB
        )",
            (),
        )?;
    }

    if let Err(rusqlite::Error::QueryReturnedNoRows) = db.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='guests'",
        (),
        |row| row.get::<usize, String>(0),
    ) {
        info!("creating guests table!");
        db.execute(
            "CREATE TABLE guests (
            uuid BLOB PRIMARY KEY,
            event_uuid BLOB NOT NULL,
            name TEXT NOT NULL,
            note TEXT,
            response INTEGER NOT NULL,
            password TEXT
        )",
            (),
        )?;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn clean_database(db: Arc<Mutex<Connection>>) -> Result<()> {
    loop {
        {
            let conn = db.lock().await;
            let mut search_stmt = conn.prepare("SELECT uuid FROM events WHERE time <= ?1")?;
            let mut delete_stmt = conn.prepare("DELETE FROM events WHERE uuid = ?1")?;
            let mut delete_guests_stmt =
                conn.prepare("DELETE FROM guests WHERE event_uuid = ?1")?;
            info!("Running database cleanup task...");
            let now = Utc::now().timestamp_millis() - CLEANUP_THRESHOLD.as_millis() as i64;
            let num_removed =
                if let Ok(ids) = search_stmt.query_map((now,), |row| row.get::<usize, Uuid>(0)) {
                    // iterate over all old events
                    ids.fold(0, |acc, maybe_uuid| {
                        if let Ok(uuid) = maybe_uuid {
                            if let Ok(_) = delete_stmt.execute((uuid,))
                                && let Ok(_) = delete_guests_stmt.execute((uuid,))
                            {
                                acc + 1
                            } else {
                                error!("Failed to delete {}", uuid);
                                acc
                            }
                        } else {
                            acc
                        }
                    })
                } else {
                    error!("Failed to query for finished events!");
                    0
                };
            info!("Removed {} entries", num_removed);
        }

        // run every 5 hours
        tokio::time::sleep(CLEANUP_PERIOD).await;
    }
}
