use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::{Form, Router, extract::Query, routing::get};
use chrono::{DateTime, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use lazy_static::lazy_static;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, signal, sync::Mutex};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventCreationForm {
    event_name: String,
    hosts_name: String,
    address: String,
    description: String,
    date: String,
    time: String,
    timezone: String,
}

#[derive(Debug, Clone)]
struct Event {
    event_name: String,
    host_name: String,
    address: String,
    description: String,
    password: Option<String>,
    time: DateTime<Tz>,
}

impl TryFrom<EventCreationForm> for Event {
    type Error = anyhow::Error;

    fn try_from(value: EventCreationForm) -> Result<Self> {
        if value.event_name.is_empty()
            || value.hosts_name.is_empty()
            || value.address.is_empty()
            || value.description.is_empty()
            || value.date.is_empty()
            || value.time.is_empty()
            || value.timezone.is_empty()
        {
            return Err(anyhow!("Event creation form had a blank field"));
        }

        let tz = value.timezone.parse::<Tz>()?;
        let form = format!("{} {}", value.date, value.time);
        let naive_time = NaiveDateTime::parse_from_str(&form, "%Y-%m-%d %H:%M")?;
        let time = tz
            .from_local_datetime(&naive_time)
            .single()
            .ok_or(anyhow!("time + timezone was ambigious"))?;
        Ok(Event {
            event_name: value.event_name,
            host_name: value.hosts_name,
            address: value.address,
            description: value.description,
            password: None,
            time,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventViewQuery {
    uuid: String,
}

lazy_static! {
    static ref DB: Arc<Mutex<Connection>> =
        Arc::new(Mutex::new(Connection::open("partyless.db").unwrap()));
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("tower_http=warn"))
                .unwrap(),
        )
        .init();

    init_db_schema().await.unwrap();

    let app = Router::new()
        .route("/event", get(get_event).post(post_event))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("server started on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/*
 * Checks the existance of each table in the DB, and if it does not exist, creates it
 */
async fn init_db_schema() -> Result<()> {
    let db = DB.lock().await;
    if let Err(rusqlite::Error::QueryReturnedNoRows) = db.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'",
        (),
        |row| row.get::<usize, String>(0),
    ) {
        info!("creating events table!");
        db.execute(
            "CREATE TABLE events (
            id    INTEGER PRIMARY KEY,
            event_name  TEXT NOT NULL,
            host_name TEXT NOT NULL,
            address TEXT NOT NULL,
            time TEXT NOT NULL,
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

async fn get_event(Query(params): Query<EventViewQuery>) {
    info!("{params:?}");
}

async fn post_event(Form(event_payload): Form<EventCreationForm>) {
    match Event::try_from(event_payload) {
        Ok(event) => {
            info!("got event {event:?}");
        }
        Err(err) => error!("failed POST /event due to parsing error: {err:#}"),
    }
}
