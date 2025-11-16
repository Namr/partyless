use std::{fs::read_to_string, sync::Arc};

use anyhow::{Result, anyhow};
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::get,
};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use clap::Parser;
use ramhorns::{Content, Template};
use rusqlite::{Connection, Row};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, signal, sync::Mutex};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to Configuration TOML file
    #[arg(short, long, default_value = "Config.toml")]
    config_file: String,

    /// Path to SQLite DB file
    #[arg(short, long, default_value = "partyless.db")]
    db_file: String,

    /// Path to SQLite DB file
    #[arg(long, default_value = "static")]
    static_pages: String,

    /// Path to SQLite DB file
    #[arg(long, default_value = "templates")]
    templates: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    bcrypt_cost: u32,
    bcrypt_salt: [u8; 16],
}

#[derive(Clone)]
struct RouteState {
    config: Config,
    db: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventCreationForm {
    event_name: String,
    hosts_name: String,
    address: String,
    description: String,
    date: String,
    time: String,
    timezone: String,
    password: Option<String>,
}

#[derive(Debug, Clone, Content)]
struct EventViewContent<'a> {
    event_name: &'a str,
    hosts_name: &'a str,
    address: &'a str,
    description: &'a str,
    time: String,
    guests: Vec<GuestContent<'a>>,
}

impl<'a> From<&'a Event> for EventViewContent<'a> {
    fn from(value: &'a Event) -> EventViewContent<'a> {
        let time_string = format!("{}", value.time.format("%A %B %d %Y %I:%M%p UTC %:::z"));

        EventViewContent {
            event_name: &value.event_name,
            hosts_name: &value.host_name,
            address: &value.address,
            description: &value.description,
            time: time_string,
            guests: vec![],
        }
    }
}

#[derive(Debug, Clone, Content)]
struct GuestContent<'a> {
    name: &'a str,
    note: &'a str,
    status: &'a str,
}

#[derive(Debug, Clone)]
struct Event {
    uuid: Uuid,
    event_name: String,
    host_name: String,
    address: String,
    description: String,
    password: Option<String>,
    time: DateTime<FixedOffset>,
}

impl Event {
    fn from_event_creation_form(value: EventCreationForm, config: &Config) -> Result<Self> {
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
            .ok_or(anyhow!("time + timezone was ambigious"))?
            .fixed_offset();

        let password = if let Some(password) = value.password {
            if password.len() >= 72 || password.is_empty() {
                None
            } else {
                Some(
                    bcrypt::hash_with_salt(password, config.bcrypt_cost, config.bcrypt_salt)?
                        .format_for_version(bcrypt::Version::TwoB),
                )
            }
        } else {
            None
        };

        Ok(Event {
            uuid: Uuid::new_v4(),
            event_name: value.event_name,
            host_name: value.hosts_name,
            address: value.address,
            description: value.description,
            password,
            time,
        })
    }

    fn commit(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT into events (
                uuid, 
                event_name, 
                host_name, 
                address, 
                description, 
                time, 
                password
                ) 
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        stmt.execute((
            &self.uuid,
            &self.event_name,
            &self.host_name,
            &self.address,
            &self.description,
            &self.time.to_rfc3339(),
            &self.password,
        ))?;
        Ok(())
    }

    fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let password = row.get::<&str, String>("password").ok();
        if let Ok(time) = DateTime::parse_from_rfc3339(&row.get::<&str, String>("time")?) {
            Ok(Self {
                uuid: row.get::<&str, Uuid>("uuid")?,
                event_name: row.get::<&str, String>("event_name")?,
                host_name: row.get::<&str, String>("host_name")?,
                address: row.get::<&str, String>("address")?,
                description: row.get::<&str, String>("description")?,
                time,
                password,
            })
        } else {
            // (note: amoussa) this ain't the right error but oh well
            Err(rusqlite::Error::InvalidQuery)
        }
    }

    fn load_from_uuid(uuid: Uuid, conn: &Connection) -> Option<Self> {
        let mut stmt = conn
            .prepare_cached("SELECT * FROM events WHERE uuid = ?1")
            .ok()?;
        stmt.query_one((&uuid,), Self::from_sql).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventViewQuery {
    uuid: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("tower_http=warn"))
                .unwrap(),
        )
        .init();

    let args = Args::parse();
    let config: Config = toml::from_str(&read_to_string(args.config_file)?)?;
    let db = Arc::new(Mutex::new(Connection::open(args.db_file)?));
    let mut route_state = RouteState { config, db };

    init_db_schema(&mut route_state).await.unwrap();

    let app = Router::new()
        .fallback_service(ServeDir::new(args.static_pages))
        .route("/event", get(get_event).post(post_event))
        .layer(TraceLayer::new_for_http())
        .with_state(route_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("server started on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

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
            id    INTEGER PRIMARY KEY,
            uuid BLOB NOT NULL,
            event_name  TEXT NOT NULL,
            host_name TEXT NOT NULL,
            address TEXT NOT NULL,
            description TEXT NOT NULL,
            time TEXT NOT NULL,
            password BLOB
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

#[axum::debug_handler]
async fn get_event(
    State(route_state): State<RouteState>,
    Query(params): Query<EventViewQuery>,
) -> (StatusCode, Html<String>) {
    if let Ok(uuid) = Uuid::parse_str(&params.uuid) {
        info!("{params:?}");
        let maybe_event = {
            let db_conn = route_state.db.lock().await;
            Event::load_from_uuid(uuid, &db_conn)
        };

        if let Some(event) = maybe_event {
            info!("got event {event:?}");
            let template =
                Template::new(read_to_string("templates/event.mustache").unwrap()).unwrap();
            let content = EventViewContent::from(&event);
            (StatusCode::OK, Html(template.render(&content)))
        } else {
            (StatusCode::NOT_FOUND, Html("".to_owned()))
        }
    } else {
        (StatusCode::BAD_REQUEST, Html("".to_owned()))
    }
}

async fn post_event(
    State(route_state): State<RouteState>,
    Form(event_payload): Form<EventCreationForm>,
) -> (HeaderMap, StatusCode) {
    let mut headers = HeaderMap::new();
    match Event::from_event_creation_form(event_payload, &route_state.config) {
        Ok(event) => {
            debug!("got event {event:?}");
            {
                let db_conn = route_state.db.lock().await;
                if let Err(err) = event.commit(&db_conn) {
                    error!("failed POST /event due sql error: {err:#}");
                    return (headers, StatusCode::BAD_REQUEST);
                }
            }
            let link = format!("/event?uuid={}", event.uuid);
            match link.parse() {
                Err(_) => return (headers, StatusCode::INTERNAL_SERVER_ERROR),
                Ok(link_header) => headers.insert("HX-Location", link_header),
            };
            (headers, StatusCode::OK)
        }
        Err(err) => {
            error!("failed to parse event payload; err: {err:#}");
            (headers, StatusCode::BAD_REQUEST)
        }
    }
}
