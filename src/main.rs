use std::{fmt, fs::read_to_string, sync::Arc};

use anyhow::{Result, anyhow};
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use clap::Parser;
use ramhorns::{Content, Template};
use rusqlite::{Connection, Row, ToSql, types::FromSql};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RsvpForm {
    uuid: String,
    name: String,
    note: String,
    password: Option<String>,
    response: String,
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

impl<'a> EventViewContent<'a> {
    fn new(event: &'a Event, guests: &'a Vec<Guest>) -> EventViewContent<'a>{
        let time_string = format!("{}", event.time.format("%A %B %d %Y %I:%M%p UTC %:::z"));
        EventViewContent {
            event_name: &event.event_name,
            hosts_name: &event.host_name,
            address: &event.address,
            description: &event.description,
            time: time_string,
            guests: guests.iter().map(|g| GuestContent::from(g)).collect(),
        }
    }
}

#[derive(Debug, Clone, Content)]
struct GuestContent<'a> {
    name: &'a str,
    note: &'a str,
    status: String,
}

impl<'a> From<&'a Guest> for GuestContent<'a> {
    fn from(value: &'a Guest) -> Self {
        Self {
            name: &value.name,
            note: &value.note,
            status: value.response.to_string(),
        }
    }
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

        let password = hash_password(value.password, config)?;
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

    fn row_id_from_uuid(uuid: &Uuid, conn: &Connection) -> Option<u64> {
        let mut stmt = conn
            .prepare_cached("SELECT id FROM events WHERE uuid = ?1")
            .ok()?;
        let id: u64 = stmt.query_one((uuid,), |row| row.get(0)).ok()?;
        Some(id)
    }
}

#[derive(Debug, Copy, Clone)]
enum Response {
    Yes,
    No,
    Maybe,
}

impl ToSql for Response {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            Response::Yes => 0.to_sql(),
            Response::No => 1.to_sql(),
            Response::Maybe => 2.to_sql(),
        }
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromSql for Response {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let i = value.as_i64()?;
        match i {
            0 => Ok(Response::Yes),
            1 => Ok(Response::No),
            2 => Ok(Response::Maybe),
            other => Err(rusqlite::types::FromSqlError::OutOfRange(other)),
        }
    }
}

impl TryFrom<&str> for Response {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "yes" => Ok(Response::Yes),
            "no" => Ok(Response::No),
            "maybe" => Ok(Response::Maybe),
            other => Err(anyhow!(
                "failed to convert string {} to Response enum",
                other
            )),
        }
    }
}

#[derive(Debug, Clone)]
struct Guest {
    name: String,
    note: String,
    password: Option<String>,
    response: Response,
}

impl Guest {
    fn from_rsvp_form(value: RsvpForm, config: &Config) -> Result<Self> {
        let password = hash_password(value.password, config)?;
        let response = Response::try_from(value.response.as_str())?;
        Ok(Guest {
            name: value.name,
            note: value.note,
            password,
            response,
        })
    }

    fn commit(&self, conn: &Connection, event_uuid: &Uuid) -> Result<()> {
        let event_id = Event::row_id_from_uuid(event_uuid, conn)
            .ok_or(anyhow!("no event with uuid {}", event_uuid))?;
        let mut stmt = conn.prepare_cached(
            "INSERT into guests(
                event_id, 
                name, 
                note,
                password, 
                response
                ) 
            VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        stmt.execute((event_id, &self.name, &self.note, &self.password, self.response))?;
        Ok(())
    }

    fn load_from_event_uuid(event_uuid: Uuid, conn: &Connection) -> Option<Vec<Self>> {
        let mut stmt = conn
            .prepare_cached("SELECT name, note, response FROM events RIGHT JOIN guests ON guests.event_id = events.id WHERE uuid = ?1").ok()?;
        let res = stmt.query_map((event_uuid,), |row| Ok(Guest {
            name: row.get("name")?,
            note: row.get("note")?,
            response: row.get("response")?,
            password: None
        })).ok()?;

        Some(res.filter_map(|guest| guest.ok()).collect::<Vec<Self>>())
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
            EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("tower_http=warn"))?,
        )
        .init();

    let args = Args::parse();
    let config: Config = toml::from_str(&read_to_string(args.config_file)?)?;
    let db = Arc::new(Mutex::new(Connection::open(args.db_file)?));
    let mut route_state = RouteState { config, db };

    init_db_schema(&mut route_state).await?;

    let app = Router::new()
        .fallback_service(ServeDir::new(args.static_pages))
        .route("/event", get(get_event).post(post_event))
        .route("/rsvp", post(post_rsvp))
        .layer(TraceLayer::new_for_http())
        .with_state(route_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    info!("server started on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn hash_password(maybe_password: Option<String>, config: &Config) -> Result<Option<String>> {
    if let Some(password) = maybe_password {
        if password.len() >= 72 || password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                bcrypt::hash_with_salt(password, config.bcrypt_cost, config.bcrypt_salt)?
                    .format_for_version(bcrypt::Version::TwoB),
            ))
        }
    } else {
        Ok(None)
    }
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

    if let Err(rusqlite::Error::QueryReturnedNoRows) = db.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='guests'",
        (),
        |row| row.get::<usize, String>(0),
    ) {
        info!("creating guests table!");
        db.execute(
            "CREATE TABLE guests (
            id    INTEGER PRIMARY KEY,
            event_id INTEGER NOT NULL,
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

#[axum::debug_handler]
async fn get_event(
    State(route_state): State<RouteState>,
    Query(params): Query<EventViewQuery>,
) -> (StatusCode, Html<String>) {
    if let Ok(uuid) = Uuid::parse_str(&params.uuid) {
        info!("{params:?}");
        let (maybe_event, maybe_guests) = {
            let db_conn = route_state.db.lock().await;
            (Event::load_from_uuid(uuid, &db_conn), Guest::load_from_event_uuid(uuid, &db_conn))
        };

        if let Some(event) = maybe_event && let Some(guests) = maybe_guests {
            info!("got event {event:?}");
            let template =
                Template::new(read_to_string("templates/event.mustache").unwrap()).unwrap();
            let content = EventViewContent::new(&event, &guests);
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

async fn post_rsvp(
    State(route_state): State<RouteState>,
    Form(rsvp_payload): Form<RsvpForm>,
) -> (HeaderMap, StatusCode) {
    let mut headers = HeaderMap::new();
    if let Ok(event_uuid) = Uuid::parse_str(&rsvp_payload.uuid)
        && let Ok(guest) = Guest::from_rsvp_form(rsvp_payload, &route_state.config)
    {
        let db_conn = route_state.db.lock().await;
        info!("event_uuid: {} guest {:?}", event_uuid, guest);
        match guest.commit(&db_conn, &event_uuid) {
            Ok(()) => {
                headers.insert("HX-Refresh", "true".parse().unwrap());
                (headers, StatusCode::OK)
            }
            Err(err) => {
                error!("failed to commit guest into db {err:#}");
                (headers, StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        (headers, StatusCode::BAD_REQUEST)
    }
}
