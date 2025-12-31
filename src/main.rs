use std::{fmt, fs::read_to_string, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use clap::Parser;
use ramhorns::{Content, Template};
use rusqlite::{Connection, Row, ToSql, types::FromSql};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, signal, sync::Mutex};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use uuid::Uuid;

const CLEANUP_PERIOD: Duration = Duration::from_secs(5 * 60 * 60);
const CLEANUP_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

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
    event_template: Arc<Template<'static>>,
    guest_edit_template: Arc<Template<'static>>,
    event_edit_template: Arc<Template<'static>>,
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
struct EventUpdateForm {
    event_id: String,
    event_name: String,
    hosts_name: String,
    address: String,
    description: String,
    date: String,
    time: String,
    timezone: String,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RsvpForm {
    uuid: String,
    name: String,
    note: String,
    password: Option<String>,
    response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateRsvpForm {
    guest_id: String,
    name: String,
    note: String,
    password: String,
    response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthForm {
    uuid: String,
    password: String,
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
    fn new(event: &'a Event, guests: &'a [Guest]) -> EventViewContent<'a> {
        EventViewContent {
            event_name: &event.event_name,
            hosts_name: &event.host_name,
            address: &event.address,
            description: &event.description,
            time: event.time.to_rfc2822(),
            guests: guests.iter().map(GuestContent::from).collect(),
        }
    }
}

#[derive(Debug, Clone, Content)]
struct GuestContent<'a> {
    id: String,
    name: &'a str,
    note: &'a str,
    status: String,
}

impl<'a> From<&'a Guest> for GuestContent<'a> {
    fn from(value: &'a Guest) -> Self {
        Self {
            id: value.uuid.to_string(),
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
    time: DateTime<Utc>,
}

fn parse_time_data(date: &str, time: &str, timezone: &str) -> Result<DateTime<Utc>> {
    let tz = timezone.parse::<Tz>()?;
    let form = format!("{} {}", date, time);
    let naive_time = NaiveDateTime::parse_from_str(&form, "%Y-%m-%d %H:%M")?;
    Ok(tz
        .from_local_datetime(&naive_time)
        .single()
        .ok_or(anyhow!("time + timezone was ambigious"))?
        .to_utc())
}

impl Event {
    fn from_event_creation_form(value: EventCreationForm, config: &Config) -> Result<Self> {
        if value.event_name.is_empty()
            || value.hosts_name.is_empty()
            || value.address.is_empty()
            || value.date.is_empty()
            || value.time.is_empty()
            || value.timezone.is_empty()
        {
            return Err(anyhow!("Event creation form had a blank field"));
        }

        let time = parse_time_data(&value.date, &value.time, &value.timezone)?;
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
            &self.time.timestamp_millis(),
            &self.password,
        ))?;
        Ok(())
    }

    fn commit_update(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "UPDATE events SET
                event_name = ?1, 
                host_name = ?2,
                address = ?3,
                description = ?4,
                time = ?5
            WHERE uuid = ?6",
        )?;
        stmt.execute((
            &self.event_name,
            &self.host_name,
            &self.address,
            &self.description,
            &self.time.timestamp_millis(),
            self.uuid,
        ))?;
        Ok(())
    }

    fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let password = row.get::<&str, String>("password").ok();
        if let Some(time) = DateTime::from_timestamp_millis(row.get::<&str, i64>("time")?) {
            Ok(Self {
                uuid: row.get::<&str, Uuid>("uuid")?,
                event_name: row.get::<&str, String>("event_name")?,
                host_name: row.get::<&str, String>("host_name")?,
                address: row.get::<&str, String>("address")?,
                description: row.get::<&str, String>("description")?,
                time: time.to_utc(),
                password,
            })
        } else {
            // (note: amoussa) this ain't the right error but oh well
            Err(rusqlite::Error::InvalidQuery)
        }
    }

    fn load_from_uuid(uuid: Uuid, conn: &Connection) -> Result<Self> {
        let mut stmt = conn.prepare_cached("SELECT * FROM events WHERE uuid = ?1")?;
        Ok(stmt.query_one((&uuid,), Self::from_sql)?)
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
    uuid: Uuid,
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
            uuid: Uuid::new_v4(),
            name: value.name,
            note: value.note,
            password,
            response,
        })
    }

    fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let password = row.get::<&str, String>("password").ok();
        Ok(Guest {
            uuid: row.get("uuid")?,
            name: row.get("name")?,
            note: row.get("note")?,
            response: row.get("response")?,
            password,
        })
    }

    fn commit(&self, conn: &Connection, event_uuid: &Uuid) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT into guests(
                uuid,
                event_uuid, 
                name, 
                note,
                password, 
                response
                ) 
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        stmt.execute((
            &self.uuid,
            event_uuid,
            &self.name,
            &self.note,
            &self.password,
            self.response,
        ))?;
        Ok(())
    }

    fn commit_update(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "UPDATE guests SET
                name = ?1, 
                note = ?2,
                response = ?3
            WHERE uuid = ?4",
        )?;
        stmt.execute((&self.name, &self.note, self.response, self.uuid))?;
        Ok(())
    }

    fn get_event_uuid(&self, conn: &Connection) -> Result<Uuid> {
        let mut stmt = conn.prepare_cached("SELECT event_uuid FROM guests WHERE uuid = ?1")?;
        Ok(stmt.query_one((self.uuid,), |r| r.get("event_uuid"))?)
    }

    fn load_from_event_uuid(event_uuid: Uuid, conn: &Connection) -> Result<Vec<Self>> {
        let mut stmt = conn.prepare_cached(
            "SELECT guests.uuid, name, note, response 
                FROM events RIGHT JOIN guests ON guests.event_uuid = events.uuid 
                WHERE events.uuid = ?1",
        )?;
        let res = stmt.query_map((event_uuid,), |row| {
            Ok(Guest {
                uuid: row.get("uuid")?,
                name: row.get("name")?,
                note: row.get("note")?,
                response: row.get("response")?,
                password: None,
            })
        })?;

        Ok(res.filter_map(|guest| guest.ok()).collect::<Vec<Self>>())
    }

    fn load_from_guest_uuid(guest_uuid: Uuid, conn: &Connection) -> Result<Self> {
        let mut stmt = conn.prepare_cached(
            "SELECT uuid, name, note, response, password FROM guests WHERE uuid = ?1",
        )?;
        Ok(stmt.query_one((guest_uuid,), Self::from_sql)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventViewQuery {
    uuid: String,
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
    let config: Config = toml::from_str(
        &read_to_string(args.config_file)
            .with_context(|| "Couldn't find configuration TOML file")?,
    )?;

    let db = Arc::new(Mutex::new(Connection::open(args.db_file)?));

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
        config,
        db,
        event_template,
        guest_edit_template,
        event_edit_template,
    };

    init_db_schema(&mut route_state).await?;

    let app = Router::new()
        .fallback_service(ServeDir::new(args.static_pages))
        .route("/event", get(get_event).post(post_event).put(put_event))
        .route("/rsvp", post(post_rsvp).put(put_rsvp))
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

#[axum::debug_handler]
async fn get_event(
    State(route_state): State<RouteState>,
    Query(params): Query<EventViewQuery>,
) -> Result<(StatusCode, Html<String>), AppError> {
    let uuid = Uuid::parse_str(&params.uuid)?;
    let (event, guests) = {
        let db_conn = route_state.db.lock().await;
        (
            Event::load_from_uuid(uuid, &db_conn).context("failed to load event from uuid")?,
            Guest::load_from_event_uuid(uuid, &db_conn)
                .context("failed to load guests from event uuid")?,
        )
    };

    debug!("got event {event:?}");
    let content = EventViewContent::new(&event, &guests);
    Ok((
        StatusCode::OK,
        Html(route_state.event_template.render(&content)),
    ))
}

async fn post_event(
    State(route_state): State<RouteState>,
    Form(event_payload): Form<EventCreationForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let event = Event::from_event_creation_form(event_payload, &route_state.config)?;
    debug!("got event {event:?}");
    {
        let db_conn = route_state.db.lock().await;
        event.commit(&db_conn)?;
    }
    let link = format!("/event?uuid={}", event.uuid).parse()?;
    headers.insert("HX-Redirect", link);
    Ok((headers, StatusCode::OK))
}

async fn put_event(
    State(route_state): State<RouteState>,
    Form(event_payload): Form<EventUpdateForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let db_conn = route_state.db.lock().await;
    let event_uuid =
        Uuid::parse_str(&event_payload.event_id).with_context(|| "Failed to parse event UUID.")?;
    let mut old_event = Event::load_from_uuid(event_uuid, &db_conn)
        .with_context(|| "Failed to load event from UUID.")?;

    let new_time = parse_time_data(
        &event_payload.date,
        &event_payload.time,
        &event_payload.timezone,
    )
    .with_context(|| "Failed to pars time data")?;
    old_event.event_name = event_payload.event_name;
    old_event.host_name = event_payload.hosts_name;
    old_event.address = event_payload.address;
    old_event.description = event_payload.description;
    old_event.time = new_time;

    if let Some(ref password_hash) = old_event.password {
        if bcrypt::verify(event_payload.password, &password_hash)? {
            old_event
                .commit_update(&db_conn)
                .with_context(|| "Failed to update event in database")?;
            let link = format!("/event?uuid={}", event_uuid.to_string()).parse()?;
            headers.insert("HX-Redirect", link);
            return Ok((headers, StatusCode::OK));
        }
    }

    Ok((headers, StatusCode::FORBIDDEN))
}

async fn post_rsvp(
    State(route_state): State<RouteState>,
    Form(rsvp_payload): Form<RsvpForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let event_uuid = Uuid::parse_str(&rsvp_payload.uuid)?;
    let guest = Guest::from_rsvp_form(rsvp_payload, &route_state.config)?;
    info!("event_uuid: {} guest {:?}", event_uuid, guest);

    let db_conn = route_state.db.lock().await;
    guest.commit(&db_conn, &event_uuid)?;

    headers.insert("HX-Refresh", "true".parse()?);
    Ok((headers, StatusCode::OK))
}

async fn put_rsvp(
    State(route_state): State<RouteState>,
    Form(rsvp_payload): Form<UpdateRsvpForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let guest_uuid = Uuid::parse_str(&rsvp_payload.guest_id)?;
    let db_conn = route_state.db.lock().await;
    let mut old_guest = Guest::load_from_guest_uuid(guest_uuid, &db_conn)?;

    if let Some(ref password_hash) = old_guest.password {
        if bcrypt::verify(rsvp_payload.password, &password_hash)? {
            let event_uuid = old_guest.get_event_uuid(&db_conn)?;
            let link = format!("/event?uuid={}", event_uuid).parse()?;

            old_guest.name = rsvp_payload.name;
            old_guest.note = rsvp_payload.note;
            old_guest.response = Response::try_from(rsvp_payload.response.as_str())?;
            old_guest.commit_update(&db_conn)?;

            headers.insert("HX-Redirect", link);
            return Ok((headers, StatusCode::OK));
        }
    }

    Ok((headers, StatusCode::FORBIDDEN))
}

async fn post_auth_guest(
    State(route_state): State<RouteState>,
    Form(auth_form): Form<AuthForm>,
) -> Result<(StatusCode, Html<String>), AppError> {
    let db_conn = route_state.db.lock().await;
    let guest = Guest::load_from_guest_uuid(Uuid::from_str(&auth_form.uuid)?, &db_conn)?;
    if let Some(ref password_hash) = guest.password {
        if bcrypt::verify(auth_form.password, &password_hash)? {
            // send edit guest form template
            let content = GuestContent::from(&guest);
            Ok((
                StatusCode::OK,
                Html(route_state.guest_edit_template.render(&content)),
            ))
        } else {
            Ok((
                StatusCode::BAD_REQUEST,
                Html("<p class=\"error\">Incorrect password.</p>".to_owned()),
            ))
        }
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Html("<p class=\"error\">This guest did not set a password.</p>".to_owned()),
        ))
    }
}

async fn post_auth_event(
    State(route_state): State<RouteState>,
    Form(auth_form): Form<AuthForm>,
) -> Result<(StatusCode, Html<String>), AppError> {
    let db_conn = route_state.db.lock().await;
    let event = Event::load_from_uuid(
        Uuid::from_str(&auth_form.uuid).with_context(|| "Failed to parse UUID")?,
        &db_conn,
    )
    .with_context(|| "Failed to load event from UUID")?;
    if let Some(ref password_hash) = event.password {
        if bcrypt::verify(auth_form.password, &password_hash)
            .with_context(|| "Failed to validate password")?
        {
            // send edit guest form template
            let content = EventViewContent::new(&event, &[]);
            Ok((
                StatusCode::OK,
                Html(route_state.event_edit_template.render(&content)),
            ))
        } else {
            Ok((
                StatusCode::BAD_REQUEST,
                Html("<p class=\"error\">Incorrect password.</p>".to_owned()),
            ))
        }
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Html("<p class=\"error\">This guest did not set a password.</p>".to_owned()),
        ))
    }
}
