use super::data::*;
use super::*;

use anyhow::{Context, Result};
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
};
use metrics::{Metric, increment_metric};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Content)]
struct EventViewContent<'a> {
    event_name: &'a str,
    hosts_name: &'a str,
    address: &'a str,
    description: &'a str,
    time: String,
    yes_num: u32,
    no_num: u32,
    maybe_num: u32,
    guests: Vec<GuestContent<'a>>,
}

impl<'a> EventViewContent<'a> {
    fn new(event: &'a Event, guests: &'a [Guest]) -> EventViewContent<'a> {
        let (yes_num, no_num, maybe_num) = guests.iter().fold((0, 0, 0), |acc, g| {
            (
                acc.0 + (g.response == Response::Yes) as u32,
                acc.1 + (g.response == Response::No) as u32,
                acc.2 + (g.response == Response::Maybe) as u32,
            )
        });

        EventViewContent {
            event_name: &event.event_name,
            hosts_name: &event.host_name,
            address: &event.address,
            description: &event.description,
            time: event.time.to_rfc2822(),
            yes_num,
            no_num,
            maybe_num,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventViewQuery {
    uuid: String,
}

pub async fn get_event(
    State(route_state): State<RouteState>,
    Query(params): Query<EventViewQuery>,
) -> Result<(StatusCode, Html<String>), AppError> {
    let uuid = Uuid::parse_str(&params.uuid)?;
    let db_conn = route_state.db.lock().await;
    let maybe_event = Event::load_from_uuid(uuid, &db_conn);

    if let Ok(event) = maybe_event {
        let guests = Guest::load_from_event_uuid(uuid, &db_conn)
            .context("Failed to load guests from event UUID.")?;
        let content = EventViewContent::new(&event, &guests);
        Ok((
            StatusCode::OK,
            Html(route_state.event_template.render(&content)),
        ))
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Html(include_str!("../static/404.html").to_string()),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCreationForm {
    pub event_name: String,
    pub hosts_name: String,
    pub address: String,
    pub description: String,
    pub date: String,
    pub time: String,
    pub timezone: String,
    pub password: Option<String>,
}

pub async fn post_event(
    State(route_state): State<RouteState>,
    Form(event_payload): Form<EventCreationForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let event =
        Event::try_from(event_payload).with_context(|| "Failed to create event from form.")?;
    {
        let db_conn = route_state.db.lock().await;
        event
            .commit(&db_conn)
            .with_context(|| "Failed to write event to the database.")?;
    }
    info!(
        "event {} created! Has UUID {}",
        event.event_name, event.uuid
    );

    {
        let metrics = route_state.metrics.lock().await;
        increment_metric(Metric::EventAdded, &metrics)?;
    }

    let link = format!("/event?uuid={}", event.uuid).parse()?;
    headers.insert("HX-Redirect", link);
    Ok((headers, StatusCode::OK))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventUpdateForm {
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

pub async fn put_event(
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
    .with_context(|| "Failed to parse time data.")?;
    old_event.event_name = event_payload.event_name;
    old_event.host_name = event_payload.hosts_name;
    old_event.address = event_payload.address;
    old_event.description = event_payload.description;
    old_event.time = new_time;

    if let Some(ref password_hash) = old_event.password
        && bcrypt::verify(event_payload.password, password_hash)?
    {
        info!("Updating event {}", old_event.event_name);
        old_event
            .commit_update(&db_conn)
            .with_context(|| "Failed to update event in database")?;
        let link = format!("/event?uuid={}", event_uuid).parse()?;

        {
            let metrics = route_state.metrics.lock().await;
            increment_metric(Metric::EventChanged, &metrics)?;
        }

        headers.insert("HX-Redirect", link);
        return Ok((headers, StatusCode::OK));
    }

    info!(
        "Failed to update event {}; Wrong password.",
        old_event.event_name
    );
    {
        let metrics = route_state.metrics.lock().await;
        increment_metric(Metric::EventLoginFailed, &metrics)?;
    }
    Ok((headers, StatusCode::FORBIDDEN))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDeleteForm {
    event_id: String,
    password: String,
}

pub async fn delete_event(
    State(route_state): State<RouteState>,
    Form(event_payload): Form<EventDeleteForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let db_conn = route_state.db.lock().await;
    let event_uuid =
        Uuid::parse_str(&event_payload.event_id).with_context(|| "Failed to parse event UUID.")?;
    let old_event = Event::load_from_uuid(event_uuid, &db_conn)
        .with_context(|| "Failed to load event from UUID.")?;

    if let Some(ref password_hash) = old_event.password
        && bcrypt::verify(event_payload.password, password_hash)
            .with_context(|| "Failed password verification for event deletion.")?
    {
        let link = "/index.html".parse()?;
        headers.insert("HX-Redirect", link);
        info!("Deleting event {}", old_event.event_name);

        old_event
            .commit_delete(&db_conn)
            .with_context(|| "Failed to delete event in database")?;
        {
            let metrics = route_state.metrics.lock().await;
            increment_metric(Metric::EventDeleted, &metrics)?;
        }
        return Ok((headers, StatusCode::OK));
    }

    info!(
        "Failed to delete event {}; Wrong password",
        old_event.event_name
    );
    {
        let metrics = route_state.metrics.lock().await;
        increment_metric(Metric::EventLoginFailed, &metrics)?;
    }
    Ok((headers, StatusCode::FORBIDDEN))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsvpForm {
    pub uuid: String,
    pub name: String,
    pub note: String,
    pub password: Option<String>,
    pub response: String,
}

pub async fn post_rsvp(
    State(route_state): State<RouteState>,
    Form(rsvp_payload): Form<RsvpForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let event_uuid = Uuid::parse_str(&rsvp_payload.uuid)?;
    let guest =
        Guest::try_from(rsvp_payload).with_context(|| "Failed to create guest from form.")?;
    info!("Created RSVP for guest {}", guest.name);

    let db_conn = route_state.db.lock().await;
    guest
        .commit(&db_conn, &event_uuid)
        .with_context(|| "Failed to write guest to the database.")?;

    {
        let metrics = route_state.metrics.lock().await;
        increment_metric(Metric::RSVPAdded, &metrics)?;
    }
    headers.insert("HX-Refresh", "true".parse()?);
    Ok((headers, StatusCode::OK))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRsvpForm {
    guest_id: String,
    name: String,
    note: String,
    password: String,
    response: String,
}

pub async fn put_rsvp(
    State(route_state): State<RouteState>,
    Form(rsvp_payload): Form<UpdateRsvpForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let guest_uuid =
        Uuid::parse_str(&rsvp_payload.guest_id).with_context(|| "Failed to parse guest UUID.")?;
    let db_conn = route_state.db.lock().await;
    let mut old_guest = Guest::load_from_guest_uuid(guest_uuid, &db_conn)
        .with_context(|| "Failed to load guest from UUID.")?;

    if let Some(ref password_hash) = old_guest.password
        && bcrypt::verify(rsvp_payload.password, password_hash)
            .with_context(|| "Failed password verification for guest registration.")?
    {
        let event_uuid = old_guest
            .get_event_uuid(&db_conn)
            .with_context(|| "Failed to get event uuid for guest.")?;
        let link = format!("/event?uuid={}", event_uuid).parse()?;
        info!("Updated RSVP for guest {}", old_guest.name);

        old_guest.name = rsvp_payload.name;
        old_guest.note = rsvp_payload.note;
        old_guest.response = Response::try_from(rsvp_payload.response.as_str())
            .with_context(|| "Failed to parse response field from payload.")?;
        old_guest.commit_update(&db_conn)?;

        {
            let metrics = route_state.metrics.lock().await;
            increment_metric(Metric::RSVPChanged, &metrics)?;
        }
        headers.insert("HX-Redirect", link);
        return Ok((headers, StatusCode::OK));
    }

    info!(
        "Failed to update RSVP for guest {}; Wrong password.",
        old_guest.name
    );
    {
        let metrics = route_state.metrics.lock().await;
        increment_metric(Metric::RSVPLoginFailed, &metrics)?;
    }
    Ok((headers, StatusCode::FORBIDDEN))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRsvpForm {
    guest_id: String,
    password: String,
}

pub async fn delete_rsvp(
    State(route_state): State<RouteState>,
    Form(rsvp_payload): Form<DeleteRsvpForm>,
) -> Result<(HeaderMap, StatusCode), AppError> {
    let mut headers = HeaderMap::new();
    let guest_uuid = Uuid::parse_str(&rsvp_payload.guest_id)?;
    let db_conn = route_state.db.lock().await;
    let old_guest = Guest::load_from_guest_uuid(guest_uuid, &db_conn)?;

    if let Some(ref password_hash) = old_guest.password
        && bcrypt::verify(rsvp_payload.password, password_hash)
            .with_context(|| "Failed password verification for rsvp deletion.")?
    {
        info!("Deleting RSVP for {}", old_guest.name);
        let event_uuid = old_guest
            .get_event_uuid(&db_conn)
            .with_context(|| "Failed to get event UUID for guest.")?;
        let link = format!("/event?uuid={}", event_uuid).parse()?;
        headers.insert("HX-Redirect", link);

        old_guest
            .commit_delete(&db_conn)
            .with_context(|| "Failed to delete guest from database.")?;

        {
            let metrics = route_state.metrics.lock().await;
            increment_metric(Metric::RSVPDeleted, &metrics)?;
        }
        return Ok((headers, StatusCode::OK));
    }

    info!(
        "Failed to delete RSVP for {}; Wrong password.",
        old_guest.name
    );
    {
        let metrics = route_state.metrics.lock().await;
        increment_metric(Metric::RSVPLoginFailed, &metrics)?;
    }
    Ok((headers, StatusCode::FORBIDDEN))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthForm {
    uuid: String,
    password: String,
}

pub async fn post_auth_guest(
    State(route_state): State<RouteState>,
    Form(auth_form): Form<AuthForm>,
) -> Result<(StatusCode, Html<String>), AppError> {
    let db_conn = route_state.db.lock().await;
    let guest = Guest::load_from_guest_uuid(
        Uuid::from_str(&auth_form.uuid).with_context(|| "Failed to parse UUID.")?,
        &db_conn,
    )
    .with_context(|| "Failed to load guest from UUID")?;
    if let Some(ref password_hash) = guest.password {
        if bcrypt::verify(auth_form.password, password_hash)
            .with_context(|| "Failed to verify password for guest authentication.")?
        {
            info!("Authorized guest {}", guest.name);
            // send edit guest form template
            let content = GuestContent::from(&guest);
            Ok((
                StatusCode::OK,
                Html(route_state.guest_edit_template.render(&content)),
            ))
        } else {
            info!("Guest {} failed to authorize", guest.name);
            {
                let metrics = route_state.metrics.lock().await;
                increment_metric(Metric::RSVPLoginFailed, &metrics)?;
            }
            Ok((
                StatusCode::BAD_REQUEST,
                Html("<p class=\"error\">Incorrect password.</p>".to_owned()),
            ))
        }
    } else {
        {
            let metrics = route_state.metrics.lock().await;
            increment_metric(Metric::RSVPLoginFailed, &metrics)?;
        }
        info!(
            "Guest {} failed to authorize due to a lack of password",
            guest.name
        );
        Ok((
            StatusCode::NOT_FOUND,
            Html("<p class=\"error\">This guest did not set a password.</p>".to_owned()),
        ))
    }
}

pub async fn post_auth_event(
    State(route_state): State<RouteState>,
    Form(auth_form): Form<AuthForm>,
) -> Result<(StatusCode, Html<String>), AppError> {
    let db_conn = route_state.db.lock().await;
    let event = Event::load_from_uuid(
        Uuid::from_str(&auth_form.uuid).with_context(|| "Failed to parse UUID.")?,
        &db_conn,
    )
    .with_context(|| "Failed to load event from UUID.")?;
    if let Some(ref password_hash) = event.password {
        if bcrypt::verify(auth_form.password, password_hash)
            .with_context(|| "Failed to validate password for event authentication.")?
        {
            // send edit guest form template
            info!("Event {} authorized", event.event_name);
            let content = EventViewContent::new(&event, &[]);
            Ok((
                StatusCode::OK,
                Html(route_state.event_edit_template.render(&content)),
            ))
        } else {
            info!("Event {} failed authorization", event.event_name);
            {
                let metrics = route_state.metrics.lock().await;
                increment_metric(Metric::EventLoginFailed, &metrics)?;
            }
            Ok((
                StatusCode::BAD_REQUEST,
                Html("<p class=\"error\">Incorrect password.</p>".to_owned()),
            ))
        }
    } else {
        info!(
            "User tried to authorize event {} which has no password",
            event.event_name
        );
        {
            let metrics = route_state.metrics.lock().await;
            increment_metric(Metric::EventLoginFailed, &metrics)?;
        }
        Ok((
            StatusCode::NOT_FOUND,
            Html("<p class=\"error\">This guest did not set a password.</p>".to_owned()),
        ))
    }
}
