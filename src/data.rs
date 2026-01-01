use std::fmt;

use anyhow::{Result, anyhow};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use rusqlite::{Connection, Row, ToSql, types::FromSql};
use uuid::Uuid;

use crate::{
    BCRYPT_COST,
    routes::{EventCreationForm, RsvpForm},
};

#[derive(Debug, Clone)]
pub struct Guest {
    pub uuid: Uuid,
    pub name: String,
    pub note: String,
    pub password: Option<String>,
    pub response: Response,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub uuid: Uuid,
    pub event_name: String,
    pub host_name: String,
    pub address: String,
    pub description: String,
    pub password: Option<String>,
    pub time: DateTime<Utc>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Response {
    Yes,
    No,
    Maybe,
}

fn hash_password(maybe_password: Option<String>) -> Result<Option<String>> {
    if let Some(password) = maybe_password {
        if password.len() >= 72 || password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(bcrypt::hash(password, BCRYPT_COST)?))
        }
    } else {
        Ok(None)
    }
}

pub fn parse_time_data(date: &str, time: &str, timezone: &str) -> Result<DateTime<Utc>> {
    let tz = timezone.parse::<Tz>()?;
    let form = format!("{} {}", date, time);
    let naive_time = NaiveDateTime::parse_from_str(&form, "%Y-%m-%d %H:%M")?;
    Ok(tz
        .from_local_datetime(&naive_time)
        .single()
        .ok_or(anyhow!("time + timezone was ambigious"))?
        .to_utc())
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

impl TryFrom<RsvpForm> for Guest {
    type Error = anyhow::Error;

    fn try_from(value: RsvpForm) -> Result<Self> {
        let password = hash_password(value.password)?;
        let response = Response::try_from(value.response.as_str())?;
        Ok(Guest {
            uuid: Uuid::new_v4(),
            name: value.name,
            note: value.note,
            password,
            response,
        })
    }
}

impl Guest {
    pub fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let password = row.get::<&str, String>("password").ok();
        Ok(Guest {
            uuid: row.get("uuid")?,
            name: row.get("name")?,
            note: row.get("note")?,
            response: row.get("response")?,
            password,
        })
    }

    pub fn commit(&self, conn: &Connection, event_uuid: &Uuid) -> Result<()> {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO guests(
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

    pub fn commit_update(&self, conn: &Connection) -> Result<()> {
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

    pub fn commit_delete(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached("DELETE FROM guests WHERE uuid = ?1")?;
        stmt.execute((self.uuid,))?;
        Ok(())
    }

    pub fn get_event_uuid(&self, conn: &Connection) -> Result<Uuid> {
        let mut stmt = conn.prepare_cached("SELECT event_uuid FROM guests WHERE uuid = ?1")?;
        Ok(stmt.query_one((self.uuid,), |r| r.get("event_uuid"))?)
    }

    pub fn load_from_event_uuid(event_uuid: Uuid, conn: &Connection) -> Result<Vec<Self>> {
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

    pub fn load_from_guest_uuid(guest_uuid: Uuid, conn: &Connection) -> Result<Self> {
        let mut stmt = conn.prepare_cached(
            "SELECT uuid, name, note, response, password FROM guests WHERE uuid = ?1",
        )?;
        Ok(stmt.query_one((guest_uuid,), Self::from_sql)?)
    }
}

impl TryFrom<EventCreationForm> for Event {
    type Error = anyhow::Error;
    fn try_from(value: EventCreationForm) -> Result<Self> {
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
        let password = hash_password(value.password)?;
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
}
impl Event {
    pub fn commit(&self, conn: &Connection) -> Result<()> {
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

    pub fn commit_update(&self, conn: &Connection) -> Result<()> {
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

    pub fn commit_delete(&self, conn: &Connection) -> Result<()> {
        let mut stmt = conn.prepare_cached("DELETE FROM events WHERE uuid = ?1")?;
        stmt.execute((self.uuid,))?;
        Ok(())
    }

    pub fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
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

    pub fn load_from_uuid(uuid: Uuid, conn: &Connection) -> Result<Self> {
        let mut stmt = conn.prepare_cached("SELECT * FROM events WHERE uuid = ?1")?;
        Ok(stmt.query_one((&uuid,), Self::from_sql)?)
    }
}
