/*
 * (note: amoussa) Make no mistake, this is a bad metrics system which only provides counters.
 * It really needs a time series database to track how the counters are moving over time.
 * This could be done via periodic sampling on-top of this current method but... bleh.
 */
use anyhow::Context;
use anyhow::Result;
use rusqlite::Connection;
use strum::{Display, EnumIter, IntoEnumIterator};
use tracing::info;

pub struct MetricsConnection {
    metrics_db: Connection,
}

#[derive(Clone, Copy, Debug, Display, EnumIter)]
pub enum Metric {
    EventAdded,
    RSVPAdded,
    EventChanged,
    RSVPChanged,
    EventDeleted,
    RSVPDeleted,
    RSVPLoginFailed,
    EventLoginFailed,
}

pub fn init_metrics(metrics_db_file: &str) -> Result<MetricsConnection> {
    let db =
        Connection::open(metrics_db_file).context("Failed to open metrics database connection.")?;
    if let Err(rusqlite::Error::QueryReturnedNoRows) = db.query_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='metrics'",
        (),
        |row| row.get::<usize, String>(0),
    ) {
        info!("creating metrics table!");
        db.execute(
            "CREATE TABLE metrics (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            count INTEGER NOT NULL
        )",
            (),
        )?;
    }

    // init event entries
    for metric in Metric::iter() {
        init_metric(&metric.to_string(), &db)?;
    }
    Ok(MetricsConnection { metrics_db: db })
}

fn init_metric(name: &str, db: &Connection) -> Result<()> {
    // query for row
    let mut exists_stmt = db
        .prepare_cached("SELECT count FROM metrics WHERE name = ?1")
        .with_context(|| "Couldn't prepare metric exists check SQL query.")?;
    let mut create_stmt = db
        .prepare_cached("INSERT INTO metrics(name, count) VALUES (?1, 0)")
        .with_context(|| "Couldn't prepare metric insert SQL query.")?;
    if let Err(rusqlite::Error::QueryReturnedNoRows) = exists_stmt.query_row((name,), |_r| Ok(0)) {
        // if it doesn't exist, push it
        create_stmt
            .execute((name,))
            .with_context(|| format!("Could not create metric {}", name))?;
    }
    Ok(())
}

pub fn increment_metric(metric: Metric, connection: &MetricsConnection) -> Result<()> {
    let mut inc_stmt = connection
        .metrics_db
        .prepare_cached("UPDATE METRICS SET count = count + 1 WHERE name = ?1")
        .with_context(|| "Couldn't prepare metric update SQL query.")?;
    inc_stmt.execute((&metric.to_string(),))?;
    Ok(())
}
