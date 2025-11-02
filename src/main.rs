use axum::{Form, Router, extract::Query, routing::get};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, signal};
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventViewQuery {
    uuid: String,
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

    info!("hi");

    let app = Router::new()
        .route("/event", get(get_event).post(post_event))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
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

async fn post_event(Form(event): Form<EventCreationForm>) {
    info!("got event {event:?}");
}
