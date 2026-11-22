//! authcraft M1 OAuth HTTP demo (ADR 0005).

use oauth_http::{app, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let state = AppState::demo();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8089")
        .await
        .expect("bind 127.0.0.1:8089");
    tracing::info!("oauth-http listening on http://127.0.0.1:8089");
    axum::serve(listener, app(state)).await.expect("serve");
}
