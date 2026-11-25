//! authcraft OAuth HTTP demo (ADR 0005, ADR 0017).
//!
//! Plain HTTP on 127.0.0.1:8089 by default. With `AUTHCRAFT_TLS_CERT` and
//! `AUTHCRAFT_TLS_KEY` (PEM paths) set, serves HTTPS with optional mutual TLS
//! and issuer `https://localhost:8089`. `AUTHCRAFT_TLS_CLIENT_CA` (PEM) adds
//! CAs trusted for `tls_client_auth` client certificates (ADR 0019).

use std::sync::Arc;

use oauth_http::{app, tls, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8089")
        .await
        .expect("bind 127.0.0.1:8089");

    match (
        std::env::var("AUTHCRAFT_TLS_CERT"),
        std::env::var("AUTHCRAFT_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => {
            let config = tls::server_config_from_pem_files(&cert, &key).expect("TLS config");
            let client_cas = match std::env::var("AUTHCRAFT_TLS_CLIENT_CA") {
                Ok(path) => tls::ders_from_pem_file(&path).expect("client CA PEM"),
                Err(_) => Vec::new(),
            };
            let state = AppState::demo_tls("https://localhost:8089", client_cas);
            tracing::info!("oauth-http listening on https://localhost:8089 (mTLS optional)");
            tls::serve_tls(listener, app(state), Arc::new(config))
                .await
                .expect("serve");
        }
        _ => {
            tracing::info!("oauth-http listening on http://localhost:8089");
            axum::serve(listener, app(AppState::demo()))
                .await
                .expect("serve");
        }
    }
}
