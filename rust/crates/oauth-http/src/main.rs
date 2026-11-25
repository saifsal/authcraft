//! authcraft OAuth 2.0 / OpenID Connect server (ADR 0005, ADR 0017, ADR 0023).
//!
//! Two explicit modes:
//!
//! - `--demo`: the walkthrough server (published admin token, user `alice`,
//!   open registration, in-memory, `http://localhost:8089`).
//! - production: `--data-dir` and `--public-url` are required. Nothing from the
//!   demo is enabled; clients come from `--clients`, the signing key is
//!   persisted, and the admin API is off unless an admin token file exists.
//!
//! With neither, the binary refuses to start.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use oauth::ServerConfig;
use oauth_http::mailer::{self, Mailer, ResendConfig, RESEND_ENDPOINT};
use oauth_http::{app, config, store, tls, AppState};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "authcraft OAuth 2.0 / OpenID Connect server")]
struct Args {
    /// Run the in-memory demo (published admin token and demo user).
    #[arg(long, conflicts_with_all = ["data_dir", "public_url", "clients"])]
    demo: bool,
    /// Address to listen on.
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// Production: directory for persistent state (signing key, database).
    #[arg(long, requires = "public_url")]
    data_dir: Option<PathBuf>,
    /// Production: the issuer, e.g. https://authcraft.accumu.cc.
    #[arg(long, requires = "data_dir")]
    public_url: Option<String>,
    /// Production: JSON file of configured clients (RFC 7591 metadata).
    #[arg(long)]
    clients: Option<PathBuf>,
    /// Admin bearer token file. Defaults to $CREDENTIALS_DIRECTORY/admin-token
    /// when that exists; without one the admin API is disabled.
    #[arg(long)]
    admin_token_file: Option<PathBuf>,
    /// Mark cookies Secure (behind a TLS-terminating reverse proxy).
    #[arg(long)]
    secure_cookies: bool,
    /// Serve HTTPS directly with this PEM certificate chain.
    #[arg(long, env = "AUTHCRAFT_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<String>,
    /// PEM private key for --tls-cert.
    #[arg(long, env = "AUTHCRAFT_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<String>,
    /// PEM CA certificates trusted for tls_client_auth (ADR 0019).
    #[arg(long, env = "AUTHCRAFT_TLS_CLIENT_CA")]
    tls_client_ca: Option<String>,
    /// Sender for account email, e.g. "authcraft <noreply@accumu.cc>". Enables
    /// Resend; without it, email is printed to the log.
    #[arg(long)]
    mail_from: Option<String>,
    /// Reply-To for account email.
    #[arg(long)]
    mail_reply_to: Option<String>,
    /// Resend API key file. Defaults to $CREDENTIALS_DIRECTORY/resend-api-key.
    #[arg(long)]
    mail_key_file: Option<PathBuf>,
    /// Override the Resend endpoint (testing).
    #[arg(long, default_value = RESEND_ENDPOINT)]
    mail_endpoint: String,
}

/// Resend when a sender is configured (the key is then required), otherwise
/// log mode (ADR 0025).
fn mailer_from(args: &Args) -> Result<Mailer, BoxError> {
    let Some(from) = args.mail_from.clone() else {
        tracing::warn!("mail: no --mail-from; account email is printed to the log");
        return Ok(Mailer::Log);
    };
    let key_file = match &args.mail_key_file {
        Some(path) => path.clone(),
        None => PathBuf::from(
            std::env::var_os("CREDENTIALS_DIRECTORY")
                .ok_or("--mail-from needs --mail-key-file or systemd LoadCredential=resend-api-key")?,
        )
        .join("resend-api-key"),
    };
    Ok(Mailer::Resend(ResendConfig {
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?,
        endpoint: args.mail_endpoint.clone(),
        api_key: config::read_secret(&key_file)?,
        from,
        reply_to: args.mail_reply_to.clone(),
    }))
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn production_state(args: &Args, data_dir: &PathBuf, public_url: &str) -> Result<AppState, BoxError> {
    std::fs::create_dir_all(data_dir)?;
    let signing = config::load_or_create_signing_key(data_dir)?;
    let mut server_config = ServerConfig::new(public_url, "api");
    let admin_file = args.admin_token_file.clone().or_else(|| {
        std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(|d| PathBuf::from(d).join("admin-token"))
            .filter(|p| p.exists())
    });
    if let Some(path) = admin_file {
        server_config.admin_token = config::read_secret(&path)?;
    }
    if let Some(ca) = &args.tls_client_ca {
        server_config.tls_client_auth_trust_anchors =
            tls::ders_from_pem_file(ca).map_err(|e| e.to_string())?;
    }
    let clients = match &args.clients {
        Some(path) => config::parse_clients(&std::fs::read_to_string(path)?)?,
        None => Vec::new(),
    };
    let mut state = AppState::production(server_config, clients, signing)?;
    state.secure_cookies = args.secure_cookies;
    // ADR 0024 / 0025: accounts, link tokens, and the outbox share one database.
    let db = store::open_db(&data_dir.join("authcraft.db"))?;
    state.with_database(db)
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    let args = Args::parse();

    let (state, default_listen, scheme_hint) = match (&args.data_dir, &args.public_url) {
        (Some(dir), Some(url)) => (production_state(&args, dir, url)?, "127.0.0.1:8083", url.clone()),
        _ if args.demo => {
            let issuer = if args.tls_cert.is_some() {
                "https://localhost:8089"
            } else {
                "http://localhost:8089"
            };
            let client_cas = match &args.tls_client_ca {
                Some(ca) => tls::ders_from_pem_file(ca).map_err(|e| e.to_string())?,
                None => Vec::new(),
            };
            (AppState::demo_tls(issuer, client_cas), "127.0.0.1:8089", issuer.to_owned())
        }
        _ => {
            return Err("choose a mode: --demo, or --data-dir with --public-url (see --help)".into())
        }
    };
    tokio::spawn(mailer::run(state.accounts.outbox(), mailer_from(&args)?));
    let listen = args.listen.unwrap_or_else(|| default_listen.parse().expect("default address"));
    let listener = tokio::net::TcpListener::bind(listen).await?;

    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let tls_config = tls::server_config_from_pem_files(cert, key).map_err(|e| e.to_string())?;
            tracing::info!("authcraft on https://{listen} (issuer {scheme_hint}, mTLS optional)");
            tls::serve_tls(listener, app(state), Arc::new(tls_config)).await?;
        }
        _ => {
            tracing::info!("authcraft on http://{listen} (issuer {scheme_hint})");
            axum::serve(listener, app(state)).await?;
        }
    }
    Ok(())
}
