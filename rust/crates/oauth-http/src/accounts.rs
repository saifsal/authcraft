//! Self-service accounts: email-verified sign-up, verification, and password
//! reset (ADR 0025). The flows follow glossa's reviewed design:
//!
//! - Answers never reveal whether an address has an account: sign-up, resend,
//!   and forgot-password show the same page for every address.
//! - Link tokens are 256-bit random values stored only as SHA-256 hashes,
//!   single-use, verify links valid 24 h and reset links 30 min.
//! - A GET never consumes a link; only the form POST does.
//! - Sign-up details travel with the verify link and are applied when it is
//!   used, so a stranger who pre-registers someone's address cannot keep the
//!   password they chose.
//! - Mail goes through the outbox in the same transaction as its token.
//! - Rate limits: mail per address, sign-up and recovery per client address,
//!   and login per account and per client address.
//!
//! Accounts themselves live in the authorization server's store (ADR 0024);
//! the login name is the lowercased email and `sub` is a random identifier.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Router};
use oauth::{hash_password, AuthnError, AuthorizationServer, UserRecord};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::Deserialize;

use crate::mailer::{escape_html, Email, Outbox};
use crate::pages::{error_line, esc, layout, message};
use crate::ratelimit::{client_key, RateLimiter};
use crate::store::Db;
use crate::AppState;

const MIN_PASSWORD: usize = 10;
const MAX_PASSWORD: usize = 1024;
const MAX_EMAIL: usize = 254;
const MAX_NAME: usize = 80;
const VERIFY_TOKEN_SECS: i64 = 24 * 3600;
const RESET_TOKEN_SECS: i64 = 30 * 60;
const HOUR: Duration = Duration::from_secs(3600);
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failed logins per account per 15 minutes.
pub const LOGIN_PER_ACCOUNT: u32 = 10;
/// Login attempts per client address per 15 minutes.
pub const LOGIN_PER_CLIENT: u32 = 50;
const MAIL_PER_ADDRESS_PER_HOUR: u32 = 3;
const REGISTER_PER_CLIENT_PER_HOUR: u32 = 10;
const RECOVERY_PER_CLIENT_PER_HOUR: u32 = 20;

/// Why an account operation failed; `message` is safe to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    Invalid,
    WeakPassword,
    PasswordTooLong,
    RateLimited,
    BadLink,
    Internal,
}

impl AccountError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid => "Check the email address and name.",
            Self::WeakPassword => "Password must be at least 10 characters.",
            Self::PasswordTooLong => "Password must be at most 1024 characters.",
            Self::RateLimited => "Too many attempts. Try again later.",
            Self::BadLink => "This link is invalid or has expired.",
            Self::Internal => "Something went wrong. Try again.",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// A trimmed, plausible email address (contains `@`, at most 254 bytes, no
/// whitespace or control characters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn parse(raw: &str) -> Option<Self> {
        let email = raw.trim();
        let at = email.find('@')?;
        let ok = email.len() >= 3
            && email.len() <= MAX_EMAIL
            && at > 0
            && at + 1 < email.len()
            && !email.chars().any(|c| c.is_whitespace() || c.is_control());
        ok.then(|| Self(email.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The login name: the lowercased address.
    pub fn username(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

fn check_password(raw: &str) -> Result<(), AccountError> {
    if raw.len() < MIN_PASSWORD {
        Err(AccountError::WeakPassword)
    } else if raw.len() > MAX_PASSWORD {
        Err(AccountError::PasswordTooLong)
    } else {
        Ok(())
    }
}

/// A link token as it appears in a URL: 64 lowercase hex characters.
pub fn token_well_formed(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_token(raw: &str) -> String {
    hex(digest::digest(&digest::SHA256, raw.as_bytes()).as_ref())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AccountError> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AccountError::Internal)?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum Purpose {
    Verify,
    Reset,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Reset => "reset",
        }
    }
}

/// Account flows and their rate limits. Clones share state.
#[derive(Clone)]
pub struct Accounts {
    server: Arc<AuthorizationServer>,
    db: Db,
    outbox: Outbox,
    public_url: Arc<str>,
    login_per_account: RateLimiter,
    login_per_client: RateLimiter,
    mail_per_address: RateLimiter,
    register_per_client: RateLimiter,
    recovery_per_client: RateLimiter,
}

impl Accounts {
    /// `public_url` is the origin used in email links (the issuer).
    pub fn new(server: Arc<AuthorizationServer>, db: Db, public_url: &str) -> Self {
        Self {
            outbox: Outbox::new(db.clone()),
            server,
            db,
            public_url: Arc::from(public_url.trim_end_matches('/')),
            login_per_account: RateLimiter::new(LOGIN_PER_ACCOUNT, LOGIN_WINDOW),
            login_per_client: RateLimiter::new(LOGIN_PER_CLIENT, LOGIN_WINDOW),
            mail_per_address: RateLimiter::new(MAIL_PER_ADDRESS_PER_HOUR, HOUR),
            register_per_client: RateLimiter::new(REGISTER_PER_CLIENT_PER_HOUR, HOUR),
            recovery_per_client: RateLimiter::new(RECOVERY_PER_CLIENT_PER_HOUR, HOUR),
        }
    }

    /// The outbox account mail is queued in.
    pub fn outbox(&self) -> Outbox {
        self.outbox.clone()
    }

    // ---- login throttling (ADR 0025; threat model R3) ----

    /// Whether a login for `username` from `client` may be attempted. Counts
    /// the attempt against the client address.
    pub fn login_allowed(&self, username: &str, client: &str) -> bool {
        let account = username.trim().to_ascii_lowercase();
        self.login_per_client.allow(client) && self.login_per_account.peek(&account)
    }

    /// Records a failed login for `username`.
    pub fn login_failed(&self, username: &str) {
        self.login_per_account
            .allow(&username.trim().to_ascii_lowercase());
    }

    /// Clears the failure count after a successful login.
    pub fn login_succeeded(&self, username: &str) {
        self.login_per_account
            .reset(&username.trim().to_ascii_lowercase());
    }

    // ---- storage helpers ----

    fn transact<T>(
        &self,
        body: impl FnOnce(&Transaction) -> Result<T, AccountError>,
    ) -> Result<T, AccountError> {
        let value = {
            let mut conn = self.db.lock().map_err(|_| AccountError::Internal)?;
            let tx = conn.transaction().map_err(|_| AccountError::Internal)?;
            let value = body(&tx)?;
            tx.commit().map_err(|_| AccountError::Internal)?;
            value
        };
        self.outbox.wake();
        Ok(value)
    }

    fn issue_token(
        tx: &Transaction,
        username: &str,
        purpose: Purpose,
        signup: Option<(&str, &str)>,
    ) -> Result<String, AccountError> {
        let raw = hex(&random_bytes::<32>()?);
        let ttl = match purpose {
            Purpose::Verify => VERIFY_TOKEN_SECS,
            Purpose::Reset => RESET_TOKEN_SECS,
        };
        let now = now();
        tx.execute("DELETE FROM auth_tokens WHERE expires_at <= ?1", params![now])
            .map_err(|_| AccountError::Internal)?;
        tx.execute(
            "INSERT INTO auth_tokens (username, purpose, token_hash, password_hash, name, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                username,
                purpose.as_str(),
                hash_token(&raw),
                signup.map(|s| s.0),
                signup.map(|s| s.1),
                now + ttl,
                now
            ],
        )
        .map_err(|_| AccountError::Internal)?;
        Ok(raw)
    }

    fn queue_mail(&self, tx: &Transaction, address: &str, email: Email) {
        if self.mail_per_address.allow(&address.to_ascii_lowercase()) {
            if let Err(error) = Outbox::queue(tx, &email) {
                tracing::warn!("could not queue mail: {error}");
            }
        }
    }

    fn link(&self, path: &str, token: &str) -> String {
        format!("{}{path}?token={token}", self.public_url)
    }

    // ---- flows ----

    /// Sign up. For valid input the outcome looks the same whatever the
    /// address's state: a new address gets an unverified account and a
    /// confirmation link, an unverified one gets a fresh link, and a verified
    /// one gets a notice by email. Hashes the password (slow): call from a
    /// blocking task.
    pub fn register(
        &self,
        email: &str,
        name: &str,
        password: &str,
        client: &str,
    ) -> Result<(), AccountError> {
        let email = EmailAddress::parse(email).ok_or(AccountError::Invalid)?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME || name.chars().any(char::is_control)
        {
            return Err(AccountError::Invalid);
        }
        check_password(password)?;
        if !self.register_per_client.allow(client) {
            return Err(AccountError::RateLimited);
        }
        // Hash before looking anything up so every branch costs the same.
        let hash = hash_password(password).map_err(|_| AccountError::Internal)?;
        let username = email.username();
        match self.server.account(&username) {
            None => {
                let record = UserRecord {
                    subject: hex(&random_bytes::<16>()?),
                    user_handle: uuid_from(random_bytes::<16>()?),
                    name: Some(name.to_owned()),
                    email: Some(email.as_str().to_owned()),
                    email_verified: false,
                    password_hash: hash.clone(),
                    totp_secret: None,
                    webauthn_credentials: Vec::new(),
                };
                match self.server.create_account(&username, record) {
                    // Lost a race with a concurrent sign-up: treat as existing.
                    Ok(_) => {}
                    Err(_) => return Err(AccountError::Internal),
                }
                self.transact(|tx| {
                    let token =
                        Self::issue_token(tx, &username, Purpose::Verify, Some((&hash, name)))?;
                    self.queue_mail(tx, email.as_str(), self.verify_email(email.as_str(), &token));
                    Ok(())
                })
            }
            Some(account) if !account.email_verified => self.transact(|tx| {
                let token = Self::issue_token(tx, &username, Purpose::Verify, Some((&hash, name)))?;
                let to = account.email.as_deref().unwrap_or(email.as_str());
                self.queue_mail(tx, to, self.verify_email(to, &token));
                Ok(())
            }),
            Some(account) => self.transact(|tx| {
                let to = account.email.as_deref().unwrap_or(email.as_str());
                self.queue_mail(tx, to, self.already_registered_email(to));
                Ok(())
            }),
        }
    }

    /// Uses a verify link: marks the address verified and applies the sign-up
    /// details stored with the link. Returns the login name.
    pub fn verify(&self, token: &str) -> Result<String, AccountError> {
        if !token_well_formed(token) {
            return Err(AccountError::BadLink);
        }
        let (username, password_hash, name) = self.transact(|tx| {
            let row = tx
                .query_row(
                    "SELECT id, username, password_hash, name FROM auth_tokens
                     WHERE token_hash = ?1 AND purpose = 'verify' AND expires_at > ?2",
                    params![hash_token(token), now()],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| AccountError::Internal)?;
            let (id, username, password_hash, name) = row.ok_or(AccountError::BadLink)?;
            tx.execute("DELETE FROM auth_tokens WHERE id = ?1", params![id])
                .map_err(|_| AccountError::Internal)?;
            Ok((username, password_hash, name))
        })?;
        self.server
            .update_user(&username, |u| {
                u.email_verified = true;
                if let Some(hash) = password_hash {
                    u.password_hash = hash;
                }
                if let Some(name) = name {
                    u.name = Some(name);
                }
                Ok(())
            })
            .map_err(|e| match e {
                AuthnError::InvalidCredentials => AccountError::BadLink,
                _ => AccountError::Internal,
            })?;
        Ok(username)
    }

    /// Sends a fresh verify link if `email` has an unverified account.
    /// Silent either way.
    pub fn resend_verification(&self, email: &str, client: &str) -> Result<(), AccountError> {
        if !self.recovery_per_client.allow(client) {
            return Err(AccountError::RateLimited);
        }
        let Some(email) = EmailAddress::parse(email) else {
            return Ok(());
        };
        let username = email.username();
        if let Some(account) = self.server.account(&username) {
            if !account.email_verified {
                self.transact(|tx| {
                    let token = Self::issue_token(tx, &username, Purpose::Verify, None)?;
                    let to = account.email.as_deref().unwrap_or(email.as_str());
                    self.queue_mail(tx, to, self.verify_email(to, &token));
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Emails a reset link if `email` has an account. Silent either way.
    pub fn request_password_reset(&self, email: &str, client: &str) -> Result<(), AccountError> {
        if !self.recovery_per_client.allow(client) {
            return Err(AccountError::RateLimited);
        }
        let Some(email) = EmailAddress::parse(email) else {
            return Ok(());
        };
        let username = email.username();
        if let Some(account) = self.server.account(&username) {
            self.transact(|tx| {
                let token = Self::issue_token(tx, &username, Purpose::Reset, None)?;
                let to = account.email.as_deref().unwrap_or(email.as_str());
                self.queue_mail(tx, to, self.reset_email(to, &token));
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Whether a reset link is still usable (for showing the form).
    pub fn reset_link_valid(&self, token: &str) -> bool {
        if !token_well_formed(token) {
            return false;
        }
        let Ok(conn) = self.db.lock() else {
            return false;
        };
        conn.query_row(
            "SELECT 1 FROM auth_tokens WHERE token_hash = ?1 AND purpose = 'reset' AND expires_at > ?2",
            params![hash_token(token), now()],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// Uses a reset link: sets the password, marks the address verified (the
    /// link proves ownership), and invalidates every other link for the
    /// account. Hashes the password (slow): call from a blocking task.
    pub fn reset_password(&self, token: &str, password: &str) -> Result<String, AccountError> {
        check_password(password)?;
        if !self.reset_link_valid(token) {
            return Err(AccountError::BadLink);
        }
        let hash = hash_password(password).map_err(|_| AccountError::Internal)?;
        let username = self.transact(|tx| {
            let username: String = tx
                .query_row(
                    "SELECT username FROM auth_tokens
                     WHERE token_hash = ?1 AND purpose = 'reset' AND expires_at > ?2",
                    params![hash_token(token), now()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| AccountError::Internal)?
                .ok_or(AccountError::BadLink)?;
            // Every outstanding link predates the new password.
            tx.execute("DELETE FROM auth_tokens WHERE username = ?1", params![username])
                .map_err(|_| AccountError::Internal)?;
            Ok(username)
        })?;
        self.server
            .update_user(&username, |u| {
                u.password_hash = hash;
                u.email_verified = true;
                Ok(())
            })
            .map_err(|_| AccountError::Internal)?;
        self.login_succeeded(&username);
        Ok(username)
    }

    // ---- email bodies ----

    fn verify_email(&self, to: &str, token: &str) -> Email {
        let link = self.link("/verify", token);
        compose(
            to,
            "Confirm your email for authcraft",
            &[
                "Confirm your email address to finish setting up your authcraft account:",
                &link,
                "The link expires in 24 hours. If you did not sign up, you can ignore this email.",
            ],
            Some(&link),
        )
    }

    fn already_registered_email(&self, to: &str) -> Email {
        let base = &self.public_url;
        compose(
            to,
            "Your authcraft account",
            &[
                "Someone tried to create an authcraft account with this email address, but it already has one.",
                &format!("Forgot your password? Reset it: {base}/forgot"),
                "If this was not you, you can ignore this email.",
            ],
            None,
        )
    }

    fn reset_email(&self, to: &str, token: &str) -> Email {
        let link = self.link("/reset", token);
        compose(
            to,
            "Reset your authcraft password",
            &[
                "Use this link to choose a new authcraft password:",
                &link,
                "The link expires in 30 minutes. If you did not ask for this, ignore this email; your password stays the same.",
            ],
            Some(&link),
        )
    }
}

/// RFC 9562 version-4 UUID from 16 random bytes (the WebAuthn user handle).
fn uuid_from(mut bytes: [u8; 16]) -> webauthn_rs::prelude::Uuid {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    webauthn_rs::prelude::Uuid::from_bytes(bytes)
}

/// Plain-text and HTML bodies from the same paragraphs. `button` turns the
/// matching paragraph into a link.
fn compose(to: &str, subject: &str, paragraphs: &[&str], button: Option<&str>) -> Email {
    let text = paragraphs.join("\n\n");
    let html_body: String = paragraphs
        .iter()
        .map(|p| {
            let escaped = escape_html(p);
            if Some(*p) == button {
                format!("<p><a href=\"{escaped}\">{escaped}</a></p>")
            } else {
                format!("<p>{escaped}</p>")
            }
        })
        .collect();
    Email {
        to: to.to_owned(),
        subject: subject.to_owned(),
        text: format!("{text}\n\n— authcraft\n"),
        html: format!(
            "<!DOCTYPE html><html><body style=\"font-family:sans-serif;line-height:1.5\">{html_body}<p>— authcraft</p></body></html>"
        ),
    }
}

// ---- HTTP ----

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/signup", get(signup_get).post(signup_post))
        .route("/verify", get(verify_get).post(verify_post))
        .route("/verify/resend", get(resend_get).post(resend_post))
        .route("/forgot", get(forgot_get).post(forgot_post))
        .route("/reset", get(reset_get).post(reset_post))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, AccountError> + Send + 'static,
) -> Result<T, AccountError> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or(Err(AccountError::Internal))
}

fn signup_page(error: Option<&str>, email: &str, name: &str) -> String {
    format!(
        r#"<h1>Create your account</h1>
<p class="lead">One authcraft account signs you in to the apps that support it.</p>
{err}
<form method="post" action="/signup">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="email" required maxlength="254" value="{email}">
  <label for="name">Name</label>
  <input id="name" name="name" autocomplete="name" required maxlength="80" value="{name}">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required minlength="{MIN_PASSWORD}" maxlength="1024">
  <p class="muted">At least {MIN_PASSWORD} characters. A passphrase works well.</p>
  <button type="submit">Create account</button>
</form>
<div class="links"><a href="/login">I already have an account</a></div>"#,
        err = error_line(error),
        email = esc(email),
        name = esc(name),
    )
}

fn check_inbox(title: &str, text: &str) -> Response {
    message(StatusCode::OK, title, text)
}

#[derive(Deserialize)]
struct SignupForm {
    email: String,
    name: String,
    password: String,
}

async fn signup_get() -> Response {
    layout("Create account", &signup_page(None, "", "")).into_response()
}

async fn signup_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignupForm>,
) -> Response {
    let accounts = state.accounts.clone();
    let client = client_key(&headers);
    let (email, name, password) = (form.email.clone(), form.name.clone(), form.password);
    match blocking(move || accounts.register(&email, &name, &password, &client)).await {
        Ok(()) => check_inbox(
            "Check your email",
            "If this address can be used, we have sent a link to finish creating your account. The link expires in 24 hours.",
        ),
        Err(err) => (
            err.status(),
            layout(
                "Create account",
                &signup_page(Some(err.message()), &form.email, &form.name),
            ),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct TokenForm {
    token: String,
}

/// Shows a confirm button; the POST consumes the link (mail scanners that
/// follow links do not verify accounts).
async fn verify_get(Query(q): Query<TokenQuery>) -> Response {
    let token = q.token.unwrap_or_default();
    if !token_well_formed(&token) {
        return message(StatusCode::BAD_REQUEST, "Link not valid", AccountError::BadLink.message());
    }
    let body = format!(
        r#"<h1>Confirm your email</h1>
<p class="lead">Confirm this address to finish creating your authcraft account.</p>
<form method="post" action="/verify">
  <input type="hidden" name="token" value="{}">
  <button type="submit">Confirm email</button>
</form>"#,
        esc(&token)
    );
    layout("Confirm email", &body).into_response()
}

async fn verify_post(State(state): State<AppState>, Form(form): Form<TokenForm>) -> Response {
    let accounts = state.accounts.clone();
    match blocking(move || accounts.verify(&form.token)).await {
        Ok(_) => {
            let body = r#"<h1>Email confirmed</h1>
<p class="lead ok">Your authcraft account is ready.</p>
<p>Go back to the app you were signing in to and choose <strong>Sign in with authcraft</strong>, or manage your account below.</p>
<div class="links"><a href="/account">Your account</a></div>"#;
            layout("Email confirmed", body).into_response()
        }
        Err(err) => message(err.status(), "Link not valid", err.message()),
    }
}

fn email_form(title: &str, lead: &str, action: &str, button: &str, error: Option<&str>) -> String {
    format!(
        r#"<h1>{title}</h1>
<p class="lead">{lead}</p>
{err}
<form method="post" action="{action}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="email" required maxlength="254">
  <button type="submit">{button}</button>
</form>
<div class="links"><a href="/login">Back to sign in</a></div>"#,
        title = esc(title),
        lead = esc(lead),
        err = error_line(error),
        action = esc(action),
        button = esc(button),
    )
}

#[derive(Deserialize)]
struct EmailForm {
    email: String,
}

async fn resend_get() -> Response {
    layout(
        "Resend confirmation",
        &email_form(
            "Resend confirmation",
            "We will send a new confirmation link if the address has an unconfirmed account.",
            "/verify/resend",
            "Send link",
            None,
        ),
    )
    .into_response()
}

async fn resend_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let accounts = state.accounts.clone();
    let client = client_key(&headers);
    match blocking(move || accounts.resend_verification(&form.email, &client)).await {
        Ok(()) => check_inbox(
            "Check your email",
            "If this address has an unconfirmed account, a new confirmation link is on its way.",
        ),
        Err(err) => message(err.status(), "Resend confirmation", err.message()),
    }
}

async fn forgot_get() -> Response {
    layout(
        "Reset password",
        &email_form(
            "Reset your password",
            "Enter your email and we will send a link to choose a new password.",
            "/forgot",
            "Send reset link",
            None,
        ),
    )
    .into_response()
}

async fn forgot_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let accounts = state.accounts.clone();
    let client = client_key(&headers);
    match blocking(move || accounts.request_password_reset(&form.email, &client)).await {
        Ok(()) => check_inbox(
            "Check your email",
            "If this address has an account, a reset link is on its way. It expires in 30 minutes.",
        ),
        Err(err) => message(err.status(), "Reset password", err.message()),
    }
}

fn reset_page(token: &str, error: Option<&str>) -> String {
    format!(
        r#"<h1>Choose a new password</h1>
{err}
<form method="post" action="/reset">
  <input type="hidden" name="token" value="{token}">
  <label for="password">New password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required minlength="{MIN_PASSWORD}" maxlength="1024">
  <button type="submit">Set password</button>
</form>"#,
        err = error_line(error),
        token = esc(token),
    )
}

async fn reset_get(State(state): State<AppState>, Query(q): Query<TokenQuery>) -> Response {
    let token = q.token.unwrap_or_default();
    if !state.accounts.reset_link_valid(&token) {
        return message(StatusCode::BAD_REQUEST, "Link not valid", AccountError::BadLink.message());
    }
    layout("New password", &reset_page(&token, None)).into_response()
}

#[derive(Deserialize)]
struct ResetForm {
    token: String,
    password: String,
}

async fn reset_post(State(state): State<AppState>, Form(form): Form<ResetForm>) -> Response {
    let accounts = state.accounts.clone();
    let token = form.token.clone();
    match blocking(move || accounts.reset_password(&form.token, &form.password)).await {
        Ok(_) => {
            let body = r#"<h1>Password changed</h1>
<p class="lead ok">Your new password is set.</p>
<div class="links"><a href="/account">Your account</a></div>"#;
            layout("Password changed", body).into_response()
        }
        Err(AccountError::BadLink) => {
            message(StatusCode::BAD_REQUEST, "Link not valid", AccountError::BadLink.message())
        }
        Err(err) => (
            err.status(),
            layout("New password", &reset_page(&token, Some(err.message()))),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::alg::Alg;
    use jose::signing::generate_signing_key;
    use oauth::ServerConfig;

    fn setup() -> (Accounts, Arc<AuthorizationServer>) {
        let server = Arc::new(AuthorizationServer::new(
            ServerConfig::new("https://auth.example", "api"),
            Vec::new(),
            generate_signing_key(Alg::EdDSA).unwrap(),
        ));
        let db = crate::store::open_db(std::path::Path::new(":memory:")).unwrap();
        (Accounts::new(server.clone(), db, "https://auth.example"), server)
    }

    /// The raw token in the newest queued mail for `to`.
    fn token_in_mail(accounts: &Accounts, to: &str, path: &str) -> String {
        let mail = accounts
            .outbox()
            .pending()
            .into_iter()
            .rev()
            .find(|m| m.email.to == to)
            .expect("mail queued");
        let marker = format!("https://auth.example{path}?token=");
        let start = mail.email.text.find(&marker).expect("link in mail") + marker.len();
        mail.email.text[start..start + 64].to_owned()
    }

    const PW: &str = "correct horse battery";

    #[test]
    fn signup_verify_then_login() {
        let (a, srv) = setup();
        a.register("Bea@Example.com", "Bea", PW, "c").unwrap();
        assert_eq!(
            srv.authenticate_password("bea@example.com", PW),
            Err(AuthnError::EmailNotVerified)
        );
        let token = token_in_mail(&a, "Bea@Example.com", "/verify");
        assert_eq!(a.verify(&token).unwrap(), "bea@example.com");
        let login = srv.authenticate_password("bea@example.com", PW).unwrap();
        assert_eq!(login.email.as_deref(), Some("Bea@Example.com"));
        assert_eq!(login.subject.len(), 32, "random hex sub, not the email");
        // Single use.
        assert_eq!(a.verify(&token), Err(AccountError::BadLink));
    }

    #[test]
    fn pre_registered_password_is_replaced_by_the_verifying_signup() {
        let (a, srv) = setup();
        a.register("v@example.com", "Mallory", "attacker-password", "c").unwrap();
        a.register("v@example.com", "Victim", "victim-password!", "c").unwrap();
        let token = token_in_mail(&a, "v@example.com", "/verify");
        a.verify(&token).unwrap();
        assert!(srv.authenticate_password("v@example.com", "attacker-password").is_err());
        let login = srv.authenticate_password("v@example.com", "victim-password!").unwrap();
        assert_eq!(login.name.as_deref(), Some("Victim"));
    }

    #[test]
    fn existing_verified_address_gets_a_notice_not_a_link() {
        let (a, _) = setup();
        a.register("n@example.com", "N", PW, "c").unwrap();
        let token = token_in_mail(&a, "n@example.com", "/verify");
        a.verify(&token).unwrap();
        a.register("n@example.com", "Other", "another password", "c").unwrap();
        let last = a.outbox().pending().into_iter().last().unwrap();
        assert_eq!(last.email.subject, "Your authcraft account");
        assert!(!last.email.text.contains("token="));
    }

    #[test]
    fn reset_flow_changes_password_and_burns_links() {
        let (a, srv) = setup();
        a.register("r@example.com", "R", PW, "c").unwrap();
        let verify = token_in_mail(&a, "r@example.com", "/verify");
        a.request_password_reset("r@example.com", "c").unwrap();
        let reset = token_in_mail(&a, "r@example.com", "/reset");
        assert!(a.reset_link_valid(&reset));
        a.reset_password(&reset, "brand new passphrase").unwrap();
        // The reset proved ownership, and burned the outstanding verify link.
        assert!(srv.authenticate_password("r@example.com", "brand new passphrase").is_ok());
        assert_eq!(a.verify(&verify), Err(AccountError::BadLink));
        assert!(!a.reset_link_valid(&reset));
    }

    #[test]
    fn unknown_addresses_are_silent() {
        let (a, _) = setup();
        assert_eq!(a.request_password_reset("nobody@example.com", "c"), Ok(()));
        assert_eq!(a.resend_verification("nobody@example.com", "c"), Ok(()));
        assert!(a.outbox().pending().is_empty());
    }

    #[test]
    fn input_and_policy_errors() {
        let (a, _) = setup();
        assert_eq!(a.register("nope", "N", PW, "c"), Err(AccountError::Invalid));
        assert_eq!(a.register("x@example.com", " ", PW, "c"), Err(AccountError::Invalid));
        assert_eq!(a.register("x@example.com", "N", "short", "c"), Err(AccountError::WeakPassword));
        assert_eq!(a.verify("not-a-token"), Err(AccountError::BadLink));
        assert_eq!(a.verify(&"0".repeat(64)), Err(AccountError::BadLink));
    }

    #[test]
    fn signup_and_mail_are_rate_limited() {
        let (a, _) = setup();
        for i in 0..REGISTER_PER_CLIENT_PER_HOUR {
            a.register(&format!("u{i}@example.com"), "U", PW, "same-client").unwrap();
        }
        assert_eq!(
            a.register("late@example.com", "U", PW, "same-client"),
            Err(AccountError::RateLimited)
        );
        // Mail per address: three per hour, then silently dropped.
        for _ in 0..5 {
            a.resend_verification("u0@example.com", "other").unwrap();
        }
        let to_u0 = a.outbox().pending().iter().filter(|m| m.email.to == "u0@example.com").count();
        assert_eq!(to_u0 as u32, MAIL_PER_ADDRESS_PER_HOUR);
    }

    #[test]
    fn login_throttle_per_account() {
        let (a, _) = setup();
        for _ in 0..LOGIN_PER_ACCOUNT {
            assert!(a.login_allowed("t@example.com", "c1"));
            a.login_failed("T@example.com");
        }
        assert!(!a.login_allowed("t@example.com", "c2"), "locked across clients");
        a.login_succeeded("t@example.com");
        assert!(a.login_allowed("t@example.com", "c2"));
    }
}
