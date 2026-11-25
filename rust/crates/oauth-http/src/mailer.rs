//! Outgoing email: a SQLite outbox drained by a background worker (ADR 0025).
//!
//! Ported from glossa (`glossa/src/mailer.rs`) so both services share one
//! reviewed design.
//!
//! Handlers never talk to the mail provider. They insert an outbox row inside
//! the same transaction as the token it carries ([`Outbox::queue`]); the worker
//! ([`run`]) delivers rows through [`Mailer`] and deletes each one once the
//! provider accepts it, so raw tokens do not stay at rest. Answers to the
//! browser are therefore identical whether or not a message was sent, mail
//! survives restarts, and a provider outage cannot stall a request.

use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

/// Resend's send-email endpoint.
pub const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";
/// Attempts before a message that keeps failing is dropped.
pub const MAX_ATTEMPTS: i64 = 8;
/// Rows claimed per delivery pass.
const BATCH: usize = 10;
/// Pending rows above which every pass logs a warning.
const BACKLOG_WARN: i64 = 50;
/// Longest wait between passes when nothing wakes the worker.
const IDLE_POLL: Duration = Duration::from_secs(30);
/// Retry delays grow as `BASE_DELAY_SECS * 2^attempt`, capped at six hours.
const BASE_DELAY_SECS: i64 = 30;
const MAX_DELAY_SECS: i64 = 6 * 3600;

/// One message to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// A queued message as stored in the outbox.
#[derive(Clone, Debug)]
pub struct OutboxRow {
    pub id: i64,
    pub email: Email,
    pub attempts: i64,
    pub created_at: i64,
}

impl OutboxRow {
    /// Stable per message, so a retry after a timeout is not sent twice.
    pub fn idempotency_key(&self) -> String {
        format!("outbox-{}-{}", self.created_at, self.id)
    }
}

/// Handle on the `outbox` table. Clones share the connection and the wake-up.
#[derive(Clone)]
pub struct Outbox {
    conn: Arc<Mutex<Connection>>,
    wake: Arc<Notify>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Seconds to wait before attempt number `attempts + 1`.
///
pub fn retry_delay_secs(attempts: i64) -> i64 {
    let shift = attempts.clamp(0, 20) as u32;
    BASE_DELAY_SECS
        .saturating_mul(1_i64 << shift)
        .min(MAX_DELAY_SECS)
}

impl Outbox {
    pub(crate) fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            wake: Arc::new(Notify::new()),
        }
    }

    /// Insert a message using a connection the caller already holds (usually
    /// inside the transaction that created the token in it). Call
    /// [`Outbox::wake`] once the lock is released.
    pub(crate) fn queue(conn: &Connection, email: &Email) -> rusqlite::Result<()> {
        let now = now();
        conn.execute(
            "INSERT INTO outbox(to_addr, subject, text_body, html_body, attempts, next_attempt_at, created_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            params![email.to, email.subject, email.text, email.html, now],
        )?;
        Ok(())
    }

    /// Tell the worker that new rows are waiting.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Messages still waiting, oldest first (for tests and operators).
    pub fn pending(&self) -> Vec<OutboxRow> {
        self.select("SELECT id, to_addr, subject, text_body, html_body, attempts, created_at FROM outbox ORDER BY id", [])
    }

    /// Make every waiting row due now (tests skip the backoff with this).
    #[doc(hidden)]
    pub fn make_all_due_for_tests(&self) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("UPDATE outbox SET next_attempt_at = 0", []);
        }
    }

    fn due(&self, at: i64) -> Vec<OutboxRow> {
        self.select(
            "SELECT id, to_addr, subject, text_body, html_body, attempts, created_at FROM outbox
             WHERE next_attempt_at <= ?1 ORDER BY id LIMIT ?2",
            params![at, BATCH as i64],
        )
    }

    fn select(&self, sql: &str, args: impl rusqlite::Params) -> Vec<OutboxRow> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut stmt) = conn.prepare(sql) else {
            return Vec::new();
        };
        stmt.query_map(args, |r| {
            Ok(OutboxRow {
                id: r.get(0)?,
                email: Email {
                    to: r.get(1)?,
                    subject: r.get(2)?,
                    text: r.get(3)?,
                    html: r.get(4)?,
                },
                attempts: r.get(5)?,
                created_at: r.get(6)?,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    fn count(&self) -> i64 {
        self.conn
            .lock()
            .ok()
            .and_then(|c| {
                c.query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
                    .ok()
            })
            .unwrap_or(0)
    }

    fn next_due_in(&self, at: i64) -> Option<Duration> {
        let next: i64 = self.conn.lock().ok().and_then(|c| {
            c.query_row("SELECT MIN(next_attempt_at) FROM outbox", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten()
        })?;
        Some(Duration::from_secs(next.saturating_sub(at).max(0) as u64))
    }

    fn delete(&self, id: i64) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("DELETE FROM outbox WHERE id = ?1", params![id]);
        }
    }

    fn reschedule(&self, id: i64, attempts: i64, next_at: i64, error: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "UPDATE outbox SET attempts = ?2, next_attempt_at = ?3, last_error = ?4 WHERE id = ?1",
                params![id, attempts, next_at, error],
            );
        }
    }
}

/// What the provider said about one message.
#[derive(Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Accepted; delete the row.
    Sent,
    /// Temporary failure (429, 5xx, network); try again, after the given
    /// delay when the provider named one.
    Retry(Option<Duration>, String),
    /// Permanent failure (other 4xx); log and delete.
    Reject(String),
}

/// Where messages go.
#[derive(Clone)]
pub enum Mailer {
    /// Development: print each message, links included, to stderr.
    Log,
    /// Resend's HTTPS API.
    Resend(ResendConfig),
}

/// Settings for [`Mailer::Resend`].
#[derive(Clone)]
pub struct ResendConfig {
    pub http: reqwest::Client,
    pub endpoint: String,
    pub api_key: String,
    /// `Name <address>` or a bare address.
    pub from: String,
    pub reply_to: Option<String>,
}

impl Mailer {
    pub async fn send(&self, row: &OutboxRow) -> SendOutcome {
        match self {
            Self::Log => {
                eprintln!(
                    "mail (log mode) to {}: {}\n{}",
                    row.email.to, row.email.subject, row.email.text
                );
                SendOutcome::Sent
            }
            Self::Resend(config) => send_resend(config, row).await,
        }
    }
}

async fn send_resend(config: &ResendConfig, row: &OutboxRow) -> SendOutcome {
    let mut body = serde_json::json!({
        "from": config.from,
        "to": [row.email.to],
        "subject": row.email.subject,
        "text": row.email.text,
        "html": row.email.html,
    });
    if let Some(reply_to) = &config.reply_to {
        body["reply_to"] = serde_json::Value::String(reply_to.clone());
    }
    let response = config
        .http
        .post(&config.endpoint)
        .bearer_auth(&config.api_key)
        .header("Idempotency-Key", row.idempotency_key())
        .json(&body)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        // Network errors carry no secrets beyond the endpoint; drop the URL anyway.
        Err(error) => return SendOutcome::Retry(None, format!("network: {}", error.without_url())),
    };
    let status = response.status();
    if status.is_success() {
        return SendOutcome::Sent;
    }
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let detail: String = response
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(300)
        .collect();
    let message = format!("HTTP {}: {detail}", status.as_u16());
    if status.as_u16() == 429 || status.is_server_error() {
        SendOutcome::Retry(retry_after, message)
    } else {
        SendOutcome::Reject(message)
    }
}

/// One delivery pass over the rows that are due. Returns how many rows were
/// handled (sent, rescheduled, or dropped).
pub async fn deliver_due(outbox: &Outbox, mailer: &Mailer) -> usize {
    let at = now();
    let due = outbox.due(at);
    for row in &due {
        match mailer.send(row).await {
            SendOutcome::Sent => outbox.delete(row.id),
            SendOutcome::Reject(error) => {
                eprintln!("mail {} to {} rejected: {error}", row.id, row.email.to);
                outbox.delete(row.id);
            }
            SendOutcome::Retry(after, error) => {
                let attempts = row.attempts + 1;
                if attempts >= MAX_ATTEMPTS {
                    eprintln!(
                        "mail {} to {} dropped after {attempts} attempts: {error}",
                        row.id, row.email.to
                    );
                    outbox.delete(row.id);
                } else {
                    let delay = after
                        .map(|d| d.as_secs().min(MAX_DELAY_SECS as u64) as i64)
                        .unwrap_or_else(|| retry_delay_secs(row.attempts))
                        .max(1);
                    eprintln!("mail {} retry in {delay}s: {error}", row.id);
                    outbox.reschedule(row.id, attempts, now() + delay, &error);
                }
            }
        }
    }
    due.len()
}

/// Deliver queued mail until the process exits.
pub async fn run(outbox: Outbox, mailer: Mailer) {
    loop {
        let handled = deliver_due(&outbox, &mailer).await;
        let backlog = outbox.count();
        if backlog > BACKLOG_WARN {
            eprintln!("mail backlog: {backlog} messages waiting");
        }
        if handled == BATCH {
            continue;
        }
        let wait = outbox
            .next_due_in(now())
            .map_or(IDLE_POLL, |d| d.min(IDLE_POLL));
        tokio::select! {
            _ = outbox.wake.notified() => {}
            _ = tokio::time::sleep(wait.max(Duration::from_millis(200))) => {}
        }
    }
}

/// Minimal HTML escaping for text placed in email bodies.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_doubles_and_caps() {
        assert_eq!(retry_delay_secs(-3), BASE_DELAY_SECS);
        assert_eq!(retry_delay_secs(2), 120);
        assert_eq!(retry_delay_secs(i64::MAX), MAX_DELAY_SECS);
    }

    #[test]
    fn escape_html_covers_markup() {
        assert_eq!(
            escape_html(r#"<a href="x">&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }
}
