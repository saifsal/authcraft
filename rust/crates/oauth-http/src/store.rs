//! SQLite account storage for production mode (ADR 0024).
//!
//! One table, `users`, keyed by login name, with the OIDC `sub` unique and the
//! full [`UserRecord`] (including WebAuthn credentials) stored as JSON. The
//! schema version lives in `PRAGMA user_version`.

use std::path::Path;
use std::sync::Mutex;

use oauth::{UserRecord, UserRepository};
use rusqlite::{params, Connection};

/// Current schema version.
pub const SCHEMA_VERSION: i64 = 1;

pub struct SqliteUserStore {
    conn: Mutex<Connection>,
}

impl SqliteUserStore {
    /// Opens (or creates) the database at `path` and migrates it.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Every stored account, for `AuthorizationServer::attach_user_repository`.
    pub fn load_all(&self) -> Result<Vec<(String, UserRecord)>, Box<dyn std::error::Error + Send + Sync>> {
        let conn = self.conn.lock().expect("db lock");
        let mut stmt = conn.prepare("SELECT username, record FROM users ORDER BY username")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (name, json) = row?;
            let record: UserRecord = serde_json::from_str(&json)
                .map_err(|e| format!("user {name}: stored record unreadable: {e}"))?;
            out.push((name, record));
        }
        Ok(out)
    }
}

fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(
            "CREATE TABLE users (
                 username   TEXT PRIMARY KEY,
                 subject    TEXT NOT NULL UNIQUE,
                 record     TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             PRAGMA user_version = 1;",
        )?;
    }
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl UserRepository for SqliteUserStore {
    fn save(&self, username: &str, record: &UserRecord) -> Result<(), String> {
        let json = serde_json::to_string(record).map_err(|e| e.to_string())?;
        let conn = self.conn.lock().map_err(|_| "db lock poisoned".to_owned())?;
        conn.execute(
            "INSERT INTO users (username, subject, record, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(username) DO UPDATE SET
                 subject = excluded.subject, record = excluded.record, updated_at = excluded.updated_at",
            params![username, record.subject, json, now_unix()],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    fn delete(&self, username: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "db lock poisoned".to_owned())?;
        conn.execute("DELETE FROM users WHERE username = ?1", params![username])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::alg::Alg;
    use jose::signing::generate_signing_key;
    use oauth::{hash_password, AuthorizationServer, ServerConfig};
    use std::sync::Arc;

    fn scratch_db() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "authcraft-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("authcraft.db")
    }

    fn record(subject: &str, verified: bool) -> UserRecord {
        UserRecord {
            subject: subject.into(),
            user_handle: uuid::Uuid::new_v4(),
            name: Some("Bea".into()),
            email: Some("bea@example.com".into()),
            email_verified: verified,
            password_hash: hash_password("correct horse battery").unwrap(),
            totp_secret: None,
            webauthn_credentials: Vec::new(),
        }
    }

    fn server() -> AuthorizationServer {
        AuthorizationServer::new(
            ServerConfig::new("https://auth.example", "api"),
            Vec::new(),
            generate_signing_key(Alg::EdDSA).unwrap(),
        )
    }

    #[test]
    fn save_load_delete_round_trip() {
        let db = scratch_db();
        let store = SqliteUserStore::open(&db).unwrap();
        store.save("bea@example.com", &record("sub-1", true)).unwrap();
        store.save("bea@example.com", &record("sub-1", false)).unwrap();
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert!(!all[0].1.email_verified, "upsert replaced the record");
        store.delete("bea@example.com").unwrap();
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn accounts_survive_a_restart() {
        let db = scratch_db();
        {
            let srv = server();
            let store = Arc::new(SqliteUserStore::open(&db).unwrap());
            let existing = store.load_all().unwrap();
            srv.attach_user_repository(store, existing).unwrap();
            srv.upsert_user("bea@example.com", record("sub-1", true)).unwrap();
            srv.set_totp_secret("bea@example.com", "JBSWY3DPEHPK3PXP").unwrap();
        }
        let srv = server();
        let store = Arc::new(SqliteUserStore::open(&db).unwrap());
        let existing = store.load_all().unwrap();
        srv.attach_user_repository(store, existing).unwrap();
        let login = srv
            .authenticate_password("bea@example.com", "correct horse battery")
            .unwrap();
        assert_eq!(login.subject, "sub-1");
        assert!(srv.user_totp_enrolled("bea@example.com"));
    }

    #[test]
    fn subject_is_unique() {
        let db = scratch_db();
        let store = SqliteUserStore::open(&db).unwrap();
        store.save("a@example.com", &record("same-sub", true)).unwrap();
        assert!(store.save("b@example.com", &record("same-sub", true)).is_err());
    }
}
