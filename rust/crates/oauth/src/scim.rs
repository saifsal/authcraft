//! SCIM 2.0 Users subset over `UserStore` (ADR 0011 B3).

use uuid::Uuid;

use crate::server::AdminError;
use crate::users::{hash_password, UserRecord};

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// Parsed SCIM User create/replace fields.
#[derive(Debug, Clone)]
pub struct ScimUserInput {
    pub user_name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}

/// SCIM User resource (read model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimUser {
    pub id: Uuid,
    pub user_name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub active: bool,
}

impl ScimUser {
    pub fn from_record(username: &str, record: &UserRecord) -> Self {
        Self {
            id: record.user_handle,
            user_name: username.to_owned(),
            display_name: record.name.clone(),
            email: record.email.clone(),
            active: true,
        }
    }

    pub fn to_json(&self) -> String {
        let mut out = format!(
            r#"{{"schemas":["{USER_SCHEMA}"],"id":"{}","userName":"{}","active":true"#,
            self.id, escape(&self.user_name)
        );
        if let Some(name) = &self.display_name {
            out.push_str(&format!(
                r#","displayName":"{}","name":{{"formatted":"{}"}}"#,
                escape(name),
                escape(name)
            ));
        }
        if let Some(email) = &self.email {
            out.push_str(&format!(
                r#","emails":[{{"value":"{}","primary":true}}]"#,
                escape(email)
            ));
        }
        out.push('}');
        out
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Parse a minimal SCIM User JSON object (hand-rolled via jose::json).
pub fn parse_user_json(bytes: &[u8]) -> Result<ScimUserInput, AdminError> {
    let root = jose::json::parse(bytes).map_err(|_| AdminError::InvalidRequest)?;
    let user_name = root
        .get("userName")
        .and_then(jose::json::Value::as_str)
        .ok_or(AdminError::InvalidRequest)?
        .trim()
        .to_owned();
    if user_name.is_empty() {
        return Err(AdminError::InvalidRequest);
    }
    let display_name = root
        .get("displayName")
        .and_then(jose::json::Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            root.get("name")
                .and_then(|n| n.get("formatted"))
                .and_then(jose::json::Value::as_str)
                .map(str::to_owned)
        });
    let email = root
        .get("emails")
        .and_then(jose::json::Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|e| e.get("value"))
        .and_then(jose::json::Value::as_str)
        .map(str::to_owned);
    let password = root
        .get("password")
        .and_then(jose::json::Value::as_str)
        .map(str::to_owned);
    Ok(ScimUserInput {
        user_name,
        display_name,
        email,
        password,
    })
}

/// Parse `filter=userName eq "value"` (optional surrounding quotes).
pub fn parse_username_filter(filter: Option<&str>) -> Result<Option<String>, AdminError> {
    let Some(filter) = filter.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let lower = filter.to_ascii_lowercase();
    if !lower.starts_with("username eq ") {
        return Err(AdminError::InvalidRequest);
    }
    let idx = lower.find(" eq ").ok_or(AdminError::InvalidRequest)? + 4;
    let mut value = filter[idx..].trim();
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        value = &value[1..value.len() - 1];
    }
    if value.is_empty() {
        return Err(AdminError::InvalidRequest);
    }
    Ok(Some(value.to_owned()))
}

pub fn build_user_record(input: &ScimUserInput, existing: Option<&UserRecord>) -> Result<UserRecord, AdminError> {
    let password_hash = if let Some(pw) = input.password.as_deref() {
        hash_password(pw).map_err(|_| AdminError::InvalidRequest)?
    } else if let Some(ex) = existing {
        ex.password_hash.clone()
    } else {
        return Err(AdminError::InvalidRequest);
    };
    Ok(UserRecord {
        subject: input.user_name.clone(),
        user_handle: existing
            .map(|e| e.user_handle)
            .unwrap_or_else(Uuid::new_v4),
        name: input.display_name.clone(),
        email: input.email.clone(),
        // An administrator vouches for addresses set through SCIM.
        email_verified: input.email.is_some(),
        password_hash,
        totp_secret: existing.and_then(|e| e.totp_secret.clone()),
        webauthn_credentials: existing
            .map(|e| e.webauthn_credentials.clone())
            .unwrap_or_default(),
    })
}

pub fn list_response_json(users: &[ScimUser]) -> String {
    let mut resources = String::from("[");
    for (i, u) in users.iter().enumerate() {
        if i > 0 {
            resources.push(',');
        }
        resources.push_str(&u.to_json());
    }
    resources.push(']');
    format!(
        r#"{{"schemas":["{LIST_SCHEMA}"],"totalResults":{},"Resources":{resources}}}"#,
        users.len()
    )
}

pub fn error_json(status: u16, detail: &str) -> String {
    format!(
        r#"{{"schemas":["{ERROR_SCHEMA}"],"status":"{status}","detail":"{}"}}"#,
        escape(detail)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filter_username() {
        assert_eq!(
            parse_username_filter(Some(r#"userName eq "alice""#)).unwrap(),
            Some("alice".into())
        );
        assert!(parse_username_filter(Some("emails eq x")).is_err());
    }

    #[test]
    fn parse_user_requires_username_and_password_on_create() {
        let input = parse_user_json(
            br#"{"userName":"bob","displayName":"Bob","password":"secret","emails":[{"value":"b@example.com"}]}"#,
        )
        .unwrap();
        assert_eq!(input.user_name, "bob");
        let record = build_user_record(&input, None).unwrap();
        assert_eq!(record.subject, "bob");
        assert_eq!(record.email.as_deref(), Some("b@example.com"));
    }
}
