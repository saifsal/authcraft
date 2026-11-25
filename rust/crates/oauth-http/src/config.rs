//! Production configuration for `oauth-http` (ADR 0023).
//!
//! - Clients come from a JSON file, not from open registration.
//! - The Ed25519 signing key is persisted in the data directory, so a restart
//!   does not invalidate issued tokens or relying parties' cached JWKS.
//! - The admin token comes from a file (a systemd credential), never argv.

use std::fs;
use std::io::Write;
use std::path::Path;

use jose::alg::Alg;
use jose::jwk::PublicKey;
use jose::signing::{generate_signing_key, SigningKey};
use oauth::{Client, ClientPolicy};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;

use crate::{PolicyBody, TlsSubjectBody};

/// One configured client. Field names follow RFC 7591 client metadata.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub require_signed_request_object: bool,
    #[serde(default)]
    pub resource_server: bool,
    #[serde(flatten)]
    pub policy: PolicyBody,
    #[serde(flatten)]
    pub tls_subject: TlsSubjectBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientsFile {
    clients: Vec<ClientConfig>,
}

pub type ConfigError = Box<dyn std::error::Error + Send + Sync>;

impl ClientConfig {
    /// Builds the client model; validity against the server is checked by
    /// `AuthorizationServer::client_is_valid` at startup.
    pub fn into_client(self) -> Result<Client, ConfigError> {
        let auth = crate::client_auth_from_body(
            self.token_endpoint_auth_method.as_deref(),
            self.jwks.as_ref(),
            &self.tls_subject,
        )
        .ok_or_else(|| format!("client {}: inconsistent auth metadata", self.client_id))?;
        Ok(Client {
            client_id: self.client_id,
            redirect_uris: self.redirect_uris,
            client_name: self.client_name,
            token_endpoint_auth: auth,
            require_signed_request_object: self.require_signed_request_object,
            resource_server: self.resource_server,
            policy: ClientPolicy::from(&self.policy),
        })
    }
}

/// Parses a clients file: `{"clients": [ {RFC 7591 metadata…}, … ]}`.
pub fn parse_clients(json: &str) -> Result<Vec<Client>, ConfigError> {
    let file: ClientsFile = serde_json::from_str(json)?;
    let clients = file
        .clients
        .into_iter()
        .map(ClientConfig::into_client)
        .collect::<Result<Vec<_>, _>>()?;
    let mut ids: Vec<&str> = clients.iter().map(|c| c.client_id.as_str()).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err("duplicate client_id in clients file".into());
    }
    Ok(clients)
}

/// Loads the Ed25519 signing key from `<data_dir>/signing-key.pk8`, creating
/// it (mode 0600) on first start.
pub fn load_or_create_signing_key(data_dir: &Path) -> Result<SigningKey, ConfigError> {
    let path = data_dir.join("signing-key.pk8");
    if path.exists() {
        let pkcs8 = fs::read(&path)?;
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| format!("{}: not an Ed25519 PKCS#8 key", path.display()))?;
        let public = PublicKey::ed25519_from_bytes(pair.public_key().as_ref())
            .map_err(|_| "bad Ed25519 public key")?;
        return Ok(SigningKey { pkcs8, public });
    }
    let key = generate_signing_key(Alg::EdDSA).map_err(|e| format!("keygen: {e}"))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    file.write_all(&key.pkcs8)?;
    file.sync_all()?;
    Ok(key)
}

/// Checks the production issuer (`--public-url`): an absolute `https` URL, or
/// `http://localhost[:port]` for local testing, without a trailing slash,
/// query, or fragment. WebAuthn derives its relying-party ID from the host,
/// and rejects IP addresses, so those are refused here with a clear message.
pub fn validate_public_url(url: &str) -> Result<(), ConfigError> {
    let parsed = url::Url::parse(url).map_err(|e| format!("--public-url {url}: {e}"))?;
    let host_ok = matches!(
        (parsed.scheme(), parsed.host()),
        ("https", Some(url::Host::Domain(_))) | ("http", Some(url::Host::Domain("localhost")))
    );
    if !host_ok {
        return Err(format!(
            "--public-url {url}: use https with a domain name (or http://localhost for testing); IP addresses cannot be WebAuthn relying parties"
        )
        .into());
    }
    if url.ends_with('/') || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!("--public-url {url}: no trailing slash, query, or fragment").into());
    }
    Ok(())
}

/// Reads a secret file, trimming one trailing newline. Empty is an error.
pub fn read_secret(path: &Path) -> Result<String, ConfigError> {
    let raw = fs::read_to_string(path)?;
    let value = raw.trim_end_matches(['\n', '\r']).to_owned();
    if value.is_empty() {
        return Err(format!("{}: empty secret", path.display()).into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "authcraft-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn signing_key_persists_across_loads() {
        let dir = scratch();
        let first = load_or_create_signing_key(&dir).unwrap();
        let second = load_or_create_signing_key(&dir).unwrap();
        assert_eq!(first.public.thumbprint(), second.public.thumbprint());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("signing-key.pk8")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clients_file_parses_private_key_jwt() {
        let json = r#"{"clients":[{
            "client_id":"tacto","client_name":"Tacto",
            "redirect_uris":["https://tacto.accumu.cc/auth/authcraft/callback"],
            "token_endpoint_auth_method":"private_key_jwt",
            "jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}
        }]}"#;
        let clients = parse_clients(json).unwrap();
        assert_eq!(clients[0].client_id, "tacto");
        assert_eq!(clients[0].token_endpoint_auth.method(), "private_key_jwt");
    }

    #[test]
    fn clients_file_rejects_bad_input() {
        for bad in [
            r#"{"clients":[{"client_id":"a","redirect_uris":[],"unknown":1}]}"#,
            r#"{"clients":[{"client_id":"a","redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}]}"#,
            r#"{"clients":[{"client_id":"a","redirect_uris":["https://a.example/cb"]},{"client_id":"a","redirect_uris":["https://a.example/cb"]}]}"#,
        ] {
            assert!(parse_clients(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn public_url_rules() {
        for ok in ["https://authcraft.accumu.cc", "http://localhost:8083", "https://a.example/idp"] {
            assert!(validate_public_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://authcraft.accumu.cc",
            "https://127.0.0.1",
            "http://127.0.0.1:8083",
            "https://authcraft.accumu.cc/",
            "https://a.example?x=1",
            "authcraft.accumu.cc",
        ] {
            assert!(validate_public_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn secret_files_trim_newline_and_reject_empty() {
        let dir = scratch();
        fs::write(dir.join("t"), "s3cret\n").unwrap();
        assert_eq!(read_secret(&dir.join("t")).unwrap(), "s3cret");
        fs::write(dir.join("e"), "\n").unwrap();
        assert!(read_secret(&dir.join("e")).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
