//! Registered OAuth clients (ADR 0005 / ADR 0011 / ADR 0014).

use crate::error::OAuthError;

/// How a client authenticates at the token endpoint (ADR 0014).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TokenEndpointAuth {
    /// Public client (`none`): no client authentication, PKCE only.
    #[default]
    None,
    /// Confidential client (`private_key_jwt`, RFC 7523) with its public JWKS
    /// document as registered.
    PrivateKeyJwt { jwks: String },
    /// Confidential client (`self_signed_tls_client_auth`, RFC 8705 §2.2)
    /// identified by the `x5t#S256` thumbprints of its registered
    /// certificates (ADR 0017).
    SelfSignedTlsClientAuth { cert_thumbprints: Vec<String> },
}

impl TokenEndpointAuth {
    /// RFC 7591 `token_endpoint_auth_method` value.
    pub fn method(&self) -> &'static str {
        match self {
            TokenEndpointAuth::None => "none",
            TokenEndpointAuth::PrivateKeyJwt { .. } => "private_key_jwt",
            TokenEndpointAuth::SelfSignedTlsClientAuth { .. } => "self_signed_tls_client_auth",
        }
    }
}

/// Per-client enforcement metadata (ADR 0018). Each flag uses the RFC client
/// metadata name and makes an optional mechanism mandatory for that client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientPolicy {
    /// RFC 9126 §6: authorize parameters must come through PAR.
    pub require_pushed_authorization_requests: bool,
    /// RFC 9449 §5.2: every token request must carry a DPoP proof.
    pub dpop_bound_access_tokens: bool,
    /// RFC 8705 §3.4: every token request must present a TLS client
    /// certificate, and tokens are bound to it.
    pub tls_client_certificate_bound_access_tokens: bool,
}

impl ClientPolicy {
    /// DPoP and certificate binding are mutually exclusive for one client:
    /// with both, DPoP would win and the certificate requirement would be
    /// meaningless.
    pub fn is_consistent(&self) -> bool {
        !(self.dpop_bound_access_tokens && self.tls_client_certificate_bound_access_tokens)
    }
}

/// A client with an exact redirect URI allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub token_endpoint_auth: TokenEndpointAuth,
    /// RFC 9101 §10.5: authorize parameters must arrive in a signed request
    /// object (ADR 0015 B2). Only valid for `private_key_jwt` clients.
    pub require_signed_request_object: bool,
    /// May introspect tokens issued to any client (RFC 7662 protected
    /// resource, ADR 0016). Set only through the admin API; requires
    /// `private_key_jwt`. Other clients introspect only their own tokens.
    pub resource_server: bool,
    /// Enforcement flags (ADR 0018).
    pub policy: ClientPolicy,
}

impl Client {
    /// A public client (`token_endpoint_auth_method` = `none`).
    pub fn new(client_id: impl Into<String>, redirect_uris: Vec<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            client_name: None,
            token_endpoint_auth: TokenEndpointAuth::None,
            require_signed_request_object: false,
            resource_server: false,
            policy: ClientPolicy::default(),
        }
    }

    /// A confidential client that authenticates with a self-signed TLS client
    /// certificate (RFC 8705 §2.2); `cert_thumbprints` are `x5t#S256` values.
    pub fn self_signed_tls(
        client_id: impl Into<String>,
        redirect_uris: Vec<String>,
        cert_thumbprints: Vec<String>,
    ) -> Self {
        Self {
            token_endpoint_auth: TokenEndpointAuth::SelfSignedTlsClientAuth { cert_thumbprints },
            ..Self::new(client_id, redirect_uris)
        }
    }

    /// A confidential client that authenticates with `private_key_jwt`.
    pub fn private_key_jwt(
        client_id: impl Into<String>,
        redirect_uris: Vec<String>,
        jwks: impl Into<String>,
    ) -> Self {
        Self {
            token_endpoint_auth: TokenEndpointAuth::PrivateKeyJwt { jwks: jwks.into() },
            ..Self::new(client_id, redirect_uris)
        }
    }

    pub fn allows_redirect(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == redirect_uri)
    }
}

/// In-memory client registry keyed by `client_id`.
#[derive(Debug, Clone, Default)]
pub struct ClientRegistry {
    clients: Vec<Client>,
}

impl ClientRegistry {
    pub fn new(clients: Vec<Client>) -> Self {
        Self { clients }
    }

    pub fn get(&self, client_id: &str) -> Result<&Client, OAuthError> {
        self.clients
            .iter()
            .find(|c| c.client_id == client_id)
            .ok_or(OAuthError::UnauthorizedClient)
    }

    pub fn list(&self) -> &[Client] {
        &self.clients
    }

    /// Insert a client. Returns `false` if `client_id` already exists.
    pub fn insert(&mut self, client: Client) -> bool {
        if self.clients.iter().any(|c| c.client_id == client.client_id) {
            return false;
        }
        self.clients.push(client);
        true
    }

    /// Remove by `client_id`. Returns whether a client was removed.
    pub fn remove(&mut self, client_id: &str) -> bool {
        let before = self.clients.len();
        self.clients.retain(|c| c.client_id != client_id);
        self.clients.len() != before
    }
}
