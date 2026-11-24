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
}

impl TokenEndpointAuth {
    /// RFC 7591 `token_endpoint_auth_method` value.
    pub fn method(&self) -> &'static str {
        match self {
            TokenEndpointAuth::None => "none",
            TokenEndpointAuth::PrivateKeyJwt { .. } => "private_key_jwt",
        }
    }
}

/// A client with an exact redirect URI allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub token_endpoint_auth: TokenEndpointAuth,
}

impl Client {
    /// A public client (`token_endpoint_auth_method` = `none`).
    pub fn new(client_id: impl Into<String>, redirect_uris: Vec<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            client_name: None,
            token_endpoint_auth: TokenEndpointAuth::None,
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
