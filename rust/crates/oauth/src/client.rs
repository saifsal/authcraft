//! Registered public OAuth clients (ADR 0005).

use crate::error::OAuthError;

/// A public client with an exact redirect URI allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
}

impl Client {
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
}
