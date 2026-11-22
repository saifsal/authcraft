//! Registered public OAuth clients (ADR 0005 / ADR 0011).

use crate::error::OAuthError;

/// A public client with an exact redirect URI allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

impl Client {
    pub fn new(client_id: impl Into<String>, redirect_uris: Vec<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uris,
            client_name: None,
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
