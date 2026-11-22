//! OAuth / OIDC wire error codes (ADR 0005, ADR 0006).

use std::fmt;

/// Protocol or configuration failure with a stable OAuth error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthError {
    InvalidRequest,
    UnauthorizedClient,
    InvalidGrant,
    UnsupportedGrantType,
    /// Bearer access token rejected at UserInfo (RFC 6750).
    InvalidToken,
    ServerError,
}

impl OAuthError {
    /// The OAuth `error` parameter value.
    pub fn code(self) -> &'static str {
        match self {
            OAuthError::InvalidRequest => "invalid_request",
            OAuthError::UnauthorizedClient => "unauthorized_client",
            OAuthError::InvalidGrant => "invalid_grant",
            OAuthError::UnsupportedGrantType => "unsupported_grant_type",
            OAuthError::InvalidToken => "invalid_token",
            OAuthError::ServerError => "server_error",
        }
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OAuthError {}
