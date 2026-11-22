//! Federation connectors (ADR 0012): OIDC RP and LDAP bind gateway.

pub mod ldap;
pub mod oidc_rp;

pub use ldap::{DirectoryBind, MemoryDirectory, MemoryDirectoryUser};
pub use oidc_rp::{
    id_token_from_token_response, login_subject_from_id_token, start_oidc_login, OidcRpConfig,
    OidcRpError, OidcRpStart,
};
