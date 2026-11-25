//! WebAuthn security-key second factor (ADR 0010 B3).

use std::collections::HashMap;
use std::sync::Mutex;

use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, SecurityKey, SecurityKeyAuthentication, SecurityKeyRegistration,
    Webauthn, WebauthnBuilder,
};

use crate::users::AuthnError;

/// In-memory WebAuthn RP + ceremony state.
pub struct WebauthnMfa {
    webauthn: Webauthn,
    reg: Mutex<HashMap<String, SecurityKeyRegistration>>,
    auth: Mutex<HashMap<String, SecurityKeyAuthentication>>,
}

impl WebauthnMfa {
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self, AuthnError> {
        let origin = Url::parse(rp_origin).map_err(|_| AuthnError::InvalidMfa)?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|_| AuthnError::InvalidMfa)?
            .build()
            .map_err(|_| AuthnError::InvalidMfa)?;
        Ok(Self {
            webauthn,
            reg: Mutex::new(HashMap::new()),
            auth: Mutex::new(HashMap::new()),
        })
    }

    pub fn start_registration(
        &self,
        username: &str,
        user_handle: Uuid,
        display_name: &str,
        exclude: Vec<SecurityKey>,
    ) -> Result<CreationChallengeResponse, AuthnError> {
        let exclude_ids = exclude.iter().map(|c| c.cred_id().clone()).collect();
        let (ccr, state) = self
            .webauthn
            .start_securitykey_registration(
                user_handle,
                username,
                display_name,
                Some(exclude_ids),
                None,
                None,
            )
            .map_err(|_| AuthnError::InvalidMfa)?;
        self.reg
            .lock()
            .expect("reg lock")
            .insert(username.to_owned(), state);
        Ok(ccr)
    }

    pub fn finish_registration(
        &self,
        username: &str,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<SecurityKey, AuthnError> {
        let state = self
            .reg
            .lock()
            .expect("reg lock")
            .remove(username)
            .ok_or(AuthnError::InvalidMfa)?;
        self.webauthn
            .finish_securitykey_registration(reg, &state)
            .map_err(|_| AuthnError::InvalidMfa)
    }

    pub fn start_authentication(
        &self,
        session_key: &str,
        creds: &[SecurityKey],
    ) -> Result<RequestChallengeResponse, AuthnError> {
        let (rcr, state) = self
            .webauthn
            .start_securitykey_authentication(creds)
            .map_err(|_| AuthnError::InvalidMfa)?;
        self.auth
            .lock()
            .expect("auth lock")
            .insert(session_key.to_owned(), state);
        Ok(rcr)
    }

    pub fn finish_authentication(
        &self,
        session_key: &str,
        auth: &PublicKeyCredential,
        creds: &mut [SecurityKey],
    ) -> Result<(), AuthnError> {
        let state = self
            .auth
            .lock()
            .expect("auth lock")
            .remove(session_key)
            .ok_or(AuthnError::InvalidMfa)?;
        let result = self
            .webauthn
            .finish_securitykey_authentication(auth, &state)
            .map_err(|_| AuthnError::InvalidMfa)?;
        for cred in creds.iter_mut() {
            if let Some(updated) = cred.update_credential(&result) {
                if updated {
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use crate::server::{AuthorizationServer, ServerConfig};
    use crate::users::{hash_password, UserRecord, DEMO_ALICE_UUID};
    use jose::alg::Alg;
    use jose::signing::generate_signing_key;
    use url::Url;
    use webauthn_authenticator_rs::prelude::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    #[test]
    fn softpasskey_register_and_authenticate() {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let srv = AuthorizationServer::new(
            ServerConfig::new("http://localhost:8089", "api"),
            vec![Client::new("spa", vec!["https://app.example/cb".into()])],
            key,
        );
        srv.upsert_user(
            "alice",
            UserRecord {
                email_verified: true,
                subject: "alice".into(),
                user_handle: DEMO_ALICE_UUID,
                name: Some("Alice".into()),
                email: None,
                password_hash: hash_password("password").unwrap(),
                totp_secret: None,
                webauthn_credentials: Vec::new(),
            },
        )
    .unwrap();

        let mut token = SoftPasskey::new(true);
        let origin = Url::parse("http://localhost:8089").unwrap();

        let ccr = srv.webauthn_start_registration("alice").unwrap();
        let reg = token.do_registration(origin.clone(), ccr).unwrap();
        srv.webauthn_finish_registration("alice", &reg).unwrap();
        assert!(srv.user_webauthn_enrolled("alice"));
        assert!(srv.user_mfa_enrolled("alice"));

        let rcr = srv
            .webauthn_start_authentication("sess-1", "alice")
            .unwrap();
        let auth = token.do_authentication(origin, rcr).unwrap();
        srv.webauthn_finish_authentication("sess-1", "alice", &auth)
            .unwrap();
    }
}
