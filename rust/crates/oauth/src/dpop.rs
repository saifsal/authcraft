//! DPoP proof verification (RFC 9449 / ADR 0009 B2). EdDSA only.

use std::collections::HashMap;

use jose::alg::Alg;
use jose::b64url;
use jose::json::{self, Value};
use jose::jwk::PublicKey;
use jose::jwks::KeyMaterial;
use jose::signature;

use crate::error::OAuthError;

/// Allowed clock skew for DPoP `iat` (seconds).
pub const DPOP_IAT_LEEWAY_SECS: i64 = 120;

/// How long DPoP proof JTIs are remembered against replay.
pub const DPOP_JTI_TTL_SECS: i64 = 600;

#[derive(Debug, Default)]
pub struct DpopJtiCache {
    /// jti → expires_at
    seen: HashMap<String, i64>,
}

impl DpopJtiCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_store(&mut self, jti: &str, now: i64) -> Result<(), OAuthError> {
        self.prune(now);
        if self.seen.contains_key(jti) {
            return Err(OAuthError::InvalidRequest);
        }
        self.seen
            .insert(jti.to_owned(), now.saturating_add(DPOP_JTI_TTL_SECS));
        Ok(())
    }

    fn prune(&mut self, now: i64) {
        self.seen.retain(|_, exp| *exp > now);
    }
}

/// Verified DPoP proof summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopProof {
    pub jkt: String,
}

/// Verifies a compact DPoP proof JWT for `htm`/`htu` at `now`.
///
/// When `expected_nonce` is `Some`, the proof must carry a matching `nonce`
/// claim; otherwise [`OAuthError::UseDpopNonce`].
pub fn verify_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    now: i64,
    jti_cache: &mut DpopJtiCache,
    expected_nonce: Option<&str>,
) -> Result<DpopProof, OAuthError> {
    let mut parts = proof.split('.');
    let header_b64 = parts.next().ok_or(OAuthError::InvalidRequest)?;
    let payload_b64 = parts.next().ok_or(OAuthError::InvalidRequest)?;
    let sig_b64 = parts.next().ok_or(OAuthError::InvalidRequest)?;
    if parts.next().is_some() || header_b64.is_empty() || payload_b64.is_empty() || sig_b64.is_empty()
    {
        return Err(OAuthError::InvalidRequest);
    }

    let header_bytes = b64url::decode(header_b64).map_err(|_| OAuthError::InvalidRequest)?;
    let payload_bytes = b64url::decode(payload_b64).map_err(|_| OAuthError::InvalidRequest)?;
    let sig_bytes = b64url::decode(sig_b64).map_err(|_| OAuthError::InvalidRequest)?;

    let header = json::parse(&header_bytes).map_err(|_| OAuthError::InvalidRequest)?;
    let payload = json::parse(&payload_bytes).map_err(|_| OAuthError::InvalidRequest)?;

    let typ = header.get("typ").and_then(Value::as_str).unwrap_or("");
    if !typ.eq_ignore_ascii_case("dpop+jwt") {
        return Err(OAuthError::InvalidRequest);
    }
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != "EdDSA" {
        return Err(OAuthError::InvalidRequest);
    }
    let jwk_val = header.get("jwk").ok_or(OAuthError::InvalidRequest)?;
    let public = parse_eddsa_jwk(jwk_val)?;
    let jkt = public.thumbprint();

    let signing_input = format!("{header_b64}.{payload_b64}");
    signature::verify(
        Alg::EdDSA,
        &KeyMaterial::Public(public),
        signing_input.as_bytes(),
        &sig_bytes,
    )
    .map_err(|_| OAuthError::InvalidRequest)?;

    let proof_htm = payload.get("htm").and_then(Value::as_str).unwrap_or("");
    let proof_htu = payload.get("htu").and_then(Value::as_str).unwrap_or("");
    if proof_htm != htm || proof_htu != htu {
        return Err(OAuthError::InvalidRequest);
    }
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(OAuthError::InvalidRequest)?;
    if (now - iat).abs() > DPOP_IAT_LEEWAY_SECS {
        return Err(OAuthError::InvalidRequest);
    }
    if let Some(expected) = expected_nonce {
        let got = payload.get("nonce").and_then(Value::as_str).unwrap_or("");
        if got != expected {
            return Err(OAuthError::UseDpopNonce);
        }
    }
    let jti = payload
        .get("jti")
        .and_then(Value::as_str)
        .ok_or(OAuthError::InvalidRequest)?;
    if jti.is_empty() {
        return Err(OAuthError::InvalidRequest);
    }
    jti_cache.check_and_store(jti, now)?;

    Ok(DpopProof { jkt })
}

fn parse_eddsa_jwk(v: &Value) -> Result<PublicKey, OAuthError> {
    let obj = v.as_object().ok_or(OAuthError::InvalidRequest)?;
    let get = |name: &str| -> Option<&str> {
        obj.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, val)| val.as_str())
    };
    if get("kty") != Some("OKP") || get("crv") != Some("Ed25519") {
        return Err(OAuthError::InvalidRequest);
    }
    let x_b64 = get("x").ok_or(OAuthError::InvalidRequest)?;
    let x = b64url::decode(x_b64).map_err(|_| OAuthError::InvalidRequest)?;
    PublicKey::ed25519_from_bytes(&x).map_err(|_| OAuthError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose::signing::{self, generate_signing_key};

    fn make_proof(htm: &str, htu: &str, iat: i64, jti: &str) -> (String, String) {
        let key = generate_signing_key(Alg::EdDSA).unwrap();
        let jkt = key.public.thumbprint();
        let x = match &key.public {
            PublicKey::Ed25519 { x } => b64url::encode(x),
            _ => panic!("eddsa"),
        };
        let header = format!(
            r#"{{"typ":"dpop+jwt","alg":"EdDSA","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
        );
        let payload = format!(r#"{{"htm":"{htm}","htu":"{htu}","iat":{iat},"jti":"{jti}"}}"#);
        // Build compact JWS without sign_compact's kid requirement (DPoP uses jwk).
        let enc_h = b64url::encode(header.as_bytes());
        let enc_p = b64url::encode(payload.as_bytes());
        let input = format!("{enc_h}.{enc_p}");
        let sig = signing::sign(Alg::EdDSA, &key.pkcs8, input.as_bytes()).unwrap();
        let proof = format!("{input}.{}", b64url::encode(&sig));
        (proof, jkt)
    }

    #[test]
    fn accepts_valid_eddsa_proof() {
        let (proof, jkt) = make_proof("POST", "https://auth.example/token", 1_000, "j1");
        let mut cache = DpopJtiCache::new();
        let out = verify_proof(
            &proof,
            "POST",
            "https://auth.example/token",
            1_000,
            &mut cache,
            None,
        )
        .unwrap();
        assert_eq!(out.jkt, jkt);
        assert!(verify_proof(
            &proof,
            "POST",
            "https://auth.example/token",
            1_001,
            &mut cache,
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_htu() {
        let (proof, _) = make_proof("POST", "https://auth.example/token", 1_000, "j2");
        let mut cache = DpopJtiCache::new();
        assert!(verify_proof(
            &proof,
            "POST",
            "https://auth.example/other",
            1_000,
            &mut cache,
            None,
        )
        .is_err());
    }

    #[test]
    fn requires_matching_nonce_when_expected() {
        let (proof, _) = make_proof("POST", "https://auth.example/token", 1_000, "j3");
        let mut cache = DpopJtiCache::new();
        assert_eq!(
            verify_proof(
                &proof,
                "POST",
                "https://auth.example/token",
                1_000,
                &mut cache,
                Some("n1"),
            ),
            Err(OAuthError::UseDpopNonce)
        );
    }
}
