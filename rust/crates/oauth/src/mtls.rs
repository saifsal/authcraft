//! OAuth 2.0 mutual-TLS helpers (RFC 8705, ADR 0017).
//!
//! The library is transport-agnostic: the HTTP layer terminates TLS and passes
//! the DER bytes of the client's leaf certificate. This module computes the
//! RFC 8705 §3.1 `x5t#S256` thumbprint and reads the certificates a
//! `self_signed_tls_client_auth` client registers as `x5c` in its JWKS
//! (RFC 8705 §2.2.2). Self-signed certificates are compared byte-for-byte by
//! thumbprint.
//!
//! For the PKI method `tls_client_auth` (RFC 8705 §2.1, ADR 0019) the leaf is
//! validated with `rustls-webpki` against the AS's configured client CAs
//! (signature, validity period, clientAuth extended key usage), and one
//! registered subject alternative name must appear in the certificate.

use std::net::IpAddr;
use std::time::Duration;

use jose::b64url;
use jose::json::{self, Value};
use ring::digest;
use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};
use x509_parser::extensions::GeneralName;

use crate::error::OAuthError;

/// The single registered certificate subject of a `tls_client_auth` client
/// (RFC 8705 §2.1.2). Subject DN matching is not supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsClientAuthSubject {
    /// `tls_client_auth_san_dns`; compared case-insensitively.
    SanDns(String),
    /// `tls_client_auth_san_uri`; exact match.
    SanUri(String),
    /// `tls_client_auth_san_email`; exact match.
    SanEmail(String),
    /// `tls_client_auth_san_ip`; compared as address octets.
    SanIp(Vec<u8>),
}

impl TlsClientAuthSubject {
    /// Builds the subject from RFC 8705 client metadata. No member gives
    /// `Ok(None)`; more than one, an unparseable IP, or
    /// `tls_client_auth_subject_dn` (unsupported) is `invalid_request`.
    pub fn from_metadata(
        subject_dn: Option<&str>,
        san_dns: Option<&str>,
        san_uri: Option<&str>,
        san_ip: Option<&str>,
        san_email: Option<&str>,
    ) -> Result<Option<Self>, OAuthError> {
        if subject_dn.is_some() {
            return Err(OAuthError::InvalidRequest);
        }
        let mut found = Vec::new();
        if let Some(v) = san_dns {
            found.push(Self::SanDns(v.to_owned()));
        }
        if let Some(v) = san_uri {
            found.push(Self::SanUri(v.to_owned()));
        }
        if let Some(v) = san_ip {
            let ip: IpAddr = v.parse().map_err(|_| OAuthError::InvalidRequest)?;
            found.push(Self::SanIp(match ip {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            }));
        }
        if let Some(v) = san_email {
            found.push(Self::SanEmail(v.to_owned()));
        }
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => Err(OAuthError::InvalidRequest),
        }
    }


    /// Whether `name` is the registered subject alternative name.
    fn matches(&self, name: &GeneralName<'_>) -> bool {
        match (self, name) {
            (Self::SanDns(want), GeneralName::DNSName(got)) => want.eq_ignore_ascii_case(got),
            (Self::SanUri(want), GeneralName::URI(got)) => want == got,
            (Self::SanEmail(want), GeneralName::RFC822Name(got)) => want == got,
            (Self::SanIp(want), GeneralName::IPAddress(got)) => want.as_slice() == *got,
            _ => false,
        }
    }

    /// A usable registration has a non-empty value.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::SanDns(s) | Self::SanUri(s) | Self::SanEmail(s) => !s.is_empty(),
            Self::SanIp(b) => !b.is_empty(),
        }
    }
}

/// Validates a `tls_client_auth` leaf certificate against `trust_anchors`
/// (DER CA certificates) at `now`, then requires `subject` among its SANs.
/// The leaf must be issued directly by a trust anchor (no intermediates).
/// Every failure is `invalid_client`.
pub fn verify_pki_client_cert(
    leaf_der: &[u8],
    trust_anchors: &[Vec<u8>],
    subject: &TlsClientAuthSubject,
    now: i64,
) -> Result<(), OAuthError> {
    let anchor_ders: Vec<CertificateDer<'_>> = trust_anchors
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let anchors = anchor_ders
        .iter()
        .map(anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OAuthError::ServerError)?;
    if anchors.is_empty() {
        return Err(OAuthError::InvalidClient);
    }
    let leaf = CertificateDer::from(leaf_der);
    let ee = EndEntityCert::try_from(&leaf).map_err(|_| OAuthError::InvalidClient)?;
    let secs = u64::try_from(now).map_err(|_| OAuthError::InvalidClient)?;
    ee.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        &anchors,
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(secs)),
        KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|_| OAuthError::InvalidClient)?;

    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf_der).map_err(|_| OAuthError::InvalidClient)?;
    let san = cert
        .subject_alternative_name()
        .map_err(|_| OAuthError::InvalidClient)?
        .ok_or(OAuthError::InvalidClient)?;
    if san.value.general_names.iter().any(|n| subject.matches(n)) {
        Ok(())
    } else {
        Err(OAuthError::InvalidClient)
    }
}

/// RFC 8705 §3.1 `x5t#S256`: base64url(SHA-256(DER certificate)).
pub fn cert_thumbprint(der: &[u8]) -> String {
    b64url::encode(digest::digest(&digest::SHA256, der).as_ref())
}

/// Decodes standard (RFC 4648 §4) base64, as used by JWK `x5c`.
///
/// Translates to the base64url alphabet and reuses the strict canonical
/// decoder, so padding must be correct and unused bits must be zero.
fn decode_std_base64(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.strip_suffix("==").or_else(|| s.strip_suffix('=')).unwrap_or(s);
    if trimmed.contains('=') || trimmed.contains('-') || trimmed.contains('_') {
        return None;
    }
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let url: String = trimmed
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    b64url::decode(&url).ok()
}

/// Thumbprints of the first `x5c` certificate of every key in a JWKS
/// document. Every key must carry a non-empty `x5c` array of base64 DER
/// strings, and there must be at least one key.
pub fn thumbprints_from_jwks(jwks_json: &str) -> Result<Vec<String>, OAuthError> {
    let doc = json::parse(jwks_json.as_bytes()).map_err(|_| OAuthError::InvalidRequest)?;
    let Some(Value::Array(keys)) = doc.get("keys") else {
        return Err(OAuthError::InvalidRequest);
    };
    if keys.is_empty() {
        return Err(OAuthError::InvalidRequest);
    }
    keys.iter()
        .map(|key| {
            let Some(Value::Array(chain)) = key.get("x5c") else {
                return Err(OAuthError::InvalidRequest);
            };
            let leaf = chain
                .first()
                .and_then(Value::as_str)
                .ok_or(OAuthError::InvalidRequest)?;
            let der = decode_std_base64(leaf).ok_or(OAuthError::InvalidRequest)?;
            if der.is_empty() {
                return Err(OAuthError::InvalidRequest);
            }
            Ok(cert_thumbprint(&der))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_is_sha256_b64url() {
        // SHA-256("abc"), FIPS 180-2 B.1.
        assert_eq!(
            cert_thumbprint(b"abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn std_base64_decoding() {
        assert_eq!(decode_std_base64("YWJj").unwrap(), b"abc");
        assert_eq!(decode_std_base64("YWI=").unwrap(), b"ab");
        assert_eq!(decode_std_base64("YQ==").unwrap(), b"a");
        assert_eq!(decode_std_base64("+/8=").unwrap(), [0xfb, 0xff]);
        for bad in ["YWI", "YQ=", "Y===", "-_8=", "YW=j", "YR=="] {
            assert!(decode_std_base64(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn jwks_thumbprints() {
        let ok = r#"{"keys":[{"kty":"OKP","x5c":["YWJj","ignored"]},{"x5c":["YWI="]}]}"#;
        assert_eq!(
            thumbprints_from_jwks(ok).unwrap(),
            vec![cert_thumbprint(b"abc"), cert_thumbprint(b"ab")]
        );
        for bad in [
            r#"{"keys":[]}"#,
            r#"{"keys":[{"kty":"OKP"}]}"#,
            r#"{"keys":[{"x5c":[]}]}"#,
            r#"{"keys":[{"x5c":[7]}]}"#,
            r#"{"keys":[{"x5c":["not base64!"]}]}"#,
            "nope",
        ] {
            assert_eq!(thumbprints_from_jwks(bad), Err(OAuthError::InvalidRequest), "{bad}");
        }
    }

    #[test]
    fn subject_metadata_rules() {
        use TlsClientAuthSubject as S;
        assert_eq!(S::from_metadata(None, None, None, None, None), Ok(None));
        assert_eq!(
            S::from_metadata(None, Some("a.example"), None, None, None),
            Ok(Some(S::SanDns("a.example".into())))
        );
        assert_eq!(
            S::from_metadata(None, None, None, Some("192.0.2.7"), None),
            Ok(Some(S::SanIp(vec![192, 0, 2, 7])))
        );
        for bad in [
            S::from_metadata(Some("CN=x"), None, None, None, None),
            S::from_metadata(None, Some("a"), Some("https://a"), None, None),
            S::from_metadata(None, None, None, Some("not-an-ip"), None),
        ] {
            assert_eq!(bad, Err(OAuthError::InvalidRequest));
        }
    }
}
