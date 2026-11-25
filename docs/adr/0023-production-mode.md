# ADR 0023: Production mode for `oauth-http`

- **Status:** Accepted (amended as M9 slices land)
- **Date:** 2026-11-25

## Context

M9 puts authcraft on the public internet at `https://authcraft.accumu.cc` as
an OpenID provider for tacto and glossa. Until now the binary was only a demo:
it ran with the published admin token, seeded user `alice`, open dynamic
registration, and a signing key regenerated on every start, so every restart
invalidated all tokens and the relying parties' cached JWKS. The threat model
lists the demo secrets (R4) and open registration (R2) as residual risks.

## Decision

1. The binary has two explicit modes, chosen by flags:
   - `--demo`: the walkthrough server, unchanged (`http://localhost:8089`).
   - production: `--data-dir` and `--public-url` (the issuer) are both
     required. The default bind is `127.0.0.1:8083`, behind Caddy.
   With neither, the binary exits with an error. A forgotten flag can never
   start a server with demo secrets.
2. Production disables everything demo-only:
   - no seeded users and no demo admin token (`AppState::production` refuses
     `DEMO_ADMIN_TOKEN`);
   - `ServerConfig.dynamic_registration = false`: `/register` answers 404 and
     discovery omits `registration_endpoint`;
   - the admin API is off unless an admin token file exists
     (`--admin-token-file`, or `$CREDENTIALS_DIRECTORY/admin-token` from a
     systemd `LoadCredential`). The token never appears in argv.
3. Clients come from `--clients`, a JSON file of RFC 7591 client metadata
   (`{"clients": [...]}`, unknown fields rejected, duplicate IDs rejected).
   Each client must pass `AuthorizationServer::client_is_valid`, the same check
   the admin API uses (ADR 0014–0020). An invalid file stops startup.
4. The Ed25519 signing key is stored at `<data-dir>/signing-key.pk8`, created
   on first start with mode 0600, and loaded afterwards.
5. `--secure-cookies` marks the login cookie `Secure` on plain HTTP, for
   Caddy terminating TLS in front (ADR 0021 B2 only covers the direct HTTPS
   listener).
6. `--tls-cert`, `--tls-key`, and `--tls-client-ca` replace the environment
   variables of ADR 0017 / 0019; the variables still work through clap.

## Consequences

- The demo command is now `cargo run -p oauth-http -- --demo`.
- User accounts are still in memory in this slice; ADR 0024 persists them.
- Threat-model R4 (demo secrets) no longer applies to production; R2 (open
  registration) is closed for production.
