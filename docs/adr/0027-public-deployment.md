# ADR 0027: Landing page and deployment on the accumu.cc VPS

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

M9 publishes authcraft at `https://authcraft.accumu.cc` as a showcase and as
the OpenID provider behind "Sign in with authcraft" on tacto and glossa. The
sibling apps already share one VPS: Caddy terminates TLS with one snippet per
app in `/etc/caddy/conf.d`, and each app is a hardened systemd service with
`DynamicUser`, `StateDirectory`, and `LoadCredential` for secrets (accumu.cc
on 8080, tacto 8081, glossa 8082).

## Decision

1. **Landing page** at `/`: what authcraft is, the apps that sign in with it
   (configured clients that have a `client_name` and an `https` redirect URI,
   linked by origin), links to sign up / sign in or the account page, the
   issuer, discovery, and JWKS URLs, and a plain statement that it has not had
   an external security audit. Same script-free layout as the other pages.
   The favicon (a keyhole on the accent blue) is `assets/favicon.svg`,
   with `favicon.ico` (16/32/48 px) generated from it by
   `assets/make-favicon.py`; both are embedded in the binary and served with
   a one-week cache.
2. **No consent screen.** Every production client is configured by the
   operator (ADR 0023) and is first-party (tacto, glossa). Third-party
   clients would need consent first.
3. **Deployment** follows the sibling apps exactly (`deploy/`):
   - `Caddyfile` → `/etc/caddy/conf.d/authcraft.caddy`: TLS 1.2/1.3, HSTS,
     64 KB body limit, proxy to `127.0.0.1:8083`, no `trusted_proxies`.
   - `authcraft.service`: `DynamicUser`, `StateDirectory=authcraft`,
     `UMask=0077`, the sibling sandboxing set, the Resend key through
     `LoadCredential`, clients from `/etc/authcraft/clients.json`, the admin
     API off unless an admin-token credential is added.
   - `mise run deploy` (root `mise.toml`) builds a portable
     `x86-64-v2` release binary and copies binary, unit, and snippet; it
     checks that the Caddy root, the Resend key, and the clients file exist
     and never copies secrets.
   - `deploy/README.md` is the runbook: DNS, credentials, clients, deploy,
     checks, backups, restart behavior, and the Cloudflare caveat for
     per-client rate limits.

## Consequences

- The release binary links SQLite statically and needs only glibc.
- The relying parties' public keys go into `clients.json` once they exist
  (M9 phases B and C).
- Tests: `tests/landing.rs`. The unit's exact command line was run locally
  against the release binary with a credentials directory; the VPS deploy
  itself is done by the operator.
