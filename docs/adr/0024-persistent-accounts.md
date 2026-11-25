# ADR 0024: Persistent accounts and `email_verified`

- **Status:** Accepted (amended as M9 slices land)
- **Date:** 2026-11-25

## Context

Accounts lived only in memory, so a restart of the production server
(ADR 0023) would delete every user. M9 also adds email-verified signup, so
the account model needs to record whether an address is verified, and
relying parties need that as the OIDC `email_verified` claim.

## Decision

1. `UserRecord.email_verified: bool`. `authenticate_password` returns
   `email_not_verified` for an unverified account, checked only after the
   password matches, so the state is revealed only to someone who knows the
   password. The demo user and SCIM-created users with an email are verified
   (an administrator vouches for them).
2. `email_verified` is emitted next to `email` in access tokens, ID tokens,
   and UserInfo. It is read from the account at minting time by `sub`, so it
   reflects the current state; subjects that are not local accounts
   (federated, LDAP) omit it.
3. `oauth::UserRepository` (`save`, `delete`) is the storage interface.
   `AuthorizationServer::attach_user_repository` loads existing accounts and
   attaches the repository once. Every account change (SCIM create, replace,
   delete; upsert; TOTP enrollment; WebAuthn registration; WebAuthn sign-in,
   which updates the authenticator counter) writes the new record through the
   repository *before* changing memory, while holding the users lock. A failed
   write leaves memory unchanged and returns `temporarily_unavailable`
   (`AuthnError::StorageUnavailable`, `AdminError::Unavailable`).
4. `oauth_http::store::SqliteUserStore` implements it with rusqlite (bundled
   SQLite): one `users` table keyed by login name, `subject` unique, the full
   record (including WebAuthn credentials) as JSON, `PRAGMA user_version`
   for migrations, WAL with `synchronous=FULL`. Production mode opens
   `<data-dir>/authcraft.db`.
5. Codes, PAR URIs, refresh families, DPoP and assertion caches, and the
   access-token denylist stay in memory. A restart signs users out of relying
   parties' refresh flows and forgets revocations of access tokens that have
   not expired (at most 300 s); see the threat model.

## Consequences

- `upsert_user` now returns `Result`.
- Tests: `oauth-http` `store` unit tests (round trip, restart, unique `sub`)
  and `email_verified` assertions in the OpenID end-to-end test.
