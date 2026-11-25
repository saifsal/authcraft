# ADR 0025: Email-verified sign-up, password reset, and login throttling

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

For M9, people sign up at `authcraft.accumu.cc` themselves, with an email
address they must verify, the same model tacto and glossa use. glossa already
has a reviewed Rust implementation of these flows (Resend mail through a
SQLite outbox, hashed single-use links, rate limits). The threat model listed
unthrottled password guessing as residual risk R3.

## Decision

1. Port glossa's design rather than invent a new one:
   - `mailer.rs` is glossa's outbox and Resend worker (`Idempotency-Key`,
     backoff, `Retry-After`, drop after 8 attempts). Without `--mail-from`,
     mail is printed to the log.
   - Link tokens: 256-bit random, stored as SHA-256 hex in `auth_tokens`,
     single-use; verify links last 24 h, reset links 30 min. A GET only shows
     a form; the POST consumes the link, so mail scanners that follow links
     do nothing.
   - Mail is queued in the same transaction as its token.
2. Accounts are authcraft's own (ADR 0024): the login name is the lowercased
   email; `sub` is 128 random bits in hex, so changing an address never
   changes the identity relying parties see; the WebAuthn user handle is a
   random v4 UUID.
3. No answer reveals whether an address has an account. Sign-up, resend, and
   forgot-password give the same page for every address. Signing up with a
   verified address emails a notice instead of a link. A correct password on
   an unverified account sends a new link and says so (only someone with the
   password learns this).
4. The name and password of a sign-up travel with its verify link and are
   applied when the link is used. Someone who pre-registers another person's
   address cannot keep the password they chose.
5. Passwords are 10 to 1024 bytes; names up to 80 characters without control
   characters. Hashing (Argon2id) and the login check run on the blocking
   pool.
6. A reset sets the password, marks the address verified (the link proves
   ownership), and deletes every other outstanding link for the account.
7. Rate limits (fixed windows, client address from Caddy's
   `X-Forwarded-For`, last entry):
   - login: 10 failed attempts per account and 50 attempts per client
     address per 15 minutes (HTTP 429). A success clears the account count;
   - sign-up: 10 per client address per hour;
   - resend and forgot-password: 20 per client address per hour;
   - mail: 3 per address per hour, beyond which mail is silently dropped.
8. Pages share one layout (`pages.rs`): system fonts, no scripts, every
   interpolated value escaped. The login page shows demo credentials only in
   `--demo`.
9. Schema version 2 of `authcraft.db` adds `auth_tokens` and `outbox`.
   Demo mode and tests use an in-memory database for them.

## Consequences

- Threat-model R3 is reduced: logins are throttled per account and per
  client address. A per-account lock can be triggered by anyone who knows an
  address (at most 15 minutes); accepted, as glossa does.
- Tests: `accounts` unit tests (flows, pre-registration, notices, reset,
  silence, limits) and `tests/accounts.rs` (HTTP sign-up to code issuance,
  identical responses, reset, throttling, no demo hints in production).
