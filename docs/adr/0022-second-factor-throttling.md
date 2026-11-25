# ADR 0022: TOTP brute-force lockout and replay protection

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

M5 (ADR 0010) added TOTP as a second factor. Writing the threat model found
two weaknesses in `AuthorizationServer::verify_totp`:

1. **Unlimited guesses.** One MFA ticket accepted any number of codes. A
   ±1-step window makes three six-digit codes valid at once, so an attacker
   who already has the password needs on the order of 330,000 guesses on
   average. That is practical online without a limit, which defeats the
   second factor.
2. **Replay.** Nothing recorded an accepted code, so a code seen once (over
   the shoulder, or by a phishing proxy) worked again for up to about
   90 seconds. RFC 6238 §5.2 says the verifier must not accept the second
   attempt after a successful validation.

## Decision

1. Per-user lockout in the library, so every caller is covered: after
   `MFA_MAX_FAILURES` (5) consecutive failed codes, `verify_totp` returns
   `too_many_attempts` for `MFA_LOCKOUT_SECS` (300 s) without checking the
   code. A success resets the count; once a lockout ends, counting starts
   again.
2. Replay protection: `totp::matching_step` returns the matched time step,
   and `verify_totp` refuses any step not later than the last accepted one
   for that user.
3. `oauth-http` answers `too_many_attempts` at `/login/mfa` with HTTP 429.
4. Vectors: `neg-totp-replay`, `neg-totp-locked`, and
   `pos-totp-after-four-failures` in `testvectors/authn/`.

## Consequences

- Someone who knows a user's password can lock that user's TOTP check for
  five minutes. This is accepted: it needs the password, and the
  alternative is an online bypass of the second factor.
- State is in memory, like the rest of the AS.
- Passwords are not throttled; that remains residual risk R3 in
  [`docs/threat-model.md`](../threat-model.md).
