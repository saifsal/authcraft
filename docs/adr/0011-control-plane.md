# ADR 0011: M6 control plane (admin, DCR, SCIM)

- **Status:** Accepted (amended as M6 slices land)
- **Date:** 2026-11-22

## Context

M1–M5 ship a working AS with a fixed demo client and in-memory users. Operators
need to register clients and manage users without rebuilding. M6 adds an
in-process Rust control plane (deferring a separate Go service).

## Decision — B1: admin API

1. `ClientRegistry` is mutable at runtime (`insert` / `remove` / `list`).
2. `Client` may carry optional `client_name`. Clients remain **public** (no secret).
3. `ServerConfig.admin_token` gates admin routes. Demo uses published
   `DEMO_ADMIN_TOKEN` (`authcraft-admin-token`). Empty token disables admin.
4. HTTP (Bearer admin token):
   - `GET/POST /admin/clients`
   - `DELETE /admin/clients/{client_id}`
   - `GET /admin/users` (no password hashes)
5. Library: `list_clients`, `create_client`, `delete_client`, `list_users`.

## Amendments

### B2 — Dynamic client registration (RFC 7591)

1. `POST /register` (no admin token) accepts JSON `redirect_uris` (≥1), optional
   `client_name`, and optional `token_endpoint_auth_method` which must be `none`.
2. Issues opaque `client_id` (random base64url). No `client_secret`, no
   registration access token, no RFC 7592 management endpoint.
3. Response includes `token_endpoint_auth_method: "none"`,
   `grant_types: ["authorization_code","refresh_token"]`,
   `response_types: ["code"]`. PKCE S256 remains required by the AS.
4. Discovery advertises `registration_endpoint` and
   `token_endpoint_auth_methods_supported: ["none"]`.

### B3 — SCIM 2.0 Users

1. Base path `/scim/v2` with the same admin bearer as `/admin`.
2. `Users` only: `POST`, `GET /Users`, `GET /Users/{id}`, `PUT`, `DELETE`.
3. Attributes: `id` (= `user_handle` UUID), `userName`, `displayName` /
   `name.formatted`, `emails`, `active`. Write-only `password` (Argon2id).
4. Optional list filter: `userName eq "..."`.
5. Errors use SCIM Error schema (`status`, `detail`).

## Consequences

- Demo `spa` and `alice` remain seed data; admin/DCR/SCIM can add more at runtime.
- Wrong admin token → HTTP 401 `unauthorized`.
- Go control plane remains a later architectural split.

## Alternatives considered

- **Go control plane first.** Deferred; keep one process with M1–M5.
- **OAuth-protected admin.** Rejected for this slice (circular bootstrap).
- **SCIM Groups.** Deferred.
