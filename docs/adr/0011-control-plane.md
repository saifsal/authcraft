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

### B2 — Dynamic client registration (pending)

### B3 — SCIM 2.0 Users (pending)

## Consequences

- Demo `spa` and `alice` remain seed data; admin can add more at runtime.
- Wrong admin token → HTTP 401 `unauthorized`.

## Alternatives considered

- **Go control plane first.** Deferred; keep one process with M1–M5.
- **OAuth-protected admin.** Rejected for this slice (circular bootstrap).
