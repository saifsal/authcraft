# M6 control plane

**Status: complete** for the admin + DCR + SCIM Users slice.
Profile: [ADR 0011](adr/0011-control-plane.md).

## B1 — Admin API

Bearer `authcraft-admin-token` (demo):

- `GET/POST /admin/clients`
- `DELETE /admin/clients/{client_id}`
- `GET /admin/users`

Vectors: `testvectors/admin/`.

## B2 — Dynamic client registration

`POST /register` (public `none` clients, or `private_key_jwt` with an inline `jwks`; ADR 0014). Discovery: `registration_endpoint`.
Vectors: `testvectors/dcr/`.

## B3 — SCIM 2.0 Users

Admin bearer on `/scim/v2/Users` (create/list/get/replace/delete).
Password is write-only on create/replace (Argon2id).

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```
