# M6 control plane

**Status: in progress** (B1 admin API landed; DCR and SCIM next).
Profile: [ADR 0011](adr/0011-control-plane.md).

## B1 — Admin API

Bearer `authcraft-admin-token` (demo):

- `GET/POST /admin/clients`
- `DELETE /admin/clients/{client_id}`
- `GET /admin/users`

Vectors: `testvectors/admin/`.

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```
