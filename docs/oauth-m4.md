# M4 hardening (PAR + DPoP)

**Status: complete** for the PAR + DPoP + RFC 9700 checklist slice.
Profile: [ADR 0009](adr/0009-hardening-par-dpop.md).
BCP map: [rfc-9700-checklist.md](rfc-9700-checklist.md).

## B1 — PAR

`POST /par` stores authorize parameters and returns `request_uri`.
`GET /authorize?client_id=…&request_uri=…` redeems it once.
Vectors: `testvectors/par/`.

## B2 — DPoP

Optional `DPoP` header on `/token` binds `cnf.jkt` and sets `token_type=DPoP`.
UserInfo requires a matching proof when `cnf` is present.
Vectors: `testvectors/dpop/`.

## Run

```bash
cargo test -p oauth --test vectors
cargo test -p oauth-http
```
