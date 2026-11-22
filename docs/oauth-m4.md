# M4 hardening (PAR + DPoP)

**Status: in progress (PAR landed).** Profile:
[ADR 0009](adr/0009-hardening-par-dpop.md).

## B1 — PAR

`POST /par` stores authorize parameters and returns `request_uri`.
`GET /authorize?client_id=…&request_uri=…` redeems it once.
Vectors: `testvectors/par/`.

## Run

```bash
cargo test -p oauth --test vectors par_shared
cargo test -p oauth-http
```
