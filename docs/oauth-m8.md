# M8 assurance

**Status: in progress** (B1 attack harness landed; fuzz + conformance checklist next).
Profile: [ADR 0013](adr/0013-assurance.md).

## B1 — Attack harness

```bash
cargo test -p oauth --test attack_harness
```

## Run

```bash
cargo test -p oauth --test attack_harness
```
