# M8 assurance

**Status: complete** for the attack harness + fuzz smoke + conformance checklist
slice. Profile: [ADR 0013](adr/0013-assurance.md).
Checklist: [openid-conformance-checklist.md](openid-conformance-checklist.md).

## B1 — Attack harness

```bash
cargo test -p oauth --test attack_harness
```

## B2 — Fuzzing

```bash
cargo test -p jose --test parser_smoke
cd rust && cargo +nightly fuzz run b64url_decode -- -max_total_time=15
```

CI job `fuzz-smoke` runs short libFuzzer passes on nightly.

## B3 — OpenID conformance map

See [openid-conformance-checklist.md](openid-conformance-checklist.md). The full
OIDF suite is not executed in CI; gaps stay **open** there.

## Run

```bash
cargo test -p oauth --test attack_harness
cargo test -p jose --test parser_smoke
```
