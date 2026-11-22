# M8 assurance

**Status: in progress** (B1 harness + B2 fuzz landed; conformance checklist next).
Profile: [ADR 0013](adr/0013-assurance.md).

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

## Run

```bash
cargo test -p oauth --test attack_harness
cargo test -p jose --test parser_smoke
```
