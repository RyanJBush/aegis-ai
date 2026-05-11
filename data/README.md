# Sample Data

This directory holds intentionally crafted sample inputs and a frozen sample scan
report. They exist to drive demos, tests, and the CLI scanner in `scripts/`.

## Layout

```
data/
├── samples/    Intentionally insecure inputs for the scanner to flag
└── reports/    Committed example output from a scan run
```

## Safety notes

- These payloads are static text fixtures. They do nothing on their own.
- They are intended for local, educational use against the bundled demo
  endpoints — never against systems you do not own or have written permission
  to test.
- See `ETHICS.md` at the repo root for full ethical-use guidance.
