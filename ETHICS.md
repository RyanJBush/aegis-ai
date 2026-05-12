# Ethical & Safe Use

This project is an **educational portfolio build** by an undergraduate Information
Science student. It exists to demonstrate familiarity with application-security
concepts — OWASP Top 10, secure coding, authentication, authorization, and
DevSecOps tooling — not as a substitute for professional security testing.

## Intended use

- ✅ Run locally against the bundled sample inputs in `data/samples/`.
- ✅ Run against your own intentionally vulnerable demo applications.
- ✅ Use as a learning resource for reading and extending a scanner engine.
- ✅ Use as a portfolio artifact in interviews and applications.

## Not for

- ❌ Scanning third-party systems, websites, or APIs you do not own or have
  explicit written authorization to test. Doing so may violate the U.S.
  Computer Fraud and Abuse Act, your jurisdiction's equivalent law, and the
  target's acceptable-use policies.
- ❌ Production deployments. The codebase is explicitly not hardened for
  production: default secrets, demo endpoints, no rate-limit tuning, and
  limited input fuzzing.
- ❌ Compliance attestation. This tool does not certify SOC 2, ISO 27001,
  PCI-DSS, or any other compliance regime.
- ❌ Exhaustive vulnerability coverage. The scanner uses **static
  pattern-matching only** and will both miss attacks and produce false
  positives — see `docs/owasp-mapping.md` for the coverage matrix and gaps.

## Reporting issues

If you find a security issue in this codebase, please follow the disclosure
process in `SECURITY.md` rather than opening a public issue.

## Authorization is mandatory

If you intend to use any technique demonstrated here against a system you do
not own, **get written authorization first**. Common formal mechanisms include
a penetration-testing statement of work, a bug-bounty program scope, or a CTF
rules-of-engagement document.
