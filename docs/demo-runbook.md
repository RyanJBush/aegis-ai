# Obsidian Demo Runbook

This runbook is for presenting Obsidian honestly for AppSec/backend/security-tooling/CI-CD roles.

## Demo guardrails (say this up front)

- This is an educational platform and local scanner.
- Demo only against bundled sample files or owned/authorized targets.
- It is not positioned as a replacement for SAST, DAST, IAST, penetration testing, or professional review.

## 2-minute CLI demo

```bash
pip install -r backend/requirements.txt
python scripts/scan.py data/samples/sqli_payload.txt
python scripts/scan.py --profile deep --json data/samples/insecure_config.yaml
python scripts/scan.py --fail-on high data/samples/sqli_payload.txt ; echo "exit=$?"
```

### Talking points

- Show severity + OWASP + CWE context in findings.
- Show SARIF/JSON-compatible workflow output.
- Show CI gate behavior via non-zero exit code.

## Full-stack demo flow (8–12 minutes)

1. Start stack (`make up`) and open UI + `/docs`.
2. Login and explain RBAC/workspace context.
3. Run or queue a scan.
4. Review findings and workflow updates.
5. Export reports (JSON/SARIF endpoints).
6. Show governance endpoints and policy gate.

## Interview-safe positioning lines

- “I built this to demonstrate secure backend design, scanner architecture, and CI integration.”
- “I intentionally document limitations to avoid over-claiming security coverage.”
- “I use this as one layer in defense-in-depth, not a complete security program.”

## Demo pitfalls to avoid

- Don’t imply broad exploit capability or unauthorized target testing.
- Don’t claim full OWASP coverage unless mapping docs show it.
- Don’t claim parity with enterprise SAST/DAST/IAST products.

## Pre-demo checklist

- Confirm sample files exist under `data/samples/`.
- Confirm CLI command outputs are reproducible.
- Confirm docs links in README are valid.
- Confirm ethics and security policies are present and aligned.
