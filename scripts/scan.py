"""Standalone CLI wrapper around the vulnerability scanner engine.

Reads a payload from a file or stdin and prints findings as a human-readable
table or as JSON. Intended for local/educational use against the sample
inputs in `data/samples/` or your own static test fixtures.

Examples:
    python scripts/scan.py data/samples/sqli_payload.txt
    python scripts/scan.py --profile deep --json data/samples/insecure_config.yaml
    cat payload.txt | python scripts/scan.py -
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.scanner_engine import build_default_registry  # noqa: E402

SEVERITY_EXIT_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _read_payload(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.is_file():
        raise SystemExit(f"input not found: {source}")
    return path.read_text(encoding="utf-8", errors="replace")


def _format_table(findings: list) -> str:
    if not findings:
        return "No findings."
    lines = [f"{'SEVERITY':<10} {'RULE':<22} {'OWASP':<48} {'CWE':<10} EVIDENCE"]
    for f in findings:
        evidence = f.evidence.replace("\n", " ")[:60]
        lines.append(
            f"{f.severity:<10} {f.rule_key:<22} {f.owasp_category:<48} {f.cwe_id:<10} {evidence}"
        )
    return "\n".join(lines)


def _summary(findings: list) -> dict:
    by_severity: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_owasp[f.owasp_category] = by_owasp.get(f.owasp_category, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_owasp": by_owasp}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local vulnerability scanner CLI.")
    parser.add_argument("input", help="Path to a payload file, or '-' to read stdin.")
    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Rule profile depth (default: standard).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit non-zero when any finding meets or exceeds this severity.",
    )
    args = parser.parse_args(argv)

    payload = _read_payload(args.input)
    registry = build_default_registry()
    findings = registry.run(payload, profile=args.profile)

    if args.json:
        out = {
            "profile": args.profile,
            "summary": _summary(findings),
            "findings": [
                {
                    "rule_key": f.rule_key,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "owasp_category": f.owasp_category,
                    "cwe_id": f.cwe_id,
                    "evidence": f.evidence,
                    "affected_endpoint": f.affected_endpoint,
                    "remediation": f.remediation,
                    "secure_example": f.secure_example,
                }
                for f in findings
            ],
        }
        print(json.dumps(out, indent=2))
    else:
        print(_format_table(findings))
        print()
        print(f"Total findings: {len(findings)} (profile={args.profile})")

    if args.fail_on:
        threshold = SEVERITY_EXIT_RANK[args.fail_on]
        if any(SEVERITY_EXIT_RANK.get(f.severity, 0) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
