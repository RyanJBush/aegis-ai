import re

import httpx

from app.config import settings

VULNERABILITY_RULES = [
    (
        "SQL Injection Pattern",
        "high",
        re.compile(r"(?i)(union\s+select|or\s+1=1|drop\s+table|select\s+\*)"),
        "Potential SQL injection payload discovered in submitted content.",
    ),
    (
        "Cross-Site Scripting Pattern",
        "high",
        re.compile(r"(?i)(<script|javascript:|onerror=)"),
        "Potential XSS payload markers detected.",
    ),
    (
        "Hardcoded Secret Pattern",
        "critical",
        re.compile(r"(?i)(AKIA[0-9A-Z]{16}|secret[_-]?key\s*=|password\s*=)"),
        "Potential hardcoded credential found.",
    ),
]


def explain_with_ai(title: str, details: str) -> str:
    if settings.llm_api_url and settings.llm_api_key:
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.post(
                    settings.llm_api_url,
                    headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                    json={
                        "prompt": (
                            "Explain this vulnerability and remediation: "
                            f"{title} - {details}"
                        ),
                    },
                )
                response.raise_for_status()
                data = response.json()
                if isinstance(data, dict) and data.get("explanation"):
                    return str(data["explanation"])
        except Exception:
            pass

    return (
        f"{title}: {details} Review affected input paths, enforce strict validation, and "
        "apply least-privilege controls to reduce exploitability."
    )


def run_scan(content: str) -> list[dict]:
    findings = []
    for title, severity, pattern, details in VULNERABILITY_RULES:
        if pattern.search(content):
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "details": details,
                    "explanation": explain_with_ai(title, details),
                }
            )

    if not findings:
        findings.append(
            {
                "title": "No obvious vulnerability signature",
                "severity": "low",
                "details": "No known high-confidence patterns were matched.",
                "explanation": explain_with_ai(
                    "No obvious vulnerability signature",
                    "No known high-confidence patterns were matched.",
                ),
            }
        )
    return findings
