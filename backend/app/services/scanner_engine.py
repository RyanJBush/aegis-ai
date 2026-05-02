import hashlib
import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RuleFinding:
    rule_key: str
    title: str
    severity: str
    confidence: float
    reason_code: str
    owasp_category: str
    cwe_id: str
    evidence: str
    description: str
    affected_endpoint: str
    remediation: str
    secure_example: str
    dedupe_key: str


@dataclass(frozen=True)
class ScannerRule:
    key: str
    title: str
    description: str
    severity: str
    confidence: float
    reason_code: str
    owasp_category: str
    cwe_id: str
    remediation: str
    secure_example: str
    profile_minimum: str
    detector: Callable[[str], list[str]]


PROFILE_ORDER = {"quick": 1, "standard": 2, "deep": 3}
# Keep aligned with persistence constraints and UI evidence panel readability.
MAX_EVIDENCE_LENGTH = 250


def _dedupe_key(rule_key: str, evidence: str) -> str:
    fingerprint = f"{rule_key}|{evidence.strip().lower()}"
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def _regex_matches(payload: str, patterns: list[str]) -> list[str]:
    return [
        match.group(0)[:MAX_EVIDENCE_LENGTH]
        for pattern in patterns
        for match in re.finditer(pattern, payload)
    ]


def _detect_insecure_headers(payload: str) -> list[str]:
    normalized = "\n".join(line.strip() for line in payload.splitlines())
    if not re.search(r"(?im)^http/\d(?:\.\d)?\s+\d{3}", normalized):
        return []
    findings: list[str] = []
    header_patterns = {
        "missing_content_security_policy": r"(?im)^content-security-policy\s*:",
        "missing_x_content_type_options": r"(?im)^x-content-type-options\s*:\s*nosniff\s*$",
        "missing_x_frame_options": r"(?im)^x-frame-options\s*:",
        "missing_strict_transport_security": r"(?im)^strict-transport-security\s*:",
    }
    for label, pattern in header_patterns.items():
        if not re.search(pattern, normalized):
            findings.append(f"{label}")

    findings.extend(_regex_matches(normalized, [r"(?im)^access-control-allow-origin\s*:\s*\*\s*$"]))
    return findings


def _detect_auth_misconfiguration(payload: str) -> list[str]:
    normalized = "\n".join(line.strip() for line in payload.splitlines())
    if not re.search(r"(?im)^authorization\s*:", normalized) and "auth_required" not in normalized.lower():
        return []
    return _regex_matches(
        normalized,
        [
            r"(?im)^authorization\s*:\s*basic\s+[A-Za-z0-9+/=]+",
            r"(?i)password\s*[:=]\s*['\"]?(admin|password|123456)['\"]?",
            r"(?i)auth_required\s*[:=]\s*false",
        ],
    )


def _infer_endpoint(payload: str) -> str:
    match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[^\s?#]+)", payload, re.IGNORECASE)
    if match:
        return match.group(2)
    path_match = re.search(r"\b(?:path|endpoint)\s*[:=]\s*['\"]?(/[^\s'\"?#]+)", payload, re.IGNORECASE)
    return path_match.group(1) if path_match else "unknown"


def _detect_sqli(payload: str) -> list[str]:
    return _regex_matches(
        payload,
        [r"(?i)\bUNION\s+SELECT\b", r"(?i)(\bOR\b\s+\d+=\d+|\bOR\b\s+'\w+'='\w+')", r"(?i)--"],
    )


def _detect_xss(payload: str) -> list[str]:
    return _regex_matches(
        payload,
        [r"(?i)<script\b[^>]*>.*?</script>", r"(?i)onerror\s*=\s*['\"].*?['\"]", r"(?i)javascript:\s*"],
    )


def _detect_insecure_auth(payload: str) -> list[str]:
    return _regex_matches(payload, [r"(?i)\bmd5\b", r"(?i)\bsha1\b", r"(?i)jwt_secret\s*=\s*['\"].+['\"]"])


def _detect_broken_access_control(payload: str) -> list[str]:
    return _regex_matches(payload, [r"(?i)\b(admin|root)\b\s*=\s*true", r"(?i)allow_all\s*=\s*true"])


def _detect_insecure_configuration(payload: str) -> list[str]:
    return _regex_matches(
        payload,
        [r"(?i)debug\s*=\s*true", r"(?i)cors_allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]"],
    )


def _detect_sensitive_data_exposure(payload: str) -> list[str]:
    return _regex_matches(
        payload,
        [r"(?i)AKIA[0-9A-Z]{16}", r"(?i)password\s*[:=]\s*['\"].+['\"]", r"(?i)private[_-]?key"],
    )


def _detect_secret_leakage(payload: str) -> list[str]:
    return _regex_matches(
        payload,
        [
            r"(?i)ghp_[0-9A-Za-z]{36}",
            r"(?i)xox[baprs]-[0-9A-Za-z-]{10,}",
            r"(?i)BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY",
            r'(?i)api[_-]?token\s*[:=]\s*[\"\'].+[\"\']',
        ],
    )

def _detect_config_audit_issues(payload: str) -> list[str]:
    return _regex_matches(
        payload,
        [
            r"(?i)allow_privilege_escalation\s*:\s*true",
            r"(?i)runAsNonRoot\s*:\s*false",
            r"(?i)latest\s*$",
            r"(?i)verify_ssl\s*[:=]\s*false",
        ],
    )


class ScannerRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, ScannerRule] = {}

    def register(self, rule: ScannerRule) -> None:
        self._rules[rule.key] = rule

    def run(self, payload: str, profile: str) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        target_profile_rank = PROFILE_ORDER.get(profile, PROFILE_ORDER["standard"])
        for rule in self._rules.values():
            if PROFILE_ORDER[rule.profile_minimum] > target_profile_rank:
                continue
            for evidence in rule.detector(payload):
                findings.append(
                    RuleFinding(
                        rule_key=rule.key,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        reason_code=rule.reason_code,
                        owasp_category=rule.owasp_category,
                        cwe_id=rule.cwe_id,
                        evidence=evidence,
                        description=rule.description,
                        affected_endpoint=_infer_endpoint(payload),
                        remediation=rule.remediation,
                        secure_example=rule.secure_example,
                        dedupe_key=_dedupe_key(rule.key, evidence),
                    )
                )
        return findings


def build_default_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    registry.register(
        ScannerRule(
            key="SQLI",
            title="Potential SQL Injection pattern",
            description="Input contains SQL syntax patterns commonly used to alter query logic.",
            severity="high",
            confidence=0.9,
            reason_code="SQLI_PATTERN_MATCH",
            owasp_category="A03:2021-Injection",
            cwe_id="CWE-89",
            remediation="Use parameterized queries and strict allow-list input validation.",
            secure_example="Use prepared statements and bind variables for all user-provided parameters.",
            profile_minimum="quick",
            detector=_detect_sqli,
        )
    )
    registry.register(
        ScannerRule(
            key="XSS",
            title="Potential Cross-Site Scripting pattern",
            description="Input contains script execution patterns that may trigger client-side code execution.",
            severity="medium",
            confidence=0.85,
            reason_code="XSS_PATTERN_MATCH",
            owasp_category="A03:2021-Injection",
            cwe_id="CWE-79",
            remediation="Apply contextual output encoding and enforce a strict Content Security Policy.",
            secure_example="Encode untrusted output by context and use non-inline scripts with CSP nonce/hash.",
            profile_minimum="quick",
            detector=_detect_xss,
        )
    )
    registry.register(
        ScannerRule(
            key="INSECURE_AUTH",
            title="Insecure authentication crypto or secret pattern",
            description="Detected weak authentication configuration or hardcoded authentication secret usage.",
            severity="high",
            confidence=0.8,
            reason_code="INSECURE_AUTH_PATTERN",
            owasp_category="A07:2021-Identification and Authentication Failures",
            cwe_id="CWE-327",
            remediation="Use modern password hashing and avoid hard-coded authentication secrets.",
            secure_example="Use Argon2/bcrypt for password hashing and load secrets from a vault or env vars.",
            profile_minimum="standard",
            detector=_detect_insecure_auth,
        )
    )
    registry.register(
        ScannerRule(
            key="BROKEN_ACCESS_CONTROL",
            title="Potential broken access control indicator",
            description="Detected permissive authorization flags that may bypass access checks.",
            severity="high",
            confidence=0.75,
            reason_code="ACCESS_CONTROL_WEAKNESS_PATTERN",
            owasp_category="A01:2021-Broken Access Control",
            cwe_id="CWE-284",
            remediation="Enforce deny-by-default authorization checks at route and service boundaries.",
            secure_example="Require explicit permission checks for every privileged operation.",
            profile_minimum="standard",
            detector=_detect_broken_access_control,
        )
    )
    registry.register(
        ScannerRule(
            key="INSECURE_CONFIG",
            title="Insecure configuration indicator",
            description="Detected configuration values frequently associated with unsafe production defaults.",
            severity="medium",
            confidence=0.7,
            reason_code="INSECURE_CONFIGURATION_PATTERN",
            owasp_category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-16",
            remediation="Disable debug in production and constrain CORS to trusted origins.",
            secure_example="Set debug=false and configure explicit CORS origin allow-lists.",
            profile_minimum="standard",
            detector=_detect_insecure_configuration,
        )
    )
    registry.register(
        ScannerRule(
            key="SENSITIVE_DATA_EXPOSURE",
            title="Potential sensitive data exposure pattern",
            description="Detected content that resembles secrets or sensitive credentials.",
            severity="critical",
            confidence=0.78,
            reason_code="SENSITIVE_DATA_PATTERN",
            owasp_category="A02:2021-Cryptographic Failures",
            cwe_id="CWE-200",
            remediation="Remove secrets from source/config and rotate exposed credentials immediately.",
            secure_example="Store secrets in secret managers and reference them via runtime injection.",
            profile_minimum="deep",
            detector=_detect_sensitive_data_exposure,
        )
    )

    registry.register(
        ScannerRule(
            key="SECRET_DETECTION",
            title="Potential secret token/private key exposure",
            description="Detected high-risk secret/token/private-key patterns in the scanned payload.",
            severity="critical",
            confidence=0.9,
            reason_code="SECRET_LEAKAGE_PATTERN",
            owasp_category="A02:2021-Cryptographic Failures",
            cwe_id="CWE-798",
            remediation="Remove committed secrets, rotate credentials, and enforce secret scanning pre-commit checks.",
            secure_example="Use secret managers and inject credentials at runtime via environment/identity bindings.",
            profile_minimum="deep",
            detector=_detect_secret_leakage,
        )
    )
    registry.register(
        ScannerRule(
            key="CONFIG_AUDIT",
            title="Configuration hardening issue in deployment/config file",
            description="Detected deployment or runtime hardening settings that increase attack surface.",
            severity="high",
            confidence=0.82,
            reason_code="CONFIG_AUDIT_PATTERN",
            owasp_category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-16",
            remediation="Harden deployment config defaults and enforce policy checks in CI.",
            secure_example="Set runAsNonRoot=true, avoid :latest tags, and keep TLS verification enabled.",
            profile_minimum="standard",
            detector=_detect_config_audit_issues,
        )
    )
    registry.register(
        ScannerRule(
            key="INSECURE_HEADERS",
            title="Missing or insecure HTTP security headers",
            description="Response headers are missing key security controls or contain permissive values.",
            severity="medium",
            confidence=0.8,
            reason_code="INSECURE_HEADERS_PATTERN",
            owasp_category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-693",
            remediation="Add CSP, HSTS, X-Frame-Options, and X-Content-Type-Options headers with secure values.",
            secure_example="Set Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.",
            profile_minimum="quick",
            detector=_detect_insecure_headers,
        )
    )
    registry.register(
        ScannerRule(
            key="AUTH_MISCONFIG",
            title="Basic auth or authentication misconfiguration indicator",
            description="Detected patterns indicating weak or misconfigured authentication controls.",
            severity="high",
            confidence=0.83,
            reason_code="AUTH_MISCONFIG_PATTERN",
            owasp_category="A07:2021-Identification and Authentication Failures",
            cwe_id="CWE-287",
            remediation="Disable basic auth for production APIs, enforce strong credentials, and require auth on protected routes.",
            secure_example="Use token-based auth (OAuth2/JWT) over TLS with MFA/strong password policy and auth_required=true.",
            profile_minimum="quick",
            detector=_detect_auth_misconfiguration,
        )
    )
    return registry
