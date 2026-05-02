from app.services.scanner_engine import MAX_EVIDENCE_LENGTH, build_default_registry


def test_registry_respects_profile_minimums() -> None:
    registry = build_default_registry()
    payload = """
    ' OR 1=1 -- <script>alert(1)</script>
    debug=true
    allow_privilege_escalation: true
    api_token='secret-token'
    ghp_abcdefghijklmnopqrstuvwxyz1234567890
    """

    quick_keys = {f.rule_key for f in registry.run(payload, profile="quick")}
    standard_keys = {f.rule_key for f in registry.run(payload, profile="standard")}
    deep_keys = {f.rule_key for f in registry.run(payload, profile="deep")}

    assert {"SQLI", "XSS"}.issubset(quick_keys)
    assert "CONFIG_AUDIT" not in quick_keys

    assert "CONFIG_AUDIT" in standard_keys
    assert "SECRET_DETECTION" not in standard_keys

    assert "SECRET_DETECTION" in deep_keys
    assert deep_keys.issuperset(standard_keys)


def test_findings_use_stable_dedupe_key_and_truncate_evidence() -> None:
    registry = build_default_registry()
    long_script = "<script>" + ("A" * (MAX_EVIDENCE_LENGTH + 80)) + "</script>"
    payload = f"{long_script}\n{long_script}"

    findings = [f for f in registry.run(payload, profile="quick") if f.rule_key == "XSS"]
    assert len(findings) == 2

    assert all(len(f.evidence) <= MAX_EVIDENCE_LENGTH for f in findings)
    assert findings[0].dedupe_key == findings[1].dedupe_key


def test_unknown_profile_defaults_to_standard_behavior() -> None:
    registry = build_default_registry()
    payload = "allow_privilege_escalation: true\napi_token='abc123'"

    unknown_profile_keys = {f.rule_key for f in registry.run(payload, profile="unexpected")}
    standard_keys = {f.rule_key for f in registry.run(payload, profile="standard")}

    assert unknown_profile_keys == standard_keys
    assert "CONFIG_AUDIT" in unknown_profile_keys
    assert "SECRET_DETECTION" not in unknown_profile_keys


def test_phase1_rules_detect_insecure_headers_and_auth_misconfiguration() -> None:
    registry = build_default_registry()
    payload = """
    GET /api/admin HTTP/1.1
    Authorization: Basic YWRtaW46YWRtaW4=
    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: *
    auth_required=false
    """

    findings = registry.run(payload, profile="quick")
    keys = {f.rule_key for f in findings}

    assert "INSECURE_HEADERS" in keys
    assert "AUTH_MISCONFIG" in keys
    assert all(f.description for f in findings)
    assert all(f.affected_endpoint == "/api/admin" for f in findings)
