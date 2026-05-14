import json
from typing import Any

import httpx
from pydantic import BaseModel


class CVEMatch(BaseModel):
    cve_id: str
    cvss_v3_base_score: float | None = None
    severity: str | None = None
    description: str
    nvd_url: str


class CVEEnrichmentService:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    TTL_SECONDS = 60 * 60 * 24
    _cache: dict[str, str] = {}

    @classmethod
    def _cache_get(cls, key: str) -> list[dict[str, Any]] | None:
        val = cls._cache.get(key)
        return json.loads(val) if val else None

    @classmethod
    def _cache_set(cls, key: str, value: list[dict[str, Any]]) -> None:
        cls._cache[key] = json.dumps(value)

    @classmethod
    def find_matches(cls, vulnerability_type: str, affected_component: str) -> list[CVEMatch]:
        keyword = f"{vulnerability_type} {affected_component}".strip().lower()
        cached = cls._cache_get(keyword)
        if cached is not None:
            return [CVEMatch.model_validate(i) for i in cached]

        params = {"keywordSearch": keyword, "resultsPerPage": 3}
        matches: list[CVEMatch] = []
        try:
            with httpx.Client(timeout=8.0) as client:
                response = client.get(cls.BASE_URL, params=params)
                response.raise_for_status()
                payload = response.json()
            for item in payload.get("vulnerabilities", [])[:3]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                metrics = cve.get("metrics", {}).get("cvssMetricV31", []) or cve.get("metrics", {}).get("cvssMetricV30", [])
                cvss = metrics[0]["cvssData"]["baseScore"] if metrics else None
                severity = metrics[0]["cvssData"].get("baseSeverity") if metrics else None
                description = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                matches.append(CVEMatch(cve_id=cve_id, cvss_v3_base_score=cvss, severity=severity, description=description, nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"))
        except Exception:
            matches = []
        cls._cache_set(keyword, [m.model_dump() for m in matches])
        return matches
