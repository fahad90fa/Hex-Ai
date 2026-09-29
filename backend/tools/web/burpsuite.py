"""BurpSuite — web security testing platform (REST API integration)."""
from __future__ import annotations

import json
import logging

import httpx

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.burpsuite")

SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "information": Severity.INFO,
    "critical": Severity.CRITICAL,
}


class BurpsuiteTool(BaseTool):
    name = "burpsuite"
    category = ToolCategory.WEB
    requires = []  # Requires Burp Suite Enterprise or running Burp with API enabled

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        burp_api_url: str = params.get("burp_api_url", "http://localhost:1337/v0.1")
        api_key: str = params.get("api_key", "")
        timeout: int = int(params.get("timeout", 3600))
        scan_config: str = params.get("scan_config", "Crawl and Audit - Balanced")

        try:
            scan_results = await self._run_burp_scan(
                target, burp_api_url, api_key, scan_config, timeout
            )
            raw_output = json.dumps(scan_results, indent=2)
            findings = self.parse(raw_output)
            return ToolResult(success=True, output=raw_output, findings=findings)
        except Exception as exc:
            logger.error("Burp Suite scan error: %s", exc)
            return ToolResult(success=False, error=f"Burp Suite API error: {exc}")

    async def _run_burp_scan(
        self, target: str, api_url: str, api_key: str, scan_config: str, timeout: int
    ) -> dict:
        import asyncio
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient(timeout=60, headers=headers) as client:
            # Create scan
            payload = {
                "scope": {"include": [{"rule": f"^{target}.*", "type": "PrefixMatch"}]},
                "scan_configurations": [{"name": scan_config, "type": "NamedConfiguration"}],
                "urls": [target],
            }
            create_resp = await client.post(f"{api_url}/scan", json=payload)
            create_resp.raise_for_status()
            task_id = create_resp.headers.get("Location", "").split("/")[-1]

            if not task_id:
                raise RuntimeError("Could not get scan task ID from Burp API")

            # Poll until done
            elapsed = 0
            while elapsed < timeout:
                status_resp = await client.get(f"{api_url}/scan/{task_id}")
                status_data = status_resp.json()
                scan_status = status_data.get("scan_status", "")
                if scan_status in ("succeeded", "failed", "paused"):
                    break
                await asyncio.sleep(15)
                elapsed += 15

            # Get issues
            issues_resp = await client.get(f"{api_url}/scan/{task_id}/issue_events")
            issues_resp.raise_for_status()
            return issues_resp.json()

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            data = json.loads(raw_output)
        except Exception:
            return []

        issues = data if isinstance(data, list) else data.get("issue_events", [])
        for event in issues:
            issue = event.get("issue", event)
            name = issue.get("name", "Unknown Issue")
            severity_str = issue.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)
            origin = issue.get("origin", "")
            path = issue.get("path", "")
            url = f"{origin}{path}"
            description = issue.get("description", "")
            remediation = issue.get("remediation", "")
            evidence_list = issue.get("evidence", [])
            evidence_str = json.dumps(evidence_list[:2]) if evidence_list else ""
            confidence = issue.get("confidence", "")

            key = f"burp:{name}:{url[:60]}"
            if key in seen:
                continue
            seen.add(key)

            findings.append(Finding(
                title=f"[Burp] {name}",
                severity=severity,
                description=f"{description}\nConfidence: {confidence}",
                affected_asset=url,
                evidence=evidence_str,
                remediation=remediation,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
