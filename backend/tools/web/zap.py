"""OWASP ZAP — web application security scanner (API mode)."""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

import httpx

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.zap")

RISK_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


class ZapTool(BaseTool):
    name = "zap"
    category = ToolCategory.WEB
    requires = []  # Uses ZAP REST API — ZAP must be running

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        zap_url: str = params.get("zap_url", "http://localhost:8080")
        api_key: str = params.get("api_key", "")
        scan_type: str = params.get("scan_type", "active")  # passive or active
        timeout: int = int(params.get("timeout", 1800))

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Verify ZAP is running
                resp = await client.get(f"{zap_url}/JSON/core/view/version/",
                                        params={"apikey": api_key})
                resp.raise_for_status()

            raw_output = await self._run_zap_scan(
                target, zap_url, api_key, scan_type, timeout
            )
            findings = self.parse(raw_output)
            return ToolResult(success=True, output=raw_output, findings=findings)
        except Exception as exc:
            logger.error("ZAP scan failed: %s", exc)
            return ToolResult(success=False, error=f"ZAP error: {exc}")

    async def _run_zap_scan(
        self, target: str, zap_url: str, api_key: str, scan_type: str, timeout: int
    ) -> str:
        async with httpx.AsyncClient(timeout=60) as client:
            # Spider the target
            spider_resp = await client.get(
                f"{zap_url}/JSON/spider/action/scan/",
                params={"apikey": api_key, "url": target, "recurse": "true"}
            )
            spider_id = spider_resp.json().get("scan", "0")

            # Wait for spider
            elapsed = 0
            while elapsed < 300:
                status_resp = await client.get(
                    f"{zap_url}/JSON/spider/view/status/",
                    params={"apikey": api_key, "scanId": spider_id}
                )
                if int(status_resp.json().get("status", "0")) >= 100:
                    break
                await __import__("asyncio").sleep(5)
                elapsed += 5

            if scan_type == "active":
                # Active scan
                scan_resp = await client.get(
                    f"{zap_url}/JSON/ascan/action/scan/",
                    params={"apikey": api_key, "url": target, "recurse": "true"}
                )
                scan_id = scan_resp.json().get("scan", "0")

                elapsed = 0
                while elapsed < timeout:
                    status_resp = await client.get(
                        f"{zap_url}/JSON/ascan/view/status/",
                        params={"apikey": api_key, "scanId": scan_id}
                    )
                    if int(status_resp.json().get("status", "0")) >= 100:
                        break
                    await __import__("asyncio").sleep(10)
                    elapsed += 10

            # Get alerts
            alerts_resp = await client.get(
                f"{zap_url}/JSON/core/view/alerts/",
                params={"apikey": api_key, "baseurl": target}
            )
            alerts = alerts_resp.json().get("alerts", [])
            return json.dumps(alerts)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        try:
            alerts = json.loads(raw_output)
            if not isinstance(alerts, list):
                return []
        except Exception:
            return []

        for alert in alerts:
            alert_name = alert.get("alert", alert.get("name", "Unknown"))
            risk = str(alert.get("riskcode", "1"))
            severity = RISK_MAP.get(risk, Severity.LOW)
            url = alert.get("url", "")
            description = alert.get("desc", "")
            solution = alert.get("solution", "")
            evidence = alert.get("evidence", "")
            cwe_id = alert.get("cweid", "")
            wascid = alert.get("wascid", "")
            other = alert.get("other", "")

            key = f"zap:{alert_name}:{url[:60]}"
            if key in seen:
                continue
            seen.add(key)

            cve_ids = []
            if "CVE" in str(alert.get("reference", "")):
                import re
                cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", str(alert.get("reference", "")))

            findings.append(Finding(
                title=f"[ZAP] {alert_name}",
                severity=severity,
                description=f"{description}\n\nOther info: {other}".strip(),
                affected_asset=url,
                evidence=evidence or f"CWE-{cwe_id}" if cwe_id else "",
                cve_ids=cve_ids,
                remediation=solution,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
