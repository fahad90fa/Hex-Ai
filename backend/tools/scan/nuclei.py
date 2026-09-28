"""Nuclei — template-based vulnerability scanner."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.nuclei")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiTool(BaseTool):
    name = "nuclei"
    category = ToolCategory.SCAN
    requires = ["nuclei"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"https://{target}"

        timeout: int = int(params.get("timeout", 1800))
        severity: str = params.get("severity", "critical,high,medium")
        templates: str = params.get("templates", "")
        tags: str = params.get("tags", "")
        concurrency: int = int(params.get("concurrency", 25))

        cmd = [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-c", str(concurrency),
            "-j",  # JSON output
            "-silent",
            "-nc",  # no colour
        ]
        if templates:
            cmd += ["-t", templates]
        if tags:
            cmd += ["-tags", tags]

        import os
        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            template_id = data.get("template-id", "unknown")
            template_name = data.get("info", {}).get("name", template_id)
            severity_str = data.get("info", {}).get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)
            matched_at = data.get("matched-at", data.get("host", ""))
            description = data.get("info", {}).get("description", "")
            reference = data.get("info", {}).get("reference", [])
            cvss_score = data.get("info", {}).get("classification", {}).get("cvss-score")
            cve_list: list[str] = []
            for ref in (reference if isinstance(reference, list) else [reference]):
                cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", str(ref))
                cve_list.extend(cve_matches)
            for cve_id in data.get("info", {}).get("classification", {}).get("cve-id", []):
                if cve_id and cve_id not in cve_list:
                    cve_list.append(cve_id)

            tags = data.get("info", {}).get("tags", [])
            remediation = data.get("info", {}).get("remediation", "")
            extracted_results = data.get("extracted-results", [])
            curl_cmd = data.get("curl-command", "")

            evidence_parts = [f"Template: {template_id}", f"Matched: {matched_at}"]
            if extracted_results:
                evidence_parts.append(f"Extracted: {', '.join(str(r) for r in extracted_results[:3])}")
            if curl_cmd:
                evidence_parts.append(f"PoC: {curl_cmd[:200]}")

            key = f"{template_id}:{matched_at}"
            if key in seen:
                continue
            seen.add(key)

            findings.append(Finding(
                title=f"[Nuclei] {template_name}",
                severity=severity,
                description=description or f"Nuclei template {template_id} triggered on {matched_at}",
                affected_asset=matched_at,
                evidence="\n".join(evidence_parts),
                cve_ids=cve_list,
                cvss_score=float(cvss_score) if cvss_score else None,
                remediation=remediation,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
