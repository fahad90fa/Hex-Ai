"""XSSer — automatic XSS testing framework."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.xsser")


class XsserTool(BaseTool):
    name = "xsser"
    category = ToolCategory.WEB
    requires = ["xsser"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 600))
        data: str = params.get("data", "")
        auto: bool = bool(params.get("auto", True))
        crawler: bool = bool(params.get("crawler", False))

        cmd = ["xsser", "--url", target, "--no-head"]
        if data:
            cmd += ["--data", data]
        if auto:
            cmd.append("--auto")
        if crawler:
            cmd.append("--crawler")

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
        xss_injected = re.compile(r"XSS Injected\!?.*?:\s*(.+)", re.IGNORECASE)
        vuln_pattern = re.compile(r"\[\!\]\s*(.*?XSS.*)", re.IGNORECASE)
        total_pattern = re.compile(r"Total injections:\s+(\d+)", re.IGNORECASE)

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = xss_injected.search(line)
            if m:
                payload_info = m.group(1).strip()
                key = f"xsser:{payload_info[:40]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title="XSS Vulnerability Confirmed",
                        severity=Severity.HIGH,
                        description=f"XSSer confirmed XSS injection: {payload_info}",
                        affected_asset=payload_info[:100],
                        evidence=line,
                        remediation="Output encode all user-supplied data; implement CSP.",
                    ))
                continue

            vp = vuln_pattern.search(line)
            if vp:
                info = vp.group(1).strip()
                key = f"xsser_vuln:{info[:40]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"XSS: {info[:80]}",
                        severity=Severity.HIGH,
                        description=f"XSSer finding: {info}",
                        affected_asset="web application",
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
