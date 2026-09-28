"""Wafw00f — web application firewall fingerprinting tool."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.wafw00f")


class Wafw00fTool(BaseTool):
    name = "wafw00f"
    category = ToolCategory.WEB
    requires = ["wafw00f"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"https://{target}"

        timeout: int = int(params.get("timeout", 120))
        test_all: bool = bool(params.get("test_all", True))

        cmd = ["wafw00f", target, "-a"] if test_all else ["wafw00f", target]

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
        # Wafw00f output: [+] The site http://... is behind ... WAF
        waf_detected = re.compile(
            r"The site .+? is behind (.+?)(?:WAF|firewall| \()", re.IGNORECASE
        )
        no_waf = re.compile(r"No WAF detected", re.IGNORECASE)
        generic_waf = re.compile(r"Generic Detection results", re.IGNORECASE)

        for line in raw_output.splitlines():
            line = line.strip()
            m = waf_detected.search(line)
            if m:
                waf_name = m.group(1).strip().rstrip("(").strip()
                findings.append(Finding(
                    title=f"WAF Detected: {waf_name}",
                    severity=Severity.INFO,
                    description=(
                        f"A Web Application Firewall ({waf_name}) is protecting this target.\n"
                        f"WAF bypass techniques may be required for further testing."
                    ),
                    affected_asset=waf_name,
                    evidence=line,
                ))
                continue

            if no_waf.search(line):
                findings.append(Finding(
                    title="No WAF Detected",
                    severity=Severity.MEDIUM,
                    description=(
                        "No Web Application Firewall was detected on the target.\n"
                        "The application may be more susceptible to direct attacks."
                    ),
                    affected_asset="web application",
                    evidence=line,
                    remediation="Consider deploying a WAF to add an additional layer of defence.",
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
