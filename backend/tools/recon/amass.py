"""Amass — attack surface mapping and subdomain enumeration."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.amass")


class AmassTool(BaseTool):
    name = "amass"
    category = ToolCategory.RECON
    requires = ["amass"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid domain.")

        target: str = params["target"]
        mode: str = params.get("mode", "passive")
        timeout: int = int(params.get("timeout", 600))

        cmd = ["amass", "enum"]
        if mode == "passive":
            cmd.append("-passive")
        else:
            cmd.append("-active")
        cmd += ["-d", target, "-nocolor"]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            import os
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=returncode == 0, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        # Amass outputs lines like: subdomain.example.com
        # Also sometimes: (FQDN) subdomain.example.com  or  addresses: 1.2.3.4
        subdomain_pattern = re.compile(
            r"(?:^|\s)((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"
        )
        ip_pattern = re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        )

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Extract subdomains
            for match in subdomain_pattern.finditer(line):
                sub = match.group(1).lower().strip(".")
                if sub not in seen and self._is_valid_domain(sub):
                    seen.add(sub)
                    findings.append(Finding(
                        title=f"Subdomain Discovered: {sub}",
                        severity=Severity.INFO,
                        description=f"Amass ({'' if 'passive' in line else 'active'} mode) discovered: {sub}",
                        affected_asset=sub,
                        evidence=line,
                    ))

            # Extract IPs
            for ip_match in ip_pattern.finditer(line):
                ip = ip_match.group(1)
                ip_key = f"ip:{ip}"
                if ip_key not in seen:
                    seen.add(ip_key)
                    findings.append(Finding(
                        title=f"IP Address Discovered: {ip}",
                        severity=Severity.INFO,
                        description=f"IP address found during Amass enumeration: {ip}",
                        affected_asset=ip,
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and self._is_valid_domain(target)
