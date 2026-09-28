"""Fierce — DNS brute-force and network reconnaissance."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.fierce")


class FierceTool(BaseTool):
    name = "fierce"
    category = ToolCategory.RECON
    requires = ["fierce"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid domain.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        wordlist: str = params.get("wordlist", "")

        cmd = ["fierce", "--domain", target]
        if wordlist:
            cmd += ["--wordlist", wordlist]

        import os
        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=returncode == 0, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        # Fierce outputs: Found: subdomain.example.com (1.2.3.4)
        found_pattern = re.compile(r"Found:\s+(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)")
        # Also: Nearby: ...
        nearby_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+(\S+\.\S+)")
        # Zone transfer
        zone_transfer_pattern = re.compile(r"zone transfer|AXFR", re.IGNORECASE)

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if zone_transfer_pattern.search(line) and "success" in line.lower():
                findings.append(Finding(
                    title="DNS Zone Transfer Possible",
                    severity=Severity.HIGH,
                    description="Zone transfer succeeded — full DNS zone exposed.",
                    affected_asset="DNS server",
                    evidence=line,
                    remediation="Restrict AXFR to authorised secondary nameservers.",
                ))

            m = found_pattern.search(line)
            if m:
                sub = m.group(1).rstrip(".")
                ip = m.group(2)
                key = sub
                if key not in seen and self._is_valid_domain(sub):
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Subdomain Found: {sub}",
                        severity=Severity.INFO,
                        description=f"Fierce brute-forced subdomain: {sub} ({ip})",
                        affected_asset=sub,
                        evidence=line,
                    ))
                continue

            nb = nearby_pattern.search(line)
            if nb and "Nearby" in raw_output[:raw_output.find(line)]:
                ip = nb.group(1)
                host = nb.group(2).rstrip(".")
                key = f"near:{host}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Adjacent Host: {host} ({ip})",
                        severity=Severity.INFO,
                        description=f"Adjacent host discovered: {host} at {ip}",
                        affected_asset=ip,
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and self._is_valid_domain(target)
