"""Dnsenum — DNS enumeration tool wrapper."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.dnsenum")


class DnsenumTool(BaseTool):
    name = "dnsenum"
    category = ToolCategory.RECON
    requires = ["dnsenum"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid domain.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        threads: int = int(params.get("threads", 10))

        cmd = [
            "dnsenum", "--nocolor", "--noreverse",
            "--threads", str(threads),
            target,
        ]

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
        # Match subdomains and IPs from dnsenum output
        sub_pattern = re.compile(r"^(\S+\.\S+)\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)")
        ns_pattern = re.compile(r"^(\S+\.\S+)\s+\d+\s+IN\s+NS\s+(\S+)")
        mx_pattern = re.compile(r"^(\S+\.\S+)\s+\d+\s+IN\s+MX\s+\d+\s+(\S+)")
        axfr_pattern = re.compile(r"AXFR|zone transfer", re.IGNORECASE)

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Zone transfer vulnerability check
            if axfr_pattern.search(line) and "successful" in line.lower():
                findings.append(Finding(
                    title="DNS Zone Transfer Allowed",
                    severity=Severity.HIGH,
                    description="The DNS server allows zone transfers (AXFR), exposing full DNS records.",
                    affected_asset=line,
                    evidence=line,
                    remediation="Restrict zone transfers to authorised secondary DNS servers only.",
                ))

            # A records
            m = sub_pattern.match(line)
            if m:
                sub = m.group(1).rstrip(".")
                ip = m.group(2)
                key = f"sub:{sub}"
                if key not in seen and self._is_valid_domain(sub):
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Subdomain: {sub} → {ip}",
                        severity=Severity.INFO,
                        description=f"DNS A record: {sub} resolves to {ip}",
                        affected_asset=sub,
                        evidence=line,
                    ))
                continue

            # NS records
            ns = ns_pattern.match(line)
            if ns:
                domain = ns.group(1).rstrip(".")
                nameserver = ns.group(2).rstrip(".")
                key = f"ns:{nameserver}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Nameserver: {nameserver}",
                        severity=Severity.INFO,
                        description=f"DNS NS record: {domain} uses nameserver {nameserver}",
                        affected_asset=domain,
                        evidence=line,
                    ))

            # MX records
            mx = mx_pattern.match(line)
            if mx:
                domain = mx.group(1).rstrip(".")
                mail_server = mx.group(2).rstrip(".")
                key = f"mx:{mail_server}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Mail Server: {mail_server}",
                        severity=Severity.INFO,
                        description=f"DNS MX record: {domain} uses mail server {mail_server}",
                        affected_asset=domain,
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and self._is_valid_domain(target)
