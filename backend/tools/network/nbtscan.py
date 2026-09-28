"""NbtscanTool — nbtscan {target}. NetBIOS name scanner."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.nbtscan")


class NbtscanTool(BaseTool):
    name = "nbtscan"
    category = ToolCategory.NETWORK
    requires = ["nbtscan"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 60))
        verbose: bool = bool(params.get("verbose", True))

        cmd = ["nbtscan"]
        if verbose:
            cmd.append("-v")
        cmd.append(target)

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

        hosts: list[dict] = []
        domain_controllers: list[str] = []

        # nbtscan output: IP  NetBIOS_Name  Server  User  MAC
        for line in raw_output.splitlines():
            # Typical verbose line: IP  Name <20>  UNIQUE  Registered
            ip_match = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if not ip_match:
                continue

            ip = ip_match.group(1)
            name_match = re.search(r"(\S+)\s+<(\w+)>\s+(UNIQUE|GROUP)", line)
            if name_match:
                name = name_match.group(1)
                nb_code = name_match.group(2)

                host = {"ip": ip, "name": name, "nb_code": nb_code}
                hosts.append(host)

                # 0x1C = Domain Controllers
                if nb_code in ("1C", "1B"):
                    domain_controllers.append(f"{ip} ({name})")

        # MAC addresses
        macs = re.findall(r"MAC:((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", raw_output, re.IGNORECASE)

        if hosts:
            unique_ips = list(set(h["ip"] for h in hosts))
            evidence_lines = [f"{h['ip']}: {h['name']} <{h['nb_code']}> " for h in hosts[:20]]
            if macs:
                evidence_lines.append(f"MACs: {', '.join(macs[:5])}")

            findings.append(Finding(
                title=f"NetBIOS Scan: {len(unique_ips)} hosts discovered",
                severity=Severity.INFO,
                description=f"nbtscan discovered {len(unique_ips)} hosts with NetBIOS names.",
                evidence="\n".join(evidence_lines),
            ))

        if domain_controllers:
            findings.append(Finding(
                title=f"Domain Controller(s) Found: {', '.join(domain_controllers)}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(domain_controllers)} Domain Controller(s) via NetBIOS. "
                    "DCs are high-value targets."
                ),
                evidence="\n".join(domain_controllers),
                remediation="Limit DC exposure. Ensure DCs are not accessible from untrusted network segments.",
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
