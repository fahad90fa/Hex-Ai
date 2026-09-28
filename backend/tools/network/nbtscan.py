"""NbtscanTool — nbtscan {range}. Parse NetBIOS names/MACs."""
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
            return ToolResult(success=False, error="Invalid params: 'target' (IP or CIDR) required.")

        target: str = params["target"]
        verbose: bool = bool(params.get("verbose", False))
        timeout: int = int(params.get("timeout", 120))

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

        # nbtscan output: IP  NetBIOS Name  Server  User    MAC address
        for line in raw_output.splitlines():
            # Skip headers
            if line.startswith("IP") or line.startswith("-") or not line.strip():
                continue

            # Parse space-separated: IP  name  type  user  mac
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 2:
                ip = parts[0]
                name = parts[1] if len(parts) > 1 else ""
                mac = parts[-1] if len(parts) > 3 else ""

                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    hosts.append({"ip": ip, "name": name, "mac": mac})

            # Verbose mode: single info per line
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            nb_match = re.search(r"<(\w+)>", line)
            if ip_match and nb_match and not any(h["ip"] == ip_match.group(1) for h in hosts):
                hosts.append({"ip": ip_match.group(1), "name": nb_match.group(1), "mac": ""})

        if hosts:
            host_list = "\n".join(
                f"{h['ip']}\t{h['name']}\t{h.get('mac', '')}"
                for h in hosts
            )
            findings.append(Finding(
                title=f"NetBIOS Hosts Discovered: {len(hosts)}",
                severity=Severity.INFO,
                description=(
                    f"nbtscan discovered {len(hosts)} hosts responding to NetBIOS queries.\n"
                    "NetBIOS responses indicate Windows hosts and can reveal machine names and workgroups."
                ),
                evidence=host_list,
                remediation=(
                    "Disable NetBIOS over TCP/IP if not required (HKEY_LOCAL_MACHINE\\SYSTEM\\"
                    "CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces)."
                ),
            ))

            # Flag Domain Controllers
            for h in hosts:
                if "DC" in h.get("name", "").upper() or "PDC" in h.get("name", "").upper():
                    findings.append(Finding(
                        title=f"Domain Controller Identified: {h['ip']} ({h['name']})",
                        severity=Severity.HIGH,
                        description=f"Host {h['ip']} appears to be a Domain Controller based on NetBIOS name.",
                        affected_asset=h["ip"],
                        evidence=f"IP: {h['ip']}, NetBIOS: {h['name']}",
                        remediation="Ensure DC is fully patched. Restrict unnecessary network exposure.",
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (
            self._is_valid_ip(target) or
            self._is_valid_cidr(target) or
            self._is_valid_domain(target)
        )
