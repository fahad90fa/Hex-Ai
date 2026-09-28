"""RpcclientTool — rpcclient -U '' -N {target}. RPC null session enumeration."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.rpcclient")


_RPC_COMMANDS = """
srvinfo
domaininfo
enumdomains
enumdomusers
enumdomgroups
getdompwinfo
"""


class RpcclientTool(BaseTool):
    name = "rpcclient"
    category = ToolCategory.NETWORK
    requires = ["rpcclient"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        username: str = params.get("username", "")
        password: str = params.get("password", "")
        commands: list[str] = params.get("commands", _RPC_COMMANDS.strip().splitlines())
        timeout: int = int(params.get("timeout", 60))

        creds = f"{username}%{password}" if username else "%"
        cmd = ["rpcclient", target, "-U", creds, "-N", "-c", ";".join(commands)]

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

        # Check for null session success
        if re.search(r"Domain=\.+\.+Server=", raw_output, re.IGNORECASE) or \
           re.search(r"srvinfo|server info", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="RPC Null Session Successful",
                severity=Severity.HIGH,
                description="Anonymous RPC null session was accepted by the target.",
                evidence=raw_output[:300],
                remediation="Restrict anonymous RPC access via registry: RestrictAnonymous=2.",
            ))

        # Users
        users = re.findall(r"user:\[([^\]]+)\].*rid:\[(0x[0-9a-f]+)\]", raw_output, re.IGNORECASE)
        if users:
            findings.append(Finding(
                title=f"RPC User Enumeration: {len(users)} users found",
                severity=Severity.MEDIUM,
                description=f"RPC anonymous session enumerated {len(users)} domain users.",
                evidence="\n".join(f"{u[0]} (RID: {u[1]})" for u in users[:20]),
                remediation="Restrict user enumeration via RPC.",
            ))

        # Groups
        groups = re.findall(r"group:\[([^\]]+)\].*rid:\[(0x[0-9a-f]+)\]", raw_output, re.IGNORECASE)
        if groups:
            findings.append(Finding(
                title=f"RPC Group Enumeration: {len(groups)} groups",
                severity=Severity.INFO,
                description=f"Found {len(groups)} domain groups via RPC.",
                evidence="\n".join(f"{g[0]} (RID: {g[1]})" for g in groups[:20]),
            ))

        # Password policy
        pw_match = re.search(
            r"(min password length.+?max password age.+?)(?=\n\n|$)",
            raw_output, re.IGNORECASE | re.DOTALL
        )
        if pw_match:
            pw_text = pw_match.group(0)[:400]
            findings.append(Finding(
                title="Domain Password Policy via RPC",
                severity=Severity.INFO,
                description="Retrieved domain password policy via RPC null session.",
                evidence=pw_text,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
