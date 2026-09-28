"""RpcclientTool — rpcclient -U {user}%{pass} {target} -c {command}. Parse user/group enums."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.rpcclient")


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
        commands: list[str] = params.get("commands", [
            "enumdomusers",
            "enumdomgroups",
            "querydominfo",
            "getdompwinfo",
        ])
        timeout: int = int(params.get("timeout", 120))

        auth_str = f"{username}%{password}" if username else "%"
        cmd = ["rpcclient", "-U", auth_str, target, "-c", ";".join(commands), "-N"]

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

        # Parse users: user:[Administrator] rid:[0x1f4]
        users: list[str] = []
        for m in re.finditer(r"user:\[(\w+)\]\s+rid:\[(0x[\da-fA-F]+)\]", raw_output):
            users.append(m.group(1))

        if users:
            findings.append(Finding(
                title=f"Domain Users Enumerated via RPC: {len(users)} accounts",
                severity=Severity.MEDIUM,
                description=(
                    f"rpcclient enumerated {len(users)} domain user accounts via MS-SAMR.\n"
                    "This includes administrator and service accounts."
                ),
                evidence="\n".join(users[:30]),
                remediation=(
                    "Restrict MS-SAMR access using RestrictRemoteSAM registry key. "
                    "Require authentication for null sessions."
                ),
            ))

            # Look for interesting accounts
            interesting = [u for u in users if any(
                k in u.lower() for k in ["admin", "backup", "service", "svc", "test", "temp"]
            )]
            if interesting:
                findings.append(Finding(
                    title=f"Privileged/Service Accounts Found: {', '.join(interesting[:5])}",
                    severity=Severity.HIGH,
                    description=f"Found {len(interesting)} potentially privileged accounts.",
                    evidence="\n".join(interesting),
                    remediation="Ensure service accounts use strong passwords and follow least-privilege.",
                ))

        # Parse groups
        groups: list[str] = []
        for m in re.finditer(r"group:\[([^\]]+)\]\s+rid:\[", raw_output):
            groups.append(m.group(1))

        if groups:
            findings.append(Finding(
                title=f"Domain Groups Enumerated: {len(groups)} groups",
                severity=Severity.LOW,
                description=f"rpcclient enumerated {len(groups)} domain groups.",
                evidence="\n".join(groups[:20]),
            ))

        # Password policy
        pw_min = re.search(r"min_password_length:\s*(\d+)", raw_output)
        pw_history = re.search(r"password_history:\s*(\d+)", raw_output)
        if pw_min:
            min_len = int(pw_min.group(1))
            if min_len < 8:
                findings.append(Finding(
                    title=f"Weak Password Policy: Minimum Length {min_len}",
                    severity=Severity.MEDIUM,
                    description=f"Domain password policy requires only {min_len} character minimum.",
                    evidence=f"min_password_length: {min_len}",
                    remediation="Set minimum password length to at least 12 characters.",
                ))

        # Null session
        if "NT_STATUS_ACCESS_DENIED" not in raw_output and users:
            findings.append(Finding(
                title="RPC Null Session Permitted",
                severity=Severity.HIGH,
                description="Server allowed unauthenticated RPC enumeration.",
                evidence="Null session enumeration successful",
                remediation="Configure RestrictAnonymous=2. Disable null sessions.",
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (self._is_valid_ip(target) or self._is_valid_domain(target))
