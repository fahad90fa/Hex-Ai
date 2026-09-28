"""Enum4linuxTool — enum4linux -a {target}. Parse users, shares, OS info."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.enum4linux")


class Enum4linuxTool(BaseTool):
    name = "enum4linux"
    category = ToolCategory.NETWORK
    requires = ["enum4linux"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        username: str = params.get("username", "")
        password: str = params.get("password", "")
        workgroup: str = params.get("workgroup", "")
        timeout: int = int(params.get("timeout", 300))

        cmd = ["enum4linux", "-a"]
        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        if workgroup:
            cmd += ["-w", workgroup]
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

        # Parse users
        users: list[str] = []
        for m in re.finditer(r"user:\[(\w+)\]", raw_output, re.IGNORECASE):
            users.append(m.group(1))
        # Also match: index: 0x1 RID: 0x3e9 acb: ... Account: username
        for m in re.finditer(r"Account:\s+(\w+)", raw_output, re.IGNORECASE):
            users.append(m.group(1))
        users = list(dict.fromkeys(users))  # deduplicate

        if users:
            findings.append(Finding(
                title=f"SMB Users Enumerated: {len(users)} accounts",
                severity=Severity.MEDIUM,
                description=f"Enum4linux enumerated {len(users)} user accounts via SMB/RPC.",
                affected_asset=raw_output.split()[0] if raw_output else "",
                evidence="\n".join(users[:30]),
                remediation=(
                    "Restrict null session access. "
                    "Disable SMBv1. Configure RestrictAnonymous=2."
                ),
            ))

        # Parse shares
        shares: list[str] = []
        for m in re.finditer(r"Sharename\s+Type\s+Comment.*?\n((?:.*?\n)+?)(?:\n|$)", raw_output, re.IGNORECASE | re.MULTILINE):
            block = m.group(1)
            for line in block.splitlines():
                parts = line.split()
                if parts and not parts[0].startswith("-"):
                    shares.append(parts[0])

        # Simpler share pattern
        for m in re.finditer(r"\s+(\w+)\s+Disk\s+", raw_output):
            shares.append(m.group(1))
        shares = list(dict.fromkeys(shares))

        if shares:
            findings.append(Finding(
                title=f"SMB Shares Discovered: {len(shares)}",
                severity=Severity.MEDIUM,
                description=f"Found {len(shares)} SMB shares: {', '.join(shares[:10])}",
                evidence="\n".join(shares),
                remediation="Restrict share permissions. Remove unnecessary shares.",
            ))

        # Password policy
        if "minimum password length" in raw_output.lower():
            m = re.search(r"minimum password length:\s*(\d+)", raw_output, re.IGNORECASE)
            if m:
                min_len = int(m.group(1))
                if min_len < 8:
                    findings.append(Finding(
                        title=f"Weak Password Policy: Min Length {min_len}",
                        severity=Severity.MEDIUM,
                        description=f"Domain minimum password length is only {min_len} characters.",
                        evidence=f"Minimum password length: {min_len}",
                        remediation="Set minimum password length to at least 12 characters.",
                    ))

        # Null session
        if "null session" in raw_output.lower() and "established" in raw_output.lower():
            findings.append(Finding(
                title="Null Session Permitted",
                severity=Severity.HIGH,
                description="Server allows null (unauthenticated) SMB sessions.",
                evidence="Null session established",
                remediation="Set RestrictAnonymous=2 and RestrictNullSessAccess=1 in registry.",
            ))

        # OS info
        os_match = re.search(r"OS:\s*([^\n]+)", raw_output, re.IGNORECASE)
        if os_match:
            os_info = os_match.group(1).strip()
            findings.append(Finding(
                title=f"OS Detected: {os_info}",
                severity=Severity.INFO,
                description=f"Enum4linux identified OS via SMB: {os_info}",
                evidence=os_info,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (self._is_valid_ip(target) or self._is_valid_domain(target))
