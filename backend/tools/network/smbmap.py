"""SmbmapTool — smbmap -H {target}. SMB share permission mapping."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.smbmap")


class SmbmapTool(BaseTool):
    name = "smbmap"
    category = ToolCategory.NETWORK
    requires = ["smbmap"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        username: str = params.get("username", "")
        password: str = params.get("password", "")
        domain: str = params.get("domain", "")
        share: str = params.get("share", "")
        timeout: int = int(params.get("timeout", 60))
        recursive: bool = bool(params.get("recursive", False))

        cmd = ["smbmap", "-H", target]
        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]
        if share:
            cmd += ["-s", share]
        if recursive:
            cmd += ["-r"]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=bool(findings) or returncode == 0, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []

        # Parse share lines: share_name  READ,WRITE  comments
        share_pattern = re.compile(
            r"\s+(\S+)\s+(READ(?:,WRITE)?|WRITE(?:,READ)?|NO ACCESS)\s+(.*)",
            re.IGNORECASE,
        )

        writable_shares: list[str] = []
        readable_shares: list[str] = []
        no_access_shares: list[str] = []

        for line in raw_output.splitlines():
            m = share_pattern.search(line)
            if m:
                share_name = m.group(1)
                perms = m.group(2).upper()
                if "WRITE" in perms:
                    writable_shares.append(f"{share_name} ({perms})")
                elif "READ" in perms:
                    readable_shares.append(f"{share_name} ({perms})")
                else:
                    no_access_shares.append(share_name)

        if writable_shares:
            findings.append(Finding(
                title=f"Writable SMB Shares: {', '.join(writable_shares[:5])}",
                severity=Severity.HIGH,
                description=f"Found {len(writable_shares)} writable SMB shares.",
                evidence="\n".join(writable_shares),
                remediation="Remove write permissions from non-admin shares.",
            ))

        if readable_shares:
            findings.append(Finding(
                title=f"Readable SMB Shares: {', '.join(readable_shares[:5])}",
                severity=Severity.MEDIUM,
                description=f"{len(readable_shares)} SMB shares are readable.",
                evidence="\n".join(readable_shares),
                remediation="Review share contents for sensitive data. Restrict read access.",
            ))

        # Command execution
        if re.search(r"NT AUTHORITY\\SYSTEM|command executed", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="SMB Command Execution as SYSTEM",
                severity=Severity.CRITICAL,
                description="smbmap achieved command execution with NT AUTHORITY\\SYSTEM privileges.",
                evidence=re.search(r".{0,200}(?:SYSTEM|command executed).{0,200}", raw_output, re.IGNORECASE).group(0).strip(),
                remediation="Immediately patch the SMB service and change all credentials.",
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
