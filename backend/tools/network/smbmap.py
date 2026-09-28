"""SmbmapTool — smbmap -H {target}. Parse accessible shares."""
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
        command: str = params.get("command", "")
        recursive: bool = bool(params.get("recursive", False))
        timeout: int = int(params.get("timeout", 120))

        cmd = ["smbmap", "-H", target]
        if username:
            cmd += ["-u", username]
        else:
            cmd += ["-u", ""]  # null session
        if password:
            cmd += ["-p", password]
        if domain:
            cmd += ["-d", domain]
        if command:
            cmd += ["-x", command]
        if recursive:
            cmd += ["-R"]

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

        # smbmap output: share_name  permissions  comment
        # Example: //192.168.1.1/ADMIN$  [NO ACCESS]
        # Example: //192.168.1.1/C$      [READ, WRITE]
        read_write_shares: list[str] = []
        read_only_shares: list[str] = []
        no_access_shares: list[str] = []

        share_pattern = re.compile(r"//[\d\w\.\-]+/(\w+)\s+(.+)")
        # Also: sharename  READ ONLY / READ, WRITE
        perm_pattern = re.compile(r"(\w[\w\$]+)\s+(READ ONLY|READ, WRITE|NO ACCESS|READ/WRITE|READ \+ WRITE)", re.IGNORECASE)

        for line in raw_output.splitlines():
            m = share_pattern.search(line)
            if m:
                share = m.group(1)
                perms = m.group(2).upper()
                if "READ" in perms and "WRITE" in perms:
                    read_write_shares.append(share)
                elif "READ" in perms:
                    read_only_shares.append(share)
                elif "NO ACCESS" in perms:
                    no_access_shares.append(share)
                continue

            m2 = perm_pattern.search(line)
            if m2:
                share = m2.group(1)
                perms = m2.group(2).upper()
                if "READ" in perms and "WRITE" in perms:
                    read_write_shares.append(share)
                elif "READ" in perms:
                    read_only_shares.append(share)

        if read_write_shares:
            findings.append(Finding(
                title=f"Writable SMB Shares: {', '.join(read_write_shares)}",
                severity=Severity.HIGH,
                description=(
                    f"SmbMap found {len(read_write_shares)} writable SMB shares: "
                    f"{', '.join(read_write_shares)}"
                ),
                affected_asset=raw_output.split()[0] if raw_output else "",
                evidence="\n".join(read_write_shares),
                remediation=(
                    "Remove write permissions from shares that don't require them. "
                    "Audit share ACLs regularly."
                ),
            ))

        if read_only_shares:
            findings.append(Finding(
                title=f"Readable SMB Shares: {', '.join(read_only_shares[:5])}",
                severity=Severity.MEDIUM,
                description=f"SmbMap found {len(read_only_shares)} readable SMB shares.",
                evidence="\n".join(read_only_shares),
                remediation="Verify that readable shares don't expose sensitive data.",
            ))

        # Check for command execution result
        if "command" in raw_output.lower() and len(raw_output) > 200:
            if "nt authority\\system" in raw_output.lower() or "nt authority\\network service" in raw_output.lower():
                findings.append(Finding(
                    title="SMB Command Execution Successful",
                    severity=Severity.CRITICAL,
                    description="SmbMap executed a command via SMB with elevated privileges.",
                    evidence=raw_output[:1000],
                    remediation="Disable SMB command execution. Apply principle of least privilege.",
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (self._is_valid_ip(target) or self._is_valid_domain(target))
