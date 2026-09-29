"""NetexecTool — netexec smb/ssh/winrm {target}. Credential testing + command execution."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.netexec")


class NetexecTool(BaseTool):
    name = "netexec"
    category = ToolCategory.NETWORK
    requires = ["netexec"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' and 'protocol' required.")

        target: str = params["target"]
        protocol: str = params.get("protocol", "smb")  # smb, ssh, winrm, ldap, ftp
        username: str = params.get("username", "")
        password: str = params.get("password", "")
        cred_file: str = params.get("cred_file", "")
        command: str = params.get("command", "")
        hash_: str = params.get("hash", "")
        timeout: int = int(params.get("timeout", 120))
        spray: bool = bool(params.get("spray", False))

        cmd = ["netexec", protocol, target]
        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        elif hash_:
            cmd += ["--hash", hash_]
        if cred_file:
            cmd += ["-u", cred_file, "-p", password or cred_file]
        if command:
            cmd += ["-x", command]
        if spray:
            cmd += ["--continue-on-success"]

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

        # Pwn3d! — local admin
        pwned_lines = [l for l in raw_output.splitlines() if "Pwn3d!" in l]
        if pwned_lines:
            findings.append(Finding(
                title="Credentials Provide Local Admin Access (Pwn3d!)",
                severity=Severity.CRITICAL,
                description="netexec confirmed local administrator access with the provided credentials.",
                evidence="\n".join(pwned_lines[:5]),
                remediation="Rotate all compromised credentials immediately. Remove unnecessary local admin grants.",
            ))

        # Valid creds
        valid_lines = [l for l in raw_output.splitlines()
                       if re.search(r"\[\+\].*:.*", l) and "Pwn3d!" not in l]
        if valid_lines:
            findings.append(Finding(
                title=f"Valid Credentials Found: {len(valid_lines)} accounts",
                severity=Severity.HIGH,
                description=f"netexec validated credentials for {len(valid_lines)} account(s).",
                evidence="\n".join(valid_lines[:10]),
                remediation="Change compromised passwords. Enforce MFA.",
            ))

        # Command output
        cmd_output = re.search(r"\[\+\] Executed command(.*?)(?=\[|$)", raw_output, re.DOTALL)
        if cmd_output:
            findings.append(Finding(
                title="Remote Command Execution Successful",
                severity=Severity.CRITICAL,
                description="Remote command was executed on target system.",
                evidence=cmd_output.group(0)[:500],
                remediation="Revoke compromised credentials. Apply patches for exploited service.",
            ))

        # Host info (even with no creds)
        host_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(Windows|Linux).*?(\d{4})", raw_output)
        if host_match:
            findings.append(Finding(
                title=f"Host Information: {host_match.group(0)[:100]}",
                severity=Severity.INFO,
                description="netexec retrieved host information.",
                evidence=host_match.group(0)[:200],
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target")) and bool(params.get("protocol", "smb"))
