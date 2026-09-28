"""NetexecTool — netexec smb/ssh/winrm {target} -u {user} -p {pass}. Parse auth results."""
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
        protocol: str = params.get("protocol", "smb").lower()
        username: str = params.get("username", "")
        password: str = params.get("password", "")
        userlist: str = params.get("userlist", "")
        passlist: str = params.get("passlist", "")
        hash_val: str = params.get("hash", "")
        command: str = params.get("command", "")
        shares: bool = bool(params.get("shares", False))
        local_auth: bool = bool(params.get("local_auth", False))
        timeout: int = int(params.get("timeout", 300))

        cmd = ["netexec", protocol, target]

        if username:
            cmd += ["-u", username]
        elif userlist:
            cmd += ["-u", userlist]

        if hash_val:
            cmd += ["-H", hash_val]
        elif password:
            cmd += ["-p", password]
        elif passlist:
            cmd += ["-p", passlist]

        if local_auth:
            cmd.append("--local-auth")
        if command:
            cmd += ["-x", command]
        if shares:
            cmd.append("--shares")

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

        # netexec output: SMB 192.168.1.1  445   DC01 [*] Windows 10 ... (Pwn3d!)
        #                 SMB 192.168.1.1  445   DC01 [+] domain\user:pass (Pwn3d!)
        # Success patterns
        pwned_pattern = re.compile(r"(\w+)\s+([\d\.]+)\s+\d+\s+\w+\s+\[\+\]\s+(\S+)\s+\(Pwn3d!\)", re.IGNORECASE)
        success_pattern = re.compile(r"\[\+\]\s+(\S+)\s+(\S+)", re.IGNORECASE)
        info_pattern = re.compile(r"\[\*\]\s+(\w.*)", re.IGNORECASE)

        seen_creds: set[str] = set()

        for line in raw_output.splitlines():
            # Pwned (admin shell)
            m = pwned_pattern.search(line)
            if m:
                proto = m.group(1)
                host = m.group(2)
                cred = m.group(3)
                key = f"{host}:{cred}"
                if key not in seen_creds:
                    seen_creds.add(key)
                    findings.append(Finding(
                        title=f"Admin Access: {cred} on {host} ({proto})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Netexec confirmed administrative access (Pwn3d!) on {host}.\n"
                            f"Protocol: {proto}, Credential: {cred}"
                        ),
                        affected_asset=host,
                        evidence=line,
                        remediation=(
                            "Immediately change compromised credentials. "
                            "Enable MFA. Audit privileged accounts."
                        ),
                    ))
                continue

            # Valid login (non-admin)
            if "[+]" in line and ("\\") in line:
                m2 = success_pattern.search(line)
                if m2:
                    cred = m2.group(1)
                    if cred not in seen_creds:
                        seen_creds.add(cred)
                        findings.append(Finding(
                            title=f"Valid Credential: {cred}",
                            severity=Severity.HIGH,
                            description=f"Netexec found valid credential: {cred}",
                            evidence=line,
                            remediation="Change compromised password. Review authentication policies.",
                        ))

            # OS info
            m3 = re.search(r"\[\*\]\s+Windows\s+[\w\s\.]+\(name:(\w+)\)", line, re.IGNORECASE)
            if m3:
                findings.append(Finding(
                    title=f"Host Info: {m3.group(0).split('[*]')[1].strip()[:100]}",
                    severity=Severity.INFO,
                    description="Netexec identified Windows host information.",
                    evidence=line,
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target")) and bool(params.get("protocol", "smb"))
