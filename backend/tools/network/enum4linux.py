"""Enum4linuxTool — enum4linux -a {target}. SMB enumeration."""
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
        flags: list[str] = params.get("flags", ["-a"])
        timeout: int = int(params.get("timeout", 120))

        cmd = ["enum4linux"] + flags + [target]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=returncode == 0 or findings, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []

        # Null session
        if re.search(r"null session", raw_output, re.IGNORECASE) and \
           re.search(r"allowed|successful", raw_output, re.IGNORECASE):
            findings.append(Finding(
                title="SMB Null Session Allowed",
                severity=Severity.HIGH,
                description="Anonymous/null SMB sessions are allowed on this host.",
                evidence=re.search(r".{0,100}null session.{0,100}", raw_output, re.IGNORECASE).group(0).strip(),
                remediation="Disable null sessions: set RestrictAnonymous=1 or 2 in the registry.",
            ))

        # Users found
        users = re.findall(r"user:\[([^\]]+)\]", raw_output, re.IGNORECASE)
        if users:
            findings.append(Finding(
                title=f"SMB Users Enumerated: {len(users)} users",
                severity=Severity.MEDIUM,
                description=f"Enum4linux enumerated {len(users)} users via SMB/RPC.",
                evidence="\n".join(users[:20]),
                remediation="Restrict anonymous account enumeration.",
            ))

        # Shares found
        shares = re.findall(r"Mapping:\s+(\S+)", raw_output)
        writable_shares = re.findall(r"mapping:\s*(\S+).*writable", raw_output, re.IGNORECASE)
        if shares:
            findings.append(Finding(
                title=f"SMB Shares Discovered: {', '.join(shares[:10])}",
                severity=Severity.MEDIUM if not writable_shares else Severity.HIGH,
                description=f"Found {len(shares)} SMB shares.",
                evidence="\n".join(shares[:20]),
                remediation="Review share permissions and restrict access.",
            ))

        # Password policy
        if re.search(r"password policy", raw_output, re.IGNORECASE):
            pw_section = re.search(r"(password policy.*?)(?=\[\+\]|$)", raw_output, re.IGNORECASE | re.DOTALL)
            if pw_section:
                pw_text = pw_section.group(0)[:500]
                if re.search(r"minimum password length:\s*[0-4]\b", pw_text, re.IGNORECASE) or \
                   re.search(r"password history count:\s*[0-2]\b", pw_text, re.IGNORECASE):
                    findings.append(Finding(
                        title="Weak SMB Password Policy",
                        severity=Severity.MEDIUM,
                        description="The domain password policy is weak.",
                        evidence=pw_text,
                        remediation="Enforce minimum password length >=12, complexity requirements, history>=5.",
                    ))

        # OS info
        os_match = re.search(r"OS:\[([^\]]+)\]", raw_output)
        if os_match:
            findings.append(Finding(
                title=f"Operating System Identified: {os_match.group(1)}",
                severity=Severity.INFO,
                description=f"Target OS: {os_match.group(1)}",
                evidence=os_match.group(0),
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
