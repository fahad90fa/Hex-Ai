"""Hydra — network login cracker."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.hydra")


class HydraTool(BaseTool):
    name = "hydra"
    category = ToolCategory.AUTH
    requires = ["hydra"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target', 'service', 'userlist', 'passlist' required.")

        target: str = params["target"]
        service: str = params["service"]  # ssh, ftp, http-post-form, etc.
        userlist: str = params.get("userlist", "")
        passlist: str = params.get("passlist", "")
        port: Optional[str] = params.get("port")
        timeout: int = int(params.get("timeout", 3600))
        tasks: int = int(params.get("tasks", 16))
        http_form_string: str = params.get("http_form_string", "")

        cmd = ["hydra", "-V", "-f"]
        if userlist:
            cmd += ["-L", userlist]
        else:
            cmd += ["-l", params.get("username", "admin")]
        if passlist:
            cmd += ["-P", passlist]
        else:
            cmd += ["-p", params.get("password", "password")]
        cmd += ["-t", str(tasks)]

        if port:
            target_str = f"-s {port} {target} {service}"
            cmd += ["-s", str(port), target, service]
        else:
            cmd += [target, service]

        if service == "http-post-form" and http_form_string:
            cmd.append(http_form_string)

        import os
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
        seen: set[str] = set()
        # Hydra success: [22][ssh] host: 192.168.1.1   login: admin   password: password123
        success_pattern = re.compile(
            r"\[(\d+)\]\[(\w[\w\-]+)\] host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
        )

        for line in raw_output.splitlines():
            m = success_pattern.search(line)
            if m:
                port = m.group(1)
                service = m.group(2)
                host = m.group(3)
                login = m.group(4)
                password = m.group(5)

                key = f"{host}:{port}:{login}"
                if key in seen:
                    continue
                seen.add(key)

                findings.append(Finding(
                    title=f"Valid Credential: {login}@{host}:{port} ({service})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Hydra cracked {service} credentials:\n"
                        f"  Host: {host}:{port}\n"
                        f"  Username: {login}\n"
                        f"  Password: {password}"
                    ),
                    affected_asset=f"{host}:{port}",
                    evidence=line,
                    remediation=(
                        "Change the compromised password immediately. "
                        "Implement account lockout policies and multi-factor authentication."
                    ),
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target")) and bool(params.get("service"))
