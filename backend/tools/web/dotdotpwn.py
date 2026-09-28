"""DotDotPwn — directory traversal fuzzer."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.dotdotpwn")


class DotdotpwnTool(BaseTool):
    name = "dotdotpwn"
    category = ToolCategory.WEB
    requires = ["dotdotpwn"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' host required.")

        target: str = params["target"]
        port: int = int(params.get("port", 80))
        timeout: int = int(params.get("timeout", 300))
        module: str = params.get("module", "http")
        depth: int = int(params.get("depth", 6))
        os_type: str = params.get("os", "unix")  # unix or windows

        # Strip protocol if present
        if "://" in target:
            target = target.split("://", 1)[1].split("/")[0]

        cmd = [
            "dotdotpwn",
            "-m", module,
            "-h", target,
            "-o", os_type,
            "-d", str(depth),
            "-q",  # quiet
            "-f",  # fast
        ]
        if port != 80:
            cmd += ["-x", str(port)]

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
        # DotDotPwn: VULNERABLE! - Traversal: ../../../etc/passwd
        vuln_pattern = re.compile(r"VULNERABLE[!\s]+.*?Traversal:\s+(.+)", re.IGNORECASE)
        # Also: [+] ../../../etc/passwd (200)
        found_pattern = re.compile(r"\[\+\]\s+(\S+)\s+\((\d+)\)")

        for line in raw_output.splitlines():
            line = line.strip()
            m = vuln_pattern.search(line)
            if m:
                traversal = m.group(1).strip()
                key = traversal
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Directory Traversal: {traversal[:80]}",
                        severity=Severity.HIGH,
                        description=f"DotDotPwn confirmed directory traversal: {traversal}",
                        affected_asset=traversal,
                        evidence=line,
                        remediation="Validate and sanitise all file path input. Use realpath() and chroot jails.",
                    ))
                continue

            fm = found_pattern.search(line)
            if fm:
                path = fm.group(1)
                status = fm.group(2)
                key = path
                if key not in seen and status == "200":
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Path Traversal Response: {path[:80]}",
                        severity=Severity.HIGH,
                        description=f"200 OK response to path traversal: {path}",
                        affected_asset=path,
                        evidence=line,
                        remediation="Restrict file access to authorised directories.",
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
