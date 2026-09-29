"""Gobuster — directory and DNS brute-force tool."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.gobuster")


class GobusterTool(BaseTool):
    name = "gobuster"
    category = ToolCategory.SCAN
    requires = ["gobuster"]

    # Status codes worth flagging
    INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403}

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' and 'wordlist' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"

        wordlist: str = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads: int = int(params.get("threads", 50))
        timeout: int = int(params.get("timeout", 600))
        extensions: str = params.get("extensions", "php,html,js,txt,json,xml,bak,zip")
        mode: str = params.get("mode", "dir")  # dir, dns, vhost
        status_codes: str = params.get("status_codes", "200,204,301,302,307,401,403")

        cmd = [
            "gobuster", mode,
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "-s", status_codes,
            "--no-error",
        ]
        if mode == "dir" and extensions:
            cmd += ["-x", extensions]

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

        # Gobuster format: /admin               (Status: 200) [Size: 4096]
        dir_pattern = re.compile(r"(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
        dns_pattern = re.compile(r"Found:\s+(\S+)")

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("["):
                continue

            m = dir_pattern.search(line)
            if m:
                path = m.group(1)
                status = int(m.group(2))
                size = m.group(3) or "unknown"

                key = path
                if key in seen:
                    continue
                seen.add(key)

                if status not in self.INTERESTING_CODES:
                    continue

                severity = Severity.INFO
                if status in (200, 201, 204):
                    # Check for sensitive paths
                    sensitive = re.compile(
                        r"(admin|backup|\.git|\.env|config|passwd|shadow|secret|key|private|credentials)",
                        re.IGNORECASE,
                    )
                    if sensitive.search(path):
                        severity = Severity.HIGH
                    else:
                        severity = Severity.LOW
                elif status == 401:
                    severity = Severity.MEDIUM  # Auth-protected endpoint
                elif status == 403:
                    severity = Severity.LOW

                findings.append(Finding(
                    title=f"Directory/File Found: {path} [{status}]",
                    severity=severity,
                    description=f"Gobuster found: {path} — HTTP {status}, size {size}",
                    affected_asset=path,
                    evidence=line,
                ))
                continue

            d = dns_pattern.search(line)
            if d:
                sub = d.group(1)
                if sub not in seen:
                    seen.add(sub)
                    findings.append(Finding(
                        title=f"DNS Subdomain: {sub}",
                        severity=Severity.INFO,
                        description=f"Gobuster DNS brute-force found subdomain: {sub}",
                        affected_asset=sub,
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
