"""Dirsearch — web path scanner."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.dirsearch")


class DirsearchTool(BaseTool):
    name = "dirsearch"
    category = ToolCategory.SCAN
    requires = ["dirsearch"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"

        wordlist: str = params.get("wordlist", "")
        threads: int = int(params.get("threads", 30))
        timeout: int = int(params.get("timeout", 600))
        extensions: str = params.get("extensions", "php,asp,aspx,jsp,html,js,txt,json,xml,bak,zip")

        cmd = [
            "dirsearch",
            "-u", target,
            "-t", str(threads),
            "-x", "400,404,500,502,503",
            "--plain-text-report", "-",
            "--no-color",
            "-q",
        ]
        if wordlist:
            cmd += ["-w", wordlist]
        if extensions:
            cmd += ["-e", extensions]

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
        # Dirsearch plain text: 200    4KB   http://example.com/admin
        pattern = re.compile(r"(\d{3})\s+\S+\s+(https?://\S+)")
        sensitive = re.compile(
            r"(admin|backup|\.git|\.svn|\.env|config|secret|passwd|\.key|private|\.sql|\.bak)",
            re.IGNORECASE,
        )

        for line in raw_output.splitlines():
            line = line.strip()
            m = pattern.search(line)
            if not m:
                continue

            status = int(m.group(1))
            url = m.group(2)

            if url in seen:
                continue
            seen.add(url)

            if status in (404, 400, 500, 502, 503):
                continue

            severity = Severity.INFO
            if status in (200, 201):
                severity = Severity.HIGH if sensitive.search(url) else Severity.LOW
            elif status in (301, 302):
                severity = Severity.INFO
            elif status == 401:
                severity = Severity.MEDIUM
            elif status == 403:
                severity = Severity.LOW

            findings.append(Finding(
                title=f"Dirsearch Found: {url} [{status}]",
                severity=severity,
                description=f"Dirsearch discovered: {url} — HTTP {status}",
                affected_asset=url,
                evidence=line,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
