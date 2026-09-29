"""Feroxbuster — fast, recursive content discovery."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.feroxbuster")


class FeroxbusterTool(BaseTool):
    name = "feroxbuster"
    category = ToolCategory.SCAN
    requires = ["feroxbuster"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"

        wordlist: str = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads: int = int(params.get("threads", 50))
        timeout: int = int(params.get("timeout", 600))
        depth: int = int(params.get("depth", 4))
        extensions: str = params.get("extensions", "php,html,js,txt,json,bak")
        filter_codes: str = params.get("filter_codes", "404,429")

        import os, tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            json_path = tmp.name

        cmd = [
            "feroxbuster",
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "-d", str(depth),
            "--output", json_path,
            "--json",
            "--silent",
            "--no-state",
            "-C", filter_codes,
        ]
        if extensions:
            cmd += ["-x", extensions]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        findings: list[Finding] = []
        try:
            if os.path.isfile(json_path):
                with open(json_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            findings.extend(self._parse_json_line(json.loads(line)))
                        except Exception:
                            continue
                os.unlink(json_path)
        except Exception:
            findings = self.parse(raw)

        return ToolResult(success=True, output=raw, findings=findings)

    def _parse_json_line(self, data: dict) -> list[Finding]:
        url = data.get("url", "")
        status = data.get("status", 0)
        content_length = data.get("content_length", 0)
        word_count = data.get("word_count", 0)

        if not url or status == 404:
            return []

        sensitive = re.compile(
            r"(admin|backup|\.git|\.env|config|secret|passwd|\.key|private|api)", re.IGNORECASE
        )
        severity = Severity.INFO
        if status in (200, 201):
            severity = Severity.HIGH if sensitive.search(url) else Severity.LOW
        elif status in (301, 302, 307):
            severity = Severity.INFO
        elif status == 401:
            severity = Severity.MEDIUM
        elif status == 403:
            severity = Severity.LOW

        return [Finding(
            title=f"Feroxbuster: {url} [{status}]",
            severity=severity,
            description=f"Feroxbuster found: {url}\nHTTP {status}, {content_length} bytes, {word_count} words",
            affected_asset=url,
            evidence=f"HTTP {status} | {content_length}B | {word_count}w",
        )]

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        pattern = re.compile(r"(\d{3})\s+\S+\s+\S+\s+(https?://\S+)")
        for line in raw_output.splitlines():
            m = pattern.search(line)
            if m:
                status = int(m.group(1))
                url = m.group(2)
                if status != 404:
                    findings.append(Finding(
                        title=f"Feroxbuster: {url} [{status}]",
                        severity=Severity.LOW if status == 200 else Severity.INFO,
                        description=f"Found {url} — HTTP {status}",
                        affected_asset=url,
                        evidence=line,
                    ))
        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
