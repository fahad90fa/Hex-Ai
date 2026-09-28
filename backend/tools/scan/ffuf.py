"""FFUF — fast web fuzzer."""
from __future__ import annotations

import json
import logging

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.ffuf")


class FfufTool(BaseTool):
    name = "ffuf"
    category = ToolCategory.SCAN
    requires = ["ffuf"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' and 'wordlist' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"

        wordlist: str = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads: int = int(params.get("threads", 200))
        timeout: int = int(params.get("timeout", 600))
        extensions: str = params.get("extensions", "")
        filter_code: str = params.get("filter_code", "404")
        match_code: str = params.get("match_code", "")

        import os, tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            json_output = tmp.name

        cmd = [
            "ffuf",
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "-o", json_output,
            "-of", "json",
            "-s",  # silent
        ]
        if extensions:
            cmd += ["-e", extensions]
        if filter_code:
            cmd += ["-fc", filter_code]
        if match_code:
            cmd += ["-mc", match_code]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        findings: list[Finding] = []
        try:
            if os.path.isfile(json_output):
                with open(json_output) as f:
                    data = json.load(f)
                findings = self._parse_json(data)
                os.unlink(json_output)
        except Exception:
            findings = self.parse(raw)

        return ToolResult(success=True, output=raw, findings=findings)

    def _parse_json(self, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        results = data.get("results", [])
        sensitive_pattern = __import__("re").compile(
            r"(admin|backup|\.git|\.env|config|secret|passwd|key|private)", __import__("re").IGNORECASE
        )
        for result in results:
            url = result.get("url", "")
            status = result.get("status", 0)
            content_length = result.get("length", 0)
            words = result.get("words", 0)

            severity = Severity.INFO
            if status in (200, 204):
                if sensitive_pattern.search(url):
                    severity = Severity.HIGH
                else:
                    severity = Severity.LOW
            elif status == 401:
                severity = Severity.MEDIUM
            elif status == 403:
                severity = Severity.LOW

            findings.append(Finding(
                title=f"FFUF Found: {url} [{status}]",
                severity=severity,
                description=f"FFUF discovered: {url}\nStatus: {status}, Size: {content_length}, Words: {words}",
                affected_asset=url,
                evidence=f"HTTP {status} | Length: {content_length} | Words: {words}",
            ))
        return findings

    def parse(self, raw_output: str) -> list[Finding]:
        import re
        findings: list[Finding] = []
        pattern = re.compile(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")
        for line in raw_output.splitlines():
            m = pattern.search(line)
            if m:
                path = m.group(1)
                status = int(m.group(2))
                size = m.group(3)
                findings.append(Finding(
                    title=f"FFUF Found: {path} [{status}]",
                    severity=Severity.LOW if status == 200 else Severity.INFO,
                    description=f"FFUF found {path} — HTTP {status}, size {size}",
                    affected_asset=path,
                    evidence=line,
                ))
        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target"))
