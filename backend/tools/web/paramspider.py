"""ParamSpider — parameter discovery from web archives."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.paramspider")


class ParamspiderTool(BaseTool):
    name = "paramspider"
    category = ToolCategory.WEB
    requires = ["paramspider"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' domain required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        level: str = params.get("level", "high")
        exclude: str = params.get("exclude", "js,css,png,jpg,gif,ico")

        import os, tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "paramspider",
                "-d", target,
                "--level", level,
                "--exclude", exclude,
                "--quiet",
                "-o", os.path.join(tmpdir, "results.txt"),
            ]

            output_file = None
            if self._job_id and self._session_id:
                from backend.config import settings
                output_file = os.path.join(
                    settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
                )

            returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

            results_file = os.path.join(tmpdir, "results.txt")
            if os.path.isfile(results_file):
                with open(results_file) as f:
                    raw += f.read()

        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        url_with_params = []

        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("http") and "=" in line:
                url_with_params.append(line)

        if url_with_params:
            findings.append(Finding(
                title=f"ParamSpider: {len(url_with_params)} URLs with Parameters",
                severity=Severity.INFO,
                description=f"ParamSpider discovered {len(url_with_params)} URLs with query parameters.",
                affected_asset="web archive",
                evidence=f"Sample: {url_with_params[0]}" if url_with_params else "",
            ))

        # Look for interesting parameter names
        fuzz_params = re.compile(
            r"[?&](id|user|admin|file|path|url|redirect|next|page|cmd|exec|query|"
            r"search|lang|callback|token|key|pass|password|secret|debug|test)=",
            re.IGNORECASE,
        )
        for url in url_with_params:
            if fuzz_params.search(url):
                key = url[:80]
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Interesting Parameter URL: {url[:100]}",
                        severity=Severity.LOW,
                        description=f"URL with potentially vulnerable parameter: {url}",
                        affected_asset=url.split("?")[0],
                        evidence=url,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
