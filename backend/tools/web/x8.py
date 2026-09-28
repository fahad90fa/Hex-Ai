"""x8 — hidden HTTP parameter discovery tool."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.x8")


class X8Tool(BaseTool):
    name = "x8"
    category = ToolCategory.WEB
    requires = ["x8"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        wordlist: str = params.get("wordlist", "")
        method: str = params.get("method", "GET")
        body: str = params.get("body", "")
        output_format: str = params.get("output_format", "json")

        cmd = ["x8", "-u", target, "-m", method.upper()]
        if wordlist:
            cmd += ["-w", wordlist]
        if body:
            cmd += ["-b", body]
        if output_format == "json":
            cmd += ["-o", "json"]

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

        # Try JSON parsing
        try:
            data = json.loads(raw_output)
            if isinstance(data, list):
                for item in data:
                    param = item.get("name", item.get("param", ""))
                    url = item.get("url", "")
                    diff = item.get("diff", "")
                    if param and param not in seen:
                        seen.add(param)
                        findings.append(Finding(
                            title=f"Hidden Parameter: {param}",
                            severity=Severity.LOW,
                            description=f"x8 discovered hidden HTTP parameter '{param}' at {url}",
                            affected_asset=url,
                            evidence=f"Diff: {diff}",
                        ))
                return findings
        except Exception:
            pass

        # Plain text fallback
        param_pattern = re.compile(r"Found parameter:\s+(\S+)", re.IGNORECASE)
        for line in raw_output.splitlines():
            m = param_pattern.search(line)
            if m:
                param = m.group(1)
                if param not in seen:
                    seen.add(param)
                    findings.append(Finding(
                        title=f"Hidden Parameter: {param}",
                        severity=Severity.LOW,
                        description=f"x8 found hidden parameter: {param}",
                        affected_asset=param,
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
