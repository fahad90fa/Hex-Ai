"""Arjun — HTTP parameter discovery suite."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.arjun")


class ArjunTool(BaseTool):
    name = "arjun"
    category = ToolCategory.WEB
    requires = ["arjun"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        method: str = params.get("method", "GET")
        threads: int = int(params.get("threads", 5))
        chunk_size: int = int(params.get("chunk_size", 250))

        import os, tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            json_output = tmp.name

        cmd = [
            "arjun",
            "-u", target,
            "-m", method.upper(),
            "-t", str(threads),
            "--chunk-size", str(chunk_size),
            "-o", json_output,
            "--stable",
        ]

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
                findings = self._parse_json(data, target)
                os.unlink(json_output)
        except Exception:
            findings = self.parse(raw)

        return ToolResult(success=True, output=raw, findings=findings)

    def _parse_json(self, data: dict, target: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(data, dict):
            return []

        for endpoint, params in data.items():
            if isinstance(params, list) and params:
                findings.append(Finding(
                    title=f"Parameters Discovered: {endpoint}",
                    severity=Severity.INFO,
                    description=(
                        f"Arjun discovered {len(params)} HTTP parameter(s) at {endpoint}:\n"
                        f"  {', '.join(params)}"
                    ),
                    affected_asset=endpoint,
                    evidence=f"Parameters: {', '.join(params)}",
                ))
                # Flag potentially sensitive parameters
                sensitive_params = {"debug", "test", "admin", "token", "key", "secret", "password",
                                    "pass", "auth", "internal", "dev", "file", "path", "cmd", "exec"}
                for p in params:
                    if p.lower() in sensitive_params:
                        findings.append(Finding(
                            title=f"Sensitive Parameter Found: {p}",
                            severity=Severity.MEDIUM,
                            description=f"Arjun found potentially sensitive parameter '{p}' at {endpoint}",
                            affected_asset=endpoint,
                            evidence=f"Parameter: {p}",
                            remediation="Validate and restrict access to internal/debug parameters.",
                        ))
        return findings

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        param_pattern = re.compile(r"Parameters found: (.+)", re.IGNORECASE)
        found_pattern = re.compile(r"\[\+\]\s+(.+?):\s+\[(.+?)\]")
        for line in raw_output.splitlines():
            m = found_pattern.search(line)
            if m:
                endpoint = m.group(1)
                params = [p.strip().strip("'\"") for p in m.group(2).split(",")]
                if params:
                    findings.append(Finding(
                        title=f"Parameters at {endpoint}: {', '.join(params[:5])}",
                        severity=Severity.INFO,
                        description=f"Arjun found parameters: {', '.join(params)}",
                        affected_asset=endpoint,
                        evidence=line,
                    ))
        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
