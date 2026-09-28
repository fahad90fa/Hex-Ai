"""Subfinder — passive subdomain enumeration tool wrapper."""
from __future__ import annotations

import logging

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.subfinder")


class SubfinderTool(BaseTool):
    name = "subfinder"
    category = ToolCategory.RECON
    requires = ["subfinder"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid domain.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        silent: bool = bool(params.get("silent", True))
        resolvers: str = params.get("resolvers", "")

        cmd = ["subfinder", "-d", target, "-o", "-"]
        if silent:
            cmd.append("-silent")
        if resolvers:
            cmd += ["-r", resolvers]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            import os
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        success = returncode == 0

        findings = self.parse(raw)
        return ToolResult(success=success, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            subdomain = line.strip().lower()
            if not subdomain or subdomain.startswith("#"):
                continue
            if subdomain in seen:
                continue
            seen.add(subdomain)
            if not self._is_valid_domain(subdomain):
                continue
            findings.append(
                Finding(
                    title=f"Subdomain Discovered: {subdomain}",
                    severity=Severity.INFO,
                    description=f"Subfinder discovered subdomain: {subdomain}",
                    affected_asset=subdomain,
                    evidence=f"Returned by subfinder passive DNS enumeration",
                )
            )
        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and self._is_valid_domain(target)
