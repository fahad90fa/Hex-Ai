"""Ghidra — NSA reverse engineering tool (headless mode)."""
from __future__ import annotations

import logging
import os
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.ghidra")


class GhidraTool(BaseTool):
    name = "ghidra"
    category = ToolCategory.REVERSING
    requires = ["analyzeHeadless"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' path required.")

        binary: str = params["binary"]
        ghidra_home: str = params.get("ghidra_home", os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
        project_dir: str = params.get("project_dir", "/tmp/ghidra_projects")
        project_name: str = params.get("project_name", "nexus_analysis")
        post_script: str = params.get("post_script", "")
        timeout: int = int(params.get("timeout", 600))

        os.makedirs(project_dir, exist_ok=True)

        cmd = [
            f"{ghidra_home}/support/analyzeHeadless",
            project_dir,
            project_name,
            "-import", binary,
            "-overwrite",
            "-deleteProject",
        ]
        if post_script:
            cmd += ["-postScript", post_script]
        else:
            # Default: run all analyzers and export a basic report
            cmd += ["-postScript", "PrintTree.java"]

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

        # Ghidra headless output patterns
        import_pattern = re.compile(r"IMPORTING.*?:\s+(.+)")
        function_pattern = re.compile(r"Function:\s+(\S+)\s+at\s+(0x[0-9a-fA-F]+)")
        strings_pattern = re.compile(r"String found:\s+(.+)")
        error_pattern = re.compile(r"ERROR.*?analysis|WARNING.*?exception", re.IGNORECASE)

        binary_name = ""
        for line in raw_output.splitlines():
            line = line.strip()
            im = import_pattern.search(line)
            if im:
                binary_name = os.path.basename(im.group(1).strip())
                findings.append(Finding(
                    title=f"Binary Analysis: {binary_name}",
                    severity=Severity.INFO,
                    description=f"Ghidra imported and analysed binary: {binary_name}",
                    affected_asset=binary_name,
                    evidence=line,
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary")) and os.path.isfile(params["binary"])
