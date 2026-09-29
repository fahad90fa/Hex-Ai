"""Radare2Tool — r2 -q -c commands binary. Extract symbols, strings, functions."""
from __future__ import annotations

import json
import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.radare2")


class Radare2Tool(BaseTool):
    name = "radare2"
    category = ToolCategory.REVERSING
    requires = ["r2"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        commands: list[str] = params.get("commands", [])
        timeout: int = int(params.get("timeout", 120))

        # Default commands for analysis
        if not commands:
            commands = [
                "aaa",            # full analysis
                "aflj",           # list functions as JSON
                "izj",            # list strings as JSON
                "ilj",            # list imports as JSON
                "isj",            # list symbols as JSON
            ]

        # Build r2 batch command
        r2_cmd_str = ";".join(commands)
        cmd = ["r2", "-q", "-c", r2_cmd_str, binary]

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

        # Parse each JSON line from r2 output
        lines = raw_output.splitlines()
        for line in lines:
            line = line.strip()
            if not line.startswith("[") and not line.startswith("{"):
                continue
            try:
                data = json.loads(line)

                # Functions
                if isinstance(data, list) and data and "name" in data[0] and "offset" in data[0]:
                    func_names = [f["name"] for f in data[:20]]
                    findings.append(Finding(
                        title=f"Binary Functions Extracted: {len(data)} found",
                        severity=Severity.INFO,
                        description=f"Radare2 extracted {len(data)} functions.",
                        evidence="\n".join(func_names[:20]),
                    ))

                    # Look for interesting function names
                    for func in data:
                        name = func.get("name", "").lower()
                        if any(k in name for k in ["gets", "strcpy", "strcat", "sprintf", "scanf"]):
                            findings.append(Finding(
                                title=f"Dangerous Function: {func['name']}",
                                severity=Severity.HIGH,
                                description=f"Use of unsafe function {func['name']} at {hex(func.get('offset', 0))}",
                                evidence=f"Function: {func['name']}, Offset: {hex(func.get('offset', 0))}",
                                remediation=f"Replace {func['name']} with a bounds-checked alternative.",
                            ))

                # Strings
                if isinstance(data, list) and data and "string" in (data[0] if data else {}):
                    interesting = [
                        s["string"] for s in data
                        if any(k in s.get("string", "").lower() for k in [
                            "password", "secret", "token", "key", "flag{", "http://", "admin",
                        ])
                    ]
                    if interesting:
                        findings.append(Finding(
                            title="Interesting Strings Found in Binary",
                            severity=Severity.MEDIUM,
                            description=f"Found {len(interesting)} interesting strings.",
                            evidence="\n".join(interesting[:20]),
                            remediation="Remove hardcoded secrets from binary.",
                        ))

            except (json.JSONDecodeError, KeyError, IndexError):
                continue

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
