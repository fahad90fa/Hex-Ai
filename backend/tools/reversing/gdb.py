"""GDB — GNU Debugger wrapper."""
from __future__ import annotations

import logging
import os
import re
import tempfile

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.gdb")


class GdbTool(BaseTool):
    name = "gdb"
    category = ToolCategory.REVERSING
    requires = ["gdb"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        commands: list[str] = params.get("commands", [
            "info functions", "info variables", "checksec", "quit"
        ])
        args: str = params.get("args", "")
        timeout: int = int(params.get("timeout", 120))
        core_file: str = params.get("core_file", "")

        # Write GDB script
        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as tmp:
            for cmd in commands:
                tmp.write(cmd + "\n")
            gdb_script = tmp.name

        cmd = ["gdb", "-batch", "-x", gdb_script, binary]
        if args:
            cmd += ["--args"] + args.split()
        if core_file:
            cmd.append(core_file)

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        try:
            returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        finally:
            try:
                os.unlink(gdb_script)
            except OSError:
                pass

        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        # Checksec output from pwndbg/gef
        nx_pattern = re.compile(r"NX\s+[:-]\s+(enabled|disabled)", re.IGNORECASE)
        pie_pattern = re.compile(r"PIE\s+[:-]\s+(enabled|disabled)", re.IGNORECASE)
        stack_canary = re.compile(r"(?:Stack.)?Canary\s+[:-]\s+(found|not found|enabled|disabled)", re.IGNORECASE)
        relro_pattern = re.compile(r"RELRO\s+[:-]\s+(Full|Partial|No\s+RELRO)", re.IGNORECASE)

        for line in raw_output.splitlines():
            nx_m = nx_pattern.search(line)
            if nx_m:
                enabled = "enabled" in nx_m.group(1).lower()
                if not enabled:
                    findings.append(Finding(
                        title="NX (Non-Executable Stack) Disabled",
                        severity=Severity.HIGH,
                        description="The binary has the NX bit disabled — shellcode can be executed on the stack.",
                        affected_asset="binary",
                        evidence=line,
                        remediation="Compile with -z noexecstack. Use modern linker flags.",
                    ))

            pie_m = pie_pattern.search(line)
            if pie_m:
                enabled = "enabled" in pie_m.group(1).lower()
                if not enabled:
                    findings.append(Finding(
                        title="PIE (Position Independent Executable) Disabled",
                        severity=Severity.MEDIUM,
                        description="PIE is disabled — binary loads at fixed address, easier to exploit.",
                        affected_asset="binary",
                        evidence=line,
                        remediation="Compile with -fPIE -pie.",
                    ))

            sc_m = stack_canary.search(line)
            if sc_m:
                state = sc_m.group(1).lower()
                if "not found" in state or "disabled" in state:
                    findings.append(Finding(
                        title="Stack Canary Not Found",
                        severity=Severity.HIGH,
                        description="Stack canary is absent — stack buffer overflow exploitation is easier.",
                        affected_asset="binary",
                        evidence=line,
                        remediation="Compile with -fstack-protector-all.",
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        binary = params.get("binary", "")
        return bool(binary) and os.path.isfile(binary)
