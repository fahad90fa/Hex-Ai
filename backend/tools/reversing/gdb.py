"""GdbTool — gdb with peda/gef, run binary with input, capture crash info."""
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
        input_data: str = params.get("input", "")
        commands: list[str] = params.get("commands", [])
        timeout: int = int(params.get("timeout", 60))
        cyclic_length: int = int(params.get("cyclic_length", 200))

        # Build GDB command file
        gdb_commands = [
            "set pagination off",
            "set confirm off",
        ]

        # Check for peda or gef
        if os.path.exists(os.path.expanduser("~/.gdbinit")):
            with open(os.path.expanduser("~/.gdbinit")) as f:
                gdbinit = f.read()
        else:
            gdbinit = ""

        gdb_commands.extend(commands or [
            f"run <<< $(python3 -c \"print('A' * {cyclic_length})\")",
            "bt",
            "info registers",
            "x/20x $esp",
            "quit",
        ])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as cf:
            cf.write("\n".join(gdb_commands))
            cmd_file = cf.name

        if input_data:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".input", delete=False) as inf:
                inf.write(input_data)
                input_file = inf.name
        else:
            input_file = None

        cmd = ["gdb", "-q", "-x", cmd_file, "--args", binary]
        if input_file:
            cmd = ["gdb", "-q", "-x", cmd_file, "--args", binary, f"< {input_file}"]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        try:
            returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
            findings = self.parse(raw)
        finally:
            os.unlink(cmd_file)
            if input_file:
                try:
                    os.unlink(input_file)
                except Exception:
                    pass

        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        lower = raw_output.lower()

        # Detect crashes / SIGSEGV
        if "sigsegv" in lower or "segmentation fault" in lower:
            # Try to extract offset if EIP contains cyclic pattern
            eip_match = re.search(r"eip\s*=\s*(0x[0-9a-f]+)", raw_output, re.IGNORECASE)
            rip_match = re.search(r"rip\s*=\s*(0x[0-9a-f]+)", raw_output, re.IGNORECASE)

            register_val = ""
            if eip_match:
                register_val = f"EIP = {eip_match.group(1)}"
            elif rip_match:
                register_val = f"RIP = {rip_match.group(1)}"

            findings.append(Finding(
                title="Buffer Overflow / Segmentation Fault Detected",
                severity=Severity.CRITICAL,
                description=(
                    "GDB detected a crash (SIGSEGV) during input fuzzing. "
                    "This may indicate an exploitable buffer overflow.\n"
                    + register_val
                ),
                evidence=raw_output[:2000],
                remediation=(
                    "Fix the buffer overflow: use safe string functions (strncpy, snprintf). "
                    "Enable stack canaries (-fstack-protector), ASLR, and NX."
                ),
            ))

        if "sigabrt" in lower:
            findings.append(Finding(
                title="SIGABRT / Heap Corruption Detected",
                severity=Severity.HIGH,
                description="Program aborted, possibly due to heap corruption or assert failure.",
                evidence=raw_output[:1000],
            ))

        if "double free" in lower or "heap overflow" in lower:
            findings.append(Finding(
                title="Heap Memory Corruption",
                severity=Severity.CRITICAL,
                description="Double free or heap overflow detected.",
                evidence=raw_output[:1000],
                remediation="Use memory-safe languages or sanitizers (AddressSanitizer).",
            ))

        # Extract backtrace
        bt_match = re.search(r"(#\d+.*)", raw_output)
        if bt_match and findings:
            findings[-1].evidence += f"\n\nBacktrace snippet:\n{bt_match.group(1)}"

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
