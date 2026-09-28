"""RopgadgetTool — ROPgadget --binary {bin}. Extract ROP gadgets."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.ropgadget")


class RopgadgetTool(BaseTool):
    name = "ropgadget"
    category = ToolCategory.REVERSING
    requires = ["ROPgadget"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        filter_str: str = params.get("filter", "")
        rop_chain: bool = bool(params.get("rop_chain", False))
        timeout: int = int(params.get("timeout", 120))

        cmd = ["ROPgadget", "--binary", binary]
        if filter_str:
            cmd += ["--filter", filter_str]
        if rop_chain:
            cmd += ["--rop"]

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

        gadget_count = 0
        interesting_gadgets: list[str] = []

        for line in raw_output.splitlines():
            # ROPgadget output: 0x0000000000401234 : pop rdi ; ret
            m = re.match(r"(0x[0-9a-f]+)\s+:\s+(.+)", line, re.IGNORECASE)
            if m:
                gadget_count += 1
                gadget_str = m.group(2).strip()

                # Flag interesting gadgets
                if any(k in gadget_str for k in ["pop rdi", "pop rsi", "pop rdx", "pop rax",
                                                   "syscall", "int 0x80", "jmp esp", "call esp"]):
                    interesting_gadgets.append(f"{m.group(1)}: {gadget_str}")

        # Count line
        count_match = re.search(r"Unique gadgets found:\s*(\d+)", raw_output)
        if count_match:
            gadget_count = int(count_match.group(1))

        if gadget_count > 0:
            severity = Severity.HIGH if gadget_count > 50 else Severity.MEDIUM
            findings.append(Finding(
                title=f"ROP Gadgets Found: {gadget_count}",
                severity=severity,
                description=(
                    f"ROPgadget found {gadget_count} unique ROP gadgets. "
                    f"{len(interesting_gadgets)} are useful for ROP chain construction."
                ),
                evidence="\n".join(interesting_gadgets[:20]),
                remediation=(
                    "Enable NX/DEP to prevent direct shellcode execution. "
                    "Use CFI (Control Flow Integrity) to mitigate ROP attacks."
                ),
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
