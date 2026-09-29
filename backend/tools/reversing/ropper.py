"""RopperTool — ropper -f {bin}. ROP chain builder."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.ropper")


class RopperTool(BaseTool):
    name = "ropper"
    category = ToolCategory.REVERSING
    requires = ["ropper"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        chain: str = params.get("chain", "")  # e.g. "execve"
        badchars: str = params.get("badchars", "")
        arch: str = params.get("arch", "")
        timeout: int = int(params.get("timeout", 120))

        cmd = ["ropper", "-f", binary, "--nocolor"]
        if chain:
            cmd += ["--chain", chain]
        if badchars:
            cmd += ["--badbytes", badchars]
        if arch:
            cmd += ["--arch", arch]

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
        chain_lines: list[str] = []
        in_chain = False

        for line in raw_output.splitlines():
            if "gadgets found" in line.lower():
                m = re.search(r"(\d+)\s+gadgets found", line, re.IGNORECASE)
                if m:
                    gadget_count = int(m.group(1))

            if "chain" in line.lower() or "rop chain" in line.lower():
                in_chain = True
            if in_chain and line.strip():
                chain_lines.append(line)
            if in_chain and line.strip() == "":
                in_chain = False

        if gadget_count > 0:
            findings.append(Finding(
                title=f"Ropper: {gadget_count} ROP Gadgets",
                severity=Severity.HIGH if gadget_count > 20 else Severity.MEDIUM,
                description=f"Ropper found {gadget_count} ROP gadgets in the binary.",
                evidence="\n".join(chain_lines[:30]) if chain_lines else raw_output[:500],
                remediation=(
                    "Compile with -fstack-protector-strong. "
                    "Enable PIE/ASLR. Consider shadow stacks (Intel CET)."
                ),
            ))

        if chain_lines:
            findings.append(Finding(
                title="ROP Chain Generated",
                severity=Severity.CRITICAL,
                description="Ropper successfully generated a ROP chain for the binary.",
                evidence="\n".join(chain_lines[:50]),
                remediation="Apply all mitigations: NX, ASLR, stack canaries, and CFI.",
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
