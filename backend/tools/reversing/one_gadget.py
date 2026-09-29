"""OneGadgetTool — one_gadget {libc}. Find one-shot RCE gadgets in libc."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.one_gadget")


class OneGadgetTool(BaseTool):
    name = "one_gadget"
    category = ToolCategory.REVERSING
    requires = ["one_gadget"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'libc' path required.")

        libc_path: str = params["libc"]
        level: int = int(params.get("level", 1))
        timeout: int = int(params.get("timeout", 60))

        cmd = ["one_gadget", libc_path, "--level", str(level)]

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
        gadgets: list[dict] = []

        current_gadget: dict | None = None
        for line in raw_output.splitlines():
            # one_gadget output: 0x45226 execve("/bin/sh", rsp+0x30, environ)
            addr_match = re.match(r"(0x[0-9a-f]+)\s+(.+)", line, re.IGNORECASE)
            if addr_match:
                if current_gadget:
                    gadgets.append(current_gadget)
                current_gadget = {
                    "address": addr_match.group(1),
                    "instruction": addr_match.group(2).strip(),
                    "constraints": [],
                }
            elif current_gadget and "constraints:" in line.lower():
                pass
            elif current_gadget and line.strip().startswith("["):
                current_gadget["constraints"].append(line.strip())

        if current_gadget:
            gadgets.append(current_gadget)

        if gadgets:
            gadget_details = "\n".join(
                f"{g['address']}: {g['instruction']} (constraints: {', '.join(g['constraints'][:2])})"
                for g in gadgets
            )
            findings.append(Finding(
                title=f"One-Gadget RCE: {len(gadgets)} Gadgets Found",
                severity=Severity.CRITICAL,
                description=(
                    f"one_gadget found {len(gadgets)} one-shot RCE gadgets in the libc. "
                    "These can be used to get a shell by controlling the appropriate registers/memory."
                ),
                evidence=gadget_details,
                remediation=(
                    "Use RELRO, PIE, and ASLR to make gadget addresses unpredictable. "
                    "Use seccomp to restrict execve system calls."
                ),
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("libc"))
