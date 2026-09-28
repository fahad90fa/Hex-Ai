"""AngrTool — symbolic execution to find paths to target addresses."""
from __future__ import annotations

import logging
import os
import tempfile
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.angr")

_ANGR_SCRIPT_TEMPLATE = """#!/usr/bin/env python3
import angr
import sys

binary = {binary!r}
find_addr = {find_addr}
avoid_addrs = {avoid_addrs}

try:
    project = angr.Project(binary, auto_load_libs=False)
    state = project.factory.entry_state()
    simgr = project.factory.simgr(state)

    find_args = [find_addr] if find_addr else []
    avoid_args = avoid_addrs if avoid_addrs else []

    if find_args:
        simgr.explore(find=find_args, avoid=avoid_args, num_find=3)
    else:
        simgr.run(n=1000)

    print(f"FOUND: {{len(simgr.found)}} paths")
    for i, state in enumerate(simgr.found[:3]):
        stdin_val = state.posix.dumps(0)
        print(f"PATH_{{i}}: {{stdin_val!r}}")

    if simgr.deadended:
        print(f"DEADENDED: {{len(simgr.deadended)}} states")
    if simgr.errored:
        print(f"ERRORED: {{len(simgr.errored)}} states")
        for e in simgr.errored[:2]:
            print(f"  Error: {{e.error}}")

except Exception as e:
    print(f"ANGR_ERROR: {{e}}")
    sys.exit(1)
"""


class AngrTool(BaseTool):
    name = "angr"
    category = ToolCategory.REVERSING
    requires = ["python3"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        find_addr = params.get("find_addr", None)
        avoid_addrs: list = params.get("avoid_addrs", [])
        timeout: int = int(params.get("timeout", 300))

        # Convert hex strings to ints
        if isinstance(find_addr, str) and find_addr.startswith("0x"):
            find_addr = int(find_addr, 16)
        if avoid_addrs:
            avoid_addrs = [int(a, 16) if isinstance(a, str) and a.startswith("0x") else int(a) for a in avoid_addrs]

        script_content = _ANGR_SCRIPT_TEMPLATE.format(
            binary=binary,
            find_addr=repr(find_addr),
            avoid_addrs=avoid_addrs,
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
            tf.write(script_content)
            script_path = tf.name

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        try:
            returncode, raw = await self._execute(
                ["python3", script_path], timeout=timeout, output_file=output_file
            )
            findings = self.parse(raw)
        finally:
            os.unlink(script_path)

        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []

        if "ANGR_ERROR:" in raw_output:
            return findings

        # Count found paths
        import re
        found_match = re.search(r"FOUND:\s*(\d+)", raw_output)
        if found_match:
            count = int(found_match.group(1))
            if count > 0:
                # Extract input values
                path_inputs = re.findall(r"PATH_\d+:\s*(.+)", raw_output)
                findings.append(Finding(
                    title=f"Symbolic Execution: {count} Paths Found",
                    severity=Severity.HIGH,
                    description=(
                        f"Angr found {count} execution paths reaching the target address.\n"
                        "These represent inputs that reach the target code."
                    ),
                    evidence="\n".join(path_inputs[:5]),
                    remediation="Review the identified code paths for security implications.",
                ))

        if "DEADENDED:" in raw_output:
            findings.append(Finding(
                title="Symbolic Execution Complete",
                severity=Severity.INFO,
                description="Angr explored the binary and reached dead-end states.",
                evidence=raw_output[:500],
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
