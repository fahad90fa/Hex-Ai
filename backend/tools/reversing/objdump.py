"""ObjdumpTool — objdump -d -M intel {bin}. Disassemble, extract sections."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.objdump")


class ObjdumpTool(BaseTool):
    name = "objdump"
    category = ToolCategory.REVERSING
    requires = ["objdump"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        sections: list[str] = params.get("sections", [])
        disassemble: bool = bool(params.get("disassemble", True))
        timeout: int = int(params.get("timeout", 120))

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        all_output: list[str] = []

        # Section headers
        cmd_headers = ["objdump", "-h", binary]
        _, headers_out = await self._execute(cmd_headers, timeout=30)
        all_output.append("=== Section Headers ===\n" + headers_out)

        # Dynamic symbols
        cmd_sym = ["objdump", "-T", binary]
        _, sym_out = await self._execute(cmd_sym, timeout=30)
        all_output.append("=== Dynamic Symbols ===\n" + sym_out)

        # Disassembly
        if disassemble:
            if sections:
                for section in sections:
                    cmd_dis = ["objdump", "-d", "-M", "intel", "-j", section, binary]
                    _, dis_out = await self._execute(cmd_dis, timeout=60)
                    all_output.append(f"=== Disassembly: {section} ===\n" + dis_out)
            else:
                cmd_dis = ["objdump", "-d", "-M", "intel", binary]
                _, dis_out = await self._execute(cmd_dis, timeout=timeout, output_file=output_file)
                all_output.append("=== Disassembly ===\n" + dis_out[:50000])  # limit size

        raw = "\n\n".join(all_output)
        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []

        # Check for interesting sections
        writable_exec = re.search(r"RWX|rwx|\brwx\b", raw_output, re.IGNORECASE)
        if writable_exec:
            findings.append(Finding(
                title="Writable+Executable Section Detected",
                severity=Severity.HIGH,
                description="Binary has sections with both write and execute permissions (RWX).",
                evidence="RWX section found in section headers.",
                remediation="Remove W^X violations. Use proper section attributes.",
            ))

        # Look for dangerous calls in disassembly
        dangerous_calls = re.findall(
            r"call\s+[0-9a-f]+\s+<(gets|strcpy|strcat|sprintf|vsprintf|scanf|system|exec)>",
            raw_output, re.IGNORECASE
        )
        if dangerous_calls:
            unique_calls = list(set(dangerous_calls))
            findings.append(Finding(
                title=f"Dangerous Function Calls: {', '.join(unique_calls)}",
                severity=Severity.HIGH,
                description=f"Disassembly shows calls to unsafe functions: {', '.join(unique_calls)}",
                evidence=f"Functions: {', '.join(unique_calls)}",
                remediation="Replace dangerous functions with safe alternatives (fgets, strncpy, snprintf).",
            ))

        # Extract section info
        section_pattern = re.findall(r"(\.\w+)\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)", raw_output)
        if section_pattern:
            findings.append(Finding(
                title=f"Binary Sections: {len(section_pattern)} sections",
                severity=Severity.INFO,
                description=f"objdump identified {len(section_pattern)} sections in the binary.",
                evidence="\n".join(f"{s[0]}" for s in section_pattern[:15]),
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
