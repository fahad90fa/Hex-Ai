"""BinwalkTool — binwalk -e {file}. Extract embedded files/firmware."""
from __future__ import annotations

import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.binwalk")


class BinwalkTool(BaseTool):
    name = "binwalk"
    category = ToolCategory.REVERSING
    requires = ["binwalk"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'file' required.")

        file_path: str = params["file"]
        extract: bool = bool(params.get("extract", True))
        recursive: bool = bool(params.get("recursive", False))
        timeout: int = int(params.get("timeout", 300))
        output_dir: str = params.get("output_dir", "")

        cmd = ["binwalk"]
        if extract:
            cmd.append("-e")
        if recursive:
            cmd.append("-r")
        if output_dir:
            cmd += ["-C", output_dir]
        cmd.append(file_path)

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
        extracted_items: list[str] = []
        interesting: list[str] = []

        for line in raw_output.splitlines():
            # binwalk output: DECIMAL   HEX   DESCRIPTION
            m = re.match(r"(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)", line)
            if m:
                decimal = m.group(1)
                offset = m.group(2)
                description = m.group(3).strip()
                extracted_items.append(f"{offset}: {description}")

                desc_lower = description.lower()
                if any(k in desc_lower for k in ["linux", "squashfs", "cramfs", "jffs2", "ext2", "filesystem"]):
                    interesting.append(f"Filesystem: {description}")
                elif any(k in desc_lower for k in ["private key", "certificate", "ssh", "ssl", "password"]):
                    interesting.append(f"Credential material: {description}")
                    findings.append(Finding(
                        title=f"Credential Material in Firmware: {description}",
                        severity=Severity.CRITICAL,
                        description=f"Binwalk found potential credential material at offset {offset}: {description}",
                        evidence=line,
                        remediation="Remove hardcoded credentials from firmware. Use secure provisioning.",
                    ))
                elif any(k in desc_lower for k in ["gzip", "zlib", "zip", "tar", "cpio"]):
                    interesting.append(f"Archive: {description}")

        if extracted_items:
            severity = Severity.HIGH if interesting else Severity.INFO
            findings.append(Finding(
                title=f"Firmware Analysis: {len(extracted_items)} Embedded Components",
                severity=severity,
                description=(
                    f"Binwalk identified {len(extracted_items)} embedded components.\n"
                    f"Interesting: {len(interesting)} items."
                ),
                evidence="\n".join(extracted_items[:20]),
                remediation="Review extracted components for sensitive data and vulnerabilities.",
            ))

        if "extracted" in raw_output.lower() and "file" in raw_output.lower():
            findings.append(Finding(
                title="Files Extracted from Binary",
                severity=Severity.INFO,
                description="Binwalk successfully extracted embedded files for further analysis.",
                evidence=raw_output[-500:],
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("file"))
