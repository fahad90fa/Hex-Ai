"""ChecksecTool — checksec --file={bin}. Parse RELRO/stack canary/NX/PIE/ASLR."""
from __future__ import annotations

import json
import logging
import os
import re
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.checksec")


class ChecksecTool(BaseTool):
    name = "checksec"
    category = ToolCategory.REVERSING
    requires = ["checksec"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        timeout: int = int(params.get("timeout", 30))

        cmd = ["checksec", "--file=" + binary, "--output=json"]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        # Fallback to text format if JSON fails
        if not raw.strip().startswith("{"):
            cmd_text = ["checksec", "--file=" + binary]
            returncode, raw = await self._execute(cmd_text, timeout=timeout)

        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []

        # Try JSON parse first
        try:
            # checksec JSON: {"path": {...}}
            start = raw_output.find("{")
            if start != -1:
                data = json.loads(raw_output[start:raw_output.rfind("}") + 1])
                for path, props in data.items():
                    missing_mitigations: list[str] = []

                    relro = str(props.get("relro", "")).lower()
                    if "no relro" in relro:
                        missing_mitigations.append("RELRO: No RELRO (full RELRO recommended)")
                    elif "partial" in relro:
                        missing_mitigations.append("RELRO: Partial RELRO (full RELRO recommended)")

                    canary = str(props.get("canary", "")).lower()
                    if "no" in canary or canary == "false":
                        missing_mitigations.append("Stack Canary: Missing")

                    nx = str(props.get("nx", "")).lower()
                    if "disabled" in nx or "no" in nx or nx == "false":
                        missing_mitigations.append("NX/DEP: Disabled (code execution on stack possible)")

                    pie = str(props.get("pie", "")).lower()
                    if "no pie" in pie or pie == "false":
                        missing_mitigations.append("PIE: Disabled (fixed base address)")

                    if missing_mitigations:
                        severity = Severity.HIGH if len(missing_mitigations) >= 3 else Severity.MEDIUM
                        findings.append(Finding(
                            title=f"Missing Security Mitigations: {path}",
                            severity=severity,
                            description=(
                                f"Binary {path} is missing {len(missing_mitigations)} security mitigations:\n"
                                + "\n".join(f"  - {m}" for m in missing_mitigations)
                            ),
                            affected_asset=path,
                            evidence="\n".join(missing_mitigations),
                            remediation=(
                                "Recompile with: -fstack-protector-strong -D_FORTIFY_SOURCE=2 "
                                "-pie -fPIE -Wl,-z,relro,-z,now"
                            ),
                        ))
                    else:
                        findings.append(Finding(
                            title=f"Binary Security Mitigations Present: {path}",
                            severity=Severity.INFO,
                            description="All major security mitigations are enabled.",
                            evidence=str(props),
                        ))
                return findings
        except (json.JSONDecodeError, AttributeError):
            pass

        # Text parsing fallback
        missing: list[str] = []
        if re.search(r"No RELRO", raw_output, re.IGNORECASE):
            missing.append("No RELRO")
        if re.search(r"No canary", raw_output, re.IGNORECASE):
            missing.append("No stack canary")
        if re.search(r"NX disabled", raw_output, re.IGNORECASE):
            missing.append("NX disabled")
        if re.search(r"No PIE", raw_output, re.IGNORECASE):
            missing.append("No PIE")

        if missing:
            findings.append(Finding(
                title=f"Missing Security Mitigations: {', '.join(missing)}",
                severity=Severity.HIGH if len(missing) >= 3 else Severity.MEDIUM,
                description="Binary is missing security hardening features.",
                evidence=raw_output[:500],
                remediation="Recompile with security hardening flags.",
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
