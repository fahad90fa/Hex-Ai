"""Dalfox — XSS vulnerability scanner."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.dalfox")


class DalfoxTool(BaseTool):
    name = "dalfox"
    category = ToolCategory.WEB
    requires = ["dalfox"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 600))
        blind_xss: str = params.get("blind_xss", "")
        custom_payload: str = params.get("custom_payload", "")
        skip_bav: bool = bool(params.get("skip_bav", False))

        cmd = [
            "dalfox", "url", target,
            "--silence",
            "--format", "json",
        ]
        if blind_xss:
            cmd += ["--blind", blind_xss]
        if custom_payload:
            cmd += ["--custom-payload", custom_payload]
        if skip_bav:
            cmd.append("--skip-bav")

        import os
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
        seen: set[str] = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                data = None

            if data and isinstance(data, dict):
                vuln_type = data.get("type", "XSS")
                param = data.get("param", "")
                url = data.get("data", data.get("poc", ""))
                payload = data.get("payload", "")
                evidence = data.get("evidence", "")

                key = f"xss:{param}:{payload[:30]}"
                if key in seen:
                    continue
                seen.add(key)

                findings.append(Finding(
                    title=f"XSS Vulnerability: Parameter '{param}'",
                    severity=Severity.HIGH,
                    description=(
                        f"Dalfox confirmed {vuln_type} in parameter '{param}'.\n"
                        f"Payload: {payload}"
                    ),
                    affected_asset=url or target if hasattr(self, "_target") else param,
                    evidence=evidence or payload,
                    remediation="Encode all user-controlled output. Implement strict Content-Security-Policy.",
                ))
            else:
                # Try plain text parsing
                xss_pattern = re.compile(r"\[V\]\s*(XSS|PoC)\s+(.+?)param=(\S+)", re.IGNORECASE)
                m = xss_pattern.search(line)
                if m:
                    vuln = m.group(1)
                    param = m.group(3)
                    key = f"xss_plain:{param}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            title=f"XSS Found: {param}",
                            severity=Severity.HIGH,
                            description=f"Dalfox found XSS vulnerability in parameter '{param}'",
                            affected_asset=param,
                            evidence=line,
                            remediation="Encode all user-controlled output. Use Content-Security-Policy.",
                        ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
