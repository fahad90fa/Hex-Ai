"""Masscan — internet-scale port scanner."""
from __future__ import annotations

import logging
import os
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.masscan")


class MasscanTool(BaseTool):
    name = "masscan"
    category = ToolCategory.SCAN
    requires = ["masscan"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required (IP or CIDR).")

        target: str = params["target"]
        ports: str = params.get("ports", "0-65535")
        rate: int = int(params.get("rate", 1000))
        timeout: int = int(params.get("timeout", 600))

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            output_path = tmp.name

        cmd = [
            "masscan",
            target,
            "-p", ports,
            "--rate", str(rate),
            "-oL", output_path,
            "--wait", "3",
        ]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        # Parse the list output file
        findings: list[Finding] = []
        try:
            if os.path.isfile(output_path):
                with open(output_path) as f:
                    list_output = f.read()
                findings = self.parse(list_output)
                os.unlink(output_path)
        except Exception:
            findings = self.parse(raw)

        return ToolResult(success=returncode == 0, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        # Masscan list format: open tcp 80 192.168.1.1 1234567890
        open_pattern = re.compile(r"^open\s+(\w+)\s+(\d+)\s+(\S+)", re.MULTILINE)

        for m in open_pattern.finditer(raw_output):
            proto = m.group(1)
            port = m.group(2)
            ip = m.group(3)
            key = f"{ip}:{port}/{proto}"
            if key in seen:
                continue
            seen.add(key)
            severity = self._severity_from_port(int(port), "")
            findings.append(Finding(
                title=f"Open Port {port}/{proto} on {ip}",
                severity=severity,
                description=f"Masscan detected open {proto} port {port} on {ip}",
                affected_asset=f"{ip}:{port}",
                evidence=m.group(0),
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (self._is_valid_ip(target) or self._is_valid_cidr(target))
