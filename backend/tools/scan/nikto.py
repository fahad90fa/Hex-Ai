"""Nikto — web server vulnerability scanner."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.nikto")


class NiktoTool(BaseTool):
    name = "nikto"
    category = ToolCategory.SCAN
    requires = ["nikto"]

    # OSVDB severity mapping
    CRITICAL_OSVDB = {"3268", "12184", "40478"}
    HIGH_OSVDB = {"877", "3092", "3093", "3268", "5290", "6694"}

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"http://{target}"

        timeout: int = int(params.get("timeout", 600))
        port: str = params.get("port", "")
        tuning: str = params.get("tuning", "123bde")  # selective checks

        cmd = ["nikto", "-h", target, "-Format", "txt", "-nointeractive"]
        if port:
            cmd += ["-p", str(port)]
        if tuning:
            cmd += ["-Tuning", tuning]

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

        # Nikto lines like: + OSVDB-3092: /admin/: This might be interesting...
        nikto_pattern = re.compile(
            r"\+\s+(?:OSVDB-(\d+):\s+)?(/[^\s:]*)?:?\s*(.+)"
        )
        # SSL/TLS issues
        ssl_pattern = re.compile(r"SSL|TLS|HTTPS|certificate", re.IGNORECASE)
        # Header issues
        header_pattern = re.compile(r"X-Frame-Options|X-XSS|Content-Security|HSTS|Clickjacking", re.IGNORECASE)
        # Default credentials
        cred_pattern = re.compile(r"default|credentials|password|username|admin", re.IGNORECASE)

        server_header = ""
        host = ""

        for line in raw_output.splitlines():
            line_stripped = line.strip()

            # Extract target host
            if "Target IP:" in line_stripped or "Target Host:" in line_stripped:
                parts = line_stripped.split(":", 1)
                if len(parts) > 1:
                    host = parts[1].strip()
                continue

            if "Server:" in line_stripped and ":" in line_stripped:
                server_header = line_stripped.split(":", 1)[1].strip()
                findings.append(Finding(
                    title=f"Web Server: {server_header}",
                    severity=Severity.INFO,
                    description=f"Web server header: {server_header}",
                    affected_asset=host or "target",
                    evidence=line_stripped,
                ))
                continue

            if not line_stripped.startswith("+"):
                continue

            m = nikto_pattern.match(line_stripped)
            if not m:
                continue

            osvdb_id = m.group(1) or ""
            path = m.group(2) or ""
            description = m.group(3).strip()

            key = f"{osvdb_id}:{path}:{description[:60]}"
            if key in seen:
                continue
            seen.add(key)

            # Determine severity
            if osvdb_id in self.CRITICAL_OSVDB:
                severity = Severity.CRITICAL
            elif osvdb_id in self.HIGH_OSVDB:
                severity = Severity.HIGH
            elif cred_pattern.search(description):
                severity = Severity.HIGH
            elif ssl_pattern.search(description) or header_pattern.search(description):
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            title = f"Nikto: {description[:80]}"
            if osvdb_id:
                title = f"OSVDB-{osvdb_id}: {description[:70]}"

            findings.append(Finding(
                title=title,
                severity=severity,
                description=description,
                affected_asset=f"{host}{path}" if path else host,
                evidence=line_stripped,
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
