"""Httpx (binary) — fast HTTP probing tool by ProjectDiscovery."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.httpx")


class HttpxTool(BaseTool):
    name = "httpx"
    category = ToolCategory.RECON
    requires = ["httpx"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'targets' list or 'target' string required.")

        targets = params.get("targets") or [params.get("target", "")]
        timeout: int = int(params.get("timeout", 300))
        threads: int = int(params.get("threads", 50))
        follow_redirects: bool = bool(params.get("follow_redirects", True))

        import os, tempfile
        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        cmd = [
            "httpx",
            "-l", targets_file,
            "-threads", str(threads),
            "-silent",
            "-json",
            "-title", "-tech-detect", "-status-code",
            "-content-length", "-web-server",
        ]
        if follow_redirects:
            cmd.append("-follow-redirects")

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        try:
            returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        finally:
            try:
                os.unlink(targets_file)
            except OSError:
                pass

        findings = self.parse(raw)
        return ToolResult(success=returncode == 0, output=raw, findings=findings)

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
                continue

            url = data.get("url", data.get("input", ""))
            status = data.get("status_code", 0)
            title = data.get("title", "")
            webserver = data.get("webserver", "")
            tech = data.get("tech", [])
            content_length = data.get("content_length", -1)

            if not url or url in seen:
                continue
            seen.add(url)

            # Classify severity based on response
            severity = Severity.INFO
            if status in (200, 201, 204):
                severity = Severity.INFO
            elif status == 403:
                severity = Severity.LOW
            elif status in (301, 302):
                severity = Severity.INFO

            finding = Finding(
                title=f"HTTP Service Active: {url}",
                severity=severity,
                description=(
                    f"HTTP probe results:\n"
                    f"  URL: {url}\n"
                    f"  Status: {status}\n"
                    f"  Title: {title}\n"
                    f"  Server: {webserver}\n"
                    f"  Technologies: {', '.join(tech) if tech else 'unknown'}\n"
                    f"  Content-Length: {content_length}"
                ),
                affected_asset=url,
                evidence=line,
            )
            findings.append(finding)

            # Flag interesting tech
            interesting_tech = {"wordpress", "drupal", "joomla", "laravel", "django", "rails", "struts"}
            for t in tech:
                if t.lower() in interesting_tech:
                    findings.append(Finding(
                        title=f"CMS/Framework Detected: {t} on {url}",
                        severity=Severity.LOW,
                        description=f"Detected {t} CMS/framework at {url}. Version-specific vulnerabilities may apply.",
                        affected_asset=url,
                        evidence=f"httpx tech-detect: {t}",
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("target") or params.get("targets"))
