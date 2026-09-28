"""Waybackurls — fetch all URLs from the Wayback Machine."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.waybackurls")


class WaybackurlsTool(BaseTool):
    name = "waybackurls"
    category = ToolCategory.RECON
    requires = ["waybackurls"]

    SENSITIVE_EXTENSIONS = re.compile(
        r"\.(bak|backup|sql|db|sqlite|mdb|old|tar|zip|gz|tgz|7z|rar|"
        r"env|config|cfg|conf|ini|log|logs|key|pem|crt|cert|p12|pfx)(\?|$)",
        re.IGNORECASE,
    )
    API_PATTERN = re.compile(r"/(api|rest|v\d+|graphql|ws)(/|$|\?)", re.IGNORECASE)
    PARAM_PATTERN = re.compile(r"\?.*=")

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid domain.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))

        cmd = ["waybackurls", target]

        import os
        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=returncode == 0, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        urls: list[str] = [l.strip() for l in raw_output.splitlines() if l.strip().startswith("http")]
        seen: set[str] = set()

        if urls:
            findings.append(Finding(
                title=f"Wayback Machine: {len(urls)} URLs Discovered",
                severity=Severity.INFO,
                description=f"Waybackurls retrieved {len(urls)} historical URLs from the Wayback Machine.",
                affected_asset="web archive",
                evidence=f"Sample URLs: {', '.join(urls[:5])}",
            ))

        for url in urls:
            try:
                parsed = urlparse(url)
                asset = parsed.netloc
            except Exception:
                asset = url

            if self.SENSITIVE_EXTENSIONS.search(url):
                key = f"sensitive:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"Sensitive File in Archive: {url[:100]}",
                        severity=Severity.HIGH,
                        description=f"Wayback Machine archived a potentially sensitive file: {url}",
                        affected_asset=asset,
                        evidence=url,
                        remediation="Verify if this file is still accessible and remove if so.",
                    ))

            if self.PARAM_PATTERN.search(url):
                key = f"param:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"URL with Parameters: {url[:100]}",
                        severity=Severity.INFO,
                        description=f"URL with query parameters found in archive: {url}",
                        affected_asset=asset,
                        evidence=url,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and self._is_valid_domain(target)
