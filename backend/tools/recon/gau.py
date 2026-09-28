"""GAU (getallurls) — fetch known URLs from multiple sources."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.gau")


class GauTool(BaseTool):
    name = "gau"
    category = ToolCategory.RECON
    requires = ["gau"]

    # Interesting URL patterns that warrant findings
    INTERESTING_PATTERNS = [
        (re.compile(r"\.(backup|bak|old|sql|db|tar|zip|gz|7z)(\?|$)", re.I), Severity.HIGH, "Backup/Database File Exposed"),
        (re.compile(r"/(admin|administrator|manage|management|dashboard|panel)(/|$|\?)", re.I), Severity.MEDIUM, "Admin Panel URL Discovered"),
        (re.compile(r"\.(env|config|conf|cfg|ini|yml|yaml|json|xml)(\?|$)", re.I), Severity.MEDIUM, "Configuration File URL"),
        (re.compile(r"/(api|v\d+|graphql|rest|swagger|openapi)(/|$|\?)", re.I), Severity.INFO, "API Endpoint Discovered"),
        (re.compile(r"/(login|signin|auth|authenticate|oauth|sso)(/|$|\?)", re.I), Severity.LOW, "Authentication Endpoint"),
        (re.compile(r"\.(log|logs|error|debug)(\?|$)", re.I), Severity.HIGH, "Log File URL Exposed"),
    ]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid domain.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        providers: str = params.get("providers", "wayback,otx,commoncrawl")

        cmd = ["gau", "--providers", providers, "--subs", target]

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
        seen: set[str] = set()
        url_set: set[str] = set()

        for line in raw_output.splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            url_set.add(url)

        # Summary finding for total URLs
        if url_set:
            findings.append(Finding(
                title=f"Discovered {len(url_set)} Historical URLs",
                severity=Severity.INFO,
                description=f"GAU found {len(url_set)} URLs across web archives and threat intelligence feeds.",
                affected_asset="web archive",
                evidence=f"Total URLs: {len(url_set)}",
            ))

        # Check for interesting patterns
        for url in url_set:
            for pattern, severity, title in self.INTERESTING_PATTERNS:
                if pattern.search(url):
                    key = f"{title}:{url}"
                    if key not in seen:
                        seen.add(key)
                        try:
                            parsed = urlparse(url)
                            asset = parsed.netloc or url
                        except Exception:
                            asset = url
                        findings.append(Finding(
                            title=f"{title}: {url[:120]}",
                            severity=severity,
                            description=f"GAU discovered potentially sensitive URL: {url}",
                            affected_asset=asset,
                            evidence=url,
                        ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and self._is_valid_domain(target)
