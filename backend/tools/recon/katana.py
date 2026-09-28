"""Katana — fast web crawler by ProjectDiscovery."""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlparse

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.katana")


class KatanaTool(BaseTool):
    name = "katana"
    category = ToolCategory.RECON
    requires = ["katana"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' must be a valid URL or domain.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"https://{target}"

        timeout: int = int(params.get("timeout", 300))
        depth: int = int(params.get("depth", 3))
        concurrency: int = int(params.get("concurrency", 10))
        js_crawl: bool = bool(params.get("js_crawl", True))
        output_fields: str = params.get("output_fields", "url")

        cmd = [
            "katana", "-u", target,
            "-d", str(depth),
            "-c", str(concurrency),
            "-silent",
            "-of", "url",
        ]
        if js_crawl:
            cmd.append("-js-crawl")

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
        form_pattern = re.compile(r"form|input|textarea|select", re.IGNORECASE)
        api_pattern = re.compile(r"/(api|v\d+|rest|graphql)(/|$|\?)", re.IGNORECASE)
        js_pattern = re.compile(r"\.js(\?|$)", re.IGNORECASE)

        urls: list[str] = [l.strip() for l in raw_output.splitlines() if l.strip().startswith("http")]

        if urls:
            findings.append(Finding(
                title=f"Katana Crawled {len(urls)} URLs",
                severity=Severity.INFO,
                description=f"Katana web crawler discovered {len(urls)} unique URLs.",
                affected_asset=urlparse(urls[0]).netloc if urls else "target",
                evidence=f"Sample: {', '.join(urls[:3])}",
            ))

        for url in urls:
            try:
                parsed = urlparse(url)
                asset = parsed.netloc
                path = parsed.path
            except Exception:
                asset = url
                path = url

            if api_pattern.search(path):
                key = f"api:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"API Endpoint Crawled: {path}",
                        severity=Severity.LOW,
                        description=f"API endpoint discovered via Katana crawling: {url}",
                        affected_asset=asset,
                        evidence=url,
                    ))

            if js_pattern.search(url):
                key = f"js:{url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"JavaScript File: {path}",
                        severity=Severity.INFO,
                        description=f"JavaScript file discovered (may contain secrets): {url}",
                        affected_asset=asset,
                        evidence=url,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        if not target:
            return False
        if target.startswith("http"):
            return True
        return self._is_valid_domain(target)
