"""Hakrawler — fast web crawler for recon."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.hakrawler")


class HakrawlerTool(BaseTool):
    name = "hakrawler"
    category = ToolCategory.RECON
    requires = ["hakrawler"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"https://{target}"

        timeout: int = int(params.get("timeout", 300))
        depth: int = int(params.get("depth", 2))
        scope: str = params.get("scope", "subs")  # subs, strict, yolo

        cmd = ["hakrawler", "-d", str(depth), "-scope", scope, "-plain"]

        import os
        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        # hakrawler reads URLs from stdin
        process_input = target + "\n"

        import asyncio
        import json

        full_env = os.environ.copy()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=full_env,
        )
        output_lines: list[str] = []
        file_handle = None
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            file_handle = open(output_file, "w", buffering=1, errors="replace")

        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(input=process_input.encode()), timeout=timeout
            )
            raw = stdout_bytes.decode("utf-8", errors="replace")
            if file_handle:
                file_handle.write(raw)
        except asyncio.TimeoutError:
            proc.kill()
            raw = ""
        finally:
            if file_handle:
                file_handle.close()

        findings = self.parse(raw)
        return ToolResult(success=(proc.returncode == 0), output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        urls: list[str] = [l.strip() for l in raw_output.splitlines() if l.strip().startswith("http")]

        if urls:
            findings.append(Finding(
                title=f"Hakrawler: {len(urls)} URLs Discovered",
                severity=Severity.INFO,
                description=f"Hakrawler crawled and found {len(urls)} URLs.",
                affected_asset=urlparse(urls[0]).netloc if urls else "target",
                evidence=f"First 3: {', '.join(urls[:3])}",
            ))

        email_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
        for url in urls:
            emails = email_pattern.findall(url)
            for email in emails:
                if email not in seen:
                    seen.add(email)
                    findings.append(Finding(
                        title=f"Email Address Found: {email}",
                        severity=Severity.LOW,
                        description=f"Email address discovered in crawled URL: {email}",
                        affected_asset=email,
                        evidence=url,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
