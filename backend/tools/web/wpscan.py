"""WPScan — WordPress vulnerability scanner."""
from __future__ import annotations

import json
import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.wpscan")


class WpscanTool(BaseTool):
    name = "wpscan"
    category = ToolCategory.WEB
    requires = ["wpscan"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        if not target.startswith("http"):
            target = f"https://{target}"

        timeout: int = int(params.get("timeout", 600))
        api_token: str = params.get("api_token", "")
        enumerate: str = params.get("enumerate", "vp,vt,u,cb,dbe")
        detection_mode: str = params.get("detection_mode", "mixed")

        cmd = [
            "wpscan",
            "--url", target,
            "--format", "json",
            "--no-banner",
            "--enumerate", enumerate,
            "--detection-mode", detection_mode,
        ]
        if api_token:
            cmd += ["--api-token", api_token]

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

        try:
            data = json.loads(raw_output)
        except Exception:
            return self._parse_text(raw_output)

        # WordPress version
        wp_version = data.get("version", {})
        if isinstance(wp_version, dict):
            ver = wp_version.get("number", "unknown")
            if ver and ver != "unknown":
                findings.append(Finding(
                    title=f"WordPress Version: {ver}",
                    severity=Severity.INFO,
                    description=f"WordPress version {ver} detected.",
                    affected_asset=data.get("target_url", ""),
                    evidence=f"WPScan version detection",
                ))
                # Check vulnerabilities in version
                for vuln in wp_version.get("vulnerabilities", []):
                    findings.extend(self._vuln_to_findings(vuln, f"WordPress Core {ver}"))

        # Plugins
        plugins = data.get("plugins", {})
        for plugin_slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            plugin_ver = plugin_data.get("version", {})
            if isinstance(plugin_ver, dict):
                plugin_ver = plugin_ver.get("number", "unknown")
            findings.append(Finding(
                title=f"WordPress Plugin: {plugin_slug} v{plugin_ver}",
                severity=Severity.INFO,
                description=f"Installed plugin: {plugin_slug} (version {plugin_ver})",
                affected_asset=data.get("target_url", "") + f"wp-content/plugins/{plugin_slug}/",
                evidence=f"WPScan plugin enumeration",
            ))
            for vuln in plugin_data.get("vulnerabilities", []):
                findings.extend(self._vuln_to_findings(vuln, f"Plugin: {plugin_slug}"))

        # Users
        users = data.get("users", {})
        for username, user_data in users.items():
            findings.append(Finding(
                title=f"WordPress User Enumerated: {username}",
                severity=Severity.MEDIUM,
                description=f"WordPress username enumerated: {username}",
                affected_asset=data.get("target_url", ""),
                evidence=json.dumps(user_data),
                remediation="Disable username enumeration. Use security plugins to block user discovery.",
            ))

        return findings

    def _vuln_to_findings(self, vuln: dict, component: str) -> list[Finding]:
        findings = []
        title = vuln.get("title", "Unknown Vulnerability")
        severity_str = vuln.get("cvss", {}).get("score", "")
        cvss = float(severity_str) if severity_str else None

        if cvss:
            if cvss >= 9.0:
                severity = Severity.CRITICAL
            elif cvss >= 7.0:
                severity = Severity.HIGH
            elif cvss >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
        else:
            severity = Severity.MEDIUM

        cve_ids = [r for r in vuln.get("references", {}).get("cve", [])]

        findings.append(Finding(
            title=f"[WPScan] {component}: {title}",
            severity=severity,
            description=f"Vulnerability in {component}: {title}",
            affected_asset=component,
            evidence=json.dumps(vuln.get("references", {})),
            cve_ids=cve_ids,
            cvss_score=cvss,
        ))
        return findings

    def _parse_text(self, raw: str) -> list[Finding]:
        findings = []
        vuln_pattern = re.compile(r"\[!\]\s+(.+)", re.IGNORECASE)
        for line in raw.splitlines():
            m = vuln_pattern.search(line)
            if m:
                findings.append(Finding(
                    title=f"WPScan: {m.group(1)[:80]}",
                    severity=Severity.MEDIUM,
                    description=m.group(1),
                    affected_asset="WordPress",
                    evidence=line,
                ))
        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target)
