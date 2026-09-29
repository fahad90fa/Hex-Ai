"""SQLMap — automatic SQL injection and database takeover tool."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.sqlmap")


class SqlmapTool(BaseTool):
    name = "sqlmap"
    category = ToolCategory.WEB
    requires = ["sqlmap"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 1800))
        level: int = int(params.get("level", 2))
        risk: int = int(params.get("risk", 1))
        dbms: str = params.get("dbms", "")
        forms: bool = bool(params.get("forms", False))
        crawl: int = int(params.get("crawl", 0))
        data: str = params.get("data", "")
        extra_params: list[str] = params.get("extra_params", [])

        cmd = [
            "sqlmap",
            "-u", target,
            "--level", str(level),
            "--risk", str(risk),
            "--batch",
            "--output-dir", "/tmp/sqlmap_output",
            "--answers=quit=N,crack=N",
        ]
        if dbms:
            cmd += ["--dbms", dbms]
        if forms:
            cmd.append("--forms")
        if crawl > 0:
            cmd += ["--crawl", str(crawl)]
        if data:
            cmd += ["--data", data]
        cmd.extend(extra_params)

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

        # SQLMap injection found
        injectable_pattern = re.compile(
            r"Parameter:\s+(.+?)\s+\((.+?)\).*?Type:\s+(.+)", re.DOTALL
        )
        # Simpler per-line patterns
        vuln_param_pattern = re.compile(r"Parameter '(.+?)' is vulnerable")
        injectable_line_pattern = re.compile(r"(GET|POST|Cookie|Header)\s+parameter\s+'(.+?)'\s+is\s+vulnerable")
        dbms_pattern = re.compile(r"back-end DBMS:\s+(.+)", re.IGNORECASE)
        dump_pattern = re.compile(r"Database:\s+(.+)|Table:\s+(.+)|dumped to", re.IGNORECASE)
        rce_pattern = re.compile(r"os-shell|os-pwn|--os-cmd", re.IGNORECASE)

        dbms_found = ""
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            dbms_m = dbms_pattern.search(line)
            if dbms_m:
                dbms_found = dbms_m.group(1).strip()
                continue

            vp = vuln_param_pattern.search(line)
            if vp:
                param = vp.group(1)
                key = f"sqli:{param}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"SQL Injection: Parameter '{param}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"SQLMap confirmed SQL injection in parameter '{param}'.\n"
                            f"DBMS: {dbms_found or 'Unknown'}"
                        ),
                        affected_asset=param,
                        evidence=line,
                        cve_ids=[],
                        remediation="Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                    ))
                continue

            il = injectable_line_pattern.search(line)
            if il:
                method = il.group(1)
                param = il.group(2)
                key = f"sqli:{method}:{param}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"SQL Injection: {method} '{param}'",
                        severity=Severity.CRITICAL,
                        description=f"SQLMap found {method} parameter '{param}' vulnerable to SQL injection.",
                        affected_asset=param,
                        evidence=line,
                        remediation="Use parameterised queries. Validate and sanitise all input.",
                    ))

            if rce_pattern.search(line):
                key = "sqli:rce"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title="SQL Injection → Remote Code Execution",
                        severity=Severity.CRITICAL,
                        description="SQLMap achieved OS command execution via SQL injection.",
                        affected_asset="OS",
                        evidence=line,
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
