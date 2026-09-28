"""API Fuzzer — REST API endpoint fuzzer using custom payloads."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Optional
from urllib.parse import urljoin

import httpx

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.api_fuzzer")

# Payloads that commonly trigger vulnerabilities
SQLI_PAYLOADS = ["'", "' OR '1'='1", "1; DROP TABLE--", "\" OR 1=1--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "'\"<img src=x onerror=alert(1)>"]
CMD_PAYLOADS = ["; id", "| id", "`id`", "$(id)", "&& id"]
LFI_PAYLOADS = ["../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc/passwd"]
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "{{config.items()}}"]


class ApiFuzzerTool(BaseTool):
    name = "api_fuzzer"
    category = ToolCategory.WEB
    requires = []

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' URL required.")

        target: str = params["target"]
        endpoints: list[str] = params.get("endpoints", ["/", "/api", "/api/v1", "/graphql"])
        methods: list[str] = params.get("methods", ["GET", "POST"])
        timeout: int = int(params.get("timeout", 300))
        auth_headers: dict = params.get("auth_headers", {})
        fuzz_types: list[str] = params.get("fuzz_types", ["sqli", "xss", "lfi", "ssti"])

        all_findings: list[Finding] = []
        output_lines: list[str] = []

        headers = {"Content-Type": "application/json"}
        headers.update(auth_headers)

        payload_map = {
            "sqli": SQLI_PAYLOADS,
            "xss": XSS_PAYLOADS,
            "cmd": CMD_PAYLOADS,
            "lfi": LFI_PAYLOADS,
            "ssti": SSTI_PAYLOADS,
        }

        async with httpx.AsyncClient(timeout=10, headers=headers, follow_redirects=True) as client:
            for endpoint in endpoints:
                url = urljoin(target, endpoint)
                for method in methods:
                    for fuzz_type in fuzz_types:
                        payloads = payload_map.get(fuzz_type, [])
                        for payload in payloads:
                            try:
                                if method == "GET":
                                    test_url = f"{url}?test={payload}"
                                    resp = await client.get(test_url)
                                else:
                                    resp = await client.post(url, json={"input": payload})

                                line = f"[{fuzz_type}] {method} {url} payload={payload[:30]} → {resp.status_code}"
                                output_lines.append(line)
                                await self._publish_line(line)

                                finding = self._analyze_response(
                                    fuzz_type, payload, url, method, resp
                                )
                                if finding:
                                    all_findings.append(finding)
                            except Exception as exc:
                                output_lines.append(f"Error fuzzing {url}: {exc}")

        raw_output = "\n".join(output_lines)
        return ToolResult(success=True, output=raw_output, findings=all_findings)

    def _analyze_response(
        self,
        fuzz_type: str,
        payload: str,
        url: str,
        method: str,
        resp: httpx.Response,
    ) -> Optional[Finding]:
        body = resp.text[:2000]
        status = resp.status_code

        if fuzz_type == "sqli":
            sql_errors = re.compile(
                r"(sql syntax|mysql_fetch|ORA-\d+|pg_query|unclosed quotation|"
                r"SQLite|Microsoft OLE DB|ODBC SQL|syntax error)", re.IGNORECASE
            )
            if sql_errors.search(body):
                return Finding(
                    title=f"SQL Injection Error: {url}",
                    severity=Severity.CRITICAL,
                    description=f"SQL error triggered by payload: {payload}",
                    affected_asset=url,
                    evidence=f"{method} {url} → {status}: {body[:200]}",
                    remediation="Use parameterised queries / ORMs.",
                )

        elif fuzz_type == "xss":
            if payload in body and status in (200, 201):
                return Finding(
                    title=f"Reflected XSS: {url}",
                    severity=Severity.HIGH,
                    description=f"XSS payload reflected unescaped in response: {payload}",
                    affected_asset=url,
                    evidence=f"{method} {url} → {status}: payload reflected",
                    remediation="Encode output. Implement CSP.",
                )

        elif fuzz_type == "lfi":
            lfi_indicators = re.compile(r"root:x:\d+:|bin:x:\d+:", re.IGNORECASE)
            if lfi_indicators.search(body):
                return Finding(
                    title=f"Local File Inclusion: {url}",
                    severity=Severity.CRITICAL,
                    description=f"LFI confirmed — /etc/passwd content in response",
                    affected_asset=url,
                    evidence=f"{method} {url} payload={payload}",
                    remediation="Whitelist file paths. Use realpath() validation.",
                )

        elif fuzz_type == "ssti":
            if "49" in body and "{{7*7}}" in payload:
                return Finding(
                    title=f"SSTI Detected: {url}",
                    severity=Severity.CRITICAL,
                    description=f"Server-Side Template Injection: {{{{7*7}}}} evaluated to 49",
                    affected_asset=url,
                    evidence=f"{method} {url} → {status}: 7*7=49 in response",
                    remediation="Sanitise template inputs. Use sandboxed template engines.",
                )

        return None

    def parse(self, raw_output: str) -> list[Finding]:
        return []

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and target.startswith("http")
