"""HashPump — hash length extension attack tool."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.hashpump")


class HashpumpTool(BaseTool):
    name = "hashpump"
    category = ToolCategory.AUTH
    requires = ["hashpump"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'signature', 'data', 'key_length', 'additional_data' required.")

        signature: str = params["signature"]
        data: str = params["data"]
        key_length: int = int(params["key_length"])
        additional_data: str = params["additional_data"]
        timeout: int = int(params.get("timeout", 60))

        cmd = [
            "hashpump",
            "-s", signature,
            "-d", data,
            "-k", str(key_length),
            "-a", additional_data,
        ]

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
        # HashPump outputs: New Signature: <hex>
        #                   New String: <data>
        sig_pattern = re.compile(r"New Signature:\s+([a-fA-F0-9]+)")
        str_pattern = re.compile(r"New String:\s+(.+)")

        new_sig = ""
        new_string = ""
        for line in raw_output.splitlines():
            sm = sig_pattern.search(line)
            if sm:
                new_sig = sm.group(1)
            stm = str_pattern.search(line)
            if stm:
                new_string = stm.group(1).strip()

        if new_sig and new_string:
            findings.append(Finding(
                title="Hash Length Extension Attack Successful",
                severity=Severity.HIGH,
                description=(
                    f"HashPump generated a valid extended signature.\n"
                    f"New Signature: {new_sig}\n"
                    f"New Data: {new_string[:100]}"
                ),
                affected_asset="HMAC/hash-based authentication",
                evidence=raw_output[:500],
                remediation=(
                    "Use HMAC (e.g., HMAC-SHA256) instead of a simple hash(key|message). "
                    "HMAC is not vulnerable to length extension attacks."
                ),
            ))
        elif raw_output.strip():
            findings.append(Finding(
                title="HashPump Output Generated",
                severity=Severity.MEDIUM,
                description="HashPump ran and produced output (check raw output for forged signatures).",
                affected_asset="hash-based auth",
                evidence=raw_output[:200],
            ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return (
            bool(params.get("signature"))
            and bool(params.get("data"))
            and bool(params.get("key_length"))
            and bool(params.get("additional_data"))
        )
