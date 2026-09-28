"""Hashcat — advanced password recovery tool."""
from __future__ import annotations

import logging
import re
from typing import Optional

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.hashcat")

# Common hash mode mappings
HASH_MODES = {
    "md5": "0",
    "sha1": "100",
    "sha256": "1400",
    "sha512": "1700",
    "ntlm": "1000",
    "net-ntlmv2": "5600",
    "bcrypt": "3200",
    "md5crypt": "500",
    "sha512crypt": "1800",
    "sha256crypt": "7400",
    "wordpress": "400",
    "wpa": "2500",
    "wpa2": "22000",
}


class HashcatTool(BaseTool):
    name = "hashcat"
    category = ToolCategory.AUTH
    requires = ["hashcat"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'hash_file' and 'hash_type' required.")

        hash_file: str = params["hash_file"]
        hash_type: str = params["hash_type"].lower()
        wordlist: str = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        rules: str = params.get("rules", "")
        attack_mode: int = int(params.get("attack_mode", 0))  # 0=dict, 3=brute
        mask: str = params.get("mask", "?a?a?a?a?a?a?a?a")
        timeout: int = int(params.get("timeout", 3600))

        hash_mode = HASH_MODES.get(hash_type, "0")

        cmd = [
            "hashcat",
            "-m", hash_mode,
            "-a", str(attack_mode),
            "--potfile-disable",
            "--status",
            "--status-timer=10",
            "--quiet",
            hash_file,
        ]
        if attack_mode == 0:
            cmd.append(wordlist)
            if rules:
                cmd += ["-r", rules]
        elif attack_mode == 3:
            cmd.append(mask)

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
        # Hashcat cracked: hash:plaintext
        cracked_pattern = re.compile(r"^([a-fA-F0-9\$\.\/:]+):(.+)$", re.MULTILINE)
        # Status line
        cracked_count_pattern = re.compile(r"Recovered\.*:\s+(\d+)/(\d+)", re.IGNORECASE)

        cracked_total = 0
        total = 0
        for m in cracked_count_pattern.finditer(raw_output):
            cracked_total = int(m.group(1))
            total = int(m.group(2))

        if cracked_total > 0:
            findings.append(Finding(
                title=f"Hashcat: {cracked_total}/{total} Hashes Cracked",
                severity=Severity.CRITICAL,
                description=f"Hashcat successfully cracked {cracked_total} out of {total} hashes.",
                affected_asset="password hashes",
                evidence=f"Recovered: {cracked_total}/{total}",
                remediation="Force password resets. Implement stronger hashing (bcrypt/Argon2) with salt.",
            ))

        for m in cracked_pattern.finditer(raw_output):
            hash_val = m.group(1)
            plaintext = m.group(2).strip()
            key = hash_val[:32]
            if key not in seen and len(hash_val) >= 8:
                seen.add(key)
                findings.append(Finding(
                    title=f"Password Cracked: {plaintext[:30]}",
                    severity=Severity.CRITICAL,
                    description=f"Hash {hash_val[:32]}... cracked to: {plaintext}",
                    affected_asset=hash_val[:32],
                    evidence=f"{hash_val[:32]}:{plaintext}",
                    remediation="Rotate compromised credentials. Use bcrypt/Argon2 for password storage.",
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("hash_file")) and bool(params.get("hash_type"))
