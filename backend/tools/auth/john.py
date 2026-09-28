"""John the Ripper — password cracker."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.john")


class JohnTool(BaseTool):
    name = "john"
    category = ToolCategory.AUTH
    requires = ["john"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'hash_file' required.")

        hash_file: str = params["hash_file"]
        wordlist: str = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type: str = params.get("format", "")
        rules: str = params.get("rules", "")
        timeout: int = int(params.get("timeout", 3600))
        show: bool = bool(params.get("show", False))

        if show:
            cmd = ["john", "--show", hash_file]
        else:
            cmd = ["john", hash_file]
            if wordlist:
                cmd += ["--wordlist=" + wordlist]
            if format_type:
                cmd += ["--format=" + format_type]
            if rules:
                cmd += ["--rules=" + rules]

        import os
        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        # Run show to get cracked passwords
        if not show:
            _, show_output = await self._execute(["john", "--show", hash_file], timeout=30)
            raw += "\n[CRACKED]\n" + show_output

        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        # John --show output: user:password:...
        cracked_pattern = re.compile(r"^([^:]+):([^:]+):")
        # Summary: N password hashes cracked, M left
        summary_pattern = re.compile(r"(\d+) password hash(?:es)? cracked", re.IGNORECASE)

        in_cracked_section = False
        for line in raw_output.splitlines():
            if "[CRACKED]" in line:
                in_cracked_section = True
                continue

            if in_cracked_section:
                m = cracked_pattern.match(line.strip())
                if m:
                    user = m.group(1)
                    password = m.group(2)
                    key = f"john:{user}:{password[:20]}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            title=f"John Cracked: {user}:{password[:30]}",
                            severity=Severity.CRITICAL,
                            description=f"John the Ripper cracked password for '{user}': {password}",
                            affected_asset=user,
                            evidence=line,
                            remediation="Enforce strong password policy. Use bcrypt/Argon2.",
                        ))

            sm = summary_pattern.search(line)
            if sm:
                count = sm.group(1)
                if int(count) > 0 and f"summary:{count}" not in seen:
                    seen.add(f"summary:{count}")
                    findings.append(Finding(
                        title=f"John: {count} Passwords Cracked",
                        severity=Severity.CRITICAL,
                        description=f"John the Ripper cracked {count} password(s).",
                        affected_asset="password hashes",
                        evidence=line,
                        remediation="Rotate compromised credentials immediately.",
                    ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("hash_file"))
