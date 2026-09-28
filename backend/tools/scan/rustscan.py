"""RustScan — ultra-fast port scanner."""
from __future__ import annotations

import logging
import re

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.rustscan")


class RustscanTool(BaseTool):
    name = "rustscan"
    category = ToolCategory.SCAN
    requires = ["rustscan"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 300))
        batch_size: int = int(params.get("batch_size", 65535))
        ulimit: int = int(params.get("ulimit", 5000))
        ports: str = params.get("ports", "")

        cmd = [
            "rustscan",
            "-a", target,
            "--ulimit", str(ulimit),
            "-b", str(batch_size),
            "--no-nmap",
            "--timeout", str(timeout * 1000),
        ]
        if ports:
            cmd += ["-p", ports]

        import os
        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout + 60, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=returncode == 0, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        # RustScan outputs: Open <ip>:<port>
        open_pattern = re.compile(r"Open\s+(\S+):(\d+)")
        # Also: [~] The open ports are: 22,80,443
        ports_list_pattern = re.compile(r"open ports are:\s+([\d,\s]+)", re.IGNORECASE)

        host = "unknown"
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            m = open_pattern.search(line)
            if m:
                ip = m.group(1)
                port = m.group(2)
                host = ip
                key = f"{ip}:{port}"
                if key not in seen:
                    seen.add(key)
                    severity = self._severity_from_port(int(port), "")
                    findings.append(Finding(
                        title=f"Open Port {port}/tcp on {ip}",
                        severity=severity,
                        description=f"RustScan confirmed open TCP port {port} on {ip}",
                        affected_asset=f"{ip}:{port}",
                        evidence=line,
                    ))

            pl = ports_list_pattern.search(line)
            if pl:
                ports_str = pl.group(1)
                for p in re.findall(r"\d+", ports_str):
                    key = f"{host}:{p}"
                    if key not in seen:
                        seen.add(key)
                        severity = self._severity_from_port(int(p), "")
                        findings.append(Finding(
                            title=f"Open Port {p}/tcp on {host}",
                            severity=severity,
                            description=f"RustScan found open port {p} on {host}",
                            affected_asset=f"{host}:{p}",
                            evidence=line,
                        ))

        return findings

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (
            self._is_valid_ip(target)
            or self._is_valid_domain(target)
            or self._is_valid_cidr(target)
        )
