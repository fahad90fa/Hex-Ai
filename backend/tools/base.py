"""Base abstractions for all NEXUS tool wrappers."""
from __future__ import annotations

import asyncio
import enum
import json
import logging
import os
import re
import shutil
import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("nexus.tools")


# ─── Enumerations ──────────────────────────────────────────────────────────────

class ToolCategory(str, enum.Enum):
    RECON = "RECON"
    SCAN = "SCAN"
    WEB = "WEB"
    AUTH = "AUTH"
    EXPLOIT = "EXPLOIT"
    REVERSING = "REVERSING"
    NETWORK = "NETWORK"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ─── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    affected_asset: str = ""
    evidence: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    remediation: str = ""
    poc_path: str = ""

    def dedup_key(self, session_id: str) -> str:
        import hashlib
        raw = f"{session_id}:{self.title}:{self.affected_asset}"
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class ToolResult:
    success: bool
    output: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str = ""


# ─── Base Tool ─────────────────────────────────────────────────────────────────

class BaseTool(ABC):
    """Abstract base class every tool wrapper must subclass."""

    name: str = "base"
    category: ToolCategory = ToolCategory.RECON
    requires: list[str] = []

    # Internal state set by orchestrator before run()
    _job_id: Optional[str] = None
    _session_id: Optional[str] = None
    _redis = None  # aioredis.Redis instance

    def configure(self, job_id: str, session_id: str, redis=None) -> None:
        self._job_id = job_id
        self._session_id = session_id
        self._redis = redis

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    async def run(self, params: dict) -> ToolResult:
        """Execute the tool and return a ToolResult."""
        ...

    @abstractmethod
    def parse(self, raw_output: str) -> list[Finding]:
        """Parse raw tool stdout/stderr into a list of Finding objects."""
        ...

    @abstractmethod
    def validate_params(self, params: dict) -> bool:
        """Return True if params are valid for this tool."""
        ...

    # ── Optional streaming implementation ─────────────────────────────────────

    async def stream(self, params: dict) -> AsyncIterator[str]:
        """
        Async generator that yields stdout lines one-by-one.
        Default implementation calls run() and yields the output line-by-line.
        Override for true streaming.
        """
        result = await self.run(params)
        for line in result.output.splitlines():
            yield line

    # ── Binary availability check ──────────────────────────────────────────────

    def check_requirements(self) -> list[str]:
        """Return a list of missing required binaries."""
        missing = []
        for req in self.requires:
            if not shutil.which(req):
                missing.append(req)
        return missing

    # ── Internal subprocess execution ─────────────────────────────────────────

    async def _execute(
        self,
        cmd: list[str],
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        timeout: int = 3600,
        output_file: Optional[str] = None,
    ) -> tuple[int, str]:
        """
        Execute *cmd* as an asyncio subprocess.

        Stdout is streamed line-by-line to:
          - A Redis PUBLISH on channel job:{job_id}:output
          - The returned accumulated string
          - An optional output file

        Returns (returncode, accumulated_output).
        """
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
            env=full_env,
        )

        output_lines: list[str] = []
        file_handle = None
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            file_handle = open(output_file, "w", buffering=1, errors="replace")

        try:
            async def _read_lines():
                assert process.stdout is not None
                async for raw_line in process.stdout:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
                    output_lines.append(line)
                    if file_handle:
                        file_handle.write(line + "\n")
                    await self._publish_line(line)

            await asyncio.wait_for(_read_lines(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning("Tool %s timed out after %ds", self.name, timeout)
        finally:
            if file_handle:
                file_handle.close()

        returncode = process.returncode if process.returncode is not None else -1
        return returncode, "\n".join(output_lines)

    async def _publish_line(self, line: str) -> None:
        """Publish a single output line to Redis for live streaming."""
        if self._redis is None or self._job_id is None:
            return
        try:
            channel = f"job:{self._job_id}:output"
            payload = json.dumps({
                "type": "job.output",
                "job_id": self._job_id,
                "session_id": self._session_id,
                "line": line,
            })
            await self._redis.publish(channel, payload)
        except Exception as exc:
            logger.debug("Redis publish failed: %s", exc)

    # ── Utility helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _is_valid_domain(target: str) -> bool:
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, target))

    @staticmethod
    def _is_valid_ip(target: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_cidr(target: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def _severity_from_port(port: int, service: str) -> Severity:
        """Heuristic severity based on port/service type."""
        service_lower = service.lower()
        high_risk_services = {
            "telnet", "ftp", "rsh", "rlogin", "vnc", "rdp", "smb", "netbios"
        }
        medium_risk_services = {
            "ssh", "http", "https", "smtp", "pop3", "imap", "mysql",
            "mssql", "postgresql", "mongodb", "redis", "memcached"
        }
        if any(s in service_lower for s in high_risk_services):
            return Severity.HIGH
        if any(s in service_lower for s in medium_risk_services):
            return Severity.MEDIUM
        if port < 1024:
            return Severity.LOW
        return Severity.INFO
