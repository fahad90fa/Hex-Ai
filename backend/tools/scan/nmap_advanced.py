"""NmapAdvanced — comprehensive vuln-script and all-ports nmap scan."""
from __future__ import annotations

import logging
import os
import tempfile
import xml.etree.ElementTree as ET

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult
from backend.tools.scan.nmap import NmapTool

logger = logging.getLogger("nexus.tools.nmap_advanced")


class NmapAdvancedTool(NmapTool):
    """Full-featured nmap: all ports + vuln scripts + OS fingerprint."""
    name = "nmap_advanced"
    category = ToolCategory.SCAN
    requires = ["nmap"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        timeout: int = int(params.get("timeout", 7200))
        scripts: str = params.get("scripts", "vuln,exploit,auth,default")

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = [
            "nmap",
            "-sV", "--version-intensity", "9",
            "-O", "--osscan-guess",
            "-p-",
            f"--script={scripts}",
            "--script-args=unsafe=1",
            "-oX", xml_path,
            "-T4",
            "--open",
            target,
        ]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        findings: list[Finding] = []
        try:
            if os.path.isfile(xml_path) and os.path.getsize(xml_path) > 0:
                findings = self._parse_xml(xml_path)
        except Exception as exc:
            logger.error("Nmap advanced XML parse error: %s", exc)
            findings = self.parse(raw)
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

        return ToolResult(success=returncode == 0, output=raw, findings=findings)
