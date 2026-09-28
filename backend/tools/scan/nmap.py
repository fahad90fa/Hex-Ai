"""Nmap — network scanner with XML output parsing."""
from __future__ import annotations

import logging
import os
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.nmap")

# Services that warrant higher severity ratings
HIGH_RISK_SERVICES = {"telnet", "ftp", "rsh", "rlogin", "exec", "login", "shell"}
MEDIUM_RISK_SERVICES = {
    "ssh", "http", "https", "smtp", "pop3", "imap", "ms-sql-s",
    "postgresql", "mysql", "mongodb", "redis", "memcached", "vnc",
    "rdp", "netbios-ssn", "microsoft-ds",
}


class NmapTool(BaseTool):
    name = "nmap"
    category = ToolCategory.SCAN
    requires = ["nmap"]

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'target' required.")

        target: str = params["target"]
        ports: str = params.get("ports", "1-65535")
        flags: list[str] = params.get("flags", [])
        os_detect: bool = bool(params.get("os_detect", False))
        service_version: bool = bool(params.get("service_version", True))
        script: Optional[str] = params.get("script")
        timeout: int = int(params.get("timeout", 3600))
        top_ports: Optional[int] = params.get("top_ports")

        # Use a temp file for XML output
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = ["nmap"]
        if service_version:
            cmd += ["-sV", "--version-intensity", "5"]
        if os_detect:
            cmd += ["-O", "--osscan-guess"]
        if script:
            cmd += [f"--script={script}"]
        if top_ports:
            cmd += ["--top-ports", str(top_ports)]
        elif ports:
            cmd += ["-p", ports]
        cmd += ["-oX", xml_path, "--open", "-T4"]
        cmd += flags
        cmd.append(target)

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)

        # Parse XML
        findings: list[Finding] = []
        try:
            if os.path.isfile(xml_path) and os.path.getsize(xml_path) > 0:
                findings = self._parse_xml(xml_path)
        except Exception as exc:
            logger.error("Nmap XML parse error: %s", exc)
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

        if not findings:
            # Fallback: parse plain text
            findings = self.parse(raw)

        return ToolResult(success=returncode == 0, output=raw, findings=findings)

    def _parse_xml(self, xml_path: str) -> list[Finding]:
        """Parse nmap XML output and produce findings."""
        findings: list[Finding] = []
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            # Get host address
            host_addr = ""
            hostnames: list[str] = []
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    host_addr = addr.get("addr", "")
            for hn_elem in host.findall(".//hostname"):
                hostnames.append(hn_elem.get("name", ""))

            display_host = hostnames[0] if hostnames else host_addr

            # OS detection
            for osmatch in host.findall(".//osmatch"):
                os_name = osmatch.get("name", "Unknown")
                os_accuracy = osmatch.get("accuracy", "0")
                findings.append(Finding(
                    title=f"OS Detected: {os_name}",
                    severity=Severity.INFO,
                    description=f"Nmap OS detection: {os_name} (accuracy {os_accuracy}%)",
                    affected_asset=display_host,
                    evidence=f"Nmap OS fingerprinting on {host_addr}",
                ))

            # Port/service findings
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                protocol = port_elem.get("protocol", "tcp")
                portid = port_elem.get("portid", "0")
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = "unknown"
                product = ""
                version = ""
                extra_info = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extra_info = service_elem.get("extrainfo", "")

                service_display = " ".join(filter(None, [product, version, extra_info])).strip()
                severity = self._classify_severity(int(portid), service_name)

                finding = Finding(
                    title=f"Open Port {portid}/{protocol}: {service_name}",
                    severity=severity,
                    description=(
                        f"Nmap detected open port {portid}/{protocol} on {display_host}.\n"
                        f"Service: {service_name}"
                        + (f" ({service_display})" if service_display else "")
                    ),
                    affected_asset=f"{display_host}:{portid}/{protocol}",
                    evidence=f"nmap -sV -p {portid} {host_addr} → {service_name} {service_display}",
                )

                # Script output
                scripts_output: list[str] = []
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    scripts_output.append(f"[{script_id}] {script_output}")
                    # Check for CVE references in script output
                    import re
                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", script_output)
                    finding.cve_ids.extend(cve_matches)
                    if cve_matches:
                        finding.severity = Severity.HIGH

                if scripts_output:
                    finding.evidence += "\nScript output:\n" + "\n".join(scripts_output)

                findings.append(finding)

        return findings

    def parse(self, raw_output: str) -> list[Finding]:
        """Fallback plain-text parser when XML is unavailable."""
        import re
        findings: list[Finding] = []
        # Match lines like: 80/tcp   open  http    Apache httpd 2.4.41
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?"
        )
        # Try to find host from line: Nmap scan report for <host>
        host = "unknown"
        host_pattern = re.compile(r"Nmap scan report for (.+)")
        for line in raw_output.splitlines():
            hm = host_pattern.search(line)
            if hm:
                host = hm.group(1).strip()
                continue
            pm = port_pattern.match(line.strip())
            if pm:
                port = pm.group(1)
                proto = pm.group(2)
                service = pm.group(3)
                extra = pm.group(4) or ""
                severity = self._classify_severity(int(port), service)
                findings.append(Finding(
                    title=f"Open Port {port}/{proto}: {service}",
                    severity=severity,
                    description=f"Open port {port}/{proto} running {service} {extra}".strip(),
                    affected_asset=f"{host}:{port}/{proto}",
                    evidence=line.strip(),
                ))
        return findings

    def _classify_severity(self, port: int, service: str) -> Severity:
        s = service.lower()
        if any(r in s for r in HIGH_RISK_SERVICES):
            return Severity.HIGH
        if any(r in s for r in MEDIUM_RISK_SERVICES):
            return Severity.MEDIUM
        if port < 1024:
            return Severity.LOW
        return Severity.INFO

    def validate_params(self, params: dict) -> bool:
        target = params.get("target", "")
        return bool(target) and (
            self._is_valid_domain(target)
            or self._is_valid_ip(target)
            or self._is_valid_cidr(target)
        )
