"""GhidraTool — headless Ghidra analysis, extract functions/strings/imports."""
from __future__ import annotations

import logging
import os
import re
import tempfile
from backend.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

logger = logging.getLogger("nexus.tools.ghidra")

_GHIDRA_SCRIPT = """# Ghidra headless analysis script
# Extracts functions, strings, and imports
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

monitor = ConsoleTaskMonitor()
program = currentProgram
listing = program.getListing()

# Get functions
functions = []
for func in listing.getFunctions(True):
    functions.append({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
    })

# Get defined strings
strings = []
for defined_data in listing.getDefinedData(True):
    if defined_data.hasStringValue():
        s = str(defined_data.getValue())
        if len(s) > 4:
            strings.append(s)

# Get imports
imports = []
symbol_table = program.getSymbolTable()
for sym in symbol_table.getExternalSymbols():
    imports.append(sym.getName())

result = {"functions": functions[:100], "strings": strings[:200], "imports": imports[:100]}
print("GHIDRA_JSON:" + json.dumps(result))
"""


class GhidraTool(BaseTool):
    name = "ghidra"
    category = ToolCategory.REVERSING
    requires = []  # ghidra is checked via GHIDRA_HOME env

    async def run(self, params: dict) -> ToolResult:
        if not self.validate_params(params):
            return ToolResult(success=False, error="Invalid params: 'binary' required.")

        binary: str = params["binary"]
        timeout: int = int(params.get("timeout", 300))
        ghidra_home = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
        analyze_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")

        if not os.path.exists(analyze_headless):
            # Fallback: use strings/nm for basic analysis
            return await self._fallback_analysis(binary, timeout)

        project_dir = tempfile.mkdtemp(prefix="ghidra_")
        script_path = os.path.join(project_dir, "extract.py")
        with open(script_path, "w") as f:
            f.write(_GHIDRA_SCRIPT)

        cmd = [
            analyze_headless,
            project_dir, "nexus_project",
            "-import", binary,
            "-postScript", script_path,
            "-deleteProject",
            "-noanalysis" if params.get("no_analysis") else "-analyse",
        ]

        output_file = None
        if self._job_id and self._session_id:
            from backend.config import settings
            output_file = os.path.join(
                settings.data_dir, "sessions", self._session_id, "jobs", f"{self._job_id}.log"
            )

        returncode, raw = await self._execute(cmd, timeout=timeout, output_file=output_file)
        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    async def _fallback_analysis(self, binary: str, timeout: int) -> ToolResult:
        """Use strings + nm + file for basic binary analysis without Ghidra."""
        all_output = []

        for cmd in [
            ["file", binary],
            ["strings", "-n", "8", binary],
            ["nm", "-D", binary],
        ]:
            try:
                _, out = await self._execute(cmd, timeout=30)
                all_output.append(out)
            except Exception:
                pass

        raw = "\n---\n".join(all_output)
        findings = self.parse(raw)
        return ToolResult(success=True, output=raw, findings=findings)

    def parse(self, raw_output: str) -> list[Finding]:
        findings: list[Finding] = []

        # Extract JSON if present
        import json
        if "GHIDRA_JSON:" in raw_output:
            try:
                json_str = raw_output.split("GHIDRA_JSON:")[1].split("\n")[0]
                data = json.loads(json_str)
                funcs = data.get("functions", [])
                strings = data.get("strings", [])
                imports = data.get("imports", [])

                if funcs:
                    findings.append(Finding(
                        title=f"Binary Analysis: {len(funcs)} Functions Found",
                        severity=Severity.INFO,
                        description=f"Ghidra extracted {len(funcs)} functions from the binary.",
                        evidence=json.dumps(funcs[:10], indent=2),
                    ))

                # Look for suspicious strings
                suspicious = [s for s in strings if any(
                    k in s.lower() for k in ["password", "secret", "admin", "http://", "https://", "/etc/passwd", "cmd.exe"]
                )]
                if suspicious:
                    findings.append(Finding(
                        title="Suspicious Strings in Binary",
                        severity=Severity.MEDIUM,
                        description=f"Found {len(suspicious)} suspicious hardcoded strings.",
                        evidence="\n".join(suspicious[:20]),
                        remediation="Review hardcoded credentials and URLs. Remove sensitive data from binaries.",
                    ))
            except Exception as e:
                logger.debug(f"Ghidra JSON parse error: {e}")

        # Check for interesting strings via regex
        for line in raw_output.splitlines():
            if re.search(r"password|passwd|secret|api.?key", line, re.IGNORECASE):
                findings.append(Finding(
                    title="Potential Credential in Binary",
                    severity=Severity.HIGH,
                    description=f"Possible hardcoded credential found: {line[:200]}",
                    evidence=line,
                    remediation="Remove hardcoded credentials from binaries.",
                ))

        return findings

    def validate_params(self, params: dict) -> bool:
        return bool(params.get("binary"))
