"""NEXUS tool registry — import all tools and build TOOL_REGISTRY."""
from __future__ import annotations

import logging
from typing import Type

from backend.tools.base import BaseTool

logger = logging.getLogger("nexus.tools")

# ─── Recon ────────────────────────────────────────────────────────────────────
from backend.tools.recon.subfinder import SubfinderTool
from backend.tools.recon.amass import AmassTool
from backend.tools.recon.dnsenum import DnsenumTool
from backend.tools.recon.fierce import FierceTool
from backend.tools.recon.gau import GauTool
from backend.tools.recon.waybackurls import WaybackurlsTool
from backend.tools.recon.katana import KatanaTool
from backend.tools.recon.hakrawler import HakrawlerTool
from backend.tools.recon.httpx import HttpxTool

# ─── Scan ─────────────────────────────────────────────────────────────────────
from backend.tools.scan.nmap import NmapTool
from backend.tools.scan.nmap_advanced import NmapAdvancedTool
from backend.tools.scan.rustscan import RustscanTool
from backend.tools.scan.masscan import MasscanTool
from backend.tools.scan.nikto import NiktoTool
from backend.tools.scan.nuclei import NucleiTool
from backend.tools.scan.gobuster import GobusterTool
from backend.tools.scan.ffuf import FfufTool
from backend.tools.scan.feroxbuster import FeroxbusterTool
from backend.tools.scan.dirsearch import DirsearchTool

# ─── Web ──────────────────────────────────────────────────────────────────────
from backend.tools.web.sqlmap import SqlmapTool
from backend.tools.web.dalfox import DalfoxTool
from backend.tools.web.xsser import XsserTool
from backend.tools.web.zap import ZapTool
from backend.tools.web.burpsuite import BurpsuiteTool
from backend.tools.web.wpscan import WpscanTool
from backend.tools.web.wafw00f import Wafw00fTool
from backend.tools.web.arjun import ArjunTool
from backend.tools.web.paramspider import ParamspiderTool
from backend.tools.web.x8 import X8Tool
from backend.tools.web.graphql_scanner import GraphQLScannerTool
from backend.tools.web.dotdotpwn import DotdotpwnTool
from backend.tools.web.api_fuzzer import ApiFuzzerTool

# ─── Auth ─────────────────────────────────────────────────────────────────────
from backend.tools.auth.hydra import HydraTool
from backend.tools.auth.hashcat import HashcatTool
from backend.tools.auth.john import JohnTool
from backend.tools.auth.hashpump import HashpumpTool
from backend.tools.auth.jwt_analyzer import JwtAnalyzerTool
from backend.tools.auth.responder import ResponderTool

# ─── Exploit ──────────────────────────────────────────────────────────────────
from backend.tools.exploit.metasploit import MetasploitTool
from backend.tools.exploit.msfvenom import MsfvenomTool
from backend.tools.exploit.pwntools import PwntoolsTool
from backend.tools.exploit.pacu import PacuTool
from backend.tools.exploit.cve_exploit_gen import CveExploitGenTool
from backend.tools.exploit.http_intruder import HttpIntruderTool
from backend.tools.exploit.http_repeater import HttpRepeaterTool

# ─── Reversing ────────────────────────────────────────────────────────────────
from backend.tools.reversing.ghidra import GhidraTool
from backend.tools.reversing.gdb import GdbTool
from backend.tools.reversing.radare2 import Radare2Tool
from backend.tools.reversing.angr import AngrTool
from backend.tools.reversing.ropgadget import RopgadgetTool
from backend.tools.reversing.ropper import RopperTool
from backend.tools.reversing.one_gadget import OneGadgetTool
from backend.tools.reversing.checksec import ChecksecTool
from backend.tools.reversing.objdump import ObjdumpTool
from backend.tools.reversing.binwalk import BinwalkTool

# ─── Network ──────────────────────────────────────────────────────────────────
from backend.tools.network.enum4linux import Enum4linuxTool
from backend.tools.network.smbmap import SmbmapTool
from backend.tools.network.netexec import NetexecTool
from backend.tools.network.nbtscan import NbtscanTool
from backend.tools.network.rpcclient import RpcclientTool

# ─── Registry ─────────────────────────────────────────────────────────────────

_ALL_TOOL_CLASSES: list[Type[BaseTool]] = [
    # Recon
    SubfinderTool, AmassTool, DnsenumTool, FierceTool, GauTool,
    WaybackurlsTool, KatanaTool, HakrawlerTool, HttpxTool,
    # Scan
    NmapTool, NmapAdvancedTool, RustscanTool, MasscanTool, NiktoTool,
    NucleiTool, GobusterTool, FfufTool, FeroxbusterTool, DirsearchTool,
    # Web
    SqlmapTool, DalfoxTool, XsserTool, ZapTool, BurpsuiteTool, WpscanTool,
    Wafw00fTool, ArjunTool, ParamspiderTool, X8Tool, GraphQLScannerTool,
    DotdotpwnTool, ApiFuzzerTool,
    # Auth
    HydraTool, HashcatTool, JohnTool, HashpumpTool, JwtAnalyzerTool, ResponderTool,
    # Exploit
    MetasploitTool, MsfvenomTool, PwntoolsTool, PacuTool, CveExploitGenTool,
    HttpIntruderTool, HttpRepeaterTool,
    # Reversing
    GhidraTool, GdbTool, Radare2Tool, AngrTool, RopgadgetTool, RopperTool,
    OneGadgetTool, ChecksecTool, ObjdumpTool, BinwalkTool,
    # Network
    Enum4linuxTool, SmbmapTool, NetexecTool, NbtscanTool, RpcclientTool,
]

TOOL_REGISTRY: dict[str, BaseTool] = {}

for _cls in _ALL_TOOL_CLASSES:
    try:
        _instance = _cls()
        TOOL_REGISTRY[_instance.name] = _instance
    except Exception as exc:
        logger.warning("Failed to register tool %s: %s", _cls.__name__, exc)

logger.info("NEXUS tool registry loaded: %d tools", len(TOOL_REGISTRY))


def get_tool(name: str) -> BaseTool | None:
    """Return tool instance by name, or None if not found."""
    return TOOL_REGISTRY.get(name)


__all__ = ["TOOL_REGISTRY", "get_tool"]
