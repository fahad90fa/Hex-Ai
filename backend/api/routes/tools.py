"""Tool catalogue route — returns metadata for all registered NEXUS tools."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal

router = APIRouter()


# ─── Schema ───────────────────────────────────────────────────────────────────

class ParamSchema(BaseModel):
    name: str
    type: Literal["string", "number", "boolean", "select"]
    required: bool
    default: str | int | bool | None = None
    options: list[str] | None = None
    placeholder: str | None = None
    description: str | None = None


class ToolMeta(BaseModel):
    name: str
    description: str
    category: Literal["RECON", "SCAN", "WEB", "AUTH", "EXPLOIT", "REVERSING", "NETWORK"]
    params: list[ParamSchema]
    tags: list[str]


# ─── Target param (shared by almost every tool) ───────────────────────────────

_TARGET = ParamSchema(name="target", type="string", required=True, placeholder="domain, IP or CIDR")
_URL_TARGET = ParamSchema(name="target", type="string", required=True, placeholder="https://example.com")
_TIMEOUT = ParamSchema(name="timeout", type="number", required=False, default=600, description="Max runtime in seconds")


# ─── Registry ─────────────────────────────────────────────────────────────────

_REGISTRY: list[ToolMeta] = [
    # ── RECON ──────────────────────────────────────────────────────────────────
    ToolMeta(name="amass", description="Attack surface mapping and subdomain enumeration", category="RECON",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="mode", type="select", required=False, default="passive",
                                 options=["passive", "active"])],
             tags=["subdomain", "dns", "recon"]),
    ToolMeta(name="subfinder", description="Fast passive subdomain enumeration", category="RECON",
             params=[_TARGET, _TIMEOUT], tags=["subdomain", "passive"]),
    ToolMeta(name="httpx", description="HTTP probing and web technology fingerprinting", category="RECON",
             params=[_TARGET, _TIMEOUT], tags=["http", "probe", "fingerprint"]),
    ToolMeta(name="gau", description="Fetch known URLs from web archives", category="RECON",
             params=[_TARGET], tags=["urls", "archive", "passive"]),
    ToolMeta(name="waybackurls", description="Pull URLs from the Wayback Machine", category="RECON",
             params=[_TARGET], tags=["urls", "wayback", "passive"]),
    ToolMeta(name="hakrawler", description="Fast web crawler for URLs and endpoints", category="RECON",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="depth", type="number", required=False, default=3)],
             tags=["crawl", "endpoints"]),
    ToolMeta(name="katana", description="Next-generation crawling and spidering framework", category="RECON",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="depth", type="number", required=False, default=3)],
             tags=["crawl", "js", "spider"]),
    ToolMeta(name="fierce", description="DNS reconnaissance tool for domain enumeration", category="RECON",
             params=[_TARGET, _TIMEOUT], tags=["dns", "zone-transfer"]),
    ToolMeta(name="dnsenum", description="Comprehensive DNS enumeration", category="RECON",
             params=[_TARGET, _TIMEOUT], tags=["dns", "enum"]),

    # ── SCAN ───────────────────────────────────────────────────────────────────
    ToolMeta(name="nmap", description="Network port scanner with service and OS detection", category="SCAN",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="ports", type="string", required=False, default="1-65535", placeholder="e.g. 80,443 or 1-1024"),
                     ParamSchema(name="service_version", type="boolean", required=False, default=True),
                     ParamSchema(name="os_detect", type="boolean", required=False, default=False),
                     ParamSchema(name="script", type="string", required=False, placeholder="e.g. vuln,default"),
                     ParamSchema(name="top_ports", type="number", required=False, placeholder="e.g. 1000")],
             tags=["port-scan", "service-detection", "os"]),
    ToolMeta(name="nmap_advanced", description="Nmap with NSE script automation for vulnerability detection", category="SCAN",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="script_categories", type="string", required=False, default="vuln,safe")],
             tags=["nse", "vuln", "port-scan"]),
    ToolMeta(name="rustscan", description="Ultra-fast port scanner (Rust-powered, feeds into Nmap)", category="SCAN",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="batch_size", type="number", required=False, default=1000)],
             tags=["port-scan", "fast"]),
    ToolMeta(name="masscan", description="Mass port scanning at internet speed", category="SCAN",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="ports", type="string", required=False, default="0-65535"),
                     ParamSchema(name="rate", type="number", required=False, default=1000)],
             tags=["port-scan", "fast", "mass"]),
    ToolMeta(name="nuclei", description="Template-based vulnerability scanning", category="SCAN",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="templates", type="string", required=False, placeholder="e.g. cves/,exposures/"),
                     ParamSchema(name="severity", type="select", required=False,
                                 options=["critical", "high", "medium", "low", "info"], default="medium")],
             tags=["vuln", "cve", "templates"]),
    ToolMeta(name="nikto", description="Web server vulnerability scanner", category="SCAN",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="port", type="number", required=False, default=443)],
             tags=["web", "vuln", "server"]),
    ToolMeta(name="gobuster", description="Directory and DNS brute-force scanner", category="SCAN",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="mode", type="select", required=False, default="dir",
                                 options=["dir", "dns", "vhost"]),
                     ParamSchema(name="wordlist", type="string", required=False,
                                 default="/usr/share/wordlists/dirb/common.txt"),
                     ParamSchema(name="threads", type="number", required=False, default=50)],
             tags=["dir-brute", "dns", "enum"]),
    ToolMeta(name="ffuf", description="Fast web fuzzer for directories and parameters", category="SCAN",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="wordlist", type="string", required=False,
                                 default="/usr/share/wordlists/dirb/common.txt"),
                     ParamSchema(name="threads", type="number", required=False, default=100),
                     ParamSchema(name="filter_status", type="string", required=False, placeholder="e.g. 404,301")],
             tags=["fuzz", "dir", "param"]),
    ToolMeta(name="feroxbuster", description="Recursive content discovery tool", category="SCAN",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="wordlist", type="string", required=False,
                                 default="/usr/share/wordlists/dirb/common.txt"),
                     ParamSchema(name="depth", type="number", required=False, default=4),
                     ParamSchema(name="threads", type="number", required=False, default=50)],
             tags=["dir-brute", "recursive"]),
    ToolMeta(name="dirsearch", description="Web path scanner with multi-threading support", category="SCAN",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="extensions", type="string", required=False, default="php,html,js,json"),
                     ParamSchema(name="threads", type="number", required=False, default=30)],
             tags=["dir-brute", "path-scan"]),

    # ── WEB ────────────────────────────────────────────────────────────────────
    ToolMeta(name="sqlmap", description="Automated SQL injection detection and exploitation", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="level", type="number", required=False, default=3),
                     ParamSchema(name="risk", type="number", required=False, default=2),
                     ParamSchema(name="dbs", type="boolean", required=False, default=False),
                     ParamSchema(name="dump", type="boolean", required=False, default=False)],
             tags=["sqli", "injection", "database"]),
    ToolMeta(name="dalfox", description="XSS parameter analysis and scanning", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="blind_xss", type="string", required=False, placeholder="your blind XSS callback URL")],
             tags=["xss", "injection", "web"]),
    ToolMeta(name="xsser", description="Cross-site scripting detection framework", category="WEB",
             params=[_URL_TARGET, _TIMEOUT], tags=["xss", "web"]),
    ToolMeta(name="wpscan", description="WordPress vulnerability scanner", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="enumerate", type="string", required=False, default="vp,vt,cb,dbe,u"),
                     ParamSchema(name="api_token", type="string", required=False)],
             tags=["wordpress", "cms", "vuln"]),
    ToolMeta(name="wafw00f", description="Web application firewall detection", category="WEB",
             params=[_URL_TARGET], tags=["waf", "fingerprint"]),
    ToolMeta(name="arjun", description="HTTP parameter discovery", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="method", type="select", required=False, default="GET",
                                 options=["GET", "POST", "JSON", "XML"])],
             tags=["params", "discovery"]),
    ToolMeta(name="paramspider", description="Mining parameters from web archives for fuzzing", category="WEB",
             params=[_TARGET], tags=["params", "passive", "archive"]),
    ToolMeta(name="api_fuzzer", description="REST/GraphQL API security fuzzing", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="wordlist", type="string", required=False)],
             tags=["api", "fuzz", "rest"]),
    ToolMeta(name="graphql_scanner", description="GraphQL introspection and vulnerability scanner", category="WEB",
             params=[_URL_TARGET, _TIMEOUT], tags=["graphql", "api", "introspection"]),
    ToolMeta(name="dotdotpwn", description="Directory traversal fuzzer", category="WEB",
             params=[_URL_TARGET, _TIMEOUT], tags=["lfi", "traversal"]),
    ToolMeta(name="x8", description="Hidden HTTP parameter discovery", category="WEB",
             params=[_URL_TARGET, _TIMEOUT], tags=["params", "hidden"]),
    ToolMeta(name="burpsuite", description="Burp Suite Pro — proxied scan via REST API", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="api_key", type="string", required=False)],
             tags=["burp", "proxy", "scan"]),
    ToolMeta(name="zap", description="OWASP ZAP active/passive web scanner", category="WEB",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="active", type="boolean", required=False, default=True),
                     ParamSchema(name="ajax_spider", type="boolean", required=False, default=False)],
             tags=["owasp", "zap", "spider"]),

    # ── AUTH ───────────────────────────────────────────────────────────────────
    ToolMeta(name="hydra", description="Fast network login brute-forcer", category="AUTH",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="service", type="select", required=True,
                                 options=["ssh", "ftp", "http-post-form", "smb", "rdp", "telnet", "mysql"]),
                     ParamSchema(name="username", type="string", required=False),
                     ParamSchema(name="userlist", type="string", required=False),
                     ParamSchema(name="passlist", type="string", required=False,
                                 default="/usr/share/wordlists/rockyou.txt"),
                     ParamSchema(name="threads", type="number", required=False, default=16)],
             tags=["brute-force", "login", "creds"]),
    ToolMeta(name="john", description="John the Ripper — offline password cracker", category="AUTH",
             params=[ParamSchema(name="hash_file", type="string", required=True, placeholder="/path/to/hashes.txt"),
                     ParamSchema(name="wordlist", type="string", required=False, default="/usr/share/wordlists/rockyou.txt"),
                     _TIMEOUT],
             tags=["crack", "hash", "offline"]),
    ToolMeta(name="hashcat", description="GPU-accelerated password recovery", category="AUTH",
             params=[ParamSchema(name="hash_file", type="string", required=True),
                     ParamSchema(name="hash_type", type="number", required=False, default=0,
                                 description="Hashcat -m value, e.g. 0=MD5, 1000=NTLM"),
                     ParamSchema(name="wordlist", type="string", required=False, default="/usr/share/wordlists/rockyou.txt"),
                     _TIMEOUT],
             tags=["crack", "hash", "gpu"]),
    ToolMeta(name="jwt_analyzer", description="JWT token analysis and weak-secret brute-force", category="AUTH",
             params=[ParamSchema(name="token", type="string", required=True, placeholder="eyJ..."),
                     ParamSchema(name="wordlist", type="string", required=False)],
             tags=["jwt", "token", "auth"]),
    ToolMeta(name="hashpump", description="Hash length extension attack tool", category="AUTH",
             params=[ParamSchema(name="hash", type="string", required=True),
                     ParamSchema(name="data", type="string", required=True),
                     ParamSchema(name="add", type="string", required=True),
                     ParamSchema(name="key_length", type="number", required=True)],
             tags=["hash", "extension", "crypto"]),
    ToolMeta(name="responder", description="LLMNR/NBT-NS poisoner and credential harvester", category="AUTH",
             params=[ParamSchema(name="interface", type="string", required=True, placeholder="eth0"),
                     ParamSchema(name="analyze", type="boolean", required=False, default=False),
                     _TIMEOUT],
             tags=["llmnr", "ntlm", "harvest", "mitm"]),

    # ── EXPLOIT ────────────────────────────────────────────────────────────────
    ToolMeta(name="metasploit", description="Metasploit Framework — module-based exploitation", category="EXPLOIT",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="module", type="string", required=True, placeholder="exploit/multi/handler"),
                     ParamSchema(name="payload", type="string", required=False),
                     ParamSchema(name="lhost", type="string", required=False),
                     ParamSchema(name="lport", type="number", required=False, default=4444)],
             tags=["msf", "exploit", "payload"]),
    ToolMeta(name="msfvenom", description="Payload generator and encoder", category="EXPLOIT",
             params=[ParamSchema(name="payload", type="string", required=True, placeholder="windows/x64/meterpreter/reverse_tcp"),
                     ParamSchema(name="lhost", type="string", required=True),
                     ParamSchema(name="lport", type="number", required=False, default=4444),
                     ParamSchema(name="format", type="select", required=False, default="exe",
                                 options=["exe", "elf", "raw", "py", "ps1", "jar", "apk"])],
             tags=["payload", "shellcode", "encoder"]),
    ToolMeta(name="http_repeater", description="HTTP request replay and tampering tool", category="EXPLOIT",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="method", type="select", required=False, default="GET",
                                 options=["GET", "POST", "PUT", "DELETE", "PATCH"]),
                     ParamSchema(name="headers", type="string", required=False),
                     ParamSchema(name="body", type="string", required=False)],
             tags=["http", "replay", "tamper"]),
    ToolMeta(name="http_intruder", description="HTTP parameter brute-force (Burp Intruder-style)", category="EXPLOIT",
             params=[_URL_TARGET, _TIMEOUT,
                     ParamSchema(name="wordlist", type="string", required=False,
                                 default="/usr/share/wordlists/dirb/common.txt"),
                     ParamSchema(name="position", type="string", required=False, placeholder="§value§")],
             tags=["fuzz", "brute", "http"]),
    ToolMeta(name="cve_exploit_gen", description="AI-assisted CVE exploit generation", category="EXPLOIT",
             params=[ParamSchema(name="cve_id", type="string", required=True, placeholder="CVE-2024-XXXX"),
                     _TARGET],
             tags=["cve", "ai", "exploit"]),
    ToolMeta(name="pwntools", description="CTF and exploit development framework", category="EXPLOIT",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="port", type="number", required=False, default=9999),
                     ParamSchema(name="script_path", type="string", required=False)],
             tags=["pwn", "ctf", "rop"]),
    ToolMeta(name="pacu", description="AWS penetration testing framework", category="EXPLOIT",
             params=[ParamSchema(name="access_key", type="string", required=False),
                     ParamSchema(name="secret_key", type="string", required=False),
                     ParamSchema(name="modules", type="string", required=False, placeholder="iam__enum_permissions")],
             tags=["aws", "cloud", "iam"]),

    # ── NETWORK ────────────────────────────────────────────────────────────────
    ToolMeta(name="enum4linux", description="Windows/Samba enumeration tool", category="NETWORK",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="all", type="boolean", required=False, default=True)],
             tags=["smb", "windows", "enum"]),
    ToolMeta(name="smbmap", description="SMB share enumeration and access checking", category="NETWORK",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="username", type="string", required=False),
                     ParamSchema(name="password", type="string", required=False)],
             tags=["smb", "shares", "enum"]),
    ToolMeta(name="netexec", description="Network exploitation automation (CrackMapExec successor)", category="NETWORK",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="protocol", type="select", required=False, default="smb",
                                 options=["smb", "ssh", "rdp", "winrm", "mssql", "ldap"]),
                     ParamSchema(name="username", type="string", required=False),
                     ParamSchema(name="password", type="string", required=False)],
             tags=["smb", "rdp", "lateral", "spray"]),
    ToolMeta(name="nbtscan", description="NetBIOS name service scanner", category="NETWORK",
             params=[_TARGET, _TIMEOUT], tags=["netbios", "smb", "scan"]),
    ToolMeta(name="rpcclient", description="MS-RPC enumeration via rpcclient", category="NETWORK",
             params=[_TARGET, _TIMEOUT,
                     ParamSchema(name="username", type="string", required=False, default=""),
                     ParamSchema(name="password", type="string", required=False, default="")],
             tags=["rpc", "windows", "enum"]),

    # ── REVERSING ──────────────────────────────────────────────────────────────
    ToolMeta(name="checksec", description="Binary security properties checker", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True, placeholder="/path/to/binary")],
             tags=["binary", "security", "mitigations"]),
    ToolMeta(name="binwalk", description="Firmware analysis and extraction", category="REVERSING",
             params=[ParamSchema(name="file_path", type="string", required=True),
                     ParamSchema(name="extract", type="boolean", required=False, default=False)],
             tags=["firmware", "extract", "entropy"]),
    ToolMeta(name="objdump", description="Binary disassembler and object file analyser", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True),
                     ParamSchema(name="disassemble", type="boolean", required=False, default=True)],
             tags=["disasm", "binary", "symbols"]),
    ToolMeta(name="ghidra", description="NSA Ghidra — headless decompilation and analysis", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True),
                     _TIMEOUT],
             tags=["decompile", "re", "ghidra"]),
    ToolMeta(name="radare2", description="Radare2 binary analysis framework", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True),
                     ParamSchema(name="commands", type="string", required=False, placeholder="aaa;afl;pdf@main")],
             tags=["re", "disasm", "binary"]),
    ToolMeta(name="gdb", description="GNU Debugger with PEDA/pwndbg integration", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True),
                     ParamSchema(name="commands", type="string", required=False)],
             tags=["debug", "gdb", "pwn"]),
    ToolMeta(name="angr", description="Binary analysis and symbolic execution", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True),
                     _TIMEOUT],
             tags=["symbolic", "analysis", "binary"]),
    ToolMeta(name="ropgadget", description="ROP gadget finder", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True)],
             tags=["rop", "gadget", "exploit"]),
    ToolMeta(name="ropper", description="ROP chain builder and gadget finder", category="REVERSING",
             params=[ParamSchema(name="binary_path", type="string", required=True)],
             tags=["rop", "chain", "exploit"]),
    ToolMeta(name="one_gadget", description="Magic gadget finder for libc", category="REVERSING",
             params=[ParamSchema(name="libc_path", type="string", required=True, placeholder="/lib/x86_64-linux-gnu/libc.so.6")],
             tags=["rop", "libc", "one-gadget"]),
]

_INDEX: dict[str, ToolMeta] = {t.name: t for t in _REGISTRY}


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/tools", response_model=list[ToolMeta])
async def list_tools():
    return _REGISTRY


@router.get("/tools/{name}", response_model=ToolMeta)
async def get_tool(name: str):
    tool = _INDEX.get(name)
    if tool is None:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")
    return tool
