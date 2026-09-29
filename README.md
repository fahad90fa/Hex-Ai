# NEXUS — AI Pentest Framework

A professional, cross-platform penetration testing framework powered by an AI orchestration engine. NEXUS combines a FastAPI/Python backend with a Tauri v2 + React desktop frontend to deliver automated recon, scanning, exploitation, and reporting — all in a dark, terminal-native UI.

---

## Requirements

| Dependency | Version |
|---|---|
| Node.js | 20+ |
| Python | 3.12+ |
| Rust + Cargo | stable (latest) |
| Docker | 24+ (optional, for Redis / DB) |

---

## Quick Start

```bash
# 1. Start infrastructure (Redis, Postgres)
docker-compose up -d

# 2. Install Python dependencies
pip install -r backend/requirements.txt

# 3. Start the backend
python backend/main.py

# 4. Install frontend dependencies & launch desktop app
cd app
npm install
npm run tauri dev
```

The desktop window opens automatically. If you only need the web UI (no Tauri):

```bash
cd app && npm run dev   # opens http://localhost:1420
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     NEXUS Desktop (Tauri v2)                │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              React 19 + TypeScript Frontend           │   │
│  │                                                      │   │
│  │  TopBar │ Sidebar │  Panel Area          StatusBar   │   │
│  │         │         │                                  │   │
│  │         │ ┌───────┴────────────────────────────┐    │   │
│  │ Dashboard│ │  Attack Graph  │  Live Terminal    │    │   │
│  │ Modules  │ │  Findings Board│  Exploit WS       │    │   │
│  │ Report   │ │  Module Runner │  Target Dashboard │    │   │
│  │         │ └────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────┐  WebSocket  ┌───────────────────────┐    │
│  │  Tauri IPC   │◄───────────►│   FastAPI Backend      │    │
│  │  (Rust core) │   REST API  │   (localhost:8000)     │    │
│  └──────────────┘             └───────────┬───────────┘    │
└──────────────────────────────────────────┼────────────────┘
                                           │
              ┌─────────────────────────────▼──────────────┐
              │              Tool Orchestration Layer        │
              │                                             │
              │  Recon    Scan     Web     Auth    Exploit  │
              │  ──────   ─────    ───     ────    ───────  │
              │  subfinder nmap   nikto   hydra   msf       │
              │  amass   masscan  ffuf    medusa  sqlmap     │
              │  httpx   nuclei   wapiti  burp    exploit-db│
              │  shodan  rustscan zap     john    msfvenom  │
              └─────────────────────────────────────────────┘
```

---

## Tool Categories

| Category | Tools |
|---|---|
| **RECON** | subfinder, amass, httpx, shodan, censys, theHarvester, dnsx |
| **SCAN** | nmap, masscan, rustscan, nuclei, openvas |
| **WEB** | nikto, ffuf, wapiti, feroxbuster, whatweb, wpscan, zaproxy |
| **AUTH** | hydra, medusa, john, hashcat, crackmapexec |
| **EXPLOIT** | metasploit, sqlmap, exploit-db, searchsploit |
| **REVERSING** | binwalk, strings, ghidra-headless, radare2 |
| **NETWORK** | tcpdump, wireshark, scapy, netcat, socat |

---

## Project Layout

```
Hex-Ai/
├── app/                   # Tauri v2 + React frontend
│   ├── src-tauri/         # Rust Tauri backend
│   │   ├── src/
│   │   │   ├── main.rs    # Tauri app entry
│   │   │   ├── commands.rs# IPC commands
│   │   │   ├── backend.rs # Python backend spawner
│   │   │   └── tray.rs    # System tray
│   │   ├── Cargo.toml
│   │   └── tauri.conf.json
│   ├── src/
│   │   ├── api/           # Axios API layer
│   │   ├── store/         # Zustand state stores
│   │   ├── hooks/         # Custom React hooks
│   │   └── components/
│   │       ├── layout/    # TopBar, Sidebar, StatusBar
│   │       ├── panels/    # One file per panel
│   │       └── shared/    # SeverityBadge, CvssScore, etc.
│   ├── package.json
│   └── vite.config.ts
├── backend/               # FastAPI + Python (separate agent)
├── docker-compose.yml
└── README.md
```

---

## License

For authorised penetration testing and security research only.
Always obtain written permission before testing any system you do not own.
