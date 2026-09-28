#!/bin/bash
# NEXUS Penetration Testing Framework — Tool Installer
# Supports: Debian/Ubuntu (apt), RHEL/CentOS (yum/dnf), Arch (pacman)
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[nexus]${NC} $*"; }
warn() { echo -e "${YELLOW}[nexus]${NC} $*"; }
err() { echo -e "${RED}[nexus]${NC} $*"; }

# ─── Detect distro ────────────────────────────────────────────────────────────
detect_distro() {
    if command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then PKG_MGR="yum"
    elif command -v pacman &>/dev/null; then PKG_MGR="pacman"
    else err "Unsupported package manager"; exit 1; fi
    log "Detected package manager: $PKG_MGR"
}

install_pkg() {
    case "$PKG_MGR" in
        apt) apt-get install -y "$@" 2>/dev/null || warn "apt: $* - skipped" ;;
        dnf) dnf install -y "$@" 2>/dev/null || warn "dnf: $* - skipped" ;;
        yum) yum install -y "$@" 2>/dev/null || warn "yum: $* - skipped" ;;
        pacman) pacman -S --noconfirm "$@" 2>/dev/null || warn "pacman: $* - skipped" ;;
    esac
}

# ─── Base dependencies ────────────────────────────────────────────────────────
install_base() {
    log "Installing base dependencies..."
    case "$PKG_MGR" in
        apt)
            apt-get update -qq
            install_pkg curl wget git python3 python3-pip python3-venv ruby ruby-dev \
                        golang-go nmap masscan hydra john hashcat john \
                        gdb binutils objdump netcat-openbsd \
                        smbclient nbtscan enum4linux rpcclient \
                        nikto wfuzz dirb \
                        build-essential libssl-dev libffi-dev
            ;;
        dnf|yum)
            install_pkg curl wget git python3 python3-pip ruby golang \
                        nmap masscan hydra john hashcat gdb binutils \
                        nmap-ncat samba-client \
                        nikto build-base openssl-dev
            ;;
        pacman)
            install_pkg curl wget git python ruby go \
                        nmap masscan hydra john hashcat gdb binutils \
                        openbsd-netcat samba nikto base-devel
            ;;
    esac
}

# ─── Go-based tools ───────────────────────────────────────────────────────────
install_go_tools() {
    log "Installing Go-based tools..."
    export GOPATH="${HOME}/go"
    export PATH="${PATH}:${GOPATH}/bin"
    mkdir -p "${GOPATH}/bin"

    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && log "subfinder installed" || warn "subfinder failed"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && log "httpx installed" || warn "httpx failed"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && log "nuclei installed" || warn "nuclei failed"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null && log "katana installed" || warn "katana failed"
    go install -v github.com/hakluke/hakrawler@latest 2>/dev/null && log "hakrawler installed" || warn "hakrawler failed"
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null && log "gau installed" || warn "gau failed"
    go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null && log "waybackurls installed" || warn "waybackurls failed"
    go install -v github.com/OJ/gobuster/v3@latest 2>/dev/null && log "gobuster installed" || warn "gobuster failed"
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null && log "ffuf installed" || warn "ffuf failed"
    go install -v github.com/epi052/feroxbuster@latest 2>/dev/null || warn "feroxbuster go install failed"

    # nuclei templates
    log "Downloading nuclei templates..."
    nuclei -update-templates 2>/dev/null || warn "nuclei templates update failed"

    # Copy binaries to /usr/local/bin
    for bin in subfinder httpx nuclei katana hakrawler gau waybackurls gobuster ffuf; do
        if [ -f "${GOPATH}/bin/${bin}" ]; then
            cp "${GOPATH}/bin/${bin}" /usr/local/bin/ 2>/dev/null || true
        fi
    done
}

# ─── Python-based tools ───────────────────────────────────────────────────────
install_python_tools() {
    log "Installing Python-based tools..."
    pip3 install --quiet --break-system-packages \
        sqlmap dirsearch wafw00f wpscan-wrapper arjun paramspider \
        impacket pwntools angr ROPgadget ropper one_gadget \
        dnspython requests httpx aiohttp 2>/dev/null || \
    pip3 install --quiet \
        sqlmap dirsearch wafw00f arjun paramspider \
        impacket pwntools 2>/dev/null || warn "Some Python tools failed"

    # Install specific tools via pip
    pip3 install --quiet dalfox 2>/dev/null || warn "dalfox pip failed"
    pip3 install --quiet checksec 2>/dev/null || warn "checksec pip failed"
}

# ─── Ruby gems ────────────────────────────────────────────────────────────────
install_ruby_tools() {
    log "Installing Ruby gems..."
    gem install wpscan 2>/dev/null && log "wpscan installed" || warn "wpscan gem failed"
    gem install one_gadget 2>/dev/null && log "one_gadget installed" || warn "one_gadget gem failed"
}

# ─── Rust/cargo tools ─────────────────────────────────────────────────────────
install_rust_tools() {
    log "Installing Rust tools..."
    if ! command -v cargo &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet 2>/dev/null
        source "${HOME}/.cargo/env" 2>/dev/null || true
    fi
    cargo install rustscan 2>/dev/null && log "rustscan installed" || warn "rustscan cargo install failed"
    cargo install feroxbuster 2>/dev/null && log "feroxbuster installed" || warn "feroxbuster cargo install failed"
    # Copy to /usr/local/bin
    for bin in rustscan feroxbuster; do
        [ -f "${HOME}/.cargo/bin/${bin}" ] && cp "${HOME}/.cargo/bin/${bin}" /usr/local/bin/ 2>/dev/null || true
    done
}

# ─── Metasploit ───────────────────────────────────────────────────────────────
install_metasploit() {
    log "Installing Metasploit Framework..."
    if command -v msfconsole &>/dev/null; then
        log "Metasploit already installed"
        return
    fi
    if [ "$PKG_MGR" = "apt" ]; then
        curl -sSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
            > /tmp/msfinstall 2>/dev/null
        chmod +x /tmp/msfinstall
        /tmp/msfinstall 2>/dev/null && log "Metasploit installed" || warn "Metasploit install failed"
    else
        warn "Metasploit auto-install only supported on apt systems. Install manually."
    fi
}

# ─── Amass ────────────────────────────────────────────────────────────────────
install_amass() {
    log "Installing amass..."
    case "$PKG_MGR" in
        apt) install_pkg amass 2>/dev/null || go install github.com/owasp-amass/amass/v4/...@latest 2>/dev/null ;;
        *) go install github.com/owasp-amass/amass/v4/...@latest 2>/dev/null ;;
    esac
    [ -f "${GOPATH:-$HOME/go}/bin/amass" ] && cp "${GOPATH:-$HOME/go}/bin/amass" /usr/local/bin/ 2>/dev/null || true
}

# ─── Additional DNS tools ─────────────────────────────────────────────────────
install_dns_tools() {
    log "Installing DNS tools..."
    install_pkg dnsutils 2>/dev/null || install_pkg bind-utils 2>/dev/null || true

    # dnsenum
    if ! command -v dnsenum &>/dev/null; then
        git clone --depth=1 https://github.com/fwaeytens/dnsenum.git /opt/dnsenum 2>/dev/null || true
        [ -f /opt/dnsenum/dnsenum.pl ] && ln -sf /opt/dnsenum/dnsenum.pl /usr/local/bin/dnsenum 2>/dev/null || true
    fi

    # fierce
    pip3 install --quiet fierce 2>/dev/null || warn "fierce pip install failed"
}

# ─── SMB/Windows tools ────────────────────────────────────────────────────────
install_smb_tools() {
    log "Installing SMB/Windows tools..."
    install_pkg smbmap 2>/dev/null || pip3 install smbmap 2>/dev/null || warn "smbmap install failed"

    # netexec (formerly crackmapexec)
    if ! command -v netexec &>/dev/null; then
        pip3 install --quiet netexec 2>/dev/null || \
        pip3 install --quiet crackmapexec 2>/dev/null || \
        warn "netexec install failed"
    fi
}

# ─── Reversing tools ─────────────────────────────────────────────────────────
install_reversing_tools() {
    log "Installing reversing tools..."
    install_pkg binwalk gdb 2>/dev/null || true

    # radare2
    if ! command -v r2 &>/dev/null; then
        git clone --depth=1 https://github.com/radareorg/radare2 /tmp/radare2 2>/dev/null || true
        if [ -d /tmp/radare2 ]; then
            cd /tmp/radare2 && ./sys/install.sh 2>/dev/null && log "radare2 installed" || warn "radare2 install failed"
            cd -
        fi
    fi

    # GDB peda/gef
    if [ ! -f ~/.gdbinit ] || ! grep -q "gef\|peda" ~/.gdbinit 2>/dev/null; then
        # Install peda
        git clone --depth=1 https://github.com/longld/peda.git ~/peda 2>/dev/null || true
        [ -d ~/peda ] && echo "source ~/peda/peda.py" >> ~/.gdbinit 2>/dev/null || true
    fi

    # checksec
    pip3 install --quiet checksec 2>/dev/null || \
    ( curl -sSL https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec -o /usr/local/bin/checksec 2>/dev/null && chmod +x /usr/local/bin/checksec ) || \
    warn "checksec install failed"
}

# ─── Web tools ────────────────────────────────────────────────────────────────
install_web_tools() {
    log "Installing web tools..."

    # nikto
    install_pkg nikto 2>/dev/null || \
    git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto 2>/dev/null && \
    [ -f /opt/nikto/program/nikto.pl ] && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto 2>/dev/null || true

    # dirsearch
    pip3 install --quiet dirsearch 2>/dev/null || \
    git clone --depth=1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch 2>/dev/null || true

    # x8 - parameter discovery
    cargo install x8 2>/dev/null || warn "x8 cargo install failed"

    # XSStrike/XSSer
    pip3 install --quiet xsser 2>/dev/null || warn "xsser pip failed"

    # wafw00f
    pip3 install --quiet wafw00f 2>/dev/null || warn "wafw00f pip failed"

    # dotdotpwn
    git clone --depth=1 https://github.com/wireghoul/dotdotpwn.git /opt/dotdotpwn 2>/dev/null || true
    [ -f /opt/dotdotpwn/dotdotpwn.pl ] && ln -sf /opt/dotdotpwn/dotdotpwn.pl /usr/local/bin/dotdotpwn 2>/dev/null || true

    # dalfox
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || warn "dalfox go install failed"
}

# ─── Wordlists ────────────────────────────────────────────────────────────────
install_wordlists() {
    log "Installing wordlists..."
    mkdir -p /usr/share/wordlists

    # rockyou
    if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
            gunzip /usr/share/wordlists/rockyou.txt.gz
        else
            case "$PKG_MGR" in
                apt) install_pkg wordlists 2>/dev/null || true ;;
            esac
            if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
                curl -sSL "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
                    -o /usr/share/wordlists/rockyou.txt 2>/dev/null || warn "rockyou download failed"
            fi
        fi
    fi

    # SecLists
    if [ ! -d /usr/share/seclists ]; then
        log "Downloading SecLists (this may take a while)..."
        git clone --depth=1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || \
        warn "SecLists download failed"
    else
        log "SecLists already present"
    fi
}

# ─── PATH setup ───────────────────────────────────────────────────────────────
setup_path() {
    log "Setting up PATH..."
    PROFILE_FILE="${HOME}/.bashrc"
    [ -f "${HOME}/.zshrc" ] && PROFILE_FILE="${HOME}/.zshrc"

    for path_entry in "${HOME}/go/bin" "${HOME}/.cargo/bin" "/usr/local/bin"; do
        if ! grep -q "${path_entry}" "${PROFILE_FILE}" 2>/dev/null; then
            echo "export PATH=\"\${PATH}:${path_entry}\"" >> "${PROFILE_FILE}"
        fi
    done
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    log "NEXUS Tool Installer starting..."
    detect_distro
    install_base
    install_go_tools
    install_python_tools
    install_ruby_tools
    install_rust_tools
    install_metasploit
    install_amass
    install_dns_tools
    install_smb_tools
    install_reversing_tools
    install_web_tools
    install_wordlists
    setup_path
    log "Installation complete! Restart your shell or run: source ~/.bashrc"
}

main "$@"
