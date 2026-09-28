# NEXUS Penetration Testing Framework — Windows Tool Installer
# Requires: PowerShell 5.1+, Administrator privileges
# Uses: Chocolatey, WinGet, Go, pip, gem

#Requires -RunAsAdministrator

param(
    [switch]$SkipChoco,
    [switch]$SkipGo,
    [switch]$SkipPython,
    [switch]$SkipWordlists
)

$ErrorActionPreference = "Continue"

function Write-Log {
    param([string]$Message, [string]$Color = "Green")
    Write-Host "[nexus] $Message" -ForegroundColor $Color
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[nexus] WARNING: $Message" -ForegroundColor Yellow
}

# ─── Chocolatey ───────────────────────────────────────────────────────────────
function Install-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Log "Chocolatey already installed"
        return
    }
    Write-Log "Installing Chocolatey..."
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:PATH += ";$env:ProgramData\chocolatey\bin"
}

function choco-install {
    param([string[]]$Packages)
    foreach ($pkg in $Packages) {
        Write-Log "Installing $pkg via choco..."
        choco install $pkg -y --no-progress 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "$pkg installed" } else { Write-Warn "$pkg install failed" }
    }
}

# ─── WinGet ───────────────────────────────────────────────────────────────────
function winget-install {
    param([string[]]$Packages)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warn "winget not available"
        return
    }
    foreach ($pkg in $Packages) {
        Write-Log "Installing $pkg via winget..."
        winget install --id $pkg --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "$pkg installed" } else { Write-Warn "$pkg install failed" }
    }
}

# ─── Base tools via Chocolatey ────────────────────────────────────────────────
function Install-BaseTools {
    Write-Log "Installing base tools via Chocolatey..."
    choco-install @(
        "nmap",
        "python3",
        "golang",
        "ruby",
        "git",
        "curl",
        "wget",
        "7zip",
        "hashcat",
        "gdb-mingw",
        "sysinternals",
        "putty"
    )
}

# ─── Security tools via Chocolatey ────────────────────────────────────────────
function Install-SecurityTools {
    Write-Log "Installing security tools via Chocolatey..."
    choco-install @(
        "metasploit",
        "nikto",
        "hydra",
        "wireshark",
        "netcat",
        "ncat",
        "wfuzz",
        "masscan",
        "binwalk",
        "radare2",
        "ghidra",
        "cutter"
    )
}

# ─── Go tools ─────────────────────────────────────────────────────────────────
function Install-GoTools {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Warn "Go not found, skipping Go tools"
        return
    }
    $env:GOPATH = "$env:USERPROFILE\go"
    $env:PATH += ";$env:GOPATH\bin"

    Write-Log "Installing Go-based tools..."
    $goTools = @(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "github.com/projectdiscovery/katana/cmd/katana@latest",
        "github.com/hakluke/hakrawler@latest",
        "github.com/lc/gau/v2/cmd/gau@latest",
        "github.com/tomnomnom/waybackurls@latest",
        "github.com/OJ/gobuster/v3@latest",
        "github.com/ffuf/ffuf/v2@latest",
        "github.com/hahwul/dalfox/v2@latest"
    )

    foreach ($tool in $goTools) {
        $toolName = ($tool -split "/")[-1].Split("@")[0]
        Write-Log "Installing $toolName..."
        go install $tool 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "$toolName installed" } else { Write-Warn "$toolName failed" }
    }
}

# ─── Python tools ─────────────────────────────────────────────────────────────
function Install-PythonTools {
    if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
        Write-Warn "pip not found, skipping Python tools"
        return
    }
    Write-Log "Installing Python tools..."
    $pyPkgs = @(
        "sqlmap", "wafw00f", "dirsearch", "arjun", "impacket",
        "pwntools", "requests", "httpx", "aiohttp", "xsser",
        "ROPgadget", "checksec", "netexec", "paramspider"
    )
    foreach ($pkg in $pyPkgs) {
        Write-Log "pip install $pkg..."
        pip install --quiet $pkg 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "$pkg installed" } else { Write-Warn "$pkg pip install failed" }
    }
}

# ─── Ruby gems ────────────────────────────────────────────────────────────────
function Install-RubyTools {
    if (-not (Get-Command gem -ErrorAction SilentlyContinue)) {
        Write-Warn "gem not found, skipping Ruby tools"
        return
    }
    Write-Log "Installing Ruby gems..."
    gem install wpscan --quiet 2>&1 | Out-Null
    gem install one_gadget --quiet 2>&1 | Out-Null
}

# ─── Wordlists ────────────────────────────────────────────────────────────────
function Install-Wordlists {
    Write-Log "Installing wordlists..."
    $wordlistDir = "C:\wordlists"
    New-Item -ItemType Directory -Force -Path $wordlistDir | Out-Null

    # rockyou
    if (-not (Test-Path "$wordlistDir\rockyou.txt")) {
        Write-Log "Downloading rockyou.txt..."
        $url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        Invoke-WebRequest -Uri $url -OutFile "$wordlistDir\rockyou.txt" -ErrorAction SilentlyContinue
    }

    # SecLists (partial)
    if (-not (Test-Path "$wordlistDir\SecLists")) {
        Write-Log "Cloning SecLists (this may take a while)..."
        git clone --depth=1 "https://github.com/danielmiessler/SecLists.git" "$wordlistDir\SecLists" 2>&1 | Out-Null
    }
}

# ─── Add to PATH ──────────────────────────────────────────────────────────────
function Update-PATH {
    Write-Log "Updating PATH..."
    $paths = @(
        "$env:USERPROFILE\go\bin",
        "$env:USERPROFILE\.cargo\bin",
        "C:\Python3\Scripts",
        "$env:ProgramData\chocolatey\bin"
    )
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    foreach ($p in $paths) {
        if ($currentPath -notlike "*$p*" -and (Test-Path $p)) {
            [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$p", "User")
            Write-Log "Added to PATH: $p"
        }
    }
}

# ─── Main ─────────────────────────────────────────────────────────────────────
Write-Log "NEXUS Tool Installer for Windows starting..."
Write-Log "Running as Administrator: OK"

if (-not $SkipChoco) { Install-Chocolatey }
Install-BaseTools
Install-SecurityTools
if (-not $SkipGo) { Install-GoTools }
if (-not $SkipPython) { Install-PythonTools }
Install-RubyTools
if (-not $SkipWordlists) { Install-Wordlists }
Update-PATH

Write-Log "Installation complete! Please restart your terminal."
Write-Log "Tools available in: $env:USERPROFILE\go\bin, C:\Python3\Scripts, C:\ProgramData\chocolatey\bin"
