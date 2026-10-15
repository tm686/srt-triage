#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# srt-triage installer
# Checks dependencies, installs missing tools, and validates setup.
# Tested on Kali Linux / Debian-based systems.
# ──────────────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo '         _        _       _                  '
echo '  ___ _ _| |_ ___ | |_ _ _|_|___ ___ ___     '
echo ' |_ -|  _|  _|___||  _|  _| |  .|   | -_|    '
echo ' |___|_| |_|      |_| |_| |_|__,|_  |___|    '
echo '                                |___|         '
echo -e "${NC}"
echo -e "${CYAN}srt-triage installer${NC}"
echo ""

# ── Python check ─────────────────────────────────────────────────────
echo -e "[*] Checking Python..."
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "  ${GREEN}[+]${NC} Python ${PY_VER} found"
else
    echo -e "  ${RED}[-]${NC} Python 3 not found. Install with: sudo apt install python3"
    exit 1
fi

# Verify minimum version (3.10+)
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo -e "  ${RED}[-]${NC} Python 3.10+ required (found ${PY_VER})"
    exit 1
fi

# ── Required tools ───────────────────────────────────────────────────
MISSING=()

echo -e "\n[*] Checking required tools..."

check_tool() {
    local name=$1
    local pkg=$2
    local install_cmd=$3

    if command -v "$name" &>/dev/null; then
        local path=$(which "$name")
        echo -e "  ${GREEN}[+]${NC} ${name} found at ${path}"
    else
        echo -e "  ${RED}[-]${NC} ${name} not found"
        MISSING+=("$name|$pkg|$install_cmd")
    fi
}

check_tool "nmap"         "nmap"         "sudo apt install -y nmap"
check_tool "rustscan"     "rustscan"     "sudo apt install -y rustscan"

echo -e "\n[*] Checking optional tools..."
check_tool "httpx"        "httpx"        "sudo apt install -y httpx-toolkit"
check_tool "searchsploit" "exploitdb"    "sudo apt install -y exploitdb"
check_tool "ffuf"         "ffuf"         "sudo apt install -y ffuf"

# ── Install missing tools ────────────────────────────────────────────
if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}[!] Missing tools detected:${NC}"
    for entry in "${MISSING[@]}"; do
        IFS='|' read -r name pkg cmd <<< "$entry"
        echo -e "    ${name}: ${cmd}"
    done

    echo ""
    read -p "Install missing tools? (y/N) " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "\n[*] Updating package lists..."
        sudo apt update -qq 2>/dev/null

        for entry in "${MISSING[@]}"; do
            IFS='|' read -r name pkg cmd <<< "$entry"
            echo -e "[*] Installing ${name}..."
            if eval "$cmd" 2>/dev/null; then
                echo -e "  ${GREEN}[+]${NC} ${name} installed"
            else
                echo -e "  ${YELLOW}[!]${NC} Failed to install ${name} — install manually"
            fi
        done
    else
        echo -e "${YELLOW}[!] Skipping installation. nmap and rustscan are required to scan.${NC}"
    fi
fi

# ── Verify config files ──────────────────────────────────────────────
echo -e "\n[*] Checking config files..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

for f in paths.json ports.json lead_signals.json tiers.json; do
    if [ -f "$SCRIPT_DIR/config/$f" ]; then
        echo -e "  ${GREEN}[+]${NC} config/$f"
    else
        echo -e "  ${RED}[-]${NC} config/$f missing"
    fi
done

# ── Make entry point executable ──────────────────────────────────────
chmod +x "$SCRIPT_DIR/srt_triage.py" 2>/dev/null

# ── Verify imports ───────────────────────────────────────────────────
echo -e "\n[*] Verifying Python imports..."
cd "$SCRIPT_DIR"
if python3 -c "from lib.scope import ScopeEnforcer; from lib.scorer import score_hosts; from lib.nmap_xml import parse_nmap_xml; from lib.db import init_db; print('OK')" 2>/dev/null; then
    echo -e "  ${GREEN}[+]${NC} All modules import successfully"
else
    echo -e "  ${RED}[-]${NC} Import error — check Python version and file integrity"
    exit 1
fi

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  srt-triage is ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Usage:"
echo -e "    ${CYAN}python3 srt_triage.py 10.0.0.0/24${NC}"
echo -e "    ${CYAN}python3 srt_triage.py targets.txt --scope scope.json${NC}"
echo -e "    ${CYAN}python3 srt_triage.py 10.0.0.0/24 --skip-scan --db previous.db${NC}"
echo ""
echo -e "  Run ${CYAN}python3 srt_triage.py --help${NC} for all options."
echo ""
