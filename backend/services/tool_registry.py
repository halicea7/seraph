import os
import pathlib
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

# Canonical tool registry — the single source of truth for tool detection,
# install hints, and the Settings → Tools page. Each entry carries a "tier":
#   required    — core; primary workflows depend on it
#   recommended — broadly used across engagements/modules
#   optional    — engagement-specific or niche
# Every tool referenced by data/tool_chains.json MUST have an entry here
# (enforced by check_tool_chain_coverage()).
TOOL_META: Dict[str, Dict] = {
    # ── Required ──────────────────────────────────────────────────────────────
    "nmap":          {"label": "Nmap",          "tier": "required",    "apt": "nmap",                    "brew": "nmap",           "url": "https://nmap.org"},

    # ── Recommended ───────────────────────────────────────────────────────────
    "nikto":         {"label": "Nikto",         "tier": "recommended", "apt": "nikto",                   "brew": "nikto",          "url": "https://cirt.net/nikto2"},
    "testssl":       {"label": "testssl.sh",    "tier": "recommended", "apt": "testssl.sh",              "brew": "testssl",        "url": "https://testssl.sh"},
    "masscan":       {"label": "Masscan",       "tier": "recommended", "apt": "masscan",                 "brew": "masscan",        "url": "https://github.com/robertdavidgraham/masscan"},
    "gobuster":      {"label": "Gobuster",      "tier": "recommended", "apt": "gobuster",                "brew": "gobuster",       "url": "https://github.com/OJ/gobuster"},
    "ffuf":          {"label": "ffuf",          "tier": "recommended", "apt": "ffuf",                    "brew": "ffuf",           "url": "https://github.com/ffuf/ffuf"},
    "sqlmap":        {"label": "SQLMap",        "tier": "recommended", "apt": "sqlmap",                  "brew": "sqlmap",         "url": "https://sqlmap.org"},
    "hydra":         {"label": "Hydra",         "tier": "recommended", "apt": "hydra",                   "brew": "hydra",          "url": "https://github.com/vanhauser-thc/thc-hydra"},
    "whois":         {"label": "Whois",         "tier": "recommended", "apt": "whois",                   "brew": "whois",          "url": None},
    "dig":           {"label": "dig",           "tier": "recommended", "apt": "dnsutils",                "brew": "bind",           "url": None},
    "whatweb":       {"label": "WhatWeb",       "tier": "recommended", "apt": "whatweb",                 "brew": None,             "url": "https://github.com/urbanadventurer/WhatWeb"},
    "wafw00f":       {"label": "wafw00f",       "tier": "recommended", "apt": None,                      "brew": None,             "url": "https://github.com/EnableSecurity/wafw00f",
                     "note": "pipx install wafw00f"},
    "subfinder":     {"label": "Subfinder",     "tier": "recommended", "apt": None,                      "brew": "subfinder",      "url": "https://github.com/projectdiscovery/subfinder",
                     "note": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "nuclei":        {"label": "Nuclei",        "tier": "recommended", "apt": None,                      "brew": "nuclei",         "url": "https://github.com/projectdiscovery/nuclei",
                     "note": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "feroxbuster":   {"label": "Feroxbuster",   "tier": "recommended", "apt": None,                      "brew": "feroxbuster",    "url": "https://github.com/epi052/feroxbuster",
                     "note": "curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -o /tmp/feroxbuster.zip && sudo unzip -o -d /usr/local/bin /tmp/feroxbuster.zip feroxbuster && sudo chmod +x /usr/local/bin/feroxbuster"},
    "dalfox":        {"label": "Dalfox",        "tier": "recommended", "apt": None,                      "brew": "dalfox",         "url": "https://github.com/hahwul/dalfox",
                     "note": "go install github.com/hahwul/dalfox/v2@latest"},
    "enum4linux":    {"label": "Enum4linux",    "tier": "recommended", "apt": None,                      "brew": None,             "url": "https://github.com/CiscoCXSecurity/enum4linux",
                     "note": "sudo apt-get install -y samba-common-bin ldap-utils smbclient && sudo curl -fsSL https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -o /usr/local/bin/enum4linux && sudo chmod +x /usr/local/bin/enum4linux"},
    "smbclient":     {"label": "smbclient",     "tier": "recommended", "apt": "smbclient",               "brew": "samba",          "url": "https://www.samba.org"},
    "nxc":           {"label": "NetExec (nxc)", "tier": "recommended", "apt": None,                      "brew": None,             "url": "https://github.com/Pennyw0rth/NetExec",
                     "note": "pipx install netexec"},
    "responder":     {"label": "Responder",     "tier": "recommended", "apt": None,                      "brew": None,             "url": "https://github.com/lgandx/Responder",
                     "note": "sudo git clone https://github.com/lgandx/Responder /opt/responder && sudo ln -sf /opt/responder/Responder.py /usr/local/bin/responder && sudo chmod +x /usr/local/bin/responder"},
    "searchsploit":  {"label": "SearchSploit",  "tier": "recommended", "apt": None,                      "brew": None,             "url": "https://www.exploit-db.com/searchsploit",
                     "note": "sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit"},
    "hashcat":       {"label": "Hashcat",       "tier": "recommended", "apt": "hashcat",                 "brew": "hashcat",        "url": "https://hashcat.net"},
    "john":          {"label": "John the Ripper","tier": "recommended","apt": "john",                    "brew": "john",           "url": "https://www.openwall.com/john"},
    "linpeas":       {"label": "linPEAS",       "tier": "recommended", "apt": None,                      "brew": None,             "url": "https://github.com/peass-ng/PEASS-ng",
                     "note": "sudo curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas && sudo chmod +x /usr/local/bin/linpeas"},

    # ── Optional ──────────────────────────────────────────────────────────────
    "lynis":         {"label": "Lynis",         "tier": "optional",    "apt": "lynis",                   "brew": "lynis",          "url": "https://cisofy.com/lynis"},
    "oscap":         {"label": "OpenSCAP",      "tier": "optional",    "apt": "libopenscap8 openscap-scanner", "brew": None,       "url": "https://www.open-scap.org"},
    "theHarvester":  {"label": "theHarvester",  "tier": "optional",    "apt": None,                      "brew": None,             "url": "https://github.com/laramies/theHarvester",
                     "note": "sudo apt-get install -y pipx && pipx install git+https://github.com/laramies/theHarvester && pipx ensurepath"},
    "amass":         {"label": "Amass",         "tier": "optional",    "apt": None,                      "brew": "amass",          "url": "https://github.com/owasp-amass/amass",
                     "note": "sudo snap install amass"},
    "sherlock":      {"label": "Sherlock",      "tier": "optional",    "apt": None,                      "brew": None,             "url": "https://github.com/sherlock-project/sherlock",
                     "note": "pip install sherlock-project"},
    "wfuzz":         {"label": "Wfuzz",         "tier": "optional",    "apt": "wfuzz",                   "brew": None,             "url": "https://github.com/xmendez/wfuzz",
                     "note": "pipx install wfuzz"},
    "netdiscover":   {"label": "Netdiscover",   "tier": "optional",    "apt": "netdiscover",             "brew": None,             "url": "https://github.com/netdiscover-scanner/netdiscover"},
    "arp-scan":      {"label": "arp-scan",      "tier": "optional",    "apt": "arp-scan",                "brew": "arp-scan",       "url": "https://github.com/royhills/arp-scan"},
    "rpcclient":     {"label": "rpcclient",     "tier": "optional",    "apt": "samba-common-bin",        "brew": "samba",          "url": "https://www.samba.org"},
    "pspy":          {"label": "pspy",          "tier": "optional",    "apt": None,                      "brew": None,             "url": "https://github.com/DominicBreuker/pspy",
                     "note": "sudo curl -fsSL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /usr/local/bin/pspy && sudo chmod +x /usr/local/bin/pspy"},
    "aws":           {"label": "AWS CLI",       "tier": "optional",    "apt": None,                      "brew": "awscli",         "url": "https://aws.amazon.com/cli",
                     "note": "pip3 install awscli"},
    "rustscan":      {"label": "RustScan",      "tier": "optional",    "apt": None,                      "brew": None,             "url": "https://github.com/RustScan/RustScan",
                     "note": "sudo snap install rustscan"},
    "kerbrute":      {"label": "Kerbrute",      "tier": "optional",    "apt": None,                      "brew": None,             "url": "https://github.com/ropnop/kerbrute",
                     "note": "go install github.com/ropnop/kerbrute@latest"},
    "bloodhound-python": {"label": "BloodHound.py", "tier": "optional", "apt": None,  "brew": None,  "url": "https://github.com/dirkjanm/BloodHound.py",
                     "note": "pipx install bloodhound-ce"},
    "gowitness":     {"label": "gowitness",     "tier": "optional",    "apt": None,                      "brew": None,             "url": "https://github.com/sensepost/gowitness",
                     "note": "go install github.com/sensepost/gowitness@latest"},
    "impacket-GetUserSPNs": {"label": "impacket-GetUserSPNs", "tier": "optional", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                     "note": "pip3 install impacket", "alt_binary": "GetUserSPNs.py"},
    "impacket-GetNPUsers":  {"label": "impacket-GetNPUsers",  "tier": "optional", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                     "note": "pip3 install impacket", "alt_binary": "GetNPUsers.py"},
    "impacket-secretsdump": {"label": "impacket-secretsdump", "tier": "optional", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                     "note": "pip3 install impacket", "alt_binary": "secretsdump.py"},
    "impacket-psexec":      {"label": "impacket-psexec",      "tier": "optional", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                     "note": "pip3 install impacket", "alt_binary": "psexec.py"},
    "impacket-wmiexec":     {"label": "impacket-wmiexec",     "tier": "optional", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                     "note": "pip3 install impacket", "alt_binary": "wmiexec.py"},
    "go":            {"label": "Go Runtime",    "tier": "optional",    "apt": "golang-go",               "brew": "go",             "url": "https://go.dev/dl/"},
    # Wireless (engagement-specific)
    "airmon-ng":     {"label": "airmon-ng",     "tier": "optional",    "apt": "aircrack-ng",             "brew": None,             "url": "https://www.aircrack-ng.org"},
    "airodump-ng":   {"label": "airodump-ng",   "tier": "optional",    "apt": "aircrack-ng",             "brew": None,             "url": "https://www.aircrack-ng.org"},
    "aircrack-ng":   {"label": "Aircrack-ng",   "tier": "optional",    "apt": "aircrack-ng",             "brew": "aircrack-ng",    "url": "https://www.aircrack-ng.org"},
    "wifite":        {"label": "Wifite",        "tier": "optional",    "apt": "wifite",                  "brew": None,             "url": "https://github.com/derv82/wifite2"},
    "reaver":        {"label": "Reaver",        "tier": "optional",    "apt": "reaver",                  "brew": None,             "url": "https://github.com/t6x/reaver-wps-fork-t6x"},
    "bettercap":     {"label": "bettercap",     "tier": "optional",    "apt": "bettercap",               "brew": "bettercap",      "url": "https://www.bettercap.org"},
}


def _get_version(tool_name: str, path: str) -> Optional[str]:
    """Attempt to retrieve a version string for a tool without user-controlled input."""
    version_flags = ["--version", "-V", "-v", "version"]
    for flag in version_flags:
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout or result.stderr or "").strip()
            if output:
                first_line = output.splitlines()[0]
                return first_line[:120]
        except (subprocess.TimeoutExpired, OSError, PermissionError):
            continue
    return None


def _extra_search_paths() -> List[str]:
    """Return additional binary dirs that may not be in the server process's PATH."""
    home = pathlib.Path.home()
    gopath = os.environ.get("GOPATH", str(home / "go"))
    candidates = [
        str(home / "go" / "bin"),           # default `go install` output dir
        str(pathlib.Path(gopath) / "bin"),   # explicit $GOPATH/bin
        str(home / ".local" / "bin"),        # pipx / user installs
        str(home / ".cargo" / "bin"),        # cargo install output dir
        "/usr/local/go/bin",                 # system Go installation
        "/snap/bin",                         # snap packages (amass, etc.)
    ]
    # If running inside a venv, its bin/ dir may not be in the inherited PATH
    venv_bin = os.environ.get("VIRTUAL_ENV") or (
        str(pathlib.Path(sys.prefix) / "bin") if sys.prefix != sys.base_prefix else None
    )
    if venv_bin:
        candidates.append(str(pathlib.Path(venv_bin) / "bin") if not venv_bin.endswith("/bin") else venv_bin)
    return [p for p in candidates if pathlib.Path(p).is_dir()]


def _install_hint(tool: str) -> Optional[str]:
    """Return the most likely install command based on available package managers."""
    meta = TOOL_META.get(tool, {})
    if shutil.which("apt-get") and meta.get("apt"):
        return f"sudo apt-get install -y {meta['apt']}"
    if shutil.which("brew") and meta.get("brew"):
        return f"brew install {meta['brew']}"
    if meta.get("note"):
        return meta["note"]
    if meta.get("url"):
        return meta["url"]
    return None


def detect_tools() -> Dict[str, Dict]:
    results: Dict[str, Dict] = {}

    # Augment PATH with dirs that go install / pipx use but the server process may lack
    extra = ":".join(_extra_search_paths())
    search_path = f"{extra}:{os.environ.get('PATH', '')}" if extra else None

    # TOOL_META is the single source of truth — iterate it directly so the
    # registry, the chains, and the Settings page can never drift apart.
    for tool in TOOL_META:
        meta = TOOL_META.get(tool, {})
        path = shutil.which(tool, path=search_path)
        # Some tools (e.g. pip-installed impacket in a venv) use a different binary name
        if path is None and meta.get("alt_binary"):
            path = shutil.which(meta["alt_binary"], path=search_path)
        # Sherlock may be importable as a module even without a CLI shim
        if path is None and tool == "sherlock":
            import importlib.util as _ilu
            if _ilu.find_spec("sherlock_project"):
                path = sys.executable  # mark as available via python -m
        available = path is not None
        version: Optional[str] = None

        if available and path:
            version = _get_version(tool, path)

        results[tool] = {
            "available": available,
            "path": path,
            "version": version,
            "label": meta.get("label", tool),
            "tier": meta.get("tier", "optional"),
            "install_hint": None if available else _install_hint(tool),
            "url": meta.get("url"),
        }

    return results


def check_tool_chain_coverage() -> List[str]:
    """Return tool names referenced by data/tool_chains.json that are missing
    from TOOL_META. Used as a startup consistency guard so chain edits can't
    reference an unregistered (undetectable, install-hint-less) tool."""
    import json

    chains_path = pathlib.Path(__file__).parent.parent / "data" / "tool_chains.json"
    try:
        with open(chains_path) as f:
            chains = json.load(f)
    except (OSError, ValueError):
        return []

    referenced: set[str] = set()
    for phases in chains.values():
        for tools in phases.values():
            for entry in tools:
                name = entry.get("tool")
                if name:
                    referenced.add(name)
    return sorted(t for t in referenced if t not in TOOL_META)


# Module-level registry cache — populated on startup
_registry: Dict[str, Dict] = {}


def initialize_registry() -> None:
    global _registry
    _registry = detect_tools()


def get_registry() -> Dict[str, Dict]:
    return _registry
