import os
import pathlib
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

from config import settings


# Human-readable labels and install instructions per tool
TOOL_META: Dict[str, Dict] = {
    "nmap":          {"label": "Nmap",          "apt": "nmap",                    "brew": "nmap",           "url": "https://nmap.org"},
    "nikto":         {"label": "Nikto",         "apt": "nikto",                   "brew": "nikto",          "url": "https://cirt.net/nikto2"},
    "testssl":       {"label": "testssl.sh",    "apt": "testssl.sh",              "brew": "testssl",        "url": "https://testssl.sh"},
    "lynis":         {"label": "Lynis",         "apt": "lynis",                   "brew": "lynis",          "url": "https://cisofy.com/lynis"},
    "oscap":         {"label": "OpenSCAP",      "apt": "libopenscap8 openscap-scanner", "brew": None,       "url": "https://www.open-scap.org"},
    "masscan":       {"label": "Masscan",       "apt": "masscan",                 "brew": "masscan",        "url": "https://github.com/robertdavidgraham/masscan"},
    "gobuster":      {"label": "Gobuster",      "apt": "gobuster",                "brew": "gobuster",       "url": "https://github.com/OJ/gobuster"},
    "sqlmap":        {"label": "SQLMap",        "apt": "sqlmap",                  "brew": "sqlmap",         "url": "https://sqlmap.org"},
    "hydra":         {"label": "Hydra",         "apt": "hydra",                   "brew": "hydra",          "url": "https://github.com/vanhauser-thc/thc-hydra"},
    "whois":         {"label": "Whois",         "apt": "whois",                   "brew": "whois",          "url": None},
    "dig":           {"label": "dig",           "apt": "dnsutils",                "brew": "bind",           "url": None},
    "theHarvester":  {"label": "theHarvester",  "apt": None,                      "brew": None,             "url": "https://github.com/laramies/theHarvester",
                     "note": "sudo apt-get install -y pipx && pipx install git+https://github.com/laramies/theHarvester && pipx ensurepath"},
    "subfinder":     {"label": "Subfinder",     "apt": None,                      "brew": "subfinder",      "url": "https://github.com/projectdiscovery/subfinder", "note": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "amass":         {"label": "Amass",         "apt": None,                      "brew": "amass",          "url": "https://github.com/owasp-amass/amass",
                     "note": "sudo snap install amass"},
    "hashcat":       {"label": "Hashcat",       "apt": "hashcat",                 "brew": "hashcat",        "url": "https://hashcat.net"},
    "john":          {"label": "John the Ripper","apt": "john",                   "brew": "john",           "url": "https://www.openwall.com/john"},
    "enum4linux":    {"label": "Enum4linux",    "apt": None,                      "brew": None,             "url": "https://github.com/CiscoCXSecurity/enum4linux",
                     "note": "sudo apt-get install -y samba-common-bin ldap-utils smbclient && sudo curl -fsSL https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -o /usr/local/bin/enum4linux && sudo chmod +x /usr/local/bin/enum4linux"},
    "ffuf":          {"label": "ffuf",          "apt": "ffuf",                    "brew": "ffuf",           "url": "https://github.com/ffuf/ffuf"},
    "searchsploit":  {"label": "SearchSploit",  "apt": None,                      "brew": None,             "url": "https://www.exploit-db.com/searchsploit",
                     "note": "sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit"},
    "aws":           {"label": "AWS CLI",       "apt": None,                      "brew": "awscli",         "url": "https://aws.amazon.com/cli",
                     "note": "pip3 install awscli"},
    "go":            {"label": "Go Runtime",    "apt": "golang-go",               "brew": "go",             "url": "https://go.dev/dl/"},
    "rustscan":      {"label": "RustScan",      "apt": None,                        "brew": None,           "url": "https://github.com/RustScan/RustScan",
                     "note": "sudo snap install rustscan"},
    "nuclei":        {"label": "Nuclei",        "apt": None,                        "brew": "nuclei",       "url": "https://github.com/projectdiscovery/nuclei",
                     "note": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "feroxbuster":        {"label": "Feroxbuster",           "apt": None,    "brew": "feroxbuster",  "url": "https://github.com/epi052/feroxbuster",
                          "note": "curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -o /tmp/feroxbuster.zip && sudo unzip -o -d /usr/local/bin /tmp/feroxbuster.zip feroxbuster && sudo chmod +x /usr/local/bin/feroxbuster"},
    "kerbrute":           {"label": "Kerbrute",              "apt": None,    "brew": None,           "url": "https://github.com/ropnop/kerbrute",
                          "note": "go install github.com/ropnop/kerbrute@latest"},
    "nxc":                {"label": "NetExec (nxc)",         "apt": None,    "brew": None,           "url": "https://github.com/Pennyw0rth/NetExec",
                          "note": "pipx install netexec"},
    "impacket-GetUserSPNs": {"label": "impacket-GetUserSPNs", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                          "note": "pip3 install impacket", "alt_binary": "GetUserSPNs.py"},
    "impacket-GetNPUsers":  {"label": "impacket-GetNPUsers",  "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                          "note": "pip3 install impacket", "alt_binary": "GetNPUsers.py"},
    "impacket-secretsdump": {"label": "impacket-secretsdump", "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                          "note": "pip3 install impacket", "alt_binary": "secretsdump.py"},
    "impacket-psexec":      {"label": "impacket-psexec",      "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                          "note": "pip3 install impacket", "alt_binary": "psexec.py"},
    "impacket-wmiexec":     {"label": "impacket-wmiexec",     "apt": None,  "brew": None,  "url": "https://github.com/fortra/impacket",
                          "note": "pip3 install impacket", "alt_binary": "wmiexec.py"},
    "responder":            {"label": "Responder",            "apt": None,  "brew": None,           "url": "https://github.com/lgandx/Responder",
                          "note": "sudo git clone https://github.com/lgandx/Responder /opt/responder && sudo ln -sf /opt/responder/Responder.py /usr/local/bin/responder && sudo chmod +x /usr/local/bin/responder"},
    "wafw00f":              {"label": "wafw00f",              "apt": None,  "brew": None,           "url": "https://github.com/EnableSecurity/wafw00f",
                          "note": "pipx install wafw00f"},
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

    for tool in settings.tools:
        meta = TOOL_META.get(tool, {})
        path = shutil.which(tool, path=search_path)
        # Some tools (e.g. pip-installed impacket in a venv) use a different binary name
        if path is None and meta.get("alt_binary"):
            path = shutil.which(meta["alt_binary"], path=search_path)
        available = path is not None
        version: Optional[str] = None

        if available and path:
            version = _get_version(tool, path)

        results[tool] = {
            "available": available,
            "path": path,
            "version": version,
            "label": meta.get("label", tool),
            "install_hint": None if available else _install_hint(tool),
            "url": meta.get("url"),
        }

    return results


# Module-level registry cache — populated on startup
_registry: Dict[str, Dict] = {}


def initialize_registry() -> None:
    global _registry
    _registry = detect_tools()


def get_registry() -> Dict[str, Dict]:
    return _registry
