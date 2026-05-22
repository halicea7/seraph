from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# .env lives one level up from backend/ (i.e. seraph/.env)
_ENV_FILE = Path(__file__).parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        env_prefix="SERAPH_",
        extra="ignore",
    )
    app_name: str = "Seraph"
    version: str = "0.1.0"
    database_url: str = "sqlite:///./seraph.db"
    # WebAuthn / Passkey settings.
    # rp_id must match the domain the browser sees (e.g. "yourdomain.com").
    # rp_origins is a comma-separated list of allowed origins; defaults cover all
    # localhost variants so both the dev server (22123) and production (8000) work.
    rp_id: str = "localhost"
    rp_origins: str = "http://localhost:8000,https://localhost:8000,http://localhost:22123,https://localhost:22123"
    # Extra CORS origins beyond rp_origins — comma-separated.
    # Add "null" here to allow Electron/Chronos requests (Origin: null).
    extra_cors_origins: str = ""
    tools: list[str] = [
        "nmap",
        "nikto",
        "testssl",
        "lynis",
        "oscap",
        "masscan",
        "gobuster",
        "sqlmap",
        "hydra",
        "whois",
        "dig",
        "theHarvester",
        "subfinder",
        "go",
        "amass",
        "hashcat",
        "john",
        "enum4linux",
        "ffuf",
        "searchsploit",
        "aws",
        "rustscan",
        "nuclei",
        "feroxbuster",
        "kerbrute",
        "nxc",
        "impacket-GetUserSPNs",
        "impacket-GetNPUsers",
        "impacket-secretsdump",
        "impacket-psexec",
        "impacket-wmiexec",
        "responder",
        "wafw00f",
        "sherlock",
    ]


settings = Settings()
