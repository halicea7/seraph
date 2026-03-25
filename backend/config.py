from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Seraph"
    version: str = "0.1.0"
    database_url: str = "sqlite:///./seraph.db"
    tools: list[str] = [
        "nmap",
        "nikto",
        "testssl",
        "lynis",
        "openscap",
        "masscan",
        "gobuster",
        "sqlmap",
        "hydra",
        "whois",
        "dig",
        "theHarvester",
        "subfinder",
        "amass",
        "hashcat",
        "john",
        "enum4linux",
        "ffuf",
        "searchsploit",
        "aws",
    ]


settings = Settings()
