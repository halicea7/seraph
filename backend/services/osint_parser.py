import re
from typing import NamedTuple


class OSINTResults(NamedTuple):
    emails: list[str]
    subdomains: list[str]
    ips: list[str]


def parse_osint_output(output: str, domain: str) -> OSINTResults:
    emails = sorted(set(re.findall(r'[\w.+\-]+@[\w\-]+\.[\w.\-]+', output, re.IGNORECASE)))

    ips = sorted(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output)))

    # Match any hostname ending with the target domain
    subdomain_re = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain) + r'\b',
        re.IGNORECASE,
    )
    subdomains = sorted({
        m.group(0).lower()
        for m in subdomain_re.finditer(output)
        if m.group(0).lower() != domain.lower()
    })

    return OSINTResults(emails=emails, subdomains=subdomains, ips=ips)
