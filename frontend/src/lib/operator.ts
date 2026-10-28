import type { Finding, TargetSummary } from '@/types'
import { TEMPLATES, CommandTemplate, getTemplatesForTools, formatTemplatesForOperator } from '@/lib/templates'

// ── Mode definitions ──────────────────────────────────────────────────────────

export type OperatorMode = 'attack' | 'audit' | 'recon'

export interface ModeConfig {
  id: OperatorMode
  label: string
  color: string     // hex — used for text and accents
  bg: string        // rgba — card background when active
  border: string    // rgba — card border when active
  desc: string
  defaultTools: string[]
  defaultMsf: string[]
}

export const MODE_CONFIGS: Record<OperatorMode, ModeConfig> = {
  attack: {
    id: 'attack',
    label: 'Attack',
    color: '#f87171',
    bg: 'rgba(239,68,68,0.08)',
    border: 'rgba(239,68,68,0.35)',
    desc: 'Exploit, escalate, persist',
    defaultTools: ['nmap', 'sqlmap', 'hydra', 'nxc', 'kerbrute', 'searchsploit'],
    defaultMsf: [
      'exploit/windows/smb/ms17_010_eternalblue',
      'exploit/unix/ftp/vsftpd_234_backdoor',
      'exploit/multi/handler',
      'post/multi/recon/local_exploit_suggester',
      'post/windows/gather/hashdump',
    ],
  },
  recon: {
    id: 'recon',
    label: 'Recon',
    color: '#94a3b8',
    bg: 'rgba(100,116,139,0.08)',
    border: 'rgba(100,116,139,0.35)',
    desc: 'Map the surface, no exploitation',
    defaultTools: ['nmap', 'masscan', 'rustscan', 'gobuster', 'ffuf', 'theHarvester', 'subfinder'],
    defaultMsf: [
      'auxiliary/scanner/portscan/tcp',
      'auxiliary/scanner/http/http_version',
      'auxiliary/scanner/ssh/ssh_version',
      'auxiliary/scanner/ftp/ftp_version',
    ],
  },
  audit: {
    id: 'audit',
    label: 'Audit',
    color: '#fbbf24',
    bg: 'rgba(251,191,36,0.08)',
    border: 'rgba(251,191,36,0.35)',
    desc: 'Identify and document, do not exploit',
    defaultTools: ['nmap', 'nikto', 'testssl', 'nuclei', 'enum4linux', 'nxc'],
    defaultMsf: [
      'auxiliary/scanner/smb/smb_ms17_010',
      'auxiliary/scanner/http/http_version',
    ],
  },
}

// ── Tool definitions ──────────────────────────────────────────────────────────

export interface OperatorTool {
  id: string
  label: string
  category: string
  desc: string
  isMsf?: boolean
}

export const PENTEST_TOOLS: OperatorTool[] = [
  { id: 'nmap',         label: 'nmap',         category: 'Network',          desc: 'Port scanner & service detection' },
  { id: 'masscan',      label: 'masscan',      category: 'Network',          desc: 'Fast mass port scanner' },
  { id: 'rustscan',     label: 'rustscan',     category: 'Network',          desc: 'Ultra-fast scanner → nmap' },
  { id: 'nikto',        label: 'nikto',        category: 'Web',              desc: 'Web server misconfiguration scanner' },
  { id: 'gobuster',     label: 'gobuster',     category: 'Web',              desc: 'Directory / subdomain brute-forcer' },
  { id: 'ffuf',         label: 'ffuf',         category: 'Web',              desc: 'Fast web fuzzer' },
  { id: 'feroxbuster',  label: 'feroxbuster',  category: 'Web',              desc: 'Recursive content discovery' },
  { id: 'nuclei',       label: 'nuclei',       category: 'Web',              desc: 'Template-based vuln scanner' },
  { id: 'testssl',      label: 'testssl',      category: 'Web',              desc: 'TLS/SSL configuration tester' },
  { id: 'sqlmap',       label: 'sqlmap',       category: 'Exploitation',     desc: 'SQL injection detection & exploit' },
  { id: 'hydra',        label: 'hydra',        category: 'Exploitation',     desc: 'Online password brute-forcer' },
  { id: 'searchsploit', label: 'searchsploit', category: 'Exploitation',     desc: 'Exploit-DB local search' },
  { id: 'enum4linux',   label: 'enum4linux',   category: 'Active Directory', desc: 'SMB/NetBIOS enumeration' },
  { id: 'nxc',          label: 'nxc',          category: 'Active Directory', desc: 'NetExec (CrackMapExec)' },
  { id: 'kerbrute',     label: 'kerbrute',     category: 'Active Directory', desc: 'Kerberos user enum / spray' },
  { id: 'theHarvester', label: 'theHarvester', category: 'OSINT',            desc: 'Email & subdomain harvester' },
  { id: 'subfinder',    label: 'subfinder',    category: 'OSINT',            desc: 'Passive subdomain discovery' },
]

export const MSF_MODULES: OperatorTool[] = [
  { id: 'auxiliary/scanner/portscan/tcp',            label: 'TCP Port Scan',       category: 'Auxiliary', desc: 'MSF TCP port scanner', isMsf: true },
  { id: 'auxiliary/scanner/smb/smb_ms17_010',       label: 'EternalBlue Check',   category: 'Auxiliary', desc: 'MS17-010 vulnerability check', isMsf: true },
  { id: 'auxiliary/scanner/http/http_version',       label: 'HTTP Version',        category: 'Auxiliary', desc: 'HTTP server version scanner', isMsf: true },
  { id: 'auxiliary/scanner/ssh/ssh_version',         label: 'SSH Version',         category: 'Auxiliary', desc: 'SSH server version detection', isMsf: true },
  { id: 'auxiliary/scanner/ftp/ftp_version',         label: 'FTP Version',         category: 'Auxiliary', desc: 'FTP banner grabber', isMsf: true },
  { id: 'exploit/windows/smb/ms17_010_eternalblue', label: 'EternalBlue',         category: 'Exploit',   desc: 'MS17-010 SMB RCE (Win7/2008)', isMsf: true },
  { id: 'exploit/multi/http/tomcat_mgr_upload',     label: 'Tomcat Mgr Upload',   category: 'Exploit',   desc: 'Tomcat Manager WAR deployment RCE', isMsf: true },
  { id: 'exploit/unix/ftp/vsftpd_234_backdoor',     label: 'vsFTPd Backdoor',     category: 'Exploit',   desc: 'vsFTPd 2.3.4 backdoor shell', isMsf: true },
  { id: 'exploit/multi/handler',                    label: 'Generic Handler',     category: 'Exploit',   desc: 'Catch reverse shells / stagers', isMsf: true },
  { id: 'post/multi/recon/local_exploit_suggester', label: 'Exploit Suggester',   category: 'Post',      desc: 'Local privilege escalation suggestions', isMsf: true },
  { id: 'post/linux/gather/hashdump',               label: 'Linux Hashdump',      category: 'Post',      desc: 'Dump /etc/shadow hashes', isMsf: true },
  { id: 'post/windows/gather/hashdump',             label: 'Windows Hashdump',    category: 'Post',      desc: 'Dump SAM / NTLM hashes', isMsf: true },
  { id: 'post/windows/manage/enable_rdp',           label: 'Enable RDP',          category: 'Post',      desc: 'Enable Remote Desktop on target', isMsf: true },
]

export const PENTEST_CATEGORIES = [...new Set(PENTEST_TOOLS.map(t => t.category))]
export const MSF_CATEGORIES     = [...new Set(MSF_MODULES.map(t => t.category))]

// ── Prior recon record ────────────────────────────────────────────────────────

export interface PentestScanRecord {
  tool_name: string
  command: string
  status: string
  raw_output: string | null
}

// ── Command assembly ──────────────────────────────────────────────────────────

/**
 * Fill a CLI template's variable slots and optionally append extra flags.
 * Slots use {{ varname }} syntax. Unfilled slots are left as-is so the
 * unfilled-placeholder check in the context can catch them.
 */
export function assembleCliCommand(
  template: CommandTemplate,
  vars: Record<string, string>,
  extraFlags: string,
): string {
  let cmd = template.command.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, name) => vars[name] ?? `{{ ${name} }}`)
  if (extraFlags?.trim()) cmd += ' ' + extraFlags.trim()
  return cmd
}

/**
 * Assemble a msfconsole one-liner from a module ID and key-value options.
 * Handles quoting of option values that contain spaces.
 */
export function assembleMsfCommand(moduleId: string, options: Record<string, string>): string {
  const setLines = Object.entries(options)
    .filter(([, v]) => v?.trim())
    .map(([k, v]) => `set ${k} ${v}`)
    .join('; ')
  const body = setLines
    ? `use ${moduleId}; ${setLines}; run; exit -y`
    : `use ${moduleId}; run; exit -y`
  return `msfconsole -q -x "${body}"`
}

/** Extract only the signal lines from scan output so we don't flood the prompt. */
function extractKeyOutput(tool: string, output: string | null): string | null {
  if (!output) return null
  const lines = output.split('\n')

  // For port scanners, pull open port lines
  if (['nmap', 'masscan', 'rustscan'].includes(tool)) {
    const ports = lines
      .filter(l => /\d+\/(tcp|udp)\s+(open|filtered)/.test(l))
      .map(l => l.trim())
      .slice(0, 30)
    return ports.length ? ports.join('\n') : null
  }

  // For directory/subdomain fuzzers, grab found entries
  if (['gobuster', 'ffuf', 'feroxbuster'].includes(tool)) {
    const hits = lines
      .filter(l => /\b(200|301|302|403|401|Found|Status)\b/.test(l))
      .map(l => l.trim())
      .slice(0, 20)
    return hits.length ? hits.join('\n') : output.slice(0, 400)
  }

  // Default: first 400 chars
  return output.slice(0, 400)
}

function buildPriorReconSection(priorScans: PentestScanRecord[]): string {
  if (!priorScans.length) return '  None — this is the first engagement against this target.'

  return priorScans.map(s => {
    const cmd = s.command ? ` → \`${s.command.slice(0, 100)}${s.command.length > 100 ? '…' : ''}\`` : ''
    const key = extractKeyOutput(s.tool_name, s.raw_output)
    const outputLine = key
      ? `\n    Key output:\n${key.split('\n').map(l => `      ${l}`).join('\n')}`
      : ''
    return `  - ${s.tool_name}${cmd}${outputLine}`
  }).join('\n')
}

// ── Mode-specific persona builders ────────────────────────────────────────────

function buildPersona(mode: OperatorMode, hostname: string): string {
  switch (mode) {
    case 'attack':
      return `You are an expert penetration tester conducting an authorized red team engagement against ${hostname}. Your objective is to compromise the target, escalate privileges to the highest level achievable, and map every viable attack path. Be methodical: enumerate services, identify vulnerabilities, exploit them, then move laterally or escalate.`
    case 'recon':
      return `You are a security researcher performing authorized reconnaissance against ${hostname}. Your objective is to fully map the attack surface: open ports, running services, software versions, usernames, subdomains, and potential entry points. DO NOT attempt exploitation, brute-force credentials, or cause any disruption — discovery and enumeration only.`
    case 'audit':
      return `You are a security auditor conducting a compliance-oriented assessment of ${hostname}. Your objective is to identify, verify, and document security vulnerabilities and misconfigurations — without exploiting them. For each finding, note the severity (Critical / High / Medium / Low) and a brief remediation recommendation. Prioritize coverage breadth over exploitation depth.`
  }
}

function buildRules(mode: OperatorMode, hostname: string): string {
  const scopeRule = `1. ONLY target ${hostname}. Never expand scope.`
  const reconRule = `2. PREVIOUS RECONNAISSANCE is authoritative — treat it as ground truth. If a tool already appears there, its data is sufficient. Do NOT re-run it. Move to the next logical step.`
  const sudoRule = `3. Use sudo ONLY for tools that require raw socket access: nmap, masscan, tcpdump. Every other tool must be run WITHOUT sudo.`
  const templateRule = `4. CLI TOOLS — always use the template_id + vars approach:
   • Pick the template_id from the list above that best fits your goal.
   • Fill in vars with the actual values (target IP/hostname, ports, wordlists, etc.).
   • Use extra_flags ONLY for flags that are not already in the template base command. Keep extra_flags minimal and only use flags you are certain exist for this tool.
   • Do NOT invent flags. Do NOT duplicate flags already present in the base template.`
  const msfRule = `5. MSF MODULES — use msf_options with key-value pairs (e.g. RHOSTS, PAYLOAD, LPORT). The system assembles the msfconsole one-liner. Do NOT write msfconsole commands yourself.`
  switch (mode) {
    case 'attack':
      return `${scopeRule}
${reconRule}
${sudoRule}
${templateRule}
${msfRule}
6. Use ONLY tools and modules from the enabled lists above.
7. After each result, identify any new attack path steps worth recording.
8. When you have no more productive actions, call finish_engagement.
9. Keep commands targeted — avoid wide spray attacks.`
    case 'recon':
      return `${scopeRule}
${reconRule}
${sudoRule}
${templateRule}
6. Use ONLY recon/enumeration tools from the enabled lists — no exploitation.
7. DO NOT run password sprays, exploit modules, or any command that modifies the target.
8. After each result, note what new attack surface or information you've uncovered.
9. When the target surface is fully mapped, call finish_engagement.`
    case 'audit':
      return `${scopeRule}
${reconRule}
${sudoRule}
${templateRule}
6. Use ONLY non-destructive scanning tools from the enabled lists above.
7. DO NOT exploit vulnerabilities — identify and document them only.
8. For each finding, state the risk level: Critical, High, Medium, or Low.
9. When audit coverage is complete, call finish_engagement.`
  }
}

// ── Prompt builder ────────────────────────────────────────────────────────────

export function buildSystemPrompt(
  mode: OperatorMode,
  target: TargetSummary,
  findings: Finding[],
  enabledTools: string[],
  enabledMsf: string[],
  priorScans: PentestScanRecord[] = [],
  useToolCalling = false,
): string {
  const pentestTemplates = getTemplatesForTools(enabledTools, 999)
  const pentestSection = enabledTools.length
    ? formatTemplatesForOperator(pentestTemplates)
    : '  (none enabled)'

  const msfList = enabledMsf.length
    ? enabledMsf.map(id => {
        const t = MSF_MODULES.find(x => x.id === id)
        return `  - MSF:${id}${t ? ` — ${t.desc}` : ''}\n    Command pattern: msfconsole -q -x "use ${id}; set RHOSTS ${target.hostname_or_ip}; <set options>; run; exit -y"`
      }).join('\n')
    : '  (none enabled)'

  const findingLines = findings.length
    ? findings.slice(0, 25).map(f =>
        `  - [${f.severity.toUpperCase()}] ${f.title}${f.cve_id ? ` (${f.cve_id})` : ''}`
      ).join('\n')
    : '  None yet.'

  const knownPorts = target.ports
    ? target.ports
    : priorScans.some(s => ['nmap', 'masscan', 'rustscan'].includes(s.tool_name))
      ? 'see PREVIOUS RECONNAISSANCE below'
      : 'unknown'

  // When native tool calling is on, instructing the model to emit "JSON ONLY" fights the
  // tool path (it writes JSON text instead of calling run_tool). Branch the format section.
  const responseFormat = useToolCalling
    ? `RESPONSE FORMAT — use the provided FUNCTIONS, not text:
  • To run an action, CALL the \`run_tool\` function with structured arguments. For CLI tools pass
    tool_id + template_id + vars (and extra_flags only if needed); for MSF pass tool_id + msf_options.
    Always include a one-sentence \`rationale\` and a brief \`analysis\`.
  • To look up a technique, call \`search_attack_techniques\`.
  • When no productive actions remain, call \`finish_engagement\`.
  Do NOT write the action as plain text or JSON in your message — always make a function call.

  Example run_tool arguments:
  { "tool_id": "nmap", "template_id": "<pick one from the template list above>",
    "vars": { "target": "${target.hostname_or_ip}" },
    "analysis": "No prior service data for this host.",
    "rationale": "Enumerate open services before deeper testing." }`
    : `RESPONSE FORMAT — respond with valid JSON ONLY, no markdown, no explanation outside the JSON:
{
  "analysis": "your analysis of the current situation or previous output",
  "attack_path_note": null | "brief label for an attack path step you've just confirmed",
  "next_action": null | {
    "type": "command",
    "tool": "<EXACT tool id from the enabled lists above — e.g. 'nmap', 'hydra', 'exploit/unix/ftp/vsftpd_234_backdoor'. NEVER use generic labels like 'msf-exploit' or 'metasploit'>",
    "command": "<complete shell command to run>",
    "rationale": "<one sentence: why this step now>"
  }
}`

  return `${buildPersona(mode, target.hostname_or_ip)}

TARGET:
  Host: ${target.hostname_or_ip}
  Type: ${target.target_type.replace(/_/g, ' ')}
  Known ports/services: ${knownPorts}

PREVIOUS RECONNAISSANCE (tools already run against this target — read before acting):
${buildPriorReconSection(priorScans)}

EXISTING FINDINGS (from prior automated scans):
${findingLines}

ENABLED PENTEST TOOLS (with example command templates):
${pentestSection}

ENABLED METASPLOIT MODULES:
${msfList}

RULES — read carefully:
${buildRules(mode, target.hostname_or_ip)}

${responseFormat}`
}

// Preview variant — dynamic data shown as placeholders
export function buildPreviewPrompt(
  mode: OperatorMode,
  target: TargetSummary,
  enabledTools: string[],
  enabledMsf: string[],
  useToolCalling = false,
): string {
  const base = buildSystemPrompt(mode, target, [], enabledTools, enabledMsf, [], useToolCalling)
  return base
    .replace(
      '  None — this is the first engagement against this target.',
      '  (loaded from project database at session start)'
    )
    .replace(
      '  None yet.',
      '  (loaded from project database at session start)'
    )
}

export function buildInitialUserMessage(hasPriorRecon: boolean): string {
  if (hasPriorRecon) {
    return 'Review the PREVIOUS RECONNAISSANCE section carefully. Identify what has already been covered and what gaps remain. Start from where the prior work left off — only propose a scan if it covers something genuinely not yet explored.'
  }
  return 'Begin the engagement. Analyze what you know and propose your first action.'
}

export function buildOutputUserMessage(command: string, output: string): string {
  const trimmed = output.length > 8000 ? output.slice(0, 8000) + '\n... [truncated]' : output
  return `Command completed: ${command}\n\nOutput:\n\`\`\`\n${trimmed}\n\`\`\`\n\nAnalyze this output and propose your next action. If there are no more useful actions, set next_action to null.`
}

export function buildSkipUserMessage(): string {
  return 'Step skipped by operator. Based on what you know so far, what is your next action? If there are no more useful actions, set next_action to null.'
}

// ── Ollama tool definitions ───────────────────────────────────────────────────

export function buildTools(enabledTools: string[], enabledMsf: string[]): object[] {
  const allIds = [...enabledTools, ...enabledMsf]

  // Build compact template menu for the tool description
  const templateLines: string[] = []
  for (const toolId of enabledTools) {
    for (const t of TEMPLATES.filter(tmpl => tmpl.tool === toolId)) {
      const varHint = t.vars.length ? ` [vars: ${t.vars.join(', ')}]` : ''
      templateLines.push(`${t.id}${varHint}`)
    }
  }
  const templateMenu = templateLines.join(', ')

  return [
    {
      type: 'function',
      function: {
        name: 'run_tool',
        description: 'Execute a pentest action. CLI tools: pick a template_id and fill vars. MSF modules: provide msf_options.',
        parameters: {
          type: 'object',
          required: ['tool_id', 'rationale', 'analysis'],
          properties: {
            tool_id: {
              type: 'string',
              enum: allIds,
              description: 'Exact tool or MSF module ID from the enabled list.',
            },
            template_id: {
              type: 'string',
              description: `CLI tools only — ID of the command template to use as the base. Available: ${templateMenu}. Pick the one that fits your goal.`,
            },
            vars: {
              type: 'object',
              description: 'CLI tools only — variable values for the template slots (e.g. {"target": "10.0.0.1", "ports": "80,443"}). Match exactly the var names listed for the chosen template.',
              additionalProperties: { type: 'string' },
            },
            extra_flags: {
              type: 'string',
              description: 'CLI tools only — additional flags to append after the assembled template. Use only for flags you know are valid for this tool and are NOT already in the template. Leave empty if the template covers your need.',
            },
            msf_options: {
              type: 'object',
              description: 'MSF modules only — set options as key-value pairs (e.g. {"RHOSTS": "10.0.0.1", "PAYLOAD": "windows/meterpreter/reverse_tcp", "LPORT": "4444"}). The system assembles the msfconsole one-liner.',
              additionalProperties: { type: 'string' },
            },
            rationale: {
              type: 'string',
              description: 'One sentence: why this action now.',
            },
            analysis: {
              type: 'string',
              description: 'Brief analysis of the current situation before acting.',
            },
            attack_path_note: {
              type: 'string',
              description: 'Optional short label for an attack path step this confirms.',
            },
          },
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'search_attack_techniques',
        description: 'Search the local MITRE ATT&CK knowledge base for techniques, tactics, or procedure references. Use this to look up T-IDs, detection guidance, or understand an attack technique before running it. This is instant — no target access required.',
        parameters: {
          type: 'object',
          required: ['query'],
          properties: {
            query: {
              type: 'string',
              description: 'Technique name, tactic, behavior description, or T-ID (e.g. T1003, credential dumping, lateral movement).',
            },
          },
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'finish_engagement',
        description: 'Call this when no more productive actions remain.',
        parameters: {
          type: 'object',
          required: ['summary'],
          properties: {
            summary: { type: 'string', description: 'Brief summary of what was accomplished.' },
          },
        },
      },
    },
  ]
}

// ── Response parser ───────────────────────────────────────────────────────────

export interface OperatorResponse {
  analysis: string
  attack_path_note: string | null
  next_action: {
    type: 'command'
    tool: string
    command: string
    rationale: string
  } | null
}

function extractJSON(text: string): string | null {
  try { JSON.parse(text); return text } catch { /* continue */ }
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/)
  if (fence) { try { JSON.parse(fence[1]); return fence[1] } catch { /* continue */ } }
  const brace = text.match(/\{[\s\S]*\}/)
  if (brace) { try { JSON.parse(brace[0]); return brace[0] } catch { /* continue */ } }
  return null
}

export function parseOperatorResponse(text: string): OperatorResponse | null {
  const json = extractJSON(text)
  if (!json) return null
  try {
    const obj = JSON.parse(json)
    return {
      analysis: String(obj.analysis || ''),
      attack_path_note: obj.attack_path_note ? String(obj.attack_path_note) : null,
      next_action: obj.next_action ? {
        type: 'command',
        tool: String(obj.next_action.tool || ''),
        command: String(obj.next_action.command || ''),
        rationale: String(obj.next_action.rationale || ''),
      } : null,
    }
  } catch {
    return null
  }
}
