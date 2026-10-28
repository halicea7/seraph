import { getProject, getProjectScans, getFindings } from '@/api/client'
import type { Finding, TargetSummary } from '@/types'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function severityRank(s: string): number {
  const i = SEVERITY_ORDER.indexOf(s)
  return i === -1 ? 99 : i
}

function findingBlock(f: Finding): string {
  const lines: string[] = [`- [${f.severity.toUpperCase()}] ${f.title}`]
  if (f.cve_id) {
    lines.push(`  CVE: ${f.cve_id}${f.cvss_score ? ` | CVSS: ${f.cvss_score}` : ''}`)
  }
  if (f.framework && f.control_id) {
    lines.push(`  Control: ${f.framework} ${f.control_id}`)
  }
  if (f.tags) {
    const fwTags = f.tags.split(',').filter(t =>
      t.startsWith('OWASP:') || t.startsWith('MITRE:') || t.startsWith('PCI:')
    )
    if (fwTags.length) lines.push(`  Tags: ${fwTags.join(', ')}`)
  }
  if (f.description) lines.push(`  Description: ${f.description.slice(0, 250)}`)
  if (f.remediation) lines.push(`  Remediation: ${f.remediation.slice(0, 200)}`)
  return lines.join('\n')
}

function buildDataBlock(
  projectName: string,
  targets: TargetSummary[],
  scans: Array<{ scan_type?: string }>,
  findings: Finding[]
): string {
  const sevCounts: Record<string, number> = {}
  for (const f of findings) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1

  const sortedFindings = [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  const findingsText = sortedFindings.slice(0, 40).map(findingBlock).join('\n') || 'No findings recorded.'

  const targetLines = targets.map(t =>
    `- ${t.hostname_or_ip} [${t.target_type.replace(/_/g, ' ')}]${t.ports ? ` ports: ${t.ports}` : ''}`
  ).join('\n') || '(none)'

  const scanTypes = [...new Set(scans.map(s => s.scan_type).filter(Boolean))].sort()

  const sevSummary = Object.entries(sevCounts)
    .sort((a, b) => severityRank(a[0]) - severityRank(b[0]))
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `${k.toUpperCase()}: ${v}`)
    .join(' | ') || 'none'

  return `Project: ${projectName}
Targets (${targets.length}):
${targetLines}
Scans: ${scans.length} completed | Types: ${scanTypes.length ? scanTypes.join(', ') : 'various'}
Findings: ${findings.length} total | ${sevSummary}

${findingsText}`
}

const EXECUTIVE_SYSTEM = `You are a senior cybersecurity consultant writing a client-facing executive report.
Your audience is non-technical C-suite leadership.
Rules:
- Use ONLY the data provided. Do NOT invent findings, scores, CVEs, or details not in the data.
- Use Markdown: ## headings, **bold** for emphasis, bullet lists.
- Write in a professional, measured tone.
- Output exactly these four sections and nothing else:

## Executive Summary
2-3 paragraphs. What was assessed, the headline risk verdict, and why it matters to the business.

## Key Findings
Bullet list of the most significant issues (critical and high only). One sentence per finding in plain English — what it is and why it matters. If there are no critical/high findings, state that.

## Business Impact
2-3 sentences on realistic consequences if the findings were exploited (data breach, compliance exposure, downtime). Be factual, not alarmist.

## Recommended Actions
Three numbered tiers:
1. **Immediate (48 h)** — urgent mitigations
2. **Short-term (30 days)** — remediation tasks
3. **Ongoing** — process improvements`

const TECHNICAL_SYSTEM = `You are a penetration tester writing the technical narrative for a security assessment report.
Your audience is the client's security and engineering teams.
Rules:
- Use ONLY the data provided. Do NOT invent CVE IDs, CVSS scores, services, or findings not listed below.
- If a CVE or CVSS is not in the data, do not mention one.
- Use Markdown: ## headings, ### sub-headings, **bold** for key terms, \`code\` for CVEs and commands, bullet lists.
- Output exactly these four sections and nothing else:

## Scope & Targets
List each assessed target, its type, and the scan types run against it.

## Findings by Severity
Group under ### Critical / ### High / ### Medium / ### Low / ### Info sub-headings (skip empty groups).
For each finding: what it is, which target it affects, CVE/CVSS only if provided in the data, any OWASP/MITRE/PCI tags from the data, and a remediation note.

## Attack Chains & Exploitation Potential
Based strictly on the findings above, describe realistic attack paths an adversary could take. If findings are minor, say so honestly.

## Remediation Roadmap
- **Immediate** — critical issues to fix within 48 h
- **Short-term** — high/medium issues within 30 days
- **Ongoing** — architectural and process improvements`

export async function generateLocalNarrative(
  projectId: string,
  style: string
): Promise<{ narrative: string; savedAt: string }> {
  const [project, scans, findings] = await Promise.all([
    getProject(projectId),
    getProjectScans(projectId),
    getFindings(projectId),
  ])

  const dataBlock = buildDataBlock(project.name, project.targets, scans, findings)

  const systemMsg = style === 'executive' ? EXECUTIVE_SYSTEM : TECHNICAL_SYSTEM
  const userMsg = style === 'executive'
    ? `Write the executive report using this assessment data:\n\n${dataBlock}`
    : `Write the technical narrative using this assessment data:\n\n${dataBlock}`

  const messages = [
    { role: 'system', content: systemMsg },
    { role: 'user', content: userMsg },
  ]

  const { localOllamaModel } = await window.electronAPI!.ollamaGetSettings()
  const narrative = await window.electronAPI!.ollamaChat(messages, localOllamaModel || undefined)

  return { narrative, savedAt: new Date().toISOString() }
}
