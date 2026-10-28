import type {
  CreateProjectPayload,
  CreateTargetPayload,
  Project,
  ProjectDetail,
  TargetSummary,
  Target,
  ToolRegistry,
  UpdateProjectPayload,
  UpdateTargetPayload,
} from '@/types'
import { getApiBase } from '@/lib/config'

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const url = `${getApiBase()}${path}`
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
    ...options,
  })

  if (!response.ok) {
    let detail = `HTTP ${response.status}`
    try {
      const body = await response.json()
      detail = body?.detail ?? detail
    } catch {
      // ignore parse error
    }
    throw new Error(detail)
  }

  // 204 No Content — nothing to parse
  if (response.status === 204) {
    return undefined as T
  }

  return response.json() as Promise<T>
}

// ── Projects ──────────────────────────────────────────────────────────────────

export function getProjects(): Promise<Project[]> {
  return request<Project[]>('/projects')
}

export function createProject(data: CreateProjectPayload): Promise<Project> {
  return request<Project>('/projects', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function getProject(id: string): Promise<ProjectDetail> {
  return request<ProjectDetail>(`/projects/${id}`)
}

export function updateProject(
  id: string,
  data: UpdateProjectPayload
): Promise<Project> {
  return request<Project>(`/projects/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  })
}

export function deleteProject(id: string): Promise<void> {
  return request<void>(`/projects/${id}`, { method: 'DELETE' })
}

// ── Targets ───────────────────────────────────────────────────────────────────

export function getTargets(projectId: string): Promise<TargetSummary[]> {
  return request<TargetSummary[]>(`/projects/${projectId}/targets`)
}

export function createTarget(
  projectId: string,
  data: CreateTargetPayload
): Promise<TargetSummary> {
  return request<TargetSummary>(`/projects/${projectId}/targets`, {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function getTarget(id: string): Promise<Target> {
  return request<Target>(`/targets/${id}`)
}

export function updateTarget(
  id: string,
  data: UpdateTargetPayload
): Promise<TargetSummary> {
  return request<TargetSummary>(`/targets/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  })
}

export function deleteTarget(id: string): Promise<void> {
  return request<void>(`/targets/${id}`, { method: 'DELETE' })
}

// ── Settings ──────────────────────────────────────────────────────────────────

export function getToolStatus(): Promise<ToolRegistry> {
  return request<ToolRegistry>('/settings/tools')
}

// ── Audit ─────────────────────────────────────────────────────────────────────

export function getAuditCategories(): Promise<Record<string, import('@/types').ScanCategory>> {
  return request<Record<string, import('@/types').ScanCategory>>('/audit/categories')
}

export function generateScript(
  projectId: string,
  targetId: string,
  scanCategories: Array<{ category_id: string; config: Record<string, any> }>
): Promise<{ scan_id: string; script: string }> {
  return request<{ scan_id: string; script: string }>('/audit/generate', {
    method: 'POST',
    body: JSON.stringify({
      project_id: projectId,
      target_id: targetId,
      scan_categories: scanCategories,
    }),
  })
}

export function downloadScriptUrl(scanId: string): string {
  return `${getApiBase()}/audit/script/${scanId}/download`
}

// ── Pentest ────────────────────────────────────────────────────────────────────

export function getPentestEngagements(): Promise<Record<string, import('@/types').EngagementType>> {
  return request<Record<string, import('@/types').EngagementType>>('/pentest/engagements')
}

export function getPhaseTools(
  engagementType: string,
  phaseId: string
): Promise<{ engagement_type: string; phase_id: string; tools: import('@/types').ToolDefinition[] }> {
  return request(`/pentest/engagements/${engagementType}/phases/${phaseId}`)
}

export function createPentestScan(data: {
  project_id: string
  target_id: string
  engagement_type: string
  phase_id: string
  tool_name: string
  command: string
  notes?: string
}): Promise<{ scan_id: string; command: string }> {
  return request('/pentest/run', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

// Same shape as createPentestScan, but for ad-hoc/model-assembled commands
// (AI Operator, Hermes) rather than a human picking a reviewed template from
// the Pentest Workbench — the server requires the admin role for this one.
export function createRawPentestScan(data: {
  project_id: string
  target_id: string
  engagement_type: string
  phase_id: string
  tool_name: string
  command: string
  notes?: string
}): Promise<{ scan_id: string; command: string }> {
  return request('/pentest/raw', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function getPentestScans(projectId?: string): Promise<import('@/types').Scan[]> {
  const path = projectId
    ? `/pentest/scans?project_id=${projectId}`
    : '/pentest/scans'
  return request<import('@/types').Scan[]>(path)
}

// ── Findings ──────────────────────────────────────────────────────────────────

export function getFindings(projectId?: string): Promise<import('@/types').Finding[]> {
  const url = projectId
    ? `/audit/findings?project_id=${projectId}`
    : `/audit/findings`
  return request<import('@/types').Finding[]>(url)
}

export function getScanFindings(scanId: string): Promise<import('@/types').Finding[]> {
  return request<import('@/types').Finding[]>(`/audit/scans/${scanId}/findings`)
}

export function parseScanFindings(scanId: string): Promise<{ parsed: number; findings: Array<{ id: string; title: string; severity: string }> }> {
  return request(`/audit/scans/${scanId}/parse`, { method: 'POST' })
}

// ── Reports ───────────────────────────────────────────────────────────────────

export function generateReport(
  projectId: string,
  reportType: string = 'audit',
  auditor: string = 'Seraph (Automated)'
): Promise<{ title: string; markdown: string; html: string; risk_rating: string; severity_counts: Record<string, number> }> {
  return request('/audit/reports/generate', {
    method: 'POST',
    body: JSON.stringify({ project_id: projectId, report_type: reportType, auditor }),
  })
}

export function getReportDownloadUrl(projectId: string, format: 'html' | 'markdown'): string {
  return `${getApiBase()}/audit/reports/download/${projectId}?format=${format}`
}

// ── Profiles ──────────────────────────────────────────────────────────────────

export function getProfiles(): Promise<import('@/types').ScanProfile[]> {
  return request<import('@/types').ScanProfile[]>('/profiles')
}

export function createProfile(
  data: import('@/types').CreateProfilePayload
): Promise<import('@/types').ScanProfile> {
  return request<import('@/types').ScanProfile>('/profiles', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function getProfile(id: string): Promise<import('@/types').ScanProfile> {
  return request<import('@/types').ScanProfile>(`/profiles/${id}`)
}

export function deleteProfile(id: string): Promise<{ deleted: string }> {
  return request<{ deleted: string }>(`/profiles/${id}`, { method: 'DELETE' })
}

// ── Diff ──────────────────────────────────────────────────────────────────────

export function diffScans(scanIdA: string, scanIdB: string): Promise<any> {
  return request(`/diff/scans/${scanIdA}/${scanIdB}`)
}

export function getTargetScansForDiff(targetId: string): Promise<any[]> {
  return request<any[]>(`/diff/target/${targetId}/scans`)
}

export function getProjectScans(projectId: string): Promise<any[]> {
  return request<any[]>(`/projects/${projectId}/scans`)
}

// ── Stats ─────────────────────────────────────────────────────────────────────

export interface PlatformStats {
  projects: number
  targets: number
  scans: number
  findings: number
  severity_counts: Record<string, number>
  recent_scans: Array<{
    id: string
    scan_type: string
    status: string
    target: string
    started_at: string | null
    auto_probe: boolean
  }>
  recent_findings: Array<{
    id: string
    severity: string
    title: string
    cve_id: string | null
    cvss_score: string | null
    target: string
    project: string
    created_at: string | null
  }>
}

export function getStats(): Promise<PlatformStats> {
  return request<PlatformStats>('/stats')
}

// ── Nessus ────────────────────────────────────────────────────────────────────

export interface NessusTemplate {
  uuid: string
  name: string
  title: string
  description: string
  is_agent: boolean
}

export interface NessusPolicy {
  id: number
  name: string
  description: string
}

export interface NessusFolder {
  id: number
  name: string
  type: string
}

export function getNessusTemplates(): Promise<NessusTemplate[]> {
  return request<NessusTemplate[]>('/nessus/templates')
}

export function getNessusPolicies(): Promise<NessusPolicy[]> {
  return request<NessusPolicy[]>('/nessus/policies')
}

export function getNessusFolders(): Promise<NessusFolder[]> {
  return request<NessusFolder[]>('/nessus/folders')
}

export function launchNessusScan(data: {
  project_id: string
  template_uuid: string
  policy_id?: number | null
  folder_id?: number | null
  name?: string
  targets: string
}): Promise<{ scan_id: string; nessus_scan_id: number; name: string }> {
  return request('/nessus/scans/launch', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function controlNessusScan(
  nessusScanId: number,
  action: 'pause' | 'resume' | 'stop' | 'kill'
): Promise<{ ok: boolean; action: string }> {
  return request(`/nessus/scans/${nessusScanId}/control/${action}`, { method: 'POST' })
}

export function requestNessusExport(
  nessusScanId: number,
  format: 'nessus' | 'pdf' | 'html' | 'csv'
): Promise<{ ok: boolean; file_id: number; format: string }> {
  return request(`/nessus/scans/${nessusScanId}/export`, {
    method: 'POST',
    body: JSON.stringify({ format }),
  })
}

export function nessusExportStatus(
  nessusScanId: number,
  fileId: number
): Promise<{ status: string }> {
  return request(`/nessus/scans/${nessusScanId}/export/${fileId}/status`)
}

export function nessusExportDownloadUrl(nessusScanId: number, fileId: number): string {
  return `${getApiBase()}/nessus/scans/${nessusScanId}/export/${fileId}/download`
}

// ── Hermes Agent ────────────────────────────────────────────────────────────────

export interface HermesStatus {
  installed: boolean
  version: string
  ollama_url: string
  ollama_reachable: boolean
}

export interface HermesConfig {
  allow_private_urls: boolean
  sandbox: boolean
  default_model: string
}

export function getHermesStatus(): Promise<HermesStatus> {
  return request<HermesStatus>('/hermes/status')
}

export function getHermesConfig(): Promise<HermesConfig> {
  return request<HermesConfig>('/hermes/config')
}

export function saveHermesConfig(data: HermesConfig): Promise<{ ok: boolean }> {
  return request('/hermes/config', { method: 'POST', body: JSON.stringify(data) })
}

export function createHermesRun(data: {
  project_id: string
  target_id: string
  mode: string
  model: string
}): Promise<{ scan_id: string; mode: string; model: string }> {
  return request('/hermes/run', { method: 'POST', body: JSON.stringify(data) })
}
