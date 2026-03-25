// ── Enums ─────────────────────────────────────────────────────────────────────

export type TargetType =
  | 'linux_host'
  | 'windows_host'
  | 'web_app'
  | 'cloud_aws'
  | 'network'

export type ScanModule = 'audit' | 'pentest'

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

// ── Core models ───────────────────────────────────────────────────────────────

export interface Project {
  id: string
  name: string
  description: string | null
  created_at: string
  target_count: number
}

export interface ProjectDetail extends Omit<Project, 'target_count'> {
  targets: TargetSummary[]
}

export interface TargetSummary {
  id: string
  project_id: string
  hostname_or_ip: string
  target_type: TargetType
  ports: string | null
  notes: string | null
  created_at: string
}

export interface Target extends TargetSummary {
  scans: ScanSummary[]
}

export interface ScanSummary {
  id: string
  scan_type: string
  module: ScanModule
  status: ScanStatus
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface Scan extends ScanSummary {
  target_id: string
  config_json: string | null
  raw_output: string | null
}

export interface Finding {
  id: string
  scan_id: string
  severity: Severity
  title: string
  description: string | null
  control_id: string | null
  framework: string | null
  remediation: string | null
  evidence: string | null
  cve_id: string | null
  cvss_score: string | null
  tags: string | null   // comma-separated, includes OWASP:A05:2021 / MITRE:T1046 / PCI:6 refs
  created_at: string
}

// ── Tool registry ─────────────────────────────────────────────────────────────

export interface ToolStatus {
  available: boolean
  path: string | null
  version: string | null
}

export type ToolRegistry = Record<string, ToolStatus>

// ── API request payloads ──────────────────────────────────────────────────────

export interface CreateProjectPayload {
  name: string
  description?: string
}

export interface UpdateProjectPayload {
  name?: string
  description?: string
}

export interface CreateTargetPayload {
  hostname_or_ip: string
  target_type: TargetType
  ports?: string
  notes?: string
}

export interface UpdateTargetPayload {
  hostname_or_ip?: string
  target_type?: TargetType
  ports?: string
  notes?: string
}

// ── Scan categories ───────────────────────────────────────────────────────────

export interface ScanCategory {
  id: string
  name: string
  description: string
  tools: string[]
  control_mappings: Array<{ framework: string; control_id: string; title: string }>
  config_schema: Record<string, {
    type: 'text' | 'select' | 'multiselect' | 'boolean'
    options?: string[]
    default?: any
    placeholder?: string
  }>
}

// ── Pentest workbench ─────────────────────────────────────────────────────────

export interface EngagementType {
  id: string
  label: string
  phases: PhaseInfo[]
}

export interface PhaseInfo {
  id: string
  label: string
  tool_count: number
}

export interface ToolDefinition {
  tool: string
  command_template: string
  description: string
  install: string
}

// ── Scan profiles ─────────────────────────────────────────────────────────────

export interface ScanProfile {
  id: string
  name: string
  description: string
  scan_categories: Array<{ category_id: string; config: Record<string, any> }> | string
  created_at: string
  schedule: string | null
  scheduled_project_id: string | null
  scheduled_target_id: string | null
  last_run: string | null
  next_run: string | null
}

export interface CreateProfilePayload {
  name: string
  description?: string
  scan_categories: Array<{ category_id: string; config: Record<string, any> }>
}

// ── C2 / Metasploit ───────────────────────────────────────────────────────────

export interface C2Session {
  id: string
  msf_session_id?: string
  project_id: string
  target_id?: string
  session_type: string
  platform: string
  arch: string
  remote_host: string
  remote_port: string
  tunnel_peer: string
  via_exploit: string
  via_payload: string
  status: 'active' | 'inactive' | 'lost'
  notes: string
  established_at: string
  last_seen: string
  loot_count: number
  task_count: number
  live: boolean
}

export interface LootEntry {
  id: string
  session_id: string
  loot_type: string
  title: string
  content: string
  source_path: string
  captured_at: string
}

export interface C2Task {
  id: string
  session_id: string
  command: string
  output: string
  status: string
  executed_at: string
  completed_at?: string
}

// ── Credential Vault ──────────────────────────────────────────────────────────

export type CredType = 'password' | 'hash' | 'key' | 'token' | 'other'
export type CredSource = 'manual' | 'c2_loot' | 'osint' | 'brute_force'

export interface Credential {
  id: string
  project_id: string
  username: string
  secret: string
  cred_type: CredType
  source: CredSource
  target_host: string
  notes: string
  created_at: string
}

// ── Finding Notes ─────────────────────────────────────────────────────────────

export interface FindingNote {
  id: string
  finding_id: string
  content: string
  created_at: string
}

// ── API error ─────────────────────────────────────────────────────────────────

export interface ApiError {
  detail: string
}
