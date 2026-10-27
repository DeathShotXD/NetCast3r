export type RunStatus = 'queued' | 'running' | 'done' | 'failed' | 'stopped' | 'interrupted';

export interface Run {
  id: string;
  target: string;
  status: RunStatus;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  parent_run_id?: string;
  results_dir?: string;
  options: Record<string, unknown>;
  counts: Record<string, number>;
  error?: string;
}

export interface Finding {
  id: string;
  run_id: string;
  fingerprint: string;
  severity: string;
  title: string;
  secret_type: string;
  status: string;
  value: string;
  impact: string;
  evidence: string;
  source: string;
  confidence: number;
  created_at: string;
  triage_status: string;
  severity_override?: string;
  tags: string[];
  notes: string;
}

export interface RunEvent {
  id: number;
  seq: number;
  ts: number;
  run_id: string;
  type: string;
  level: string;
  stage: string;
  agent: string;
  progress?: Record<string, number> | null;
  payload?: Record<string, any>;
}

export interface Meta {
  name: string;
  version: string;
  api_version: string;
  auth_required: boolean;
  capabilities: string[];
}

export interface Totals {
  runs: number;
  active_runs: number;
  findings: number;
  missions: number;
  active_missions: number;
  pending_approvals: number;
  triage: Record<string, number>;
  severity: Record<string, number>;
  last_run: Run | null;
}

export type MissionStatus = 'draft' | 'active' | 'paused' | 'done' | 'archived';
export type Autonomy = 'manual' | 'supervised' | 'autonomous';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

export interface Mission {
  id: string;
  title: string;
  target: string;
  objective: string;
  status: MissionStatus;
  autonomy: Autonomy;
  budget: { max_usd?: number; max_minutes?: number; [key: string]: unknown };
  scope: string[];
  plan: unknown[];
  created_at: string;
  updated_at: string;
  started_at?: string;
  finished_at?: string;
  last_run_id?: string;
  run_count: number;
  finding_count: number;
  pending_approvals: number;
  runs?: Run[];
}

export interface Approval {
  id: string;
  mission_id: string;
  run_id: string;
  action: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  status: ApprovalStatus;
  requested_by: string;
  decided_by: string;
  reason: string;
  payload: Record<string, unknown>;
  nonce: string;
  created_at: string;
  decided_at?: string;
  mission_title?: string;
  mission_target?: string;
}

export interface KeyEntry {
  name: string;
  masked: string;
  source: string;
}

export interface Provider {
  id: string;
  name: string;
  kind: string;
  base_url: string;
  model: string;
  models: string[];
  priority: number;
  enabled: number;
  key_name: string;
  healthy: number;
  last_checked?: string;
  masked?: string;
}

export interface ProviderHealth {
  id: string;
  name: string;
  base_url: string;
  models: string[];
  enabled: number;
  priority: number;
  healthy: number;
  last_checked: string;
  key_set: boolean;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export type Screen =
  | 'home'
  | 'missions'
  | 'new'
  | 'live'
  | 'findings'
  | 'runs'
  | 'keys'
  | 'help';

export interface Inventory {
  kind: string;
  items: Record<string, any>[];
  total: number;
}

export interface Toast {
  id: number;
  kind: 'ok' | 'warn' | 'error';
  text: string;
  leaving?: boolean;
}
