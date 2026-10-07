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
  triage: Record<string, number>;
  severity: Record<string, number>;
  last_run: Run | null;
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

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export type Screen =
  | 'home'
  | 'new'
  | 'live'
  | 'findings'
  | 'runs'
  | 'keys'
  | 'help';

export interface Toast {
  id: number;
  kind: 'ok' | 'warn' | 'error';
  text: string;
}
