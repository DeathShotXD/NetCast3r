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
  training?: boolean;
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

export type AgentStatus =
  | 'idle'
  | 'planning'
  | 'running'
  | 'paused'
  | 'stopping'
  | 'stopped'
  | 'done'
  | 'error'
  | 'interrupted';

export type AgentTaskStatus =
  | 'pending'
  | 'running'
  | 'verified'
  | 'unverified'
  | 'failed'
  | 'skipped'
  | 'blocked';

export interface AgentTask {
  id: string;
  mission_id: string;
  seq: number;
  kind: 'scope' | 'probe' | 'inventory' | 'analysis' | 'verify';
  title: string;
  tool: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  status: AgentTaskStatus;
  args: Record<string, unknown>;
  result: Record<string, unknown>;
  evidence: Record<string, unknown>;
  verification: string;
  verifier_notes: string;
  started_at?: string;
  finished_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AgentModelCall {
  id: string;
  mission_id: string;
  task_id: string;
  agent: string;
  provider: string;
  model: string;
  status: 'ok' | 'error' | 'unavailable' | 'budget';
  prompt_chars: number;
  completion_chars: number;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  cost_cents: number | null;
  duration_ms: number;
  error: string;
  created_at: string;
}

export interface MissionAgent {
  mission_id: string;
  mission: {
    id: string;
    title: string;
    target: string;
    status: MissionStatus;
    autonomy: Autonomy;
    scope: string[];
    budget: Record<string, unknown>;
  };
  status: AgentStatus;
  stored_status: AgentStatus;
  phase: string;
  live: boolean;
  stale: boolean;
  summary: string;
  last_error: string;
  current_task_id: string;
  budget: {
    max_tasks: number;
    max_seconds: number;
    max_model_calls: number;
    max_usd: number | null;
  };
  usage: {
    tasks_total: number;
    tasks_done: number;
    tasks_verified: number;
    elapsed_seconds: number;
    calls: number;
    ok_calls: number;
    prompt_tokens: number | null;
    completion_tokens: number | null;
    cost_cents: number | null;
    cost_reported: boolean;
  };
  tasks: AgentTask[];
  model_calls: AgentModelCall[];
  started_at?: string;
  finished_at?: string;
  updated_at?: string;
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

export interface DirectorInFlight {
  run_id: string;
  mission_id: string;
  mode: string;
  runner: string;
  started_at: string;
  age: number;
}

export interface DirectorMissionState {
  mission_id: string;
  last_mode: string;
  no_progress: number;
  fails: number;
  parked: boolean;
  last_run: string;
}

export interface DirectorStatus {
  engaged: boolean;
  paused: boolean;
  scope_filter: string;
  tick_seconds: number;
  max_concurrent: number;
  cycles: number;
  runs_started: number;
  stop_reason: string;
  note: string;
  last_tick: string;
  in_flight: DirectorInFlight[];
  missions: DirectorMissionState[];
  eligible: number;
  running: boolean;
  portfolio?: {
    ranked: Array<Record<string, unknown>>;
    source: string;
    thought: string;
    generated_at: string;
  };
}

export interface DirectorLogEntry {
  id: number;
  ts: string;
  kind: string;
  mission_id: string;
  run_id: string;
  message: string;
  data: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  mission_id: string;
  kind: string;
  key: string;
  label: string;
  severity: string;
  confidence: string;
  data: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  mission_id: string;
  src: string;
  dst: string;
  kind: string;
  label: string;
  confidence: string;
  evidence: Record<string, unknown>;
}

export interface GraphStep {
  kind?: string;
  goal?: string;
  target?: string;
  technique?: string;
  expected?: string;
  hypothesis_id?: string;
  finding_id?: string;
  tool?: string;
  args?: Record<string, unknown>;
}

export interface GraphPath {
  id: string;
  mission_id: string;
  title: string;
  entry_node: string;
  impact_node: string;
  steps: GraphStep[];
  state: string;
  verdict: Record<string, unknown>;
  updated_at?: string;
}

export interface MissionGraph {
  mission_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: GraphPath[];
}

export interface Direction {
  id: string;
  mission_id: string;
  body: string;
  mentions: Array<{ kind: string; id: string }>;
  status: string;
  created_by: string;
  run_id: string;
  created_at: string;
  consumed_at: string | null;
}

export interface Campaign {
  mission_id: string;
  stage: string;
  mode: string;
  reason: string;
  runs: number;
  endpoints: number;
  open_leads: number;
  total_leads: number;
  verified_paths: number;
  findings: number;
  profile: boolean;
  history?: Array<{ stage: string; at: string; reason: string }>;
}

export interface TrendPoint {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ExploitModule {
  id: string;
  name: string;
  category: string;
  platform: string[];
  tech: string[];
  risk: string;
  impact: string;
  preconditions: string[];
  requires: string[];
  steps: Array<{ tool: string; note: string }>;
  evidence: string;
  source: string;
  signals: string[];
  ready?: boolean;
  blocked_reason?: string;
  missing?: string[];
  tech_match?: string[];
  score?: number;
}

export interface ExploitPlan {
  mission_id: string;
  tech: string[];
  endpoints: number;
  open_leads: number;
  proposals: ExploitModule[];
  note: string;
}

export type Screen =
  | 'home'
  | 'missions'
  | 'new'
  | 'live'
  | 'findings'
  | 'runs'
  | 'agent'
  | 'connect'
  | 'reports'
  | 'keys'
  | 'reveng'
  | 'help';

export interface RevengObservation {
  id: string;
  title: string;
  severity: string;
  category: string;
  file: string;
  line: number;
  evidence: string;
  recommendation: string;
  confidence: number;
}

export interface RevengSecret {
  type: string;
  file: string;
  line: number;
  preview: string;
  length: number;
}

export interface RevengEndpoint {
  url: string;
  file: string;
  line: number;
}

export interface RevengResult {
  ok: boolean;
  kind: string;
  path: string;
  generated_at: string;
  summary: {
    observations: number;
    severity: Record<string, number>;
    endpoints: number;
    secrets: number;
    files?: number;
    components?: number;
    permissions?: string[];
    package?: string;
    format?: string;
    decompiler?: string;
    languages?: Record<string, number>;
    [key: string]: unknown;
  };
  observations: RevengObservation[];
  endpoints: RevengEndpoint[];
  secrets: RevengSecret[];
  note: string;
  report_markdown?: string;
}

export interface RevengKinds {
  kinds: string[];
  decompilers: { jadx: boolean; apktool: boolean; readelf: boolean };
  note: string;
}

export interface Inventory {
  kind: string;
  items: Record<string, any>[];
  total: number;
}

export type ToolRisk = 'low' | 'medium' | 'high';

export type ToolCallStatus =
  | 'ok'
  | 'error'
  | 'denied'
  | 'approval_required'
  | 'confirm_required';

export interface McpTool {
  name: string;
  title: string;
  description: string;
  risk: ToolRisk;
  category: string;
  read_only: boolean;
  destructive: boolean;
  open_world: boolean;
  operator_only: boolean;
  input_schema: {
    type: string;
    properties?: Record<string, Record<string, unknown>>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

export interface McpServerState {
  schema?: number;
  pid?: number;
  transport?: string;
  policy?: 'readonly' | 'supervised' | 'full';
  backend?: string;
  plane_url?: string;
  started_at?: string;
  last_call_at?: string;
  calls?: number;
  tools?: number;
  protocol_version?: string;
  client?: { name?: string; version?: string };
  initialized?: boolean;
  version?: string;
  base?: string;
  path?: string;
  alive?: boolean;
}

export interface ControlPlaneInfo {
  schema?: number;
  pid?: number;
  host?: string;
  port?: number;
  url?: string;
  base?: string;
  results_dir?: string;
  started_at?: string;
  version?: string;
  path?: string;
  alive?: boolean;
}

export interface McpInfo {
  server: McpServerState | null;
  connected: boolean;
  control_plane: ControlPlaneInfo | null;
  state_file: string;
  tools: McpTool[];
  registry_error: string;
}

export interface ToolCall {
  id: string;
  tool: string;
  risk: ToolRisk;
  status: ToolCallStatus;
  actor: string;
  mission_id: string;
  run_id: string;
  approval_id: string;
  args: Record<string, unknown>;
  result: unknown;
  error: string;
  duration_ms: number;
  created_at: string;
}

export type SubmissionPlatform =
  | 'hackerone'
  | 'bugcrowd'
  | 'intigriti'
  | 'yeswehack'
  | 'immunefi'
  | 'other';

export type SubmissionStatus =
  | 'draft'
  | 'ready'
  | 'submitted'
  | 'triaged'
  | 'accepted'
  | 'informative'
  | 'duplicate'
  | 'rejected'
  | 'paid'
  | 'withdrawn';

export interface Submission {
  id: string;
  mission_id: string;
  finding_id: string;
  run_id: string;
  platform: SubmissionPlatform;
  program: string;
  target: string;
  title: string;
  severity: string;
  status: SubmissionStatus;
  bounty_cents: number;
  currency: string;
  external_id: string;
  url: string;
  report_path: string;
  notes: string;
  submitted_at?: string | null;
  decided_at?: string | null;
  paid_at?: string | null;
  created_at: string;
  updated_at: string;
  mission_title?: string | null;
  finding_title?: string | null;
  run_target?: string | null;
}

export interface SubmissionSummary {
  total: number;
  by_status: Partial<Record<SubmissionStatus, number>>;
  awaiting: number;
  accepted: number;
  paid: number;
  by_currency: Record<string, { awarded_cents: number; paid_cents: number }>;
}

export interface Toast {
  id: number;
  kind: 'ok' | 'warn' | 'error';
  text: string;
  leaving?: boolean;
}


export interface Harness {
  id: string;
  name: string;
  transport: string;
  summary: string;
  config: Record<string, unknown>;
  notes: string;
}

export interface ConnectInfo {
  workspace: {
    url: string;
    base: string;
    repo: string;
    python: string;
    policy: string;
    tools: number;
    version: string;
    token_header: string;
    token_file: string;
    auth_note: string;
  };
  harnesses: Harness[];
  tools: { name: string; title: string; risk: string; category: string; read_only: boolean }[];
  note: string;
}
