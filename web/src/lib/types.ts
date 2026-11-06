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
  unrestricted?: boolean;
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

export interface ThreatMapNode {
  id: string;
  type: string;
  kind: string;
  key: string;
  label: string;
  severity: string;
  risk_score: number;
  confidence: string;
  status: string;
  data: Record<string, unknown>;
}

export interface ThreatMapEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  risk_score: number;
  confidence: string;
  evidence: Record<string, unknown>;
}

export interface ThreatMap {
  schema_version: number;
  mission_id: string;
  target: string;
  summary: Record<string, number>;
  critical: ThreatMapNode[];
  nodes: ThreatMapNode[];
  edges: ThreatMapEdge[];
  paths: Array<Record<string, unknown>>;
  generated_at: string;
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

export interface Candidate {
  id: string;
  mission_id: string;
  run_id: string;
  module_id: string;
  path_id: string;
  title: string;
  severity: string;
  status: string;
  evidence: Record<string, unknown>;
  finding_id: string;
  created_at: string;
  updated_at: string;
}

export interface BrainAction {
  kind: string;
  applied?: boolean;
  reason?: string;
  direction_id?: string;
  run_id?: string;
}

export interface BrainReply {
  reply: string;
  focus: string;
  actions: BrainAction[];
  provider: string;
  model: string;
  findings: number;
}

export interface BrainTurn {
  id: number;
  ts: string;
  mission_id: string;
  role: string;
  text: string;
  focus: string;
  provider: string;
  model: string;
  source: string;
  actions: BrainAction[];
}

export interface BrainLoopStatus {
  running: boolean;
  paused: boolean;
  interval: number;
  turns: number;
  errors: number;
  last_turn: string;
  last_focus: string;
  last_model: string;
  last_reply: string;
  last_error: string;
  mission_id: string;
}

export interface BrainLiveEntry {
  id: string;
  channel: 'journal' | 'mesh' | 'run' | 'log' | string;
  role: string;
  agent: string;
  text: string;
  focus?: string;
  provider?: string;
  model?: string;
  source?: string;
  actions?: BrainAction[];
  mission_id?: string;
  ts?: string | number;
}

export interface BrainMeshAdvisory {
  id: string;
  mission_id: string;
  kind: string;
  title: string;
  tool: string;
  status: string;
  agent: string;
  provider: string;
  model: string;
  text: string;
  ts: string;
}

export interface BrainLiveFeed {
  items: BrainTurn[];
  logs: DirectorLogEntry[];
  mesh: BrainMeshAdvisory[];
  model_calls: AgentModelCall[];
  thoughts: Array<{
    id: string;
    run_id: string;
    kind: string;
    agent: string;
    stage?: string;
    text: string;
    ts?: string | number;
    seq?: number;
  }>;
  timeline: BrainLiveEntry[];
  loop: BrainLoopStatus;
}

export interface CoverageCounts {
  untested: number;
  in_progress: number;
  covered: number;
  vulnerable: number;
  blocked: number;
}

export interface CoverageCategory {
  total: number;
  covered: number;
  vulnerable: number;
  blocked: number;
  in_progress: number;
  untested: number;
}

export interface ChecklistItem {
  id: string;
  framework: string;
  category: string;
  title: string;
  objective: string;
  modules: string[];
  tools: string[];
  evidence: string;
  severity: string;
  source: string;
  status?: string;
}

export interface CoverageSummary {
  mission_id: string;
  total: number;
  counts: CoverageCounts;
  categories: Record<string, CoverageCategory>;
  percent: number;
  open: number;
  next: ChecklistItem[];
  rows: Array<{ item_id: string; status: string; evidence: string; updated_at: string }>;
}


export interface Hypothesis {
  id: string;
  mission_id: string;
  target: string;
  title: string;
  technique: string;
  rationale: string;
  expected: string;
  status: string;
  finding_id: string | null;
  created_at: string;
  updated_at: string;
  test: string | null;
  result: string | null;
}

export interface HypothesisNote {
  id: string;
  kind: string;
  title: string;
  body: string;
  run_id: string;
  created_at: string;
  matched_terms: string[];
}

export interface EvidenceProbe {
  at: string;
  tool: string;
  target: string;
  status: number;
  outcome: string;
  detail: string;
}

export interface EvidenceVerdict {
  technique: string;
  verdict: string;
  proves_technique: boolean;
  summary: string;
  counts: Record<string, number>;
  probes: EvidenceProbe[];
  next_step: string;
  reportability?: string;
  related_technique?: string;
  note?: string;
}

export interface HypothesisEvidence {
  hypothesis: Hypothesis;
  progress: string;
  terms: string[];
  counts: {
    notes: number;
    tool_calls: number;
    runs: number;
    graph_nodes: number;
    graph_edges: number;
  };
  notes: HypothesisNote[];
  tool_calls: ToolCall[];
  runs: Array<Record<string, unknown>>;
  graph_nodes: GraphNode[];
  graph_edges: Array<Record<string, unknown>>;
  finding: Finding | null;
  verdict: EvidenceVerdict | null;
  note: string;
}

export interface BenchCaseResult {
  id: string;
  kind: string;
  description: string;
  passed: boolean;
  error: string;
  expected: string[];
  actual: string[];
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  duration_ms: number;
}

export interface BenchResult {
  cases: number;
  passed: number;
  failed: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  duration_ms: number;
  results: BenchCaseResult[];
  failures: BenchCaseResult[];
  note: string;
  gate?: {
    passed: boolean;
    checks: Record<string, boolean>;
    min_precision: number;
    min_recall: number;
    precision: number;
    recall: number;
  };
}

export interface ProgramPreview {
  mission_id: string;
  parsed: {
    platform: string;
    handle: string;
    name: string;
    url: string;
    in_scope: string[];
    out_of_scope: string[];
    rules: string[];
    source: string;
    warnings: string[];
    counts: { in_scope: number; out_of_scope: number; rules: number };
  };
  diff: {
    add_in_scope: string[];
    add_exclusions: string[];
    already_present: string[];
    requires_allow_expand: string[];
    would_expand: boolean;
  };
  allow_expand: boolean;
  scope_before: string[];
  scope_after: string[];
  applied?: { added: number; scope: string[]; mission_id: string; actor: string };
}

export interface ProgramImport {
  id: string;
  mission_id: string;
  platform: string;
  handle: string;
  name: string;
  source: string;
  filename: string;
  in_scope: string[];
  out_of_scope: string[];
  rules: string[];
  diff: Record<string, unknown>;
  actor: string;
  created_at: string;
}

export interface HostShellResult {
  command: string;
  cwd: string;
  exit_code: number;
  timed_out: boolean;
  elapsed_ms: number;
  stdout: string;
  stderr: string;
  truncated?: boolean;
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
  matched_terms?: string[];
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

export interface HarnessStatus {
  ok: boolean;
  generated_at: string;
  director: {
    engaged: boolean;
    paused: boolean;
    scope_filter: string;
    cycles: number;
    runs_started: number;
    live_runs: string[];
    last_tick: string;
  };
  memory: {
    active_skills: number;
    skills_total: number;
    lessons_total: number;
    open_proposals: number;
  };
  hunt: {
    open_leads: number;
    supported_leads: number;
    hot_techniques: Array<{ technique: string; supported?: number; win_rate?: number | null }>;
    cold_techniques: Array<{ technique: string; refuted?: number; dead_ends?: number }>;
    capability_overall?: number;
    capability_level?: string;
  };
  health: {
    recent_tool_failures: number;
    top_failing_tools: Array<{ tool: string; count: number }>;
  };
  note: string;
}

export interface HarnessIssue {
  kind: string;
  title: string;
  detail: string;
  fix: string;
  severity: string;
  tool: string;
  args: Record<string, unknown>;
}

export interface HarnessDiagnose {
  mission_id: string;
  target: string;
  failure_counts: Record<string, number>;
  issues: HarnessIssue[];
  generated_at: string;
  note: string;
}

export interface HarnessLearn {
  mission_id: string;
  lessons_created: Array<{ id: string; title: string; outcome: string; source: string }>;
  skipped: number;
  expertise: Record<string, unknown> | null;
  skills: { created: Array<Record<string, unknown>>; proposed: Array<Record<string, unknown>> };
  generated_at: string;
  note: string;
}

export interface HarnessRecall {
  mission_id: string;
  goal: string;
  skills: Array<{ name: string; title: string; status: string; score: number; summary: string; tags: string[] }>;
  lessons: Array<Record<string, unknown>>;
  issues: HarnessIssue[];
  next_actions: Array<Record<string, unknown>>;
  generated_at: string;
  note: string;
}

export interface HarnessTick {
  mission_id: string;
  learned: { lessons: number; skills_created: number };
  diagnosis: HarnessIssue[];
  proposals_created: number;
  capability: { overall?: number; level?: string };
  generated_at: string;
  note: string;
}
