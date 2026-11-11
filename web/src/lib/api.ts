import type {
  BenchResult, BrainLiveFeed, BrainReply, BrainSession, Campaign, Candidate, ConnectInfo, Approval, CoverageSummary, Direction, DirectorLogEntry, DirectorStatus, ExploitPlan, Finding, HarnessDiagnose, HarnessLearn, HarnessRecall, HarnessStatus, HarnessTick, HostShellResult, Hypothesis, HypothesisEvidence, Inventory, KeyEntry, McpInfo, Meta, Mission, MissionAgent, MissionGraph, Paged, ProgramImport, ProgramPreview, Provider, ProviderHealth, RevengKinds, RevengResult, Run, RunDirective, RunEvent, Submission, SubmissionSummary, ThreatMap, ToolCall, Totals, TrendPoint, BrainTurn, BrainLoopStatus } from './types';

const BASE = '/api/v1';
const DEFAULT_TIMEOUT_MS = 60000;

/** Problem documents carry the human message in `detail` or `title`.
 * Prefer whichever is non-empty so the UI never falls back to "Bad Request". */
async function problemMessage(res: Response): Promise<string> {
  let message = res.statusText || `HTTP ${res.status}`;
  try {
    const problem = (await res.json()) as { detail?: string; title?: string; message?: string };
    message = (problem.detail || '').trim() || (problem.title || '').trim()
      || (problem.message || '').trim() || message;
  } catch {
    /* keep status text */
  }
  return message;
}

async function request<T>(method: string, path: string, body?: unknown,
                          timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  let res: Response;
  const controller = new AbortController();
  const timer = timeoutMs > 0
    ? window.setTimeout(() => controller.abort(), timeoutMs)
    : undefined;
  try {
    res = await fetch(BASE + path, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal
    });
  } catch {
    if (controller.signal.aborted) {
      throw new Error(`the control plane did not answer within ${Math.round(timeoutMs / 1000)}s`);
    }
    throw new Error('the dashboard server is not reachable');
  } finally {
    if (timer) window.clearTimeout(timer);
  }
  if (res.status === 401) {
    window.dispatchEvent(new Event('nc:locked'));
    throw new Error('session token required');
  }
  if (!res.ok) {
    throw new Error(await problemMessage(res));
  }
  return (await res.json()) as T;
}

async function requestText(path: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string> {
  let res: Response;
  const controller = new AbortController();
  const timer = timeoutMs > 0
    ? window.setTimeout(() => controller.abort(), timeoutMs)
    : undefined;
  try {
    res = await fetch(BASE + path, { credentials: 'same-origin', signal: controller.signal });
  } catch {
    if (controller.signal.aborted) {
      throw new Error(`the control plane did not answer within ${Math.round(timeoutMs / 1000)}s`);
    }
    throw new Error('the dashboard server is not reachable');
  } finally {
    if (timer) window.clearTimeout(timer);
  }
  if (res.status === 401) {
    window.dispatchEvent(new Event('nc:locked'));
    throw new Error('session token required');
  }
  if (!res.ok) {
    throw new Error(await problemMessage(res));
  }
  return await res.text();
}

export const api = {
  sessionState: () =>
    request<{ authenticated: boolean; auth_required: boolean }>('GET', '/session'),
  meta: () => request<Meta>('GET', '/meta'),
  authInfo: () => request<{ username: string; default: boolean; source: string }>('GET', '/auth'),
  changeCredentials: (username: string, password: string) =>
    request<{ username: string; default: boolean; changed: boolean }>('POST', '/auth/credentials', {
      username,
      password
    }),
  totals: () => request<Totals>('GET', '/summary'),
  connect: () => request<ConnectInfo>('GET', '/connect'),
  runs: (q = '') => request<Paged<Run>>('GET', `/runs${q}`),
  run: (id: string) => request<Run>('GET', `/runs/${id}`),
  runReport: (id: string) => requestText(`/runs/${id}/report`, 90000),
  startRun: (target: string, options: Record<string, unknown>) =>
    request<Run>('POST', '/runs', { target, options }),
  stopRun: (id: string) => request<{ stopped: boolean }>('POST', `/runs/${id}/stop`),
  rerun: (id: string) => request<Run>('POST', `/runs/${id}/rerun`),
  resumeRun: (id: string) => request<Run>('POST', `/runs/${id}/resume`),
  inventory: (id: string, kind: string, limit = 5000) =>
    request<Inventory>('GET', `/runs/${id}/inventory?kind=${encodeURIComponent(kind)}&limit=${limit}`),
  deleteRun: (id: string) =>
    request<{ deleted: boolean; files_removed?: boolean }>('DELETE', `/runs/${id}`),
  runSummary: (id: string) =>
    request<{ severity: Record<string, number>; triage: Record<string, number> }>(
      'GET', `/runs/${id}/summary`),
  runEvents: (id: string) => request<{ items: RunEvent[] }>('GET', `/runs/${id}/events`),
  directive: (id: string, text: string, kind = 'auto', target = '') =>
    request<{ queued: boolean; directive: RunDirective }>(
      'POST', `/runs/${id}/directive`, { text, kind, target }),
  directives: (id: string, limit = 60) =>
    request<{ items: RunDirective[] }>('GET', `/runs/${id}/directives?limit=${limit}`),
  findings: (q = '') => request<Paged<Finding>>('GET', `/findings${q}`),
  finding: (id: string) => request<Finding>('GET', `/findings/${id}`),
  createFinding: (body: Record<string, unknown>) =>
    request<Finding>('POST', '/findings', body),
  patchFinding: (id: string, patch: Partial<Finding>) =>
    request<Finding>('PATCH', `/findings/${id}`, patch),
  findingQuality: (id: string) =>
    request<{ finding_id: string; score: number; grade: string; artifacts: number; note: string; checks: { name: string; points: number; ok: boolean; hint: string }[]; missing: string[] }>(
      'GET', `/findings/${id}/quality`),
  candidatePocVerify: (candidateId: string) =>
    request<Record<string, unknown>>('POST', `/candidates/${candidateId}/poc/verify`, {}),
  missions: (q = '') => request<Paged<Mission>>('GET', `/missions${q}`),
  mission: (id: string) => request<Mission>('GET', `/missions/${id}`),
  missionNotes: (id: string) =>
    request<{ items: { id: string; kind: string; title: string; body: string; created_at: string }[] }>(
      'GET',
      `/missions/${id}/notes`
    ),
  createMission: (body: Record<string, unknown>) =>
    request<Mission>('POST', '/missions', body),
  patchMission: (id: string, body: Record<string, unknown>) =>
    request<Mission>('PATCH', `/missions/${id}`, body),
  deleteMission: (id: string) =>
    request<{ deleted: boolean }>('DELETE', `/missions/${id}`),
  startMissionRun: (id: string, body: Record<string, unknown>) =>
    request<{ mission: Mission; run: Run }>('POST', `/missions/${id}/runs`, body),
  startMissionHunt: (id: string) =>
    request<Run>('POST', `/missions/${id}/hunt`, {}),
  startMissionSolve: (id: string, body: Record<string, unknown> = {}) =>
    request<Run>('POST', `/missions/${id}/solve`, body),
  startMissionAutopilot: (id: string, body: Record<string, unknown> = {}) =>
    request<Run>('POST', `/missions/${id}/autopilot`, body),
  startMissionSwarm: (id: string, body: Record<string, unknown> = {}) =>
    request<Run>('POST', `/missions/${id}/swarm`, body),
  director: () => request<DirectorStatus>('GET', '/director'),
  directorControl: (body: Record<string, unknown>) =>
    request<DirectorStatus>('POST', '/director/control', body),
  directorLog: (limit = 100) =>
    request<{ items: DirectorLogEntry[] }>('GET', `/director/log?limit=${limit}`),
  missionGraph: (id: string) => request<MissionGraph>('GET', `/missions/${id}/graph`),
  threatMap: (id: string, limit = 80) =>
    request<ThreatMap>('GET', `/missions/${id}/threat-map?limit=${limit}`),
  buildMissionGraph: (id: string) =>
    request<{ nodes: number; edges: number; paths: number }>('POST', `/missions/${id}/graph/build`, {}),
  verifyPath: (pathId: string, body: Record<string, unknown> = {}) =>
    request<Run>('POST', `/paths/${pathId}/verify`, body),
  directions: (id: string, q = '') =>
    request<{ items: Direction[] }>('GET', `/missions/${id}/directions${q}`),
  queueDirection: (id: string, body: Record<string, unknown>) =>
    request<Direction>('POST', `/missions/${id}/directions`, body),
  campaign: (id: string) => request<Campaign>('GET', `/missions/${id}/campaign`),
  findingTrend: (days = 14) =>
    request<{ items: TrendPoint[] }>('GET', `/metrics/trend?days=${days}`),
  exploitPlan: (id: string, limit = 8) =>
    request<ExploitPlan>('GET', `/exploits/plan?mission_id=${id}&limit=${limit}`),
  buildExploitLeads: (id: string, limit = 5) =>
    request<{ created: Array<Record<string, unknown>>; count: number }>(
      'POST', `/missions/${id}/exploits/plan`, { limit }),
  exploitRun: (id: string, moduleId: string, policy = 'supervised') =>
    request<Run>('POST', `/missions/${id}/exploits/run`, {
      module_id: moduleId, policy
    }),
  candidates: (id: string, status = '') =>
    request<{ items: Candidate[] }>(
      'GET', `/missions/${id}/candidates${status ? `?status=${status}` : ''}`),
  promoteCandidate: (candidateId: string, body: Record<string, unknown> = {}) =>
    request<{ candidate: Candidate; finding: Finding }>(
      'POST', `/candidates/${candidateId}/promote`, body),
  dismissCandidate: (candidateId: string) =>
    request<Candidate>('POST', `/candidates/${candidateId}/dismiss`, {}),
  campaignStart: (target: string, title = '', objective = '') =>
    request<{
      mission: Mission;
      director: DirectorStatus;
      brain?: Record<string, unknown>;
      bootstrapping?: boolean;
      note?: string;
    }>('POST', '/campaigns', { target, title, objective }),
  brainContext: (missionId = '') =>
    request<Record<string, unknown>>(
      'GET', `/brain/context${missionId ? `?mission_id=${missionId}` : ''}`),
  brainChat: (message: string, body: Record<string, unknown> = {}) =>
    request<BrainReply>('POST', '/brain/chat', { message, ...body }),
  brainJournal: (limit = 60, missionId = '', sessionId = '') =>
    request<{ items: BrainTurn[]; loop: BrainLoopStatus }>(
      'GET',
      `/brain/journal?limit=${limit}${missionId ? `&mission_id=${missionId}` : ''}${sessionId ? `&session_id=${sessionId}` : ''}`),
  brainLive: (limit = 80, missionId = '', sessionId = '') =>
    request<BrainLiveFeed>(
      'GET',
      `/brain/live?limit=${limit}${missionId ? `&mission_id=${missionId}` : ''}${sessionId ? `&session_id=${sessionId}` : ''}`),
  brainSessions: (missionId = '', archived = false) =>
    request<{ items: BrainSession[] }>(
      'GET',
      `/brain/sessions?limit=40${missionId ? `&mission_id=${missionId}` : ''}${archived ? '&archived=1' : ''}`),
  brainSession: (id: string) => request<BrainSession>('GET', `/brain/sessions/${id}`),
  brainSessionCreate: (body: Record<string, unknown>) =>
    request<BrainSession>('POST', '/brain/sessions', body),
  brainSessionPatch: (id: string, body: Record<string, unknown>) =>
    request<BrainSession>('PATCH', `/brain/sessions/${id}`, body),
  brainSessionDelete: (id: string) =>
    request<{ deleted: boolean }>('DELETE', `/brain/sessions/${id}`),
  brainSessionFork: (id: string, title = '') =>
    request<BrainSession>('POST', `/brain/sessions/${id}/fork`, { title }),
  brainSessionMessages: (id: string, limit = 500) =>
    request<{ items: BrainTurn[] }>('GET', `/brain/sessions/${id}/messages?limit=${limit}`),
  brainLoop: (action = 'status', interval = 0) =>
    request<BrainLoopStatus>('POST', '/brain/loop',
      interval ? { action, interval } : { action }),
  instruct: (message: string, body: Record<string, unknown> = {}) =>
    request<Record<string, unknown>>('POST', '/instruct', { message, ...body }),
  missionCoverage: (id: string) =>
    request<CoverageSummary>('GET', `/missions/${id}/coverage`),
  markCoverage: (id: string, body: Record<string, unknown>) =>
    request<Record<string, unknown>>('POST', `/missions/${id}/coverage`, body),
  bench: () => request<BenchResult>('GET', '/bench?gate=1', undefined, 240000),
  harnessStatus: () => request<HarnessStatus>('GET', '/harness'),
  harnessDiagnose: (missionId = '', limit = 8) =>
    request<HarnessDiagnose>(
      'GET',
      `/harness/diagnose?limit=${limit}${missionId ? `&mission_id=${encodeURIComponent(missionId)}` : ''}`,
      180000),
  harnessLearn: (body: Record<string, unknown> = {}) =>
    request<HarnessLearn>('POST', '/harness/learn', body, 240000),
  harnessTick: (body: Record<string, unknown> = {}) =>
    request<HarnessTick>('POST', '/harness/tick', body, 240000),
  harnessRecall: (missionId = '', goal = '') =>
    request<HarnessRecall>(
      'GET',
      `/harness/recall?${[
        missionId ? `mission_id=${encodeURIComponent(missionId)}` : '',
        goal ? `goal=${encodeURIComponent(goal)}` : ''
      ]
        .filter(Boolean)
        .join('&')}`),
  hypotheses: (missionId: string) =>
    request<Paged<Hypothesis>>('GET', `/hypotheses?mission_id=${missionId}&size=100`),
  hypothesisEvidence: (id: string) =>
    request<HypothesisEvidence>('GET', `/hypotheses/${id}/evidence`),
  syncLeads: (id: string, limit = 3) =>
    request<{ counts: { created: number; skipped: number } }>(
      'POST', `/missions/${id}/leads/sync`, { limit }),
  programPreview: (id: string, body: Record<string, unknown>) =>
    request<ProgramPreview>('POST', `/missions/${id}/program/preview`, body),
  programImport: (id: string, body: Record<string, unknown>) =>
    request<ProgramPreview>('POST', `/missions/${id}/program`, body),
  programImports: (id: string) =>
    request<{ items: ProgramImport[] }>('GET', `/missions/${id}/program/imports`),
  surfaceSeed: (id: string, hosts: string[], probe = true) =>
    request<{
      accepted: number;
      hosts_live: number;
      hosts_unresolved: number;
      hosts_rejected: number;
      live: Array<{ host: string; status: number | null; title: string; url: string }>;
      rejected: string[];
      note: string;
    }>('POST', `/missions/${id}/surface/seed`, { hosts, probe }),
  hostCapabilities: () =>
    request<{ host: string; user: string; tools: Record<string, boolean> }>(
      'GET', '/host/capabilities'),
  hostShell: (command: string, cwd = '', timeout = 60) =>
    request<HostShellResult>('POST', '/host/shell', { command, cwd, timeout },
      Math.min(300000, (timeout + 15) * 1000)),
  hostList: (path = '.') =>
    request<{ path: string; count: number; entries: Array<Record<string, unknown>> }>(
      'GET', `/host/list?path=${encodeURIComponent(path)}`),
  missionAgent: (id: string) =>
    request<MissionAgent>('GET', `/missions/${id}/agent`),
  startMissionAgent: (id: string, body: Record<string, unknown>) =>
    request<MissionAgent>('POST', `/missions/${id}/agent/start`, body, 180000),
  pauseMissionAgent: (id: string) =>
    request<MissionAgent>('POST', `/missions/${id}/agent/pause`, {}),
  resumeMissionAgent: (id: string) =>
    request<MissionAgent>('POST', `/missions/${id}/agent/resume`, {}),
  stopMissionAgent: (id: string) =>
    request<MissionAgent>('POST', `/missions/${id}/agent/stop`, {}),
  labRecipes: () => request<{ items: Array<Record<string, unknown>>; total: number }>('GET', '/labs/recipes'),
  startLabRun: (body: Record<string, unknown>) =>
    request<Run>('POST', '/labs/run', body),
  approvals: (q = '') => request<Paged<Approval>>('GET', `/approvals${q}`),
  createApproval: (body: Record<string, unknown>) =>
    request<Approval>('POST', '/approvals', body),
  decideApproval: (id: string, body: Record<string, unknown>) =>
    request<Approval>('POST', `/approvals/${id}/decision`, body),
  submissions: (q = '') => request<Paged<Submission>>('GET', `/submissions${q}`),
  submission: (id: string) => request<Submission>('GET', `/submissions/${id}`),
  submissionSummary: () => request<SubmissionSummary>('GET', '/submissions/summary'),
  createSubmission: (body: Record<string, unknown>) =>
    request<Submission>('POST', '/submissions', body),
  patchSubmission: (id: string, body: Record<string, unknown>) =>
    request<Submission>('PATCH', `/submissions/${id}`, body),
  deleteSubmission: (id: string) =>
    request<{ deleted: boolean }>('DELETE', `/submissions/${id}`),
  submissionPoc: (id: string) =>
    request<{ submission_id: string; finding_id: string; report_path: string; markdown: string }>(
      'GET',
      `/submissions/${id}/poc`
    ),
  findingPoc: (id: string) =>
    request<{ finding_id: string; title: string; markdown: string }>('GET', `/findings/${id}/poc`),
  keys: () => request<{ items: KeyEntry[] }>('GET', '/keys'),
  putKey: (name: string, value: string) =>
    request<{ name: string; masked: string }>('PUT', `/keys/${name}`, { value }),
  deleteKey: (name: string) => request<{ deleted: boolean }>('DELETE', `/keys/${name}`),
  providers: () => request<{ items: Provider[] }>('GET', '/providers'),
  providersHealth: () => request<{ items: ProviderHealth[] }>('GET', '/providers/health'),
  addProvider: (body: Record<string, unknown>) => request<Provider>('POST', '/providers', body),
  patchProvider: (id: string, body: Record<string, unknown>) =>
    request<Provider>('PATCH', `/providers/${id}`, body),
  deleteProvider: (id: string) =>
    request<{ deleted: boolean; key_removed?: boolean }>('DELETE', `/providers/${id}`),
  testProvider: (id: string) =>
    request<{ ok: boolean; reason: string; latency_ms?: number; models?: string[]; detail?: string }>(
      'POST', `/providers/${id}/test`),
  settings: () => request<{ items: Record<string, unknown> }>('GET', '/settings'),
  patchSettings: (patch: Record<string, unknown>) =>
    request<{ items: Record<string, unknown> }>('PATCH', '/settings', patch),
  revengKinds: () => request<RevengKinds>('GET', '/reveng/kinds'),
  revengAnalyze: (body: Record<string, unknown>) =>
    request<RevengResult>('POST', '/reveng/analyze', body, 600000),
  mcpInfo: () => request<McpInfo>('GET', '/mcp'),
  toolCalls: (q = '') => request<Paged<ToolCall>>('GET', `/tool-calls${q}`),
  toolCall: (id: string) => request<ToolCall>('GET', `/tool-calls/${id}`),
  eventsUrl: (runId?: string) =>
    runId ? `${BASE}/runs/${runId}/events/stream` : `${BASE}/events/stream`
};
