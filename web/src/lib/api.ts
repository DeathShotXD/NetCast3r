import type {
  ConnectInfo, Approval, DirectorLogEntry, DirectorStatus, Finding, Inventory, KeyEntry, McpInfo, Meta, Mission, MissionAgent, MissionGraph, Paged, Provider, ProviderHealth, RevengKinds, RevengResult, Run, RunEvent, Submission, SubmissionSummary, ToolCall, Totals } from './types';

const BASE = '/api/v1';

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  } catch {
    throw new Error('the dashboard server is not reachable');
  }
  if (res.status === 401) {
    window.dispatchEvent(new Event('nc:locked'));
    throw new Error('session token required');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const problem = (await res.json()) as { detail?: string };
      detail = problem.detail || detail;
    } catch {
      /* keep status text */
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

async function requestText(path: string): Promise<string> {
  let res: Response;
  try {
    res = await fetch(BASE + path, { credentials: 'same-origin' });
  } catch {
    throw new Error('the dashboard server is not reachable');
  }
  if (res.status === 401) {
    window.dispatchEvent(new Event('nc:locked'));
    throw new Error('session token required');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const problem = (await res.json()) as { detail?: string };
      detail = problem.detail || detail;
    } catch {
      /* keep status text */
    }
    throw new Error(detail);
  }
  return await res.text();
}

export const api = {
  meta: () => request<Meta>('GET', '/meta'),
  totals: () => request<Totals>('GET', '/summary'),
  connect: () => request<ConnectInfo>('GET', '/connect'),
  runs: (q = '') => request<Paged<Run>>('GET', `/runs${q}`),
  run: (id: string) => request<Run>('GET', `/runs/${id}`),
  runReport: (id: string) => requestText(`/runs/${id}/report`),
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
  findings: (q = '') => request<Paged<Finding>>('GET', `/findings${q}`),
  finding: (id: string) => request<Finding>('GET', `/findings/${id}`),
  createFinding: (body: Record<string, unknown>) =>
    request<Finding>('POST', '/findings', body),
  patchFinding: (id: string, patch: Partial<Finding>) =>
    request<Finding>('PATCH', `/findings/${id}`, patch),
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
  buildMissionGraph: (id: string) =>
    request<{ nodes: number; edges: number; paths: number }>('POST', `/missions/${id}/graph/build`, {}),
  verifyPath: (pathId: string, body: Record<string, unknown> = {}) =>
    request<Run>('POST', `/paths/${pathId}/verify`, body),
  missionAgent: (id: string) =>
    request<MissionAgent>('GET', `/missions/${id}/agent`),
  startMissionAgent: (id: string, body: Record<string, unknown>) =>
    request<MissionAgent>('POST', `/missions/${id}/agent/start`, body),
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
  settings: () => request<{ items: Record<string, unknown> }>('GET', '/settings'),  patchSettings: (patch: Record<string, unknown>) =>
    request<{ items: Record<string, unknown> }>('PATCH', '/settings', patch),
  revengKinds: () => request<RevengKinds>('GET', '/reveng/kinds'),
  revengAnalyze: (body: Record<string, unknown>) =>
    request<RevengResult>('POST', '/reveng/analyze', body),
  mcpInfo: () => request<McpInfo>('GET', '/mcp'),
  toolCalls: (q = '') => request<Paged<ToolCall>>('GET', `/tool-calls${q}`),
  toolCall: (id: string) => request<ToolCall>('GET', `/tool-calls/${id}`),
  eventsUrl: (runId?: string) =>
    runId ? `${BASE}/runs/${runId}/events/stream` : `${BASE}/events/stream`
};
