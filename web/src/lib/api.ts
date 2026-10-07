import type { Finding, KeyEntry, Meta, Paged, Provider, Run, RunEvent, Totals } from './types';

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

export const api = {
  meta: () => request<Meta>('GET', '/meta'),
  totals: () => request<Totals>('GET', '/summary'),
  runs: (q = '') => request<Paged<Run>>('GET', `/runs${q}`),
  run: (id: string) => request<Run>('GET', `/runs/${id}`),
  startRun: (target: string, options: Record<string, unknown>) =>
    request<Run>('POST', '/runs', { target, options }),
  stopRun: (id: string) => request<{ stopped: boolean }>('POST', `/runs/${id}/stop`),
  rerun: (id: string) => request<Run>('POST', `/runs/${id}/rerun`),
  deleteRun: (id: string) => request<{ deleted: boolean }>('DELETE', `/runs/${id}`),
  runSummary: (id: string) =>
    request<{ severity: Record<string, number>; triage: Record<string, number> }>(
      'GET', `/runs/${id}/summary`),
  runEvents: (id: string) => request<{ items: RunEvent[] }>('GET', `/runs/${id}/events`),
  findings: (q = '') => request<Paged<Finding>>('GET', `/findings${q}`),
  finding: (id: string) => request<Finding>('GET', `/findings/${id}`),
  patchFinding: (id: string, patch: Partial<Finding>) =>
    request<Finding>('PATCH', `/findings/${id}`, patch),
  keys: () => request<{ items: KeyEntry[] }>('GET', '/keys'),
  putKey: (name: string, value: string) =>
    request<{ name: string; masked: string }>('PUT', `/keys/${name}`, { value }),
  deleteKey: (name: string) => request<{ deleted: boolean }>('DELETE', `/keys/${name}`),
  providers: () => request<{ items: Provider[] }>('GET', '/providers'),
  addProvider: (body: Record<string, string>) => request<Provider>('POST', '/providers', body),
  deleteProvider: (id: string) => request<{ deleted: boolean }>('DELETE', `/providers/${id}`),
  testProvider: (id: string) =>
    request<{ ok: boolean; reason: string; latency_ms?: number; models?: string[]; detail?: string }>(
      'POST', `/providers/${id}/test`),
  settings: () => request<{ items: Record<string, unknown> }>('GET', '/settings'),
  patchSettings: (patch: Record<string, unknown>) =>
    request<{ items: Record<string, unknown> }>('PATCH', '/settings', patch),
  eventsUrl: (runId?: string) =>
    runId ? `${BASE}/runs/${runId}/events/stream` : `${BASE}/events/stream`
};
