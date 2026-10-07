import { AGENT_STAGE, SEVERITIES, STAGES, STATES } from '../tokens';

export type Shape = 'dot' | 'tri' | 'sq' | 'dia' | 'ring' | 'none';

const STAGE_KEYS = (STAGES as unknown as { key: string }[]).map((stage) => stage.key);

/** Which pipeline stage a log line belongs to, same mapping the console uses. */
export function stageForAgent(agent: string): string {
  return (AGENT_STAGE as Record<string, string>)[agent] ?? '';
}

/** Every stage that is behind the current one, for the rail. */
export function finishedThrough(current: string): string[] {
  const at = STAGE_KEYS.indexOf(current);
  return at <= 0 ? [] : STAGE_KEYS.slice(0, at);
}

export function allStages(): string[] {
  return [...STAGE_KEYS];
}

const SEV_SHAPE: Record<string, Shape> = {
  critical: 'tri',
  high: 'sq',
  medium: 'dia',
  low: 'dot',
  info: 'ring',
  none: 'ring',
  unknown: 'ring'
};

const FALLBACK_COLOR = '#9698A2';

export function sevColor(severity: string): string {
  const key = severity as keyof typeof SEVERITIES;
  return (SEVERITIES[key] ?? FALLBACK_COLOR) as string;
}

export function sevShape(severity: string): Shape {
  return SEV_SHAPE[severity] ?? 'ring';
}

export function stateColor(state: string): string {
  const key = (state || 'unknown') as keyof typeof STATES;
  return (STATES[key] ?? STATES.unknown) as string;
}

export function triageLabel(status: string): string {
  return (
    {
      new: 'needs review',
      confirmed: 'confirmed',
      in_progress: 'checking',
      escalated: 'escalate-ready',
      rejected: 'rejected',
      false_positive: 'not an issue'
    }[status] ?? status
  );
}

/** Parse a backend timestamp (with or without a zone suffix) to epoch ms. */
export function isoMs(iso: string): number {
  if (!iso) return Number.NaN;
  const zoned = iso.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(iso) ? iso : `${iso}Z`;
  const ms = new Date(zoned).getTime();
  return Number.isFinite(ms) ? ms : Number.NaN;
}

export function ago(iso: string): string {
  if (!iso) return 'now';
  const then = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
  const seconds = Math.max(0, (Date.now() - then.getTime()) / 1000);
  if (seconds < 45) return 'just now';
  if (seconds < 90) return 'a minute ago';
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function clock(ts: number | string): string {
  const date = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function statusLabel(status: string): string {
  return (
    {
      queued: 'queued',
      running: 'running',
      done: 'complete',
      failed: 'failed',
      stopped: 'stopped',
      interrupted: 'interrupted'
    }[status] ?? status
  );
}

export function statusColor(status: string): string {
  return (
    {
      queued: 'var(--nc-ash)',
      running: 'var(--nc-acid)',
      done: 'var(--nc-gold)',
      failed: 'var(--nc-violet)',
      stopped: 'var(--nc-bone_dust)',
      interrupted: 'var(--nc-slate)'
    }[status] ?? 'var(--nc-ash)'
  );
}
