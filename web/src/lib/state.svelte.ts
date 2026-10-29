import { api } from './api';
import { stageForAgent } from './format';
import type { Finding, Meta, Run, RunEvent, Screen, Toast, Totals } from './types';

class Store {
  meta = $state<Meta | null>(null);
  totals = $state<Totals | null>(null);
  runs = $state<Run[]>([]);
  findings = $state<Finding[]>([]);
  screen = $state<Screen>('home');
  activeRunId = $state('');
  liveRun = $state<Run | null>(null);
  liveTab = $state('');
  locked = $state(false);
  ready = $state(false);
  busy = $state('');
  palette = $state(false);
  query = $state('');
  toasts = $state<Toast[]>([]);
  toastSeq = 0;
  lastSync = $state(0);
  syncState = $state<'idle' | 'syncing' | 'error'>('idle');
  heartbeat: number | undefined;
  liveRunId = $state('');
  liveStage = $state('');
  liveThought = $state('');
  liveEventAt = $state(0);
  source: EventSource | null = null;

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('nc:locked', () => {
        this.locked = true;
      });
      window.addEventListener('hashchange', () => this.applyHash());
    }
  }

  /** #/live/run_123 -> screen + active run. Returns true when a link set the screen. */
  applyHash(): boolean {
    const raw = window.location.hash.replace(/^#\/?/, '');
    if (!raw) return false;
    const [screen, id] = raw.split('/');
    const known: Screen[] = ['home', 'missions', 'new', 'live', 'findings', 'runs', 'agent', 'reports', 'keys', 'reveng', 'help'];
    const legacy = screen === 'engine' ? 'live' : (screen as Screen);
    if (!known.includes(legacy)) return false;
    this.screen = legacy;
    if (id) this.activeRunId = id;
    return true;
  }

  syncHash(): void {
    const tracked = this.screen === 'live';
    const next = `#/${this.screen}${tracked && this.activeRunId ? `/${this.activeRunId}` : ''}`;
    if (window.location.hash !== next) window.location.hash = next;
  }

  async boot(): Promise<void> {
    const linked = this.applyHash();
    const work = (async () => {
      this.meta = await api.meta();
      await Promise.all([this.refreshTotals(), this.refreshRuns()]);
      if (linked) return;
      const running = this.runs.find((run) => run.status === 'running');
      if (running) {
        this.activeRunId = running.id;
        this.liveRun = running;
        this.screen = 'live';
      }
    })();
    let failed = false;
    const settled = work.then(
      () => false,
      () => {
        failed = true;
        return false;
      }
    );
    const timedOut = new Promise<boolean>((resolve) => window.setTimeout(() => resolve(true), 8000));
    if (await Promise.race([settled, timedOut])) {
      this.toast('warn', 'the server is slow to answer; showing what has loaded so far');
    } else if (failed) {
      this.toast('error', 'the dashboard server did not answer; start it with netcast3r ui');
    }
    this.ready = true;
    this.syncHash();
  }

  go(screen: Screen, runId = ''): void {
    this.screen = screen;
    if (runId) this.activeRunId = runId;
    this.syncHash();
    window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
  }

  watch(runId: string, tab = ''): void {
    this.activeRunId = runId;
    this.liveTab = tab;
    this.screen = 'live';
    this.syncHash();
  }

  /** Select a run without changing screens (used by the live inspector). */
  select(runId: string): void {
    this.activeRunId = runId;
    this.syncHash();
  }

  async refreshTotals(): Promise<void> {
    try {
      this.totals = await api.totals();
      this.lastSync = Date.now();
      this.syncState = 'idle';
    } catch {
      this.syncState = 'error';
      /* a refresh failure must not blank the screen */
    }
  }

  async refreshRuns(): Promise<void> {
    try {
      const page = await api.runs('?size=25');
      this.runs = page.items;
      this.lastSync = Date.now();
      this.syncState = 'idle';
    } catch {
      this.syncState = 'error';
      /* offline from the backend */
    }
  }

  /** Poll the small control-plane endpoints so every screen feels alive.
   *  Active runs get a faster cadence; an idle dashboard stays quiet. */
  async refreshPulse(): Promise<void> {
    if (this.syncState === 'syncing') return;
    this.syncState = 'syncing';
    try {
      const [totals, page] = await Promise.all([api.totals(), api.runs('?size=25')]);
      this.totals = totals;
      this.runs = page.items;
      const active = page.items.find((run) => run.status === 'running' || run.status === 'queued');
      if (!active) {
        this.liveRunId = '';
        this.liveStage = '';
        this.liveThought = '';
      }
      this.lastSync = Date.now();
      this.syncState = 'idle';
    } catch {
      this.syncState = 'error';
    }
  }

  startHeartbeat(): void {
    if (this.heartbeat) return;
    this.startLiveStream();
    const tick = () => {
      if (typeof document === 'undefined' || !document.hidden) void this.refreshPulse();
      const active = this.runs.some((run) => run.status === 'running' || run.status === 'queued');
      this.heartbeat = window.setTimeout(tick, active ? 2500 : 12000);
    };
    this.heartbeat = window.setTimeout(tick, 2500);
  }

  stopHeartbeat(): void {
    if (this.heartbeat) window.clearTimeout(this.heartbeat);
    this.heartbeat = undefined;
    this.source?.close();
    this.source = null;
  }

  /** One global SSE connection feeds the shell's live status rail. The
   *  inspector opens its own run-scoped stream so history can replay. */
  startLiveStream(): void {
    if (this.source) return;
    try {
      const stream = new EventSource(api.eventsUrl());
      stream.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as RunEvent;
          if (!event.run_id) return;
          this.liveRunId = event.run_id;
          this.liveEventAt = Math.round(event.ts * 1000);
          const stage = event.stage || stageForAgent(event.agent);
          if (stage) this.liveStage = stage;
          if (event.type === 'reasoning' && event.payload?.text) {
            this.liveThought = String(event.payload.text).replace(/\s+/g, ' ').slice(-280);
          }
          if (event.type === 'run.finished' || event.type === 'run.state') {
            void this.refreshPulse();
          }
        } catch {
          /* ignore a malformed frame */
        }
      };
      this.source = stream;
    } catch {
      /* no EventSource in this browser; polling still works */
    }
  }

  async refreshFindings(query = '?size=100'): Promise<void> {
    try {
      const page = await api.findings(query);
      this.findings = page.items;
    } catch {
      /* offline from the backend */
    }
  }

  async activeRun(): Promise<Run | null> {
    if (!this.activeRunId) return null;
    try {
      const run = await api.run(this.activeRunId);
      this.liveRun = run;
      return run;
    } catch {
      return null;
    }
  }

  toast(kind: Toast['kind'], text: string): void {
    const id = ++this.toastSeq;
    this.toasts = [...this.toasts, { id, kind, text }];
    window.setTimeout(() => {
      this.toasts = this.toasts.map((toast) =>
        toast.id === id ? { ...toast, leaving: true } : toast
      );
    }, 3980);
    window.setTimeout(() => {
      this.toasts = this.toasts.filter((toast) => toast.id !== id);
    }, 4200);
  }

  async fail(message: string): Promise<void> {
    this.toast('error', message);
  }
}

export const store = new Store();
