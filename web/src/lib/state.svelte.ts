import { api } from './api';
import type { Finding, Meta, Run, Screen, Toast, Totals } from './types';

class Store {
  meta = $state<Meta | null>(null);
  totals = $state<Totals | null>(null);
  runs = $state<Run[]>([]);
  findings = $state<Finding[]>([]);
  screen = $state<Screen>('home');
  activeRunId = $state('');
  liveRun = $state<Run | null>(null);
  locked = $state(false);
  ready = $state(false);
  busy = $state('');
  query = $state('');
  toasts = $state<Toast[]>([]);
  toastSeq = 0;

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
    const known: Screen[] = ['home', 'new', 'live', 'findings', 'runs', 'keys', 'help'];
    if (!known.includes(screen as Screen)) return false;
    this.screen = screen as Screen;
    if (id) this.activeRunId = id;
    return true;
  }

  syncHash(): void {
    const next = `#/${this.screen}${this.screen === 'live' && this.activeRunId ? `/${this.activeRunId}` : ''}`;
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
    const settled = work.then(
      () => false,
      () => false
    );
    const timedOut = new Promise<boolean>((resolve) => window.setTimeout(() => resolve(true), 8000));
    if (await Promise.race([settled, timedOut])) {
      this.toast('warn', 'the server is slow to answer; showing what has loaded so far');
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

  watch(runId: string): void {
    this.activeRunId = runId;
    this.screen = 'live';
    this.syncHash();
  }

  async refreshTotals(): Promise<void> {
    try {
      this.totals = await api.totals();
    } catch {
      /* a refresh failure must not blank the screen */
    }
  }

  async refreshRuns(): Promise<void> {
    try {
      const page = await api.runs('?size=25');
      this.runs = page.items;
    } catch {
      /* offline from the backend */
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
      this.toasts = this.toasts.filter((toast) => toast.id !== id);
    }, 4200);
  }

  async fail(message: string): Promise<void> {
    this.toast('error', message);
  }
}

export const store = new Store();
