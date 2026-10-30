<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import { api } from '../api';
  import { AGENT_COLORS, STAGES } from '../../tokens';
  import { clock, finishedThrough, isoMs, sevColor, sevShape, stageForAgent, statusColor, statusLabel } from '../format';
  import { renderMarkdown } from '../markdown';
  import { store } from '../state.svelte';
  import type { Run, RunEvent } from '../types';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import RunScope from '../ui/RunScope.svelte';
  import StageRail from '../ui/StageRail.svelte';
  import StageSignal from '../ui/StageSignal.svelte';
  import { countup, spotlight } from '../actions';

  const stages = STAGES as unknown as { key: string; label: string }[];
  const LAB_STAGES = [
    { key: 'launch', label: 'Launch', detail: 'Start the lab instance' },
    { key: 'identity', label: 'Identity', detail: 'Log in with an owned account' },
    { key: 'test', label: 'Test', detail: 'Run the minimum exploit steps' },
    { key: 'verify', label: 'Verify', detail: 'Check the solved banner' },
    { key: 'record', label: 'Record', detail: 'Store evidence and the lesson' }
  ];
  const HUNT_STAGES = [
    { key: 'scope', label: 'Scope', detail: 'Confirm the mission boundary' },
    { key: 'fingerprint', label: 'Fingerprint', detail: 'Read headers and title' },
    { key: 'surface', label: 'Surface', detail: 'Check safe public paths' },
    { key: 'research', label: 'Research', detail: 'Rank techniques and chains' },
    { key: 'hypotheses', label: 'Hypotheses', detail: 'Record falsifiable leads' }
  ];
  const TERMINAL = ['done', 'failed', 'stopped', 'interrupted'];
  const RESUMABLE = ['stopped', 'interrupted', 'failed'];
  const BUCKET_MS = 250;
  const BUCKETS = 96;
  const STREAM_CAP = 700;

  type StreamRow = { seq: number; ts: number; kind: string; agent: string; text: string; sub: string };

  const TABS: { id: string; label: string }[] = [
    { id: 'feed', label: 'transmission' },
    { id: 'assets', label: 'assets' },
    { id: 'endpoints', label: 'endpoints' },
    { id: 'js', label: 'js & code' },
    { id: 'secrets', label: 'secrets' },
    { id: 'findings', label: 'findings' },
    { id: 'report', label: 'report' }
  ];

  const FILTERS: { id: string; label: string }[] = [
    { id: 'all', label: 'everything' },
    { id: 'log', label: 'logs' },
    { id: 'think', label: 'thinking' },
    { id: 'url', label: 'fetches' },
    { id: 'call', label: 'model calls' },
    { id: 'found', label: 'findings' }
  ];

  const TAB_KINDS: Record<string, string[]> = {
    assets: ['subdomains', 'pages'],
    endpoints: ['endpoints'],
    js: ['js', 'reviews'],
    secrets: ['secrets', 'candidates', 'corroborations'],
    findings: ['findings']
  };

  let run = $state<Run | null>(null);
  const runMode = $derived(String((run?.options as Record<string, unknown> | undefined)?.mode ?? ''));
  const isLab = $derived(runMode === 'lab');
  const isHunt = $derived(runMode === 'hunt');
  const displayStages = $derived(isLab ? LAB_STAGES : isHunt ? HUNT_STAGES : stages);
  const displayTabs = $derived((isLab || isHunt) ? TABS.filter((item) => item.id === 'feed' || item.id === 'report') : TABS);
  let events = $state<RunEvent[]>([]);
  let counts = $state<Record<string, number>>({});
  let landed = $state<{ id: number; status: string; secret_type: string; value: string; detail: string }[]>([]);
  let currentStage = $state('');
  let follow = $state(true);
  let filter = $state('all');
  let tab = $state(store.liveTab || 'feed');
  let stopOpen = $state(false);
  let stop = $state<() => void>(() => {});
  let continuing = $state(false);
  let streamBox: HTMLDivElement | undefined = $state();

  // run signal: events, buckets, stages, per agent tail
  let eventCount = $state(0);
  let urlCount = $state(0);
  let stageCounts = $state<Record<string, number>>({});
  let buckets = $state<number[]>(new Array(BUCKETS).fill(0));
  let nowTick = $state(Date.now());
  let crawled = $state(0);
  let pending = 0;
  let agents = $state<Record<string, { lines: number; calls: number; lastTs: number; lastText: string; lastCall: string; lastCallOk: boolean | null }>>({});

  // per run evidence, loaded on demand
  let inv = $state<Record<string, any[]>>({});
  let loadedInv = $state<Record<string, boolean>>({});
  let invBusy = $state('');
  const inflight = new Set<string>();

  // report preview
  let report = $state('');
  let reportErr = $state('');

  // agent spotlight
  let spotlightAgent = $state('');
  let spotlightEl = $state<HTMLDivElement | undefined>(undefined);
  let spotlightStick = $state(true);
  let panelEl = $state<HTMLElement | undefined>(undefined);

  const finished = $derived(!!run && TERMINAL.includes(run.status));
  const running = $derived(!!run && (run.status === 'running' || run.status === 'queued'));
  const canContinue = $derived(!!run && RESUMABLE.includes(run.status) && !continuing);

  const elapsed = $derived.by(() => {
    if (!run) return '--:--';
    const start = isoMs(run.started_at || run.created_at);
    if (!Number.isFinite(start)) return '--:--';
    const end = running ? nowTick : run.finished_at ? isoMs(run.finished_at) : nowTick;
    const seconds = Math.max(0, Math.floor((end - start) / 1000));
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  });

  const rate = $derived.by(() => {
    const win = buckets.slice(-8);
    const total = win.reduce((sum, value) => sum + value, 0);
    return total / ((win.length * BUCKET_MS) / 1000);
  });

  const stageCount = $derived.by(() => {
    const next: Record<string, number> = {};
    for (const stage of displayStages) next[stage.key] = stageCounts[stage.key] ?? 0;
    if (!isLab && !isHunt) next.crawl = Math.max(next.crawl ?? 0, crawled);
    return next;
  });

  /** One chronological stream: logs, model reasoning, fetches, calls,
   *  findings. Reasoning fragments from the same agent within 5s fuse
   *  into one row so the transmission reads like sentences, not tokens. */
  const streamAll = $derived.by<StreamRow[]>(() => {
    const rows: StreamRow[] = [];
    let think: StreamRow | null = null;
    for (const event of events) {
      if (event.type === 'lagged') continue;
      const agent = event.agent || 'run';
      if (event.type === 'log' || event.type === 'error') {
        rows.push({
          seq: event.seq, ts: event.ts, kind: event.type === 'error' ? 'err' : 'log', agent,
          text: String(event.payload?.text ?? event.payload?.error ?? ''), sub: ''
        });
        think = null;
      } else if (event.type === 'reasoning' && event.payload?.text) {
        const raw = String(event.payload.text).trim();
        if (!raw) continue;
        if (think && think.agent === agent && event.ts - think.ts < 5000) {
          think.text = `${think.text} ${raw}`.replace(/\s+/g, ' ').slice(-1800);
          think.ts = event.ts;
          think.seq = event.seq;
        } else {
          think = { seq: event.seq, ts: event.ts, kind: 'think', agent, text: raw.slice(0, 900), sub: '' };
          rows.push(think);
        }
      } else if (event.type === 'fetch' && event.payload?.url) {
        if (String(event.payload.kind ?? '') === 'progress') continue;
        rows.push({
          seq: event.seq, ts: event.ts, kind: 'url', agent,
          text: String(event.payload.url), sub: String(event.payload.status ?? '--')
        });
        think = null;
      } else if (event.type === 'model' && event.payload?.kind === 'done') {
        const payload = event.payload;
        rows.push({
          seq: event.seq, ts: event.ts, kind: 'call', agent,
          text: `${String(payload.provider ?? '?')}/${String(payload.model ?? '?')}`,
          sub: `${payload.ok ? 'ok' : 'failed'} ${Number(payload.ms ?? 0)}ms${payload.error ? ` / ${String(payload.error)}` : ''}`
        });
        think = null;
      } else if (event.type === 'finding.created' && event.payload) {
        rows.push({
          seq: event.seq, ts: event.ts, kind: 'found', agent,
          text: `${String(event.payload.secret_type ?? 'secret')} / ${String(event.payload.value ?? '')}`,
          sub: String(event.payload.status ?? '')
        });
        think = null;
      }
    }
    return rows;
  });

  const stream = $derived.by(() => {
    const rows = filter === 'all'
      ? streamAll
      : streamAll.filter((row) => filter === 'log' ? row.kind === 'log' || row.kind === 'err' : row.kind === filter);
    return rows.slice(-STREAM_CAP);
  });
  const lastSeq = $derived(stream.length ? stream[stream.length - 1].seq : 0);
  const reasoningCount = $derived(streamAll.filter((row) => row.kind === 'think').length);
  const agentList = $derived(
    Object.entries(agents)
      .map(([agent, stats]) => ({ agent, ...stats }))
      .filter((item) => item.lines > 0)
      .sort((a, b) => b.lastTs - a.lastTs)
  );
  const spotlightRows = $derived(
    spotlightAgent ? streamAll.filter((row) => row.agent === spotlightAgent).slice(-400) : []
  );

  function badgeOf(row: StreamRow): { text: string; color: string } {
    if (row.kind === 'log') return { text: 'log', color: 'var(--nc-ash)' };
    if (row.kind === 'err') return { text: 'err', color: 'var(--nc-violet)' };
    if (row.kind === 'think') return { text: 'think', color: (AGENT_COLORS as Record<string, string>)[row.agent] ?? 'var(--nc-bone-dust)' };
    if (row.kind === 'url') return { text: 'fetch', color: 'var(--nc-acid)' };
    if (row.kind === 'call') return { text: 'model', color: 'var(--nc-bone-dust)' };
    return { text: 'found', color: 'var(--nc-violet)' };
  }

  function rowColor(row: StreamRow): string {
    if (row.kind === 'err') return 'var(--nc-violet)';
    if (row.kind === 'think') return 'var(--nc-bone-dust)';
    if (row.kind === 'call') return 'var(--nc-ash)';
    return 'var(--nc-bone)';
  }

  function formatText(text: string, cap = 420): string {
    // Model output occasionally arrives with a newline or a wide gap between
    // every character. Collapse it so the transmission stays readable.
    return String(text ?? '').replace(/\s+/g, ' ').trim().slice(0, cap);
  }

  const seen = new Set<number>();
  let queue: RunEvent[] = [];
  let flushScheduled = false;

  function push(event: RunEvent) {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    queue.push(event);
    if (!flushScheduled) {
      flushScheduled = true;
      requestAnimationFrame(() => void flushQueue());
      window.setTimeout(() => void flushQueue(), 400); // rAF pauses in a background tab
    }
  }

  /** Apply every queued event in one reactive update, then scroll once. */
  async function flushQueue() {
    flushScheduled = false;
    const batch = queue;
    queue = [];
    if (batch.length === 0) return;
    events = [...events, ...batch].slice(-1500);
    for (const event of batch) applyEvent(event);
    await tick();
    if (follow && streamBox) streamBox.scrollTop = streamBox.scrollHeight;
  }

  function applyEvent(event: RunEvent) {
    if (event.type === 'lagged') return;
    eventCount += 1;
    pending += 1;
    const agent = event.agent || '';
    const stage = event.stage || stageForAgent(agent);
    if (stage) {
      stageCounts = { ...stageCounts, [stage]: (stageCounts[stage] ?? 0) + 1 };
      currentStage = stage;
    }
    const progressed = Number(event.progress?.crawled ?? 0);
    if (progressed > crawled) crawled = progressed;
    if (event.progress) counts = { ...counts, ...event.progress };
    if (agent) {
      const lane = agents[agent] ?? { lines: 0, calls: 0, lastTs: 0, lastText: '', lastCall: '', lastCallOk: null };
      const updated = { ...lane, lines: lane.lines + 1 };
      if (event.type === 'log' || event.type === 'error') {
        updated.lastText = String(event.payload?.text ?? event.payload?.error ?? '');
        updated.lastTs = event.ts;
      }
      if (event.type === 'reasoning' && event.payload?.text) {
        updated.lastText = String(event.payload.text);
        updated.lastTs = event.ts;
      }
      if (event.type === 'model' && event.payload?.kind === 'done') {
        updated.calls = lane.calls + 1;
        updated.lastCall = String(event.payload.model ?? '');
        updated.lastCallOk = !!event.payload.ok;
        updated.lastTs = event.ts;
      }
      agents = { ...agents, [agent]: updated };
    }
    if (event.type === 'fetch' && event.payload?.url) {
      const kind = String(event.payload.kind ?? '');
      if (kind !== 'progress') urlCount += 1;
    }
    if (event.type === 'finding.created' && event.payload) {
      landed = [
        { id: event.seq, status: event.payload.status, secret_type: event.payload.secret_type, value: event.payload.value, detail: event.payload.detail },
        ...landed
      ].slice(0, 80);
    }
    if (event.type === 'run.state' && event.payload) {
      const status = String(event.payload.status ?? '');
      if (status && !TERMINAL.includes(run?.status ?? '')) {
        run = run ? { ...run, status: status as Run['status'] } : run;
      }
      const merged = event.payload.counts ?? event.payload.summary;
      if (merged && typeof merged === 'object') {
        const numeric: Record<string, number> = {};
        for (const [key, value] of Object.entries(merged as Record<string, unknown>)) {
          if (typeof value === 'number') numeric[key] = value;
        }
        counts = { ...counts, ...numeric };
      }
    }
  }

  function seedBuckets(items: RunEvent[]) {
    if (!items.length) return;
    const end = items[items.length - 1].ts;
    const out = new Array(BUCKETS).fill(0);
    for (const item of items) {
      const slot = BUCKETS - 1 - Math.floor(((end - item.ts) * 1000) / BUCKET_MS);
      if (slot >= 0 && slot < BUCKETS) out[slot] += 1;
    }
    buckets = out;
  }

  function onStreamScroll() {
    if (!streamBox) return;
    follow = streamBox.scrollTop + streamBox.clientHeight >= streamBox.scrollHeight - 32;
  }

  function onSpotlightScroll() {
    if (!spotlightEl) return;
    spotlightStick = spotlightEl.scrollHeight - spotlightEl.scrollTop - spotlightEl.clientHeight < 48;
  }

  function openSpotlight(agent: string) {
    spotlightStick = true;
    spotlightAgent = agent;
  }

  async function loadInv(kind: string) {
    if (!run || inflight.has(kind)) return;
    inflight.add(kind);
    invBusy = kind;
    try {
      const page = await api.inventory(run.id, kind);
      inv = { ...inv, [kind]: page.items ?? [] };
      loadedInv = { ...loadedInv, [kind]: true };
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : `could not load ${kind}`);
    } finally {
      inflight.delete(kind);
      invBusy = '';
    }
  }

  async function loadReport() {
    if (!run) return;
    try {
      report = await api.runReport(run.id);
      reportErr = '';
    } catch (exc) {
      reportErr = exc instanceof Error ? exc.message : 'could not load the report';
    }
  }

  async function refreshTab() {
    if (tab === 'report') {
      report = '';
      reportErr = '';
      await loadReport();
      return;
    }
    for (const kind of TAB_KINDS[tab] ?? []) {
      loadedInv = { ...loadedInv, [kind]: false };
      void loadInv(kind);
    }
  }

  function sizeText(bytes: number): string {
    if (!bytes) return '--';
    if (bytes < 1024) return `${bytes} b`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kb`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} mb`;
  }

  function verdictColor(verdict: string): string {
    if (verdict === 'live' || verdict === 'verified') return 'var(--nc-acid)';
    if (verdict === 'suspect') return 'var(--nc-violet)';
    return 'var(--nc-slate)';
  }

  async function load(initialTab = '') {
    if (!store.activeRunId) return;
    try {
      run = await api.run(store.activeRunId);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not load the run');
      return;
    }
    events = [];
    seen.clear();
    landed = [];
    counts = run?.counts ?? {};
    currentStage = '';
    eventCount = 0;
    urlCount = 0;
    stageCounts = {};
    agents = {};
    crawled = 0;
    buckets = new Array(BUCKETS).fill(0);
    pending = 0;
    nowTick = Date.now();
    inv = {};
    loadedInv = {};
    report = '';
    reportErr = '';
    filter = 'all';
    tab = initialTab || 'feed';
    if (run) {
      try {
        const page = await api.runEvents(run.id);
        const items = (page.items ?? []) as RunEvent[];
        for (const event of items) push(event);
        await flushQueue();
        seedBuckets(items);
      } catch {
        /* show the run we have; events will resume over the stream */
      }
      counts = { ...counts, ...(run.counts ?? {}) };
      if (finished) currentStage = '';
    }
    await tick();
    if (streamBox) streamBox.scrollTop = streamBox.scrollHeight;
  }

  function connect() {
    if (!store.activeRunId || finished) return;
    const source = new EventSource(api.eventsUrl(store.activeRunId));
    source.onmessage = (message) => {
      try {
        push(JSON.parse(message.data) as RunEvent);
      } catch {
        /* ignore a malformed frame */
      }
    };
    source.onerror = () => {
      /* EventSource retries on its own; the poll below reports the real state */
    };
    stop = () => source.close();
  }

  async function poll() {
    if (!store.activeRunId || finished) return;
    let fresh: Run | null = null;
    try {
      fresh = await api.run(store.activeRunId);
    } catch {
      return;
    }
    if (!fresh) return;
    run = fresh;
    if (TERMINAL.includes(fresh.status)) {
      stop();
      currentStage = '';
      counts = { ...counts, ...(fresh.counts ?? {}) };
      store.toast('ok', `scan ${statusLabel(fresh.status)} for ${fresh.target}`);
      void store.refreshTotals();
      void store.refreshRuns();
      void store.refreshFindings('?size=100');
    }
  }

  async function requestStop() {
    if (!run) return;
    stopOpen = true;
    await Promise.resolve();
  }

  async function confirmStop() {
    stopOpen = false;
    if (!run) return;
    try {
      await api.stopRun(run.id);
      store.toast('warn', `stopping the scan of ${run.target}`);
      await poll();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not stop the run');
    }
  }

  async function rerun() {
    if (!run) return;
    try {
      const fresh = await api.rerun(run.id);
      store.runs = [fresh, ...store.runs];
      store.watch(fresh.id);
      store.toast('ok', `rerunning ${fresh.target}`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not rerun');
    }
  }

  async function continueRun() {
    if (!run || continuing) return;
    continuing = true;
    try {
      const fresh = await api.resumeRun(run.id);
      store.runs = [fresh, ...store.runs.filter((item) => item.id !== fresh.id)];
      store.watch(fresh.id);
      store.toast('ok', `continuing the scan of ${fresh.target} where it stopped`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not continue the run');
    } finally {
      continuing = false;
    }
  }

  let poller: number | undefined;
  let destroyed = false;
  let sawFinished = $state(false);

  $effect(() => {
    if (finished) {
      currentStage = '';
      stop();
    }
  });

  // one 250ms clock drives the scope bar, the hot-lane decay and elapsed
  $effect(() => {
    if (!running) return;
    const tick = window.setInterval(() => {
      nowTick = Date.now();
      buckets = [...buckets.slice(1), pending];
      pending = 0;
    }, BUCKET_MS);
    return () => window.clearInterval(tick);
  });

  // evidence for the open tab, fetched once per run
  $effect(() => {
    for (const kind of TAB_KINDS[tab] ?? []) {
      if (!loadedInv[kind]) void loadInv(kind);
    }
    if (tab === 'report' && !report && !reportErr) void loadReport();
  });

  // a finished run has written its files: refresh whatever is loaded
  $effect(() => {
    if (finished && !sawFinished) {
      sawFinished = true;
      for (const kind of Object.keys(loadedInv)) void loadInv(kind);
      if (report || reportErr) {
        report = '';
        reportErr = '';
        void loadReport();
      }
    } else if (!finished && sawFinished) {
      sawFinished = false;
    }
  });

  $effect(() => {
    spotlightRows.length;
    if (spotlightEl && spotlightStick) spotlightEl.scrollTop = spotlightEl.scrollHeight;
  });

  $effect(() => {
    if (spotlightAgent) panelEl?.focus();
  });

  $effect(() => {
    if (!spotlightAgent) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') spotlightAgent = '';
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  });

  onMount(async () => {
    const initialTab = store.liveTab;
    store.liveTab = '';
    await load(initialTab);
    if (destroyed) return;
    if (!finished) connect();
    poller = window.setInterval(() => void poll(), 2000);
    await tick();
    if (streamBox) streamBox.scrollTop = streamBox.scrollHeight;
  });

  onDestroy(() => {
    destroyed = true;
    stop();
    if (poller) window.clearInterval(poller);
  });
</script>

{#if !store.activeRunId}
  <div class="fade-rise mx-auto max-w-[720px]">
    <div class="panel overflow-hidden">
      <EmptyState
        eyebrow="live runs"
        title="No run selected"
        body="Start a scan and it appears here live: the stage rail, a verbose transmission of every agent line, and inspectable evidence for each run - assets, endpoints, scripts, secrets, findings and the report."
        action="start a scan"
        onAction={() => store.go('new')}
      >
        {#if store.runs.length > 0}
          <div class="mt-5 w-full max-w-[420px] border-t border-indigo-deep pt-4 text-left">
            <p class="eyebrow mb-2">or reopen</p>
            {#each store.runs.slice(0, 5) as item (item.id)}
              <button
                class="row-link flex w-full items-center gap-3 rounded px-3 py-2 text-left"
                type="button"
                onclick={() => store.watch(item.id)}
              >
                <span class="h-2 w-2 rounded-full" style="background:{statusColor(item.status)}"></span>
                <span class="min-w-0 flex-1 truncate text-sm text-bone">{item.target}</span>
                <span class="mono text-xs text-ash">{statusLabel(item.status)}</span>
              </button>
            {/each}
          </div>
        {/if}
      </EmptyState>
    </div>
  </div>
{:else if run}
  <div class="stagger mx-auto flex max-w-[1240px] flex-col gap-5">
    <section class="panel panel-hud p-5" class:finish-glow={finished} use:spotlight>
      <div class="flex flex-wrap items-center gap-3">
        <div class="min-w-0">
          <p class="eyebrow">run {run.id.slice(-6)}</p>
          <h1 class="truncate font-mono text-lg text-bone">{run.target}</h1>
        </div>
        <span class="chip" style="color:{statusColor(run.status)}" title={run.error || ''}>
          <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
            <circle cx="4" cy="4" r="3.4" />
          </svg>
          {statusLabel(run.status)}
        </span>
        <span class="num text-sm text-ash">{elapsed}</span>
        <span class="mono hidden text-xs text-slate sm:inline"><span use:countup={eventCount}>0</span> events</span>
        <div class="ml-auto flex gap-2">
          {#if running}
            <button class="btn btn-danger" type="button" onclick={requestStop}>stop scan</button>
          {:else if canContinue}
            <button class="btn btn-acid" type="button" onclick={continueRun} disabled={continuing}>
              {continuing ? 'continuing...' : 'continue scan'}
            </button>
            <button class="btn" type="button" onclick={rerun}>rerun</button>
          {:else}
            <button class="btn" type="button" onclick={rerun}>rerun</button>
          {/if}
          <button class="btn btn-quiet" type="button" onclick={() => store.go('home')}>close</button>
        </div>
      </div>
      <div class="mt-4">
        <StageRail stages={displayStages} current={currentStage} finished={finished ? displayStages.map((s) => s.key) : finishedThrough(currentStage)} />
      </div>
    </section>

    <section class="grid gap-3 lg:grid-cols-[1.35fr_1fr]">
      <div class="panel panel-hud flex flex-col justify-center gap-3 px-4 py-3">
        <div class="flex items-center justify-between">
          <p class="eyebrow">{isLab ? 'lab signal' : 'stage signal'}</p>
          <span
            class="mono text-[10px] tracking-[0.14em]"
            style="color:{running ? 'var(--nc-acid)' : 'var(--nc-ash)'}"
          >
            {running ? `${(currentStage || 'crawl').toLowerCase()} // live` : statusLabel(run.status)}
          </span>
        </div>
        <StageSignal stages={displayStages} counts={stageCount} current={currentStage} {running} />
      </div>

      <div class="panel flex flex-col overflow-hidden">
        <div class="flex items-center justify-between border-b border-indigo-deep px-4 py-2.5">
          <p class="eyebrow">run signal</p>
          <span class="flex items-center gap-2">
            {#if running}
              <span class="pulse-live h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
            {/if}
            <span class="mono text-[10px] tracking-[0.14em] text-ash">
              {running ? 'live' : statusLabel(run.status)}
            </span>
          </span>
        </div>
        <div class="px-4 pt-3">
          <RunScope {buckets} {running} />
        </div>
        <div class="grid grid-cols-4 gap-2 px-4 pb-3 pt-1">
          <div>
            <p class="eyebrow">events</p>
            <p class="num mt-0.5 text-[15px] text-bone"><span use:countup={eventCount}>0</span></p>
          </div>
          <div>
            <p class="eyebrow">rate</p>
            <p class="num mt-0.5 text-[15px] text-bone">
              {rate.toFixed(1)}<span class="text-xs text-ash">/s</span>
            </p>
          </div>
          <div>
            <p class="eyebrow">urls</p>
            <p class="num mt-0.5 text-[15px] text-bone"><span use:countup={urlCount}>0</span></p>
          </div>
          <div>
            <p class="eyebrow">elapsed</p>
            <p class="num mt-0.5 text-[15px] text-bone">{elapsed}</p>
          </div>
        </div>
      </div>
    </section>

    <section class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4" aria-label="counters">
      {#if isHunt}
        {#each [['pages', 'pages'], ['endpoints', 'endpoints'], ['techniques', 'techniques'], ['hypotheses', 'leads']] as [label, key] (key)}
          <div class="panel kpi px-4 py-3">
            <p class="eyebrow">{label}</p>
            <p class="num mt-1 text-xl text-bone" use:countup={counts[key] ?? 0}>0</p>
          </div>
        {/each}
      {:else if isLab}
        {#each [['steps', 'steps'], ['http calls', 'http_calls'], ['solved', 'solved'], ['lesson', 'lesson_id']] as [label, key] (key)}
          <div class="panel kpi px-4 py-3">
            <p class="eyebrow">{label}</p>
            <p class="num mt-1 text-xl text-bone">
              {key === 'solved' ? (counts.solved ? 'yes' : 'no') : key === 'lesson_id' ? (counts.lesson_id ? 'yes' : 'no') : (counts[key] ?? 0)}
            </p>
          </div>
        {/each}
      {:else}
        {#each [['pages', 'pages'], ['js files', 'js_files'], ['endpoints', 'endpoints'], ['candidates', 'candidates'], ['verified', 'verified'], ['findings', 'findings'], ['not confirmed', 'unverified'], ['weak points', 'review_loopholes']] as [label, key] (key)}
          <div class="panel kpi px-4 py-3">
            <p class="eyebrow">{label}</p>
            <p class="num mt-1 text-xl text-bone" use:countup={counts[key] ?? 0}>0</p>
          </div>
        {/each}
      {/if}
    </section>

    <section class="panel overflow-hidden">
      <div class="flex flex-wrap items-center gap-1 border-b border-indigo-deep px-3 py-2" role="tablist" aria-label="run inspector">
        {#each displayTabs as item (item.id)}
          <button
            class="live-tab"
            class:active={tab === item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            onclick={() => (tab = item.id)}
          >
            {item.label}
          </button>
        {/each}
        <button class="btn btn-quiet ml-auto px-2! py-1! text-xs" type="button" onclick={refreshTab} disabled={invBusy !== ''}>
          {invBusy ? 'loading...' : 'refresh'}
        </button>
      </div>

      {#if tab === 'feed'}
        <div class="grid lg:grid-cols-[1.55fr_1fr]">
          <div class="flex min-h-[460px] flex-col border-b border-indigo-deep lg:border-b-0 lg:border-r">
            <div class="flex flex-wrap items-center gap-2 px-4 py-2">
              {#each FILTERS as item (item.id)}
                <button
                  class="live-filter"
                  class:active={filter === item.id}
                  type="button"
                  onclick={() => (filter = item.id)}
                >
                  {item.label}
                </button>
              {/each}
              <button
                class="btn btn-quiet ml-auto px-2! py-1! text-xs"
                type="button"
                onclick={() => {
                  follow = true;
                  void tick().then(() => {
                    if (streamBox) streamBox.scrollTop = streamBox.scrollHeight;
                  });
                }}
              >
                {follow ? 'following' : 'jump to latest'}
              </button>
            </div>
            <div
              class="mono flex-1 overflow-y-auto px-4 pb-3 text-[12px] leading-relaxed"
              data-transmission="1"
              class:is-live={running}
              bind:this={streamBox}
              onscroll={onStreamScroll}
            >
              {#if stream.length === 0}
                <p class="py-2 text-slate">
                  {running
                    ? `waiting for the first line from ${run.target}...`
                    : filter === 'all'
                      ? 'Nothing was transmitted on this run.'
                      : `No ${filter} rows on this run.`}
                </p>
              {/if}
              {#each stream as row (row.seq)}
                {@const badge = badgeOf(row)}
                <p
                  class="stream-line flex items-start gap-2 py-0.5"
                  class:line-arrive={running && row.seq === lastSeq}
                  class:border-l-2={row.kind === 'think'}
                  class:pl-2={row.kind === 'think'}
                  style={row.kind === 'think' ? `border-color:${badge.color}` : ''}
                >
                  <span class="shrink-0 text-slate">{clock(row.ts)}</span>
                  <span class="w-[46px] shrink-0 text-[10px] tracking-[0.08em]" style="color:{badge.color}">
                    {badge.text}
                  </span>
                  {#if row.kind === 'found'}
                    <Chip label={row.sub} color={sevColor(row.sub)} shape={sevShape(row.sub)} />
                    <span class="min-w-0 flex-1 break-words text-bone" title={row.text}>{formatText(row.text, 900)}</span>
                  {:else}
                    <span class="min-w-0 flex-1 break-words" style="color:{rowColor(row)};overflow-wrap:anywhere" title={row.text}>
                      {formatText(row.text)}
                    </span>
                    {#if row.sub}
                      <span class="num shrink-0 text-[10px] text-ash">{row.sub}</span>
                    {/if}
                  {/if}
                </p>
              {/each}
            </div>
          </div>

          <div class="flex flex-col">
            {#if !isLab && !isHunt}
            <div class="border-b border-indigo-deep">
              <div class="flex items-center justify-between px-4 py-2.5">
                <p class="eyebrow">credentials caught</p>
                <span class="num text-xs text-ash">{landed.length}</span>
              </div>
              {#if landed.length === 0}
                <p class="px-4 pb-4 text-sm text-bone-dust">
                  {finished
                    ? 'Nothing was caught on this pass.'
                    : 'Candidates land here the moment one is validated.'}
                </p>
              {:else}
                <ul class="max-h-[220px] overflow-y-auto" data-landed="1">
                  {#each landed as item (item.id)}
                    <li class="shard-in flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                      <Chip label={item.status} color={sevColor(item.status)} shape={sevShape(item.status)} />
                      <span class="min-w-0 flex-1">
                        <span class="mono block truncate text-sm text-bone">{item.secret_type}</span>
                        <span class="mono block truncate text-xs text-bone-dust">{item.value}</span>
                      </span>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
            {/if}

            <div class="flex-1">
              <div class="flex items-center justify-between px-4 py-2.5">
                <p class="eyebrow">agents on the wire</p>
                <span class="mono text-xs text-ash">{reasoningCount} reasoning rows</span>
              </div>
              {#if agentList.length === 0}
                <p class="px-4 pb-4 text-xs text-slate">
                  {running ? 'the agents are waking up...' : 'no agent activity on this run.'}
                </p>
              {:else}
                <ul class="max-h-[320px] overflow-y-auto" data-agents="1">
                  {#each agentList as lane (lane.agent)}
                    {@const color = (AGENT_COLORS as Record<string, string>)[lane.agent] ?? 'var(--nc-bone-dust)'}
                    <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                      <span class="lane-led" style="--agent:{color}" aria-hidden="true"></span>
                      <span class="mono w-[86px] shrink-0 truncate text-xs" style="color:{color}">{lane.agent}</span>
                      <span class="num shrink-0 text-[11px] text-ash">{lane.lines}</span>
                      {#if lane.lastCall}
                        <span
                          class="mono hidden min-w-0 flex-1 truncate text-[11px] sm:block"
                          style="color:{lane.lastCallOk === false ? 'var(--nc-violet)' : 'var(--nc-ash)'}"
                        >
                          {lane.lastCall}
                        </span>
                      {:else}
                        <span class="min-w-0 flex-1"></span>
                      {/if}
                      <span class="mono hidden shrink-0 text-[10px] text-slate md:block">{clock(lane.lastTs)}</span>
                      <button
                        class="shrink-0 text-[10px] tracking-[0.12em] text-acid opacity-70 transition-opacity hover:opacity-100"
                        type="button"
                        onclick={() => openSpotlight(lane.agent)}
                      >
                        WATCH &gt;
                      </button>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
          </div>
        </div>
      {:else if tab === 'assets'}
        <div class="grid gap-0 lg:grid-cols-2">
          <div class="border-b border-indigo-deep lg:border-b-0 lg:border-r">
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">subdomains</p>
              <span class="num text-xs text-ash">{inv.subdomains?.length ?? 0}</span>
            </div>
            {#if !loadedInv.subdomains}
              <p class="px-4 pb-4 text-xs text-slate">mapping...</p>
            {:else if (inv.subdomains ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">No subdomains were mapped on this run.</p>
            {:else}
              <ul class="max-h-[420px] overflow-y-auto" data-subdomains="1">
                {#each inv.subdomains as row (row.host)}
                  <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                    <span
                      class="h-1.5 w-1.5 shrink-0 rounded-full"
                      style="background:{row.resolved ? 'var(--nc-acid)' : 'var(--nc-slate)'}"
                      title={row.resolved ? 'resolves' : 'no answer'}
                    ></span>
                    <span class="mono min-w-0 flex-1 truncate text-sm text-bone">{row.host}</span>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
          <div>
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">pages</p>
              <span class="num text-xs text-ash">{inv.pages?.length ?? 0}</span>
            </div>
            {#if !loadedInv.pages}
              <p class="px-4 pb-4 text-xs text-slate">reading...</p>
            {:else if (inv.pages ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">No pages were crawled on this run.</p>
            {:else}
              <ul class="max-h-[420px] overflow-y-auto" data-pages="1">
                {#each inv.pages as row (row.url)}
                  <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                    <span
                      class="num w-[34px] shrink-0 text-[11px]"
                      style="color:{row.status >= 400 ? 'var(--nc-violet)' : row.status === 0 ? 'var(--nc-slate)' : 'var(--nc-bone-dust)'}"
                    >
                      {row.status || '--'}
                    </span>
                    <span class="mono min-w-0 flex-1 truncate text-xs text-bone-dust" title={row.url}>{row.url}</span>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </div>
      {:else if tab === 'endpoints'}
        <div>
          <div class="flex items-center justify-between px-4 py-2.5">
            <p class="eyebrow">endpoints</p>
            <span class="num text-xs text-ash">{inv.endpoints?.length ?? 0}</span>
          </div>
          {#if !loadedInv.endpoints}
            <p class="px-4 pb-4 text-xs text-slate">collecting...</p>
          {:else if (inv.endpoints ?? []).length === 0}
            <p class="px-4 pb-4 text-sm text-bone-dust">No endpoints were extracted on this run.</p>
          {:else}
            <ul class="max-h-[520px] overflow-y-auto" data-endpoints="1">
              {#each inv.endpoints as row (row.url)}
                <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-1.5 last:border-0">
                  <span class="mono min-w-0 flex-1 truncate text-xs text-bone-dust" title={row.url}>{row.url}</span>
                  {#if row.source}
                    <span class="mono shrink-0 text-[10px] text-slate">{row.source}</span>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        </div>
      {:else if tab === 'js'}
        <div class="grid gap-0 lg:grid-cols-2">
          <div class="border-b border-indigo-deep lg:border-b-0 lg:border-r">
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">scripts read</p>
              <span class="num text-xs text-ash">{inv.js?.length ?? 0}</span>
            </div>
            {#if !loadedInv.js}
              <p class="px-4 pb-4 text-xs text-slate">reading...</p>
            {:else if (inv.js ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">No scripts were read on this run.</p>
            {:else}
              <ul class="max-h-[440px] overflow-y-auto" data-js="1">
                {#each inv.js as row (row.url)}
                  <li class="border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                    <span class="mono block truncate text-xs text-bone" title={row.url}>{row.url}</span>
                    <span class="mono mt-0.5 block text-[10px] text-slate">
                      {sizeText(Number(row.size ?? 0))}{#if row.sha256} / {String(row.sha256).slice(0, 12)}{/if}
                    </span>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
          <div>
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">code review</p>
              <span class="num text-xs text-ash">{inv.reviews?.length ?? 0}</span>
            </div>
            {#if !loadedInv.reviews}
              <p class="px-4 pb-4 text-xs text-slate">reading...</p>
            {:else if (inv.reviews ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">The source pass flagged nothing to review.</p>
            {:else}
              <ul class="max-h-[440px] overflow-y-auto" data-reviews="1">
                {#each inv.reviews as row, i (i)}
                  <li class="border-b border-indigo-deep/60 px-4 py-2.5 last:border-0">
                    <div class="flex items-center gap-2">
                      <Chip label={row.severity || 'note'} color={sevColor(row.severity)} shape={sevShape(row.severity)} />
                      <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{row.kind || 'observation'}</span>
                    </div>
                    <p class="mt-1.5 text-xs leading-relaxed text-bone-dust">{row.detail}</p>
                    {#if row.source}
                      <p class="mono mt-1 truncate text-[10px] text-slate" title={row.source}>{row.source}</p>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </div>
      {:else if tab === 'secrets'}
        <div class="grid gap-0 xl:grid-cols-3">
          <div class="border-b border-indigo-deep xl:border-b-0 xl:border-r">
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">secrets spotted</p>
              <span class="num text-xs text-ash">{inv.secrets?.length ?? 0}</span>
            </div>
            {#if !loadedInv.secrets}
              <p class="px-4 pb-4 text-xs text-slate">sweeping...</p>
            {:else if (inv.secrets ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">No secrets were spotted on this run.</p>
            {:else}
              <ul class="max-h-[440px] overflow-y-auto" data-secrets="1">
                {#each inv.secrets as row, i (i)}
                  <li class="border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                    <div class="flex items-center gap-2">
                      <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{row.type}</span>
                      <span class="num shrink-0 text-[10px] text-ash">{Math.round(Number(row.confidence ?? 0) * 100)}%</span>
                    </div>
                    <span class="mono block truncate text-[11px] text-bone-dust" title={row.value}>{row.value}</span>
                    {#if row.source}
                      <span class="mono block truncate text-[10px] text-slate" title={row.source}>{row.source}</span>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
          <div class="border-b border-indigo-deep xl:border-b-0 xl:border-r">
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">candidates</p>
              <span class="num text-xs text-ash">{inv.candidates?.length ?? 0}</span>
            </div>
            {#if !loadedInv.candidates}
              <p class="px-4 pb-4 text-xs text-slate">ranking...</p>
            {:else if (inv.candidates ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">No unconfirmed candidates on this run.</p>
            {:else}
              <ul class="max-h-[440px] overflow-y-auto" data-candidates="1">
                {#each inv.candidates as row, i (i)}
                  <li class="border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                    <div class="flex items-center gap-2">
                      <Chip label={row.severity || 'info'} color={sevColor(row.severity)} shape={sevShape(row.severity)} />
                      <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{row.type}</span>
                    </div>
                    <span class="mono block truncate text-[11px] text-bone-dust" title={row.value}>{row.value}</span>
                    {#if row.detail}
                      <p class="mt-1 text-[11px] leading-relaxed text-ash">{row.detail}</p>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
          <div>
            <div class="flex items-center justify-between px-4 py-2.5">
              <p class="eyebrow">corroboration</p>
              <span class="num text-xs text-ash">{inv.corroborations?.length ?? 0}</span>
            </div>
            {#if !loadedInv.corroborations}
              <p class="px-4 pb-4 text-xs text-slate">checking...</p>
            {:else if (inv.corroborations ?? []).length === 0}
              <p class="px-4 pb-4 text-sm text-bone-dust">
                Nothing has been through the second read yet. Verified findings are rechecked live
                and then read by models from different providers before they are reported.
              </p>
            {:else}
              <ul class="max-h-[440px] overflow-y-auto" data-corroborations="1">
                {#each inv.corroborations as row, i (i)}
                  <li class="border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                    <div class="flex items-center gap-2">
                      <span
                        class="mono shrink-0 text-[10px] tracking-[0.08em] uppercase"
                        style="color:{verdictColor(String(row.verdict))}"
                      >
                        {row.verdict}
                      </span>
                      <span class="mono min-w-0 flex-1 truncate text-[11px] text-bone" title={row.validator}>{row.validator}</span>
                    </div>
                    <span class="mono block truncate text-[11px] text-bone-dust" title={row.value}>{row.type} / {row.value}</span>
                    {#if row.detail}
                      <p class="mt-1 text-[11px] leading-relaxed text-ash">{row.detail}</p>
                    {/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </div>
      {:else if tab === 'findings'}
        <div>
          <div class="flex items-center justify-between px-4 py-2.5">
            <p class="eyebrow">findings</p>
            <span class="num text-xs text-ash">{inv.findings?.length ?? 0}</span>
          </div>
          {#if !loadedInv.findings}
            <p class="px-4 pb-4 text-xs text-slate">collecting...</p>
          {:else if (inv.findings ?? []).length === 0}
            <p class="px-4 pb-4 text-sm text-bone-dust">No confirmed findings on this run yet.</p>
          {:else}
            <ul class="max-h-[520px] overflow-y-auto" data-findings="1">
              {#each inv.findings as row, i (i)}
                {@const corroboration = row.corroboration as { live?: number; total?: number } | null}
                <li class="border-b border-indigo-deep/60 px-4 py-3 last:border-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <Chip label={row.severity || 'info'} color={sevColor(row.severity)} shape={sevShape(row.severity)} />
                    <span class="min-w-0 flex-1 truncate text-sm text-bone">{row.title}</span>
                    {#if corroboration && (corroboration.total ?? 0) > 0}
                      <span class="mono shrink-0 text-[10px] text-acid">
                        {corroboration.live ?? 0}/{corroboration.total} live
                      </span>
                    {/if}
                  </div>
                  <p class="mono mt-1 truncate text-[11px] text-bone-dust" title={row.value}>
                    {row.secret_type} / {row.value}
                  </p>
                  {#if row.status}
                    <p class="mono mt-0.5 text-[10px] text-ash">{row.status}</p>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        </div>
      {:else if tab === 'report'}
        <div class="px-5 py-4" data-report="1">
          {#if reportErr}
            <p class="text-sm text-violet">{reportErr}</p>
          {:else if report}
            <article class="report-prose max-w-[860px]">{@html renderMarkdown(report)}</article>
          {:else}
            <p class="text-sm text-slate">
              {running
                ? 'the report is written when the run finishes - this preview will refresh on its own.'
                : 'loading the report...'}
            </p>
          {/if}
        </div>
      {/if}
    </section>
  </div>
{/if}

{#if spotlightAgent}
  {@const color = (AGENT_COLORS as Record<string, string>)[spotlightAgent] ?? 'var(--nc-acid)'}
  <div
    class="palette-veil"
    role="presentation"
    onclick={() => (spotlightAgent = '')}
    onkeydown={(event) => {
      if (event.key === 'Escape') spotlightAgent = '';
    }}
  >
    <div
      class="palette-panel panel-raised panel-hud mx-auto mt-[7vh] flex w-[min(880px,94vw)] flex-col overflow-hidden"
      style="max-height:80vh"
      role="dialog"
      aria-modal="true"
      aria-label="{spotlightAgent} live thinking"
      tabindex="-1"
      bind:this={panelEl}
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <header class="flex items-center gap-3 border-b border-indigo-deep px-5 py-3">
        <span class="lane-led" style="--agent:{color}" aria-hidden="true"></span>
        <div class="min-w-0">
          <p class="eyebrow">live model spotlight</p>
          <h2 class="font-mono text-lg" style="color:{color}">{spotlightAgent}</h2>
        </div>
        <div class="ml-auto flex items-center gap-3">
          <span class="num text-xs text-ash">{spotlightRows.length} rows</span>
          <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => (spotlightAgent = '')}>
            close
          </button>
        </div>
      </header>
      <div
        class="think-stream flex-1 overflow-y-auto px-5 py-3"
        data-spotlight="1"
        bind:this={spotlightEl}
        onscroll={onSpotlightScroll}
      >
        {#if spotlightRows.length === 0}
          <p class="mono text-xs text-slate">
            {running
              ? `waiting for ${spotlightAgent} to speak...`
              : `no activity recorded for ${spotlightAgent} on this run`}
          </p>
        {/if}
        {#each spotlightRows as row, i (row.seq)}
          {@const badge = badgeOf(row)}
          <p class="think-line mono text-[11px]">
            <span class="text-slate">{clock(row.ts)} </span>
            <span style="color:{badge.color}">{badge.text} </span>
            <span style="color:{rowColor(row)};overflow-wrap:anywhere">{formatText(row.text, 900)}</span>
            {#if row.sub}<span class="text-ash"> / {row.sub}</span>{/if}
            {#if running && i === spotlightRows.length - 1}
              <span class="caret" aria-hidden="true"></span>
            {/if}
          </p>
        {/each}
      </div>
      <footer class="flex items-center gap-2 border-t border-indigo-deep px-5 py-2">
        {#if running}
          <span class="pulse-live h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
          <span class="mono text-[10px] tracking-[0.14em] text-ash">streaming // press esc to close</span>
        {:else}
          <span class="mono text-[10px] tracking-[0.14em] text-ash">
            {run ? statusLabel(run.status) : 'closed'} // press esc to close
          </span>
        {/if}
      </footer>
    </div>
  </div>
{/if}

{#if stopOpen && run}
  <Confirm
    title="Stop the scan of {run.target}?"
    body="The run stops at the next safe point and keeps everything it found so far. Partial results are written to disk, and you can continue the scan later from where it stopped. This cannot be undone."
    confirmLabel="stop this scan"
    danger
    onConfirm={confirmStop}
    onCancel={() => (stopOpen = false)}
  />
{/if}
