<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import {
    ago,
    clock,
    isoMs,
    sevColor,
    sevShape,
    stageForAgent,
    statusColor,
    statusLabel,
    triageLabel
  } from '../format';
  import { store } from '../state.svelte';
  import { AGENT_COLORS, STAGES } from '../../tokens';
  import { countup, pauseOffscreen, spotlight } from '../actions';
  import Chip from '../ui/Chip.svelte';
  import HeroArt from '../ui/HeroArt.svelte';
  import Sparkline from '../ui/Sparkline.svelte';
  import type { Finding, ProviderHealth, Run, RunEvent } from '../types';

  type Thought = { seq: number; ts: number; agent: string; stage: string; text: string };
  type Call = {
    seq: number;
    ts: number;
    agent: string;
    provider: string;
    model: string;
    ok: boolean;
    ms: number;
    error: string;
  };
  type Signal = { seq: number; ts: number; status: string; secret_type: string; value: string; detail: string };
  type LogLine = { seq: number; ts: number; level: string; text: string };
  type FleetRow = {
    key: string;
    name: string;
    providerId: string;
    healthy: boolean;
    keySet: boolean;
    models: number;
    calls: number;
    ok: number;
    failed: number;
    ms: number;
    avgMs: number;
    lastModel: string;
    error: string;
    lastChecked: string;
  };
  type Mission = {
    tone: string;
    eyebrow: string;
    lead: string;
    mark: string;
    body: string;
    primary: string;
    secondary: string;
    goPrimary: () => void;
    goSecondary: () => void;
  };
  type NextAction = {
    id: string;
    num: string;
    title: string;
    body: string;
    cta: string;
    color: string;
    go: () => void;
  };
  type QueueItem = {
    id: string;
    label: string;
    value: string;
    detail: string;
    status: string;
    severity: string;
    ts: number;
    finding: boolean;
  };
  type Host = { host: string; count: number; ok: number };

  const stages = STAGES as unknown as { key: string; label: string; detail: string }[];

  let providers = $state<ProviderHealth[]>([]);
  let recent = $state<Finding[]>([]);
  let events = $state<RunEvent[]>([]);
  let loadedRun = $state('');
  let loadingRun = $state('');
  let connectedRun = $state('');
  let feedTab = $state<'think' | 'models' | 'signals' | 'logs'>('think');
  let testing = $state('');
  let now = $state(Date.now());
  let autoFollow = $state(true);
  let pausedCount = $state(0);
  let pausedEvents: RunEvent[] = [];

  let source: EventSource | null = null;
  let refreshTimer: number | undefined;
  const seen = new Set<number>();

  const totals = $derived(store.totals);
  const lastRun = $derived(totals?.last_run ?? store.runs[0] ?? null);
  const runningRun = $derived(
    store.runs.find((run) => run.status === 'running' || run.status === 'queued') ??
      (store.liveRun && ['running', 'queued'].includes(store.liveRun.status) ? store.liveRun : null)
  );
  const focusRun = $derived(runningRun ?? lastRun);
  const live = $derived(!!focusRun && (focusRun.status === 'running' || focusRun.status === 'queued'));
  const counts = $derived((focusRun?.counts ?? {}) as Record<string, number>);
  const triage = $derived(totals?.triage ?? {});
  const openFindings = $derived((triage.new ?? 0) + (triage.in_progress ?? 0));
  const confirmed = $derived(triage.confirmed ?? 0);
  const escalated = $derived(triage.escalated ?? 0);
  const target = $derived(focusRun?.target ?? '');

  const agentColor = (agent: string) =>
    (AGENT_COLORS as Record<string, string>)[agent] ?? 'var(--nc-bone_dust)';

  /* ---- derive the useful signal from a wall of run events ---------------- */

  const thoughts = $derived.by<Thought[]>(() => {
    const rows: Thought[] = [];
    let open: Thought | null = null;
    for (const event of events) {
      if (event.type === 'reasoning' && event.payload?.text) {
        const raw = String(event.payload.text).replace(/\r/g, '').trim();
        if (!raw) continue;
        const agent = event.agent || 'run';
        if (open && open.agent === agent && event.ts - open.ts < 6000) {
          open.text = `${open.text} ${raw}`.replace(/[ \t]+/g, ' ').slice(-2400);
          open.ts = event.ts;
          open.seq = event.seq;
        } else {
          open = {
            seq: event.seq,
            ts: event.ts,
            agent,
            stage: event.stage || stageForAgent(agent),
            text: raw.slice(0, 1200)
          };
          rows.push(open);
        }
      } else if (
        event.type === 'log' ||
        event.type === 'error' ||
        event.type === 'finding.created' ||
        (event.type === 'model' && event.payload?.kind === 'done')
      ) {
        open = null;
      }
    }
    return rows;
  });

  const calls = $derived.by<Call[]>(() => {
    const rows: Call[] = [];
    for (const event of events) {
      if (event.type !== 'model' || event.payload?.kind !== 'done') continue;
      rows.push({
        seq: event.seq,
        ts: event.ts,
        agent: event.agent || 'run',
        provider: String(event.payload.provider ?? 'unknown'),
        model: String(event.payload.model ?? 'unknown'),
        ok: !!event.payload.ok,
        ms: Number(event.payload.ms ?? 0),
        error: String(event.payload.error ?? '')
      });
    }
    return rows;
  });

  const signals = $derived.by<Signal[]>(() => {
    const rows: Signal[] = [];
    for (const event of events) {
      if (event.type !== 'finding.created' || !event.payload) continue;
      rows.push({
        seq: event.seq,
        ts: event.ts,
        status: String(event.payload.status ?? 'unknown'),
        secret_type: String(event.payload.secret_type ?? 'signal'),
        value: String(event.payload.value ?? ''),
        detail: String(event.payload.detail ?? '')
      });
    }
    return rows;
  });

  const logs = $derived.by<LogLine[]>(() => {
    const rows: LogLine[] = [];
    for (const event of events) {
      if (event.type !== 'log' && event.type !== 'error') continue;
      const text = String(event.payload?.text ?? event.payload?.error ?? '').trim();
      if (!text) continue;
      rows.push({ seq: event.seq, ts: event.ts, level: event.type, text });
    }
    return rows;
  });

  const latestThought = $derived(thoughts.length ? thoughts[thoughts.length - 1] : null);
  const eventSurface = $derived.by(() => {
    const pages = new Set<string>();
    const scripts = new Set<string>();
    for (const event of events) {
      if (event.type !== 'fetch') continue;
      const payload = event.payload ?? {};
      const kind = String(payload.kind ?? '');
      const url = String(payload.url ?? '');
      if (!url) continue;
      if (kind === 'page') pages.add(url);
      else if (kind === 'js') scripts.add(url);
    }
    return { pages: pages.size, js_files: scripts.size };
  });
  const viewCounts = $derived.by<Record<string, number>>(() => ({
    ...counts,
    pages: Math.max(counts.pages ?? 0, eventSurface.pages),
    js_files: Math.max(counts.js_files ?? 0, eventSurface.js_files)
  }));

  const rawSignals = $derived(Math.max(signals.length, viewCounts.candidates ?? 0));
  const verified = $derived(viewCounts.verified ?? 0);
  const proofRate = $derived(rawSignals > 0 ? Math.min(1, verified / rawSignals) : 0);

  const stageNow = $derived.by(() => {
    let current = '';
    for (const event of events) {
      const key = event.stage || stageForAgent(event.agent);
      if (key && stages.some((stage) => stage.key === key)) current = key;
    }
    return current;
  });
  const stageIndex = $derived(stageNow ? stages.findIndex((stage) => stage.key === stageNow) : -1);
  const stageLabel = $derived(
    stageNow
      ? (stages[stageIndex]?.label ?? stageNow.toUpperCase())
      : focusRun
        ? statusLabel(focusRun.status)
        : 'STANDBY'
  );


  const pipelinePct = $derived.by(() => {
    if (!focusRun) return 0;
    if (focusRun.status === 'done') return 100;
    if (stageIndex >= 0) {
      return live
        ? Math.max(8, Math.round(((stageIndex + 0.6) / stages.length) * 100))
        : Math.round(((stageIndex + 1) / stages.length) * 100);
    }
    return live ? 8 : 0;
  });

  const fleet = $derived.by(() => {
    let total = 0;
    let ok = 0;
    let failed = 0;
    for (const call of calls) {
      total += 1;
      if (call.ok) ok += 1;
      else failed += 1;
    }
    return { total, ok, failed, rate: total > 0 ? ok / total : 0 };
  });

  const fleetRows = $derived.by<FleetRow[]>(() => {
    const map = new Map<string, FleetRow>();
    for (const provider of providers) {
      map.set(provider.name.toLowerCase(), {
        key: provider.id,
        name: provider.name,
        providerId: provider.id,
        healthy: !!provider.healthy,
        keySet: !!provider.key_set,
        models: provider.models.length,
        calls: 0,
        ok: 0,
        failed: 0,
        ms: 0,
        avgMs: 0,
        lastModel: '',
        error: '',
        lastChecked: provider.last_checked
      });
    }
    for (const call of calls) {
      const key = call.provider.toLowerCase();
      let row = map.get(key);
      if (!row) {
        row = {
          key,
          name: call.provider,
          providerId: '',
          healthy: false,
          keySet: false,
          models: 0,
          calls: 0,
          ok: 0,
          failed: 0,
          ms: 0,
          avgMs: 0,
          lastModel: '',
          error: '',
          lastChecked: ''
        };
        map.set(key, row);
      }
      row.calls += 1;
      row.ms += call.ms;
      if (call.ok) row.ok += 1;
      else {
        row.failed += 1;
        if (call.error) row.error = call.error;
      }
      row.lastModel = call.model;
      row.avgMs = row.calls ? Math.round(row.ms / row.calls) : 0;
    }
    return [...map.values()].sort((a, b) => b.calls - a.calls || a.name.localeCompare(b.name));
  });

  const elapsed = $derived.by(() => {
    if (!focusRun) return '--:--';
    const start = isoMs(focusRun.started_at || focusRun.created_at);
    if (!Number.isFinite(start)) return '--:--';
    const end = live ? now : focusRun.finished_at ? isoMs(focusRun.finished_at) : now;
    if (!Number.isFinite(end)) return '--:--';
    const seconds = Math.max(0, Math.floor((end - start) / 1000));
    return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
  });

  const syncLabel = $derived.by(() => {
    if (!store.lastSync) return 'just now';
    const seconds = Math.max(0, Math.round((now - store.lastSync) / 1000));
    if (seconds < 5) return 'just now';
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    return minutes < 60 ? `${minutes}m ago` : `${Math.floor(minutes / 60)}h ago`;
  });

  const heroStats = $derived.by(() => {
    if (!focusRun) {
      return [
        { label: 'casts', value: totals?.runs ?? 0, note: 'in the ledger', color: 'var(--nc-bone)' },
        { label: 'findings', value: totals?.findings ?? 0, note: 'written to disk', color: 'var(--nc-acid)' },
        { label: 'providers', value: providers.length, note: `${fleet.ok} model replies`, color: 'var(--nc-violet)' },
        { label: 'open work', value: openFindings, note: 'waiting for a human', color: 'var(--nc-gold)' }
      ];
    }
    return [
      { label: 'pages', value: viewCounts.pages ?? 0, note: 'under the glass', color: 'var(--nc-bone)' },
      { label: 'scripts', value: viewCounts.js_files ?? 0, note: 'parsed line by line', color: 'var(--nc-violet)' },
      { label: 'endpoints', value: viewCounts.endpoints ?? 0, note: 'mapped in the surface', color: 'var(--nc-acid)' },
      {
        label: 'signals',
        value: rawSignals,
        note: `${verified} proved · ${viewCounts.review_loopholes ?? 0} code notes`,
        color: 'var(--nc-gold)'
      }
    ];
  });

  const hosts = $derived.by<Host[]>(() => {
    const map = new Map<string, Host>();
    for (const event of events) {
      if (event.type !== 'fetch') continue;
      const raw = String(event.payload?.url ?? '');
      if (!raw) continue;
      let host = '';
      try {
        host = new URL(raw).hostname;
      } catch {
        continue;
      }
      if (!host) continue;
      const row = map.get(host) ?? { host, count: 0, ok: 0 };
      row.count += 1;
      const status = Number(event.payload?.status ?? 0);
      if (status >= 200 && status < 400) row.ok += 1;
      map.set(host, row);
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 5);
  });
  const hostMax = $derived(Math.max(1, ...hosts.map((host) => host.count)));
  const fetchCount = $derived(events.filter((event) => event.type === 'fetch').length);

  const surface = $derived.by(() => {
    const rows = [
      { key: 'pages', label: 'pages', value: viewCounts.pages ?? 0, note: 'crawled', color: 'var(--nc-bone_dust)' },
      { key: 'scripts', label: 'scripts', value: viewCounts.js_files ?? 0, note: 'read', color: 'var(--nc-violet)' },
      { key: 'endpoints', label: 'endpoints', value: viewCounts.endpoints ?? 0, note: 'mapped', color: 'var(--nc-acid)' },
      { key: 'signals', label: 'candidates', value: rawSignals, note: 'surfaced', color: 'var(--nc-gold)' },
      { key: 'verified', label: 'verified', value: verified, note: 'proved', color: 'var(--nc-acid_hot)' }
    ];
    const max = Math.max(1, ...rows.map((row) => row.value));
    return rows.map((row) => ({ ...row, pct: Math.round((row.value / max) * 100) }));
  });

  const heroMission = $derived.by<Mission>(() => {
    if (runningRun) {
      return {
        tone: 'var(--nc-acid)',
        eyebrow: 'live cast',
        lead: 'Casting over',
        mark: runningRun.target,
        body: `${stageNow ? `The ${stageLabel.toLowerCase()} stage is engaged.` : 'The agents are spinning up.'} ${viewCounts.pages ?? 0} pages are under the glass, ${viewCounts.js_files ?? 0} scripts parsed and ${viewCounts.endpoints ?? 0} endpoints mapped. The transmission beside this is coming from the models themselves.`,
        primary: 'watch live',
        secondary: 'open inspector',
        goPrimary: () => store.watch(runningRun.id),
        goSecondary: () => store.watch(runningRun.id)
      };
    }
    if (confirmed + escalated > 0) {
      const n = confirmed + escalated;
      return {
        tone: 'var(--nc-gold)',
        eyebrow: 'proof on the table',
        lead: `${n} finding${n === 1 ? '' : 's'} confirmed.`,
        mark: 'Write the report.',
        body: 'A human marked these as real. Open the evidence, tighten the impact story and move the strongest one toward submission before the trail cools.',
        primary: 'review findings',
        secondary: 'open latest run',
        goPrimary: () => store.go('findings'),
        goSecondary: () => (focusRun ? store.watch(focusRun.id) : store.go('runs'))
      };
    }
    if (openFindings > 0) {
      return {
        tone: 'var(--nc-bone)',
        eyebrow: 'human queue',
        lead: `${openFindings} candidate${openFindings === 1 ? '' : 's'} need`,
        mark: 'a call.',
        body: 'The pipeline surfaced these but did not prove them. Read the evidence, check the confidence and decide whether to confirm, escalate or reject each one.',
        primary: 'open the queue',
        secondary: 'start another cast',
        goPrimary: () => store.go('findings'),
        goSecondary: () => store.go('new')
      };
    }
    if (rawSignals > 0) {
      return {
        tone: 'var(--nc-violet)',
        eyebrow: 'last cast // unresolved',
        lead: `${rawSignals} raw signal${rawSignals === 1 ? '' : 's'} surfaced.`,
        mark: 'None proved.',
        body: `The last pass over ${target || 'the target'} read ${viewCounts.pages ?? 0} pages and ${viewCounts.js_files ?? 0} scripts but closed without proof. Open the trace to see what the classifiers saw and where validation broke down.`,
        primary: 'open the trace',
        secondary: 'cast a deeper net',
        goPrimary: () => (focusRun ? store.watch(focusRun.id) : store.go('live')),
        goSecondary: () => store.go('new')
      };
    }
    if ((totals?.runs ?? 0) === 0) {
      return {
        tone: 'var(--nc-acid)',
        eyebrow: 'the net is armed',
        lead: 'Point it at',
        mark: 'something.',
        body: 'NetCast3r crawls a site, reads its JavaScript, hunts for credentials and validates what it catches against the provider that issued it. Nothing leaves your machine until you start a cast.',
        primary: 'start your first cast',
        secondary: 'read the field guide',
        goPrimary: () => store.go('new'),
        goSecondary: () => store.go('help')
      };
    }
    return {
      tone: 'var(--nc-bone)',
      eyebrow: 'all clear',
      lead: 'The net is',
      mark: 'quiet.',
      body: `${totals?.runs ?? 0} casts are in the ledger. Nothing is waiting for a human right now. The last return is still in the trace if you want to read the agents' notes.`,
      primary: 'cast a new target',
      secondary: 'open last run',
      goPrimary: () => store.go('new'),
      goSecondary: () => (focusRun ? store.watch(focusRun.id) : store.go('runs'))
    };
  });

  const nextActions = $derived.by<NextAction[]>(() => {
    const out: Omit<NextAction, 'num'>[] = [];
    const add = (action: Omit<NextAction, 'num'>) => out.push(action);
    if (live && focusRun) {
      add({
        id: 'watch',
        title: 'Ride the live wire',
        body: `${focusRun.target} is still being read. Watch the transmission and interrupt at the right moment.`,
        cta: 'open live inspector',
        color: 'var(--nc-acid)',
        go: () => store.watch(focusRun.id)
      });
    }
    if (focusRun && rawSignals > 0) {
      add({
        id: 'signals',
        title: 'Interrogate the raw signals',
        body: `${rawSignals} value${rawSignals === 1 ? '' : 's'} surfaced but ${verified} proved. The trace shows the classifier's reasoning and where validation stopped.`,
        cta: 'open the evidence',
        color: 'var(--nc-violet)',
        go: () => store.watch(focusRun.id)
      });
    }
    if (fleet.failed > 0) {
      add({
        id: 'fleet',
        title: 'Repair the model fleet',
        body: `${fleet.failed} of ${fleet.total} model calls failed on this cast. Route around the dead providers before the next run.`,
        cta: 'test providers',
        color: 'var(--nc-gold)',
        go: () => store.go('keys')
      });
    }
    if (focusRun?.counts?.report) {
      add({
        id: 'report',
        title: 'Open the field report',
        body: 'The run wrote a readable report. Open it before the evidence gets cold.',
        cta: 'open the report',
        color: 'var(--nc-bone)',
        go: () => store.watch(focusRun.id, 'report')
      });
    }
    if (!live) {
      add({
        id: 'scan',
        title: 'Cast a deeper net',
        body: 'Change the target, widen the depth or revisit a stopped run with the current provider fleet.',
        cta: 'configure a scan',
        color: 'var(--nc-acid)',
        go: () => store.go('new')
      });
    }
    return out.slice(0, 3).map((action, index) => ({
      ...action,
      num: String(index + 1).padStart(2, '0')
    }));
  });

  const feedCounts = $derived({
    think: thoughts.length,
    models: calls.length,
    signals: signals.length,
    logs: logs.length
  });

  const ticker = $derived.by(() => {
    const items: string[] = [];
    if (latestThought) items.push(`${latestThought.agent}: ${latestThought.text.slice(0, 150)}`);
    if (fleet.total > 0) items.push(`model fleet returned ${fleet.ok}/${fleet.total} calls`);
    if (signals.length > 0) {
      items.push(`${signals[signals.length - 1].secret_type} ${signals[signals.length - 1].value} · ${signals[signals.length - 1].detail || 'unresolved'}`);
    }
    if (focusRun) items.push(`${stageLabel.toLowerCase()} · ${elapsed} elapsed · ${events.length} events on the wire`);
    return items.length ? items : ['no activity recorded on this cast'];
  });

  const tickerItems = $derived(ticker);

  const queue = $derived.by<QueueItem[]>(() => {
    if (recent.length > 0) {
      return recent.slice(0, 4).map((finding) => ({
        id: finding.id,
        label: finding.secret_type,
        value: finding.value,
        detail: finding.title,
        status: finding.triage_status || 'new',
        severity: finding.severity,
        ts: isoMs(finding.created_at) / 1000,
        finding: true
      }));
    }
    return signals
      .slice(-4)
      .reverse()
      .map((signal) => ({
        id: `signal-${signal.seq}`,
        label: signal.secret_type,
        value: signal.value,
        detail: signal.detail || 'no validator recipe matched this value',
        status: signal.status,
        severity: signal.status,
        ts: signal.ts,
        finding: false
      }));
  });

  const runTrend = $derived(
    [...store.runs]
      .slice(0, 10)
      .reverse()
      .map((run) => run.counts?.pages ?? 0)
  );

  function duration(run: Run): string {
    const start = isoMs(run.started_at || run.created_at);
    const end = run.finished_at ? isoMs(run.finished_at) : Date.now();
    if (!Number.isFinite(start) || !Number.isFinite(end)) return '--';
    const seconds = Math.max(0, Math.floor((end - start) / 1000));
    const minutes = Math.floor(seconds / 60);
    return minutes > 0 ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
  }

  async function loadHealth() {
    try {
      providers = (await api.providersHealth()).items;
    } catch {
      /* the provider card simply stays empty when the backend is asleep */
    }
  }

  async function loadRecent() {
    try {
      recent = (await api.findings('?size=6')).items;
    } catch {
      /* an empty queue is a valid state */
    }
  }

  async function testProvider(provider: ProviderHealth) {
    testing = provider.id;
    try {
      const result = await api.testProvider(provider.id);
      store.toast(
        result.ok ? 'ok' : 'warn',
        result.ok ? `${provider.name} is reachable` : `${provider.name}: ${result.reason}`
      );
      await loadHealth();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not test the provider');
    } finally {
      testing = '';
    }
  }

  function disconnect() {
    source?.close();
    source = null;
    connectedRun = '';
  }

  function ingest(event: RunEvent) {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    events = [...events, event].slice(-1800);
    if (event.type === 'run.finished' || event.type === 'run.state') scheduleRefresh();
  }

  function connect(runId: string) {
    if (connectedRun === runId) return;
    disconnect();
    const stream = new EventSource(api.eventsUrl());
    stream.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as RunEvent;
        if (event.run_id !== runId) return;
        if (!autoFollow) {
          pausedEvents.push(event);
          pausedCount = pausedEvents.length;
          return;
        }
        ingest(event);
      } catch {
        /* ignore a malformed frame */
      }
    };
    stream.onerror = () => {
      /* EventSource retries on its own; the heartbeat keeps the cards fresh */
    };
    source = stream;
    connectedRun = runId;
  }

  function toggleFollow() {
    autoFollow = !autoFollow;
    if (!autoFollow) return;
    const buffered = pausedEvents;
    pausedEvents = [];
    pausedCount = 0;
    for (const event of buffered) ingest(event);
  }

  function scheduleRefresh() {
    if (refreshTimer) return;
    refreshTimer = window.setTimeout(() => {
      refreshTimer = undefined;
      void store.refreshTotals();
      void store.refreshRuns();
      void loadRecent();
    }, 800);
  }

  async function loadFocus(run: Run) {
    if (loadedRun === run.id || loadingRun === run.id) return;
    loadingRun = run.id;
    events = [];
    pausedEvents = [];
    pausedCount = 0;
    seen.clear();
    if (run.status === 'running' || run.status === 'queued') connect(run.id);
    try {
      const page = await api.runEvents(run.id);
      const items = (page.items ?? []) as RunEvent[];
      if (focusRun?.id !== run.id) return;
      const archived = new Set(items.map((item) => item.id));
      const liveFrames = events.filter((event) => !archived.has(event.id));
      for (const item of items) seen.add(item.id);
      events = [...items, ...liveFrames].sort((a, b) => a.seq - b.seq).slice(-1800);
      loadedRun = run.id;
    } catch {
      /* mark it loaded so the SSE stream can still take over */
      if (focusRun?.id === run.id) loadedRun = run.id;
    } finally {
      if (loadingRun === run.id) loadingRun = '';
    }
  }

  $effect(() => {
    const run = focusRun;
    if (!run) {
      disconnect();
      loadedRun = '';
      events = [];
      return;
    }
    if (loadedRun !== run.id) {
      void loadFocus(run);
      return;
    }
    if (run.status === 'running' || run.status === 'queued') connect(run.id);
    else disconnect();
  });

  $effect(() => {
    const delay = live ? 1000 : 5000;
    const timer = window.setInterval(() => (now = Date.now()), delay);
    return () => window.clearInterval(timer);
  });

  onMount(() => {
    void store.refreshTotals();
    void store.refreshRuns();
    void loadHealth();
    void loadRecent();
  });

  onDestroy(() => {
    disconnect();
    if (refreshTimer) window.clearTimeout(refreshTimer);
  });
</script>

<div class="stagger mx-auto flex max-w-[1280px] flex-col gap-5">
  <!-- ------------------------------------------------------------------ -->
  <!-- command hero                                                        -->
  <!-- ------------------------------------------------------------------ -->
  <section class="cmd-hero panel-raised panel-hud relative overflow-hidden" use:pauseOffscreen>
    <HeroArt class="cmd-hero-art pointer-events-none absolute inset-0 h-full w-full" live={live} />
    <div class="cmd-hero-veil" aria-hidden="true"></div>
    <div class="cmd-hero-grid" aria-hidden="true"></div>

    <div class="relative z-[4] px-6 pt-6 sm:px-8 sm:pt-8">
      <div class="flex flex-wrap items-center gap-2.5">
        <span class="mission-beacon" style="--beacon:{heroMission.tone}" aria-hidden="true"></span>
        <p class="eyebrow" style="color:{heroMission.tone}">{heroMission.eyebrow}</p>
        {#if focusRun}
          <span class="chip" style="color:{statusColor(focusRun.status)}">
            <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
              <circle cx="4" cy="4" r="3.4" />
            </svg>
            {statusLabel(focusRun.status)}
          </span>
        {/if}
        <span class="mono hidden text-[10px] tracking-[0.16em] text-slate sm:inline">
          mission {focusRun?.id.slice(-6) ?? 'standby'}
        </span>
        <span class="ml-auto flex items-center gap-2 text-[10px] tracking-[0.12em] text-ash">
          <span class="sync-dot" class:live></span>
          <span class="mono">synced {syncLabel}</span>
        </span>
      </div>

      <div class="mt-5 max-w-[760px]">
        <h1 class="cmd-title">
          {heroMission.lead}
          {#if heroMission.mark}<span class="cmd-title-mark">{heroMission.mark}</span>{/if}
        </h1>
        <p class="cmd-sub">{heroMission.body}</p>

        {#if latestThought}
          <button
            class="hero-thought mt-5"
            type="button"
            onclick={() => focusRun && store.watch(focusRun.id)}
            title="open the full agent trace"
          >
            <span class="lane-led" style="--agent:{agentColor(latestThought.agent)}" aria-hidden="true"></span>
            <span class="eyebrow shrink-0" style="color:{agentColor(latestThought.agent)}">{latestThought.agent}</span>
            <span class="hero-thought-text">{latestThought.text}</span>
            <span class="mono hidden shrink-0 text-[10px] text-slate sm:inline">{clock(latestThought.ts)}</span>
            <span class="hero-thought-arrow" aria-hidden="true">↗</span>
          </button>
        {/if}

        <div class="mt-6 flex flex-wrap items-center gap-3">
          <button class="btn btn-acid" type="button" onclick={heroMission.goPrimary}>{heroMission.primary}</button>
          <button class="btn" type="button" onclick={heroMission.goSecondary}>{heroMission.secondary}</button>
          {#if live}
            <span class="live-now">
              <span class="pulse-live h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
              {elapsed} elapsed
            </span>
          {:else if focusRun}
            <span class="mono text-[10px] tracking-[0.1em] text-ash">last return {ago(focusRun.created_at)}</span>
          {/if}
        </div>
      </div>
    </div>

    <aside class="hero-console absolute right-7 top-[92px] z-[4] hidden w-[188px] xl:block" aria-label="run scope">
      <div class="flex items-center justify-between gap-2">
        <p class="eyebrow">scope</p>
        <span class="mono text-[9px] tracking-[0.14em]" style="color:{live ? 'var(--nc-acid)' : 'var(--nc-slate)'}">
          {live ? 'live' : 'archive'}
        </span>
      </div>
      <div class="mt-3 flex items-center gap-3">
        <div class="hero-ring" style="--ring:{pipelinePct * 3.6}deg">
          <div class="hero-ring-inner">
            <span class="num">{pipelinePct}<small>%</small></span>
            <span>pipeline</span>
          </div>
        </div>
        <div class="min-w-0">
          <p class="mono truncate text-[11px] text-bone">{stageLabel}</p>
          <p class="mono mt-1 text-[10px] text-ash">{elapsed}</p>
          <p class="mono mt-0.5 text-[10px] text-slate">{events.length} events</p>
        </div>
      </div>
      <div class="hero-console-rule"></div>
      <div class="grid grid-cols-2 gap-2">
        <div>
          <p class="eyebrow">replies</p>
          <p class="num mt-0.5 text-sm text-bone">{fleet.ok}<span class="text-ash">/{fleet.total}</span></p>
        </div>
        <div class="border-l border-indigo-deep pl-2">
          <p class="eyebrow">signals</p>
          <p class="num mt-0.5 text-sm" style="color:var(--nc-violet)">{rawSignals}</p>
        </div>
      </div>
    </aside>

    <div class="cmd-hero-stats relative z-[4]">
      {#each heroStats as stat, index (stat.label)}
        <div class="cmd-stat" use:spotlight>
          <p class="eyebrow">{stat.label}</p>
          <p class="num cmd-stat-value" style="color:{stat.color}">
            <span use:countup={stat.value}>0</span>
          </p>
          <p class="cmd-stat-note">{stat.note}</p>
          <span class="cmd-stat-index" aria-hidden="true">0{index + 1}</span>
        </div>
      {/each}
    </div>

    <div class="cmd-ticker relative z-[4]">
      <span class="ticker-pill">
        <span class="pulse-live h-1.5 w-1.5 rounded-full" class:bg-acid={live} class:bg-slate={!live} aria-hidden="true"></span>
        {live ? 'transmitting' : 'replay'}
      </span>
      <div class="ticker-track">
        {#each tickerItems as line, index (line + index)}
          <span class="ticker-item">
            <span class="ticker-glyph" aria-hidden="true">{index === 0 ? '▸' : '·'}</span>
            {line}
          </span>
        {/each}
      </div>
      <span class="mono hidden shrink-0 text-[10px] text-slate sm:inline">{events.length} ev</span>
    </div>
    <div class="cmd-hero-progress" style="width:{pipelinePct}%" aria-hidden="true"></div>
  </section>

  <!-- ------------------------------------------------------------------ -->
  <!-- intelligence + side deck                                           -->
  <!-- ------------------------------------------------------------------ -->
  <section class="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(300px,0.82fr)]">
    <div class="relative min-h-[390px] xl:min-h-0">
      <article class="panel panel-hud intel-panel overflow-hidden xl:absolute xl:inset-0" use:spotlight>
      <header class="cmd-section-head flex-wrap">
        <div class="min-w-0">
          <p class="eyebrow">agent transmission</p>
          <p class="cmd-section-sub">What the models are actually saying, as they say it.</p>
        </div>
        <div class="intel-tabs ml-auto" role="tablist" aria-label="intelligence feed">
          {#each [
            ['think', 'thinking'],
            ['models', 'model calls'],
            ['signals', 'signals'],
            ['logs', 'logs']
          ] as [id, label] (id)}
            <button
              class="intel-tab"
              class:active={feedTab === id}
              type="button"
              role="tab"
              aria-selected={feedTab === id}
              onclick={() => (feedTab = id as typeof feedTab)}
            >
              {label}
              <span>{feedCounts[id as keyof typeof feedCounts] ?? 0}</span>
            </button>
          {/each}
        </div>
        {#if focusRun}
          <button class="btn btn-quiet hidden shrink-0 px-2! py-1! text-xs xl:inline-flex" type="button" onclick={() => store.watch(focusRun.id)}>
            full trace ↗
          </button>
        {/if}
      </header>

      <div class="intel-body">
        {#if events.length === 0}
          <div class="intel-empty">
            <span class="intel-empty-glyph" aria-hidden="true">⌁</span>
            <p class="eyebrow">no transmission</p>
            <p class="mt-2 max-w-[420px] text-sm text-bone-dust">
              {focusRun
                ? 'This run did not leave a readable event trail. Open the inspector for whatever was persisted.'
                : 'Start a cast and the agents will narrate what they read, what they suspect and where they stop.'}
            </p>
            <button class="btn mt-4" type="button" onclick={() => store.go(focusRun ? 'live' : 'new')}>
              {focusRun ? 'open inspector' : 'start a cast'}
            </button>
          </div>
        {:else if feedTab === 'think'}
          {#if thoughts.length === 0}
            <div class="intel-empty">
              <span class="intel-empty-glyph" aria-hidden="true">⌁</span>
              <p class="eyebrow">{live ? 'reasoning pending' : 'no reasoning recorded'}</p>
              <p class="mt-2 max-w-[430px] text-sm text-bone-dust">
                {live
                  ? stageNow === 'crawl'
                    ? 'The crawl is still reading the surface. The first model call will narrate what it reads and where it stops.'
                    : 'The agents are between calls. Their reasoning will land here as soon as the next call returns.'
                  : 'This run left events but no model reasoning. Check the model calls and logs for what the agents were doing.'}
              </p>
              <button class="btn mt-4" type="button" onclick={() => (focusRun ? store.watch(focusRun.id) : store.go('live'))}>
                {live ? 'watch the live cast' : 'open inspector'}
              </button>
            </div>
          {:else}
          <div class="grid gap-2">
            {#each thoughts.slice(-7).reverse() as thought, index (thought.seq)}
              <button
                class="thought-row"
                class:thought-live={live && index === 0}
                type="button"
                onclick={() => focusRun && store.watch(focusRun.id)}
                title="open the full trace"
              >
                <span class="thought-meta">
                  <span class="lane-led" style="--agent:{agentColor(thought.agent)}" aria-hidden="true"></span>
                  <span class="mono" style="color:{agentColor(thought.agent)}">{thought.agent}</span>
                  <span class="mono ml-auto text-[10px] text-slate">{clock(thought.ts)}</span>
                </span>
                <span class="thought-text">{thought.text}</span>
              </button>
            {/each}
          </div>
          {/if}
        {:else if feedTab === 'models'}
          {#if calls.length === 0}
            <div class="intel-empty">
              <span class="intel-empty-glyph" aria-hidden="true">◌</span>
              <p class="eyebrow">{live ? 'no model calls yet' : 'no model calls'}</p>
              <p class="mt-2 max-w-[430px] text-sm text-bone-dust">
                {live
                  ? 'The cast has not asked a model to read anything yet. Calls will appear here as each agent starts.'
                  : 'No model traffic was recorded in this run. Add a provider or test the current fleet before the next cast.'}
              </p>
              <button class="btn mt-4" type="button" onclick={() => store.go('keys')}>manage fleet</button>
            </div>
          {:else}
          <div class="grid gap-1.5">
            {#each calls.slice(-10).reverse() as call (call.seq)}
              <div class="call-row" class:call-fail={!call.ok}>
                <span class="call-dot" class:ok={call.ok} aria-hidden="true"></span>
                <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{call.provider}/{call.model}</span>
                <span class="mono shrink-0 text-[10px] text-ash">{call.ms}ms</span>
                <span class="mono shrink-0 text-[10px]" style="color:{call.ok ? 'var(--nc-acid)' : 'var(--nc-violet)'}">
                  {call.ok ? 'returned' : 'failed'}
                </span>
                {#if !call.ok && call.error}
                  <span class="mono hidden max-w-[260px] truncate text-[10px] text-slate md:inline" title={call.error}>{call.error}</span>
                {/if}
              </div>
            {/each}
          </div>
          {/if}
        {:else if feedTab === 'signals'}
          {#if signals.length === 0}
            <div class="intel-empty">
              <span class="intel-empty-glyph" aria-hidden="true">◇</span>
              <p class="eyebrow">{live ? 'no signals yet' : 'no signals'}</p>
              <p class="mt-2 max-w-[430px] text-sm text-bone-dust">
                No raw candidate has surfaced in this cast. Values appear here only when the classifier can explain them.
              </p>
            </div>
          {:else}
          <div class="grid gap-1.5">
            {#each signals.slice(-8).reverse() as signal (signal.seq)}
              <div class="feed-signal">
                <span class="mono text-[10px] tracking-[0.08em] text-violet">{signal.secret_type}</span>
                <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{signal.value}</span>
                <span class="mono shrink-0 text-[10px] text-ash">{signal.status}</span>
                <span class="mono hidden max-w-[280px] truncate text-[10px] text-slate md:inline">{signal.detail}</span>
              </div>
            {/each}
          </div>
          {/if}
        {:else}
          {#if logs.length === 0}
            <div class="intel-empty">
              <span class="intel-empty-glyph" aria-hidden="true">⌁</span>
              <p class="eyebrow">{live ? 'no log lines yet' : 'no logs'}</p>
              <p class="mt-2 max-w-[430px] text-sm text-bone-dust">
                No log lines were emitted in this run.
              </p>
            </div>
          {:else}
          <div class="grid gap-1">
            {#each logs.slice(-12).reverse() as line (line.seq)}
              <div class="log-row" class:log-error={line.level === 'error'}>
                <span class="mono shrink-0 text-[10px] text-slate">{clock(line.ts)}</span>
                <span class="mono shrink-0 text-[10px]" style="color:{line.level === 'error' ? 'var(--nc-violet)' : 'var(--nc-acid)'}">
                  {line.level === 'error' ? 'err' : 'log'}
                </span>
                <span class="mono min-w-0 flex-1 truncate text-[11px] text-bone-dust" title={line.text}>{line.text}</span>
              </div>
            {/each}
          </div>
          {/if}
        {/if}
      </div>

      <footer class="intel-foot">
        <span class="flex items-center gap-2">
          <span class="pulse-live h-1.5 w-1.5 rounded-full" class:bg-acid={live} class:bg-slate={!live} aria-hidden="true"></span>
          <span class="mono text-[10px] tracking-[0.12em] text-ash">
            {live ? 'streaming from the live cast' : 'replay of the last cast'}
          </span>
        </span>
        <span class="mono text-[10px] text-slate">
          {thoughts.length} thoughts · {calls.length} calls · {signals.length} signals
        </span>
        <button class="btn btn-quiet ml-auto px-2! py-1! text-xs" type="button" onclick={toggleFollow}>
          {autoFollow ? 'pause feed' : pausedCount ? `resume · ${pausedCount}` : 'resume feed'}
        </button>
        </footer>
      </article>
    </div>

    <aside class="flex flex-col gap-4">
      <article class="panel panel-hud action-deck overflow-hidden">
        <header class="cmd-section-head">
          <div>
            <p class="eyebrow">next moves</p>
            <p class="cmd-section-sub">The shortest path from signal to proof.</p>
          </div>
          <span class="chip" style="color:var(--nc-acid)">{nextActions.length} open</span>
        </header>
        <div class="action-list">
          {#each nextActions as action (action.id)}
            <button class="action-card" type="button" style="--action:{action.color}" onclick={action.go}>
              <span class="action-num">{action.num}</span>
              <span class="min-w-0 flex-1">
                <span class="action-title">{action.title}<span class="action-arrow" aria-hidden="true">↗</span></span>
                <span class="action-body">{action.body}</span>
                <span class="action-cta">{action.cta} <span aria-hidden="true">→</span></span>
              </span>
            </button>
          {:else}
            <p class="px-5 py-6 text-sm text-bone-dust">The deck is clear. Cast a new target when you are ready.</p>
          {/each}
        </div>
      </article>

      <article class="panel panel-hud fleet-panel overflow-hidden">
        <header class="cmd-section-head">
          <div>
            <p class="eyebrow">model fleet</p>
            <p class="cmd-section-sub">Every reply, every stall, every reroute.</p>
          </div>
          <span class="num text-sm" style="color:{fleet.rate > 0.8 ? 'var(--nc-acid)' : 'var(--nc-gold)'}">
            {fleet.total ? Math.round(fleet.rate * 100) : 0}%
          </span>
        </header>
        <div class="fleet-meter" aria-hidden="true">
          <i style="width:{fleet.rate * 100}%; background:linear-gradient(90deg,var(--nc-violet),var(--nc-acid))"></i>
        </div>
        <div class="fleet-list">
          {#if fleetRows.length === 0}
            <p class="px-4 py-5 text-sm text-bone-dust">No model traffic yet. Add a provider to give the agents a voice.</p>
          {:else}
            {#each fleetRows.slice(0, 5) as row (row.key)}
              <div class="fleet-row" title={row.error || row.lastModel}>
                <span class="fleet-dot" class:bad={!row.healthy && row.calls === 0} class:hot={row.failed > 0} aria-hidden="true"></span>
                <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{row.name}</span>
                {#if row.calls > 0}
                  <span class="num shrink-0 text-[11px] text-ash">{row.ok}/{row.calls}</span>
                {:else}
                  <span class="mono shrink-0 text-[10px] text-slate">{row.models} models</span>
                {/if}
                {#if row.failed > 0}
                  <span class="mono shrink-0 text-[10px] text-violet">{row.failed} fail</span>
                {:else if row.avgMs > 0}
                  <span class="mono shrink-0 text-[10px] text-slate">{row.avgMs}ms</span>
                {:else if row.healthy}
                  <span class="mono shrink-0 text-[10px] text-acid">ready</span>
                {:else}
                  <span class="mono shrink-0 text-[10px] text-slate">idle</span>
                {/if}
              </div>
            {/each}
          {/if}
        </div>
        <footer class="intel-foot">
          <span class="mono text-[10px] text-slate">{providers.length} configured · {fleetRows.length} in trace</span>
          <button class="btn btn-quiet ml-auto px-2! py-1! text-xs" type="button" onclick={() => store.go('keys')}>manage fleet</button>
        </footer>
      </article>
    </aside>
  </section>

  <!-- ------------------------------------------------------------------ -->
  <!-- surface + human queue                                              -->
  <!-- ------------------------------------------------------------------ -->
  <section class="grid gap-4 xl:grid-cols-[minmax(0,1.28fr)_minmax(300px,0.72fr)]">
    <article class="panel panel-hud surface-panel p-5" use:spotlight>
      <header class="flex flex-wrap items-start gap-3">
        <div class="min-w-0">
          <p class="eyebrow">attack surface</p>
          <p class="cmd-section-sub">The funnel from crawl to proof.</p>
        </div>
        <span class="chip ml-auto" style="color:var(--nc-acid)">
          {Math.round(proofRate * 100)}% proof rate
        </span>
      </header>

      <div class="surface-chain mt-6">
        {#each surface as node, index (node.key)}
          <button
            class="surface-node"
            type="button"
            onclick={() => focusRun && store.watch(focusRun.id)}
            title="open the run inspector"
          >
            <span class="surface-index">0{index + 1}</span>
            <span class="surface-label">{node.label}</span>
            <span class="num surface-value">{node.value}</span>
            <span class="surface-bar" aria-hidden="true"><i style="width:{node.pct}%; background:{node.color}"></i></span>
            <span class="surface-note">{node.note}</span>
          </button>
          {#if index < surface.length - 1}
            <span class="surface-link" aria-hidden="true"><i></i></span>
          {/if}
        {/each}
      </div>

      {#if hosts.length > 0}
        <div class="host-board mt-5 border-t border-indigo-deep pt-3">
          <div class="flex items-center justify-between gap-2">
            <p class="eyebrow">assets under glass</p>
            <span class="mono text-[9px] tracking-[0.1em] text-slate">top {hosts.length} · {fetchCount} fetches</span>
          </div>
          <div class="mt-2 grid gap-1.5">
            {#each hosts as host (host.host)}
              <div class="host-row">
                <span class="host-dot" class:ok={host.ok > 0} aria-hidden="true"></span>
                <span class="mono min-w-0 flex-1 truncate text-[11px] text-bone-dust" title={host.host}>{host.host}</span>
                <span class="num shrink-0 text-[10px] text-ash">{host.count}</span>
                <span class="host-bar" aria-hidden="true"><i style="width:{Math.round((host.count / hostMax) * 100)}%"></i></span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <div class="surface-foot mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div>
          <p class="eyebrow">code notes</p>
          <p class="num mt-1 text-lg text-bone">{viewCounts.review_loopholes ?? 0}</p>
        </div>
        <div>
          <p class="eyebrow">endpoint notes</p>
          <p class="num mt-1 text-lg text-bone">{viewCounts.review_endpoints ?? 0}</p>
        </div>
        <div>
          <p class="eyebrow">unverified</p>
          <p class="num mt-1 text-lg" style="color:var(--nc-violet)">{viewCounts.unverified ?? 0}</p>
        </div>
        <div>
          <p class="eyebrow">last return</p>
          <p class="mt-1 text-sm text-bone-dust">{focusRun ? ago(focusRun.created_at) : 'never'}</p>
        </div>
      </div>
    </article>

    <article class="panel panel-hud queue-panel overflow-hidden">
      <header class="cmd-section-head">
        <div>
          <p class="eyebrow">human queue</p>
          <p class="cmd-section-sub">Raw signals waiting for judgement.</p>
        </div>
        <span class="chip" style="color:var(--nc-violet)">{queue.length}</span>
      </header>

      {#if queue.length === 0}
        <div class="queue-empty">
          <span class="intel-empty-glyph" aria-hidden="true">◌</span>
          <p class="eyebrow mt-2">queue empty</p>
          <p class="mt-2 text-sm text-bone-dust">
            {focusRun
              ? 'No raw signals on the last cast. The net came back clean.'
              : 'No casts yet. The queue fills as soon as a credential-shaped value surfaces.'}
          </p>
        </div>
      {:else}
        <div class="queue-list">
          {#each queue as item (item.id)}
            <button
              class="queue-item"
              type="button"
              onclick={() => (item.finding ? store.go('findings') : focusRun && store.watch(focusRun.id))}
            >
              <div class="flex items-center gap-2">
                <Chip
                  label={item.finding ? triageLabel(item.status) : item.status}
                  color={item.finding ? sevColor(item.severity) : 'var(--nc-violet)'}
                  shape={item.finding ? sevShape(item.severity) : 'dia'}
                />
                <span class="mono ml-auto text-[10px] text-slate">{clock(item.ts)}</span>
              </div>
              <p class="mt-2 flex items-center gap-2 text-sm text-bone">
                <span class="mono text-[10px] uppercase tracking-[0.12em] text-violet">{item.label}</span>
                <span class="min-w-0 flex-1 truncate">{item.value}</span>
              </p>
              <p class="mt-1 line-clamp-2 text-xs leading-relaxed text-bone-dust">{item.detail}</p>
              <span class="queue-open">open evidence <span aria-hidden="true">→</span></span>
            </button>
          {/each}
        </div>
      {/if}

      <div class="queue-guide">
        <p class="eyebrow">how to read this</p>
        <p class="mt-1.5 text-[11px] leading-relaxed text-bone-dust">
          {recent.length
            ? 'A persisted finding already passed a validator or a human. Confirm only when the evidence proves impact, not merely because the value looks secret.'
            : 'A raw signal is a lead, not a finding. These values stalled because no validator recipe matched their type; they stay visible so a human can decide whether the context makes them real.'}
        </p>
      </div>

      <footer class="intel-foot">
        <span class="mono text-[10px] text-slate">{recent.length ? 'persisted findings' : 'unwritten candidates'}</span>
        <button class="btn btn-quiet ml-auto px-2! py-1! text-xs" type="button" onclick={() => store.go('findings')}>open findings</button>
      </footer>
    </article>
  </section>

  <!-- ------------------------------------------------------------------ -->
  <!-- run ledger + provider strip                                        -->
  <!-- ------------------------------------------------------------------ -->
  <section class="panel panel-hud ledger overflow-hidden">
    <header class="cmd-section-head flex-wrap">
      <div>
        <p class="eyebrow">run ledger</p>
        <p class="cmd-section-sub">Every cast, every return, every dead end.</p>
      </div>
      <div class="ml-auto flex items-center gap-3">
        <div class="hidden items-center gap-2 text-right sm:flex">
          <Sparkline values={runTrend} width={108} height={24} color="var(--nc-acid)" />
          <div>
            <p class="eyebrow">pages / last {runTrend.length}</p>
            <p class="mono text-[10px] text-slate">coverage drift</p>
          </div>
        </div>
        <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => store.go('runs')}>history</button>
      </div>
    </header>

    {#if store.runs.length === 0}
      <p class="px-5 py-7 text-sm text-bone-dust">No scans yet. Start a cast and the ledger begins here.</p>
    {:else}
      <div class="ledger-head hidden grid-cols-[minmax(0,1.7fr)_repeat(5,minmax(54px,0.5fr))_28px] gap-4 border-b border-indigo-deep px-5 py-2 sm:grid">
        <span class="eyebrow">target</span>
        <span class="eyebrow text-right">pages</span>
        <span class="eyebrow text-right">scripts</span>
        <span class="eyebrow text-right">endpoints</span>
        <span class="eyebrow text-right">signals</span>
        <span class="eyebrow text-right">findings</span>
        <span></span>
      </div>
      <div>
        {#each store.runs.slice(0, 6) as run (run.id)}
          <button
            class="ledger-row"
            class:ledger-current={run.id === focusRun?.id}
            type="button"
            onclick={() => store.watch(run.id)}
          >
            <span class="ledger-signal" style="background:{statusColor(run.status)}" aria-hidden="true"></span>
            <span class="min-w-0">
              <span class="flex min-w-0 items-center gap-2">
                <span class="mono min-w-0 flex-1 truncate text-sm text-bone">{run.target}</span>
                <span class="chip shrink-0" style="color:{statusColor(run.status)}">{statusLabel(run.status)}</span>
              </span>
              <span class="mono mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate">
                <span>{duration(run)}</span>
                <span>{ago(run.created_at)}</span>
                <span class="hidden sm:inline">{run.id.slice(-6)}</span>
              </span>
            </span>
            <span class="ledger-metric"><b class="num">{run.counts?.pages ?? 0}</b><small>pages</small></span>
            <span class="ledger-metric"><b class="num">{run.counts?.js_files ?? 0}</b><small>scripts</small></span>
            <span class="ledger-metric"><b class="num">{run.counts?.endpoints ?? 0}</b><small>endpoints</small></span>
            <span class="ledger-metric"><b class="num" style="color:{(run.counts?.candidates ?? 0) > 0 ? 'var(--nc-violet)' : 'var(--nc-bone_dust)'}">{run.counts?.candidates ?? 0}</b><small>signals</small></span>
            <span class="ledger-metric"><b class="num" style="color:{(run.counts?.findings ?? 0) > 0 ? 'var(--nc-acid)' : 'var(--nc-bone_dust)'}">{run.counts?.findings ?? 0}</b><small>findings</small></span>
            <span class="ledger-go" aria-hidden="true">↗</span>
          </button>
        {/each}
      </div>
    {/if}
  </section>

  <section class="panel provider-strip overflow-hidden">
    <header class="cmd-section-head">
      <div>
        <p class="eyebrow">provider mesh</p>
        <p class="cmd-section-sub">The keys behind the cast.</p>
      </div>
      <button class="btn btn-quiet ml-auto px-2! py-1! text-xs" type="button" onclick={() => store.go('keys')}>manage providers</button>
    </header>
    {#if providers.length === 0}
      <div class="px-5 py-5 text-sm text-bone-dust">
        No providers configured. Add one on the providers screen to give the agents a model.
      </div>
    {:else}
      <div class="provider-grid">
        {#each providers as provider (provider.id)}
          <div class="provider-cell">
            <span class="provider-dot" class:ok={provider.healthy} aria-hidden="true"></span>
            <span class="mono min-w-0 flex-1 truncate text-xs text-bone">{provider.name}</span>
            <span class="mono hidden text-[10px] text-ash sm:inline">{provider.models.length} models</span>
            <span class="mono text-[10px] {provider.key_set ? 'text-bone-dust' : 'text-violet'}">
              {provider.key_set ? 'key set' : 'no key'}
            </span>
            <button
              class="btn btn-quiet px-2! py-1! text-[10px]"
              type="button"
              disabled={testing === provider.id || !provider.key_set}
              onclick={() => testProvider(provider)}
            >
              {testing === provider.id ? 'testing...' : 'test'}
            </button>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>
