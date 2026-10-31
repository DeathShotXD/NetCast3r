<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import {
    ago,
    clock,
    isoMs,
    sevColor,
    stageForAgent,
    statusColor,
    statusLabel,
    triageLabel
  } from '../format';
  import { store } from '../state.svelte';
  import { AGENT_COLORS, STAGES } from '../../tokens';
  import { countup, pauseOffscreen } from '../actions';
  import Icon from '../ui/Icon.svelte';
  import Sparkline from '../ui/Sparkline.svelte';
  import type { Approval, Finding, ProviderHealth, Run, RunEvent } from '../types';
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
  type NextAction = {
    id: string;
    num: string;
    title: string;
    body: string;
    cta: string;
    color: string;
    go: () => void;
  };
  type Host = { host: string; count: number; ok: number };

  const stages = STAGES as unknown as { key: string; label: string; detail: string }[];

  const roster = [
    { key: 'recon', name: 'Recon', role: 'Surface mapper', mark: 'RC' },
    { key: 'exegete', name: 'Exegete', role: 'JavaScript reader', mark: '<>' },
    { key: 'prospector', name: 'Prospector', role: 'Candidate hunter', mark: 'PR' },
    { key: 'classifier', name: 'Classifier', role: 'Credential triage', mark: 'CL' },
    { key: 'assayer', name: 'Assayer', role: 'Validator', mark: 'AS' },
    { key: 'chainer', name: 'Chainer', role: 'Impact chainer', mark: 'CH' },
    { key: 'scribe', name: 'Scribe', role: 'Report writer', mark: 'SC' },
    { key: 'sentinel', name: 'Sentinel', role: 'Adversarial verifier', mark: 'SN' }
  ];

  let providers = $state<ProviderHealth[]>([]);
  let recent = $state<Finding[]>([]);
  let missionApprovals = $state<Approval[]>([]);
  let events = $state<RunEvent[]>([]);
  let loadedRun = $state('');
  let loadingRun = $state('');
  let connectedRun = $state('');
  let feedTab = $state<'think' | 'models' | 'signals' | 'logs'>('think');
  let testing = $state('');
  let reviewing = $state('');
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

  const runOptions = $derived.by(() => {
    const options = (focusRun?.options ?? {}) as Record<string, unknown>;
    const chips: string[] = [];
    if (options.depth !== undefined) chips.push(`depth ${options.depth}`);
    if (options.tier) chips.push(`${String(options.tier)} tier`);
    if (options.subdomains) chips.push('subdomains');
    if (options.wayback) chips.push('wayback');
    if (options.random_agent) chips.push('random agent');
    if (options.resume) chips.push('resume');
    return chips;
  });
  const reportAvailable = $derived(!!counts.report);
  const pendingFindings = $derived(
    recent.filter((finding) => ['new', 'in_progress'].includes(finding.triage_status || 'new'))
  );
  const pendingCount = $derived((triage.new ?? 0) + (triage.in_progress ?? 0) + missionApprovals.length);
  const findingsPreview = $derived(recent.slice(0, 6));
  const agentsSeen = $derived(new Set(events.filter((event) => event.agent).map((event) => event.agent)).size);

  const utcTime = $derived(
    new Intl.DateTimeFormat('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      timeZone: 'UTC'
    }).format(now)
  );
  const utcDate = $derived(
    new Intl.DateTimeFormat('en-GB', {
      weekday: 'short',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      timeZone: 'UTC'
    }).format(now)
  );

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
  const stageAgent = $derived(stageIndex >= 0 ? (stages[stageIndex] as unknown as { agent: string }).agent : '');
  const agentRows = $derived.by(() =>
    roster
      .map((agent) => {
        const own = events.filter((event) => event.agent === agent.key);
        const last = own.length ? own[own.length - 1] : null;
        return {
          ...agent,
          events: own.length,
          lastLabel: last ? clock(last.ts) : 'no events',
          stage: last ? (last.stage || stageForAgent(agent.key)) : '',
          live: live && stageAgent === agent.key
        };
      })
      .sort((a, b) => Number(b.live) - Number(a.live) || b.events - a.events)
  );
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

  const kpis = $derived([
    {
      key: 'active',
      icon: 'activity',
      label: 'Active casts',
      value: live ? 1 : 0,
      note: live
        ? `${target} in flight - ${stageLabel.toLowerCase()}`
        : `${totals?.active_runs ?? 0} queued - control plane idle`,
      tone: live ? 'acid' : '',
      spark: false
    },
    {
      key: 'findings',
      icon: 'bug',
      label: 'Findings',
      value: totals?.findings ?? 0,
      note: `${openFindings} awaiting triage - ${confirmed} confirmed`,
      tone: 'violet',
      spark: false
    },
    {
      key: 'signals',
      icon: 'crosshair',
      label: 'Signals',
      value: rawSignals,
      note: `${verified} proved - ${viewCounts.review_loopholes ?? 0} code notes`,
      tone: 'gold',
      spark: false
    },
    {
      key: 'surface',
      icon: 'globe',
      label: 'Surface mapped',
      value: viewCounts.pages ?? 0,
      note: `${viewCounts.js_files ?? 0} scripts - ${viewCounts.endpoints ?? 0} endpoints`,
      tone: '',
      spark: true
    },
    {
      key: 'missions',
      icon: 'crosshair',
      label: 'Missions',
      value: totals?.missions ?? 0,
      note: `${totals?.active_missions ?? 0} active - ${totals?.pending_approvals ?? 0} approvals`,
      tone: '',
      spark: false
    }
  ]);

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
  const surface = $derived.by(() => {
    const rows = [
      { key: 'pages', label: 'pages', value: viewCounts.pages ?? 0, note: 'crawled', color: 'var(--obs-text-2)' },
      { key: 'scripts', label: 'scripts', value: viewCounts.js_files ?? 0, note: 'read', color: 'var(--obs-violet)' },
      { key: 'endpoints', label: 'endpoints', value: viewCounts.endpoints ?? 0, note: 'mapped', color: 'var(--obs-acid)' },
      { key: 'signals', label: 'candidates', value: rawSignals, note: 'surfaced', color: 'var(--obs-gold)' },
      { key: 'verified', label: 'verified', value: verified, note: 'proved', color: 'var(--obs-acid-2)' }
    ];
    const max = Math.max(1, ...rows.map((row) => row.value));
    return rows.map((row) => ({ ...row, pct: Math.round((row.value / max) * 100) }));
  });

  const heroBody = $derived.by(() => {
    if (!focusRun) {
      return 'No cast is in flight. Point the net at an authorized target and every agent, event, and decision will land here.';
    }
    const pages = viewCounts.pages ?? 0;
    const scripts = viewCounts.js_files ?? 0;
    const endpoints = viewCounts.endpoints ?? 0;
    if (live) {
      return `The ${stageLabel.toLowerCase()} stage is engaged. ${pages} pages are under the glass, ${scripts} scripts parsed and ${endpoints} endpoints mapped. The transmission below is the raw model and tool chatter, not a summary.`;
    }
    const candidates = rawSignals;
    const closure = candidates
      ? `${candidates} candidate${candidates === 1 ? '' : 's'} surfaced; ${verified} cleared validation.`
      : 'No candidate survived the classifiers.';
    return `The last cast over ${focusRun.target} closed ${statusLabel(focusRun.status)} after reading ${pages} pages, parsing ${scripts} scripts and mapping ${endpoints} endpoints. ${closure}`;
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

  function actionIcon(id: string): string {
    return (
      { watch: 'eye', signals: 'crosshair', fleet: 'plug', report: 'file', scan: 'target' }[id] ?? 'arrow-right'
    );
  }

  function hostOf(raw: string): string {
    if (!raw) return '';
    try {
      return new URL(raw).hostname;
    } catch {
      return raw;
    }
  }

  function findingSource(finding: Finding): string {
    const run = store.runs.find((item) => item.id === finding.run_id);
    return hostOf(finding.source) || hostOf(run?.target ?? '') || 'unattributed';
  }

  function confidencePct(finding: Finding): number {
    const value = Number(finding.confidence ?? 0);
    return Math.max(0, Math.min(100, Math.round(value <= 1 ? value * 100 : value)));
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
      recent = (await api.findings('?size=50')).items;
    } catch {
      /* an empty queue is a valid state */
    }
  }

  async function loadApprovals() {
    try {
      missionApprovals = (await api.approvals('?status=pending&size=20')).items;
    } catch {
      /* the queue is optional until the mission service has work */
    }
  }

  async function review(finding: Finding, status: 'confirmed' | 'rejected') {
    reviewing = finding.id;
    try {
      await api.patchFinding(finding.id, { status } as Partial<Finding>);
      store.toast('ok', status === 'confirmed' ? 'finding confirmed' : 'finding rejected');
      await Promise.all([loadRecent(), store.refreshTotals()]);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not update the finding');
    } finally {
      reviewing = '';
    }
  }

  async function decideApproval(approval: Approval, decision: 'approved' | 'rejected') {
    reviewing = approval.id;
    try {
      await api.decideApproval(approval.id, { decision, decided_by: 'operator' });
      store.toast('ok', decision === 'approved' ? 'approval granted' : 'approval rejected');
      await Promise.all([loadApprovals(), store.refreshTotals()]);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not record the decision');
    } finally {
      reviewing = '';
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
          pausedEvents = [...pausedEvents, event].slice(-1800);
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
      void loadApprovals();
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
    void loadApprovals();
  });

  onDestroy(() => {
    disconnect();
    if (refreshTimer) window.clearTimeout(refreshTimer);
  });
</script>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Operations / Command Center</div>
      <h1>Command Center</h1>
      <p class="obs-page-sub">
        The whole hunt at a glance: what the fleet is reading, what it actually proved, and what is waiting on a human decision.
      </p>
    </div>
    <div class="obs-page-actions">
      <div class="obs-page-time">
        <strong>{utcTime} UTC</strong>
        {utcDate}
      </div>
      {#if focusRun}
        <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.watch(focusRun.id)}>
          <Icon name="eye" size={13} />
          {live ? 'Inspect live cast' : 'Inspect last cast'}
        </button>
      {/if}
      <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.go('new')}>
        <Icon name="plus" size={13} />
        New scan
      </button>
    </div>
  </header>

  <section class="obs-kpis" aria-label="control plane summary">
    {#each kpis as kpi (kpi.key)}
      <article class="obs-card obs-kpi {kpi.value > 0 ? kpi.tone : ''}">
        <div class="obs-kpi-label"><Icon name={kpi.icon} size={12} />{kpi.label}</div>
        <div class="obs-kpi-value"><span use:countup={kpi.value}>0</span></div>
        <div class="obs-kpi-foot">
          <span>{kpi.note}</span>
          {#if kpi.spark}
            <Sparkline class="obs-spark" values={runTrend} width={52} height={17} color="var(--obs-acid)" />
          {/if}
        </div>
        <span class="obs-kpi-glyph" aria-hidden="true"><Icon name={kpi.icon} size={42} /></span>
      </article>
    {/each}
  </section>

  <div class="obs-command-grid">
    <div class="obs-command-main">
      <!-- mission hero -->
      <section class="obs-card obs-hero" class:is-live={live} use:pauseOffscreen aria-label="current operation">
        <svg class="obs-hero-net" viewBox="0 0 460 250" fill="none" aria-hidden="true">
          <g stroke="#9F23DD" stroke-opacity=".24">
            <path d="M58 152 146 96 240 123 318 62 390 106" />
            <path d="M58 152 156 190 240 123 306 176 390 106" />
            <path d="M146 96 156 190M318 62 306 176M240 123 252 218" />
          </g>
          <g fill="#C8F81A">
            <circle cx="146" cy="96" r="2.4" /><circle cx="240" cy="123" r="2.4" />
            <circle cx="390" cy="106" r="2.8" /><circle cx="306" cy="176" r="2" />
          </g>
          <g fill="#9F23DD" fill-opacity=".7">
            <circle cx="58" cy="152" r="1.8" /><circle cx="318" cy="62" r="1.8" />
            <circle cx="156" cy="190" r="1.8" /><circle cx="252" cy="218" r="1.8" />
          </g>
        </svg>

        <div class="obs-hero-inner">
          <div>
            <div class="obs-hero-top">
              <span class="obs-live-tag" class:is-archived={!live}>
                <span class="obs-pulse" aria-hidden="true"></span>
                {live ? 'Live cast' : focusRun ? 'Archived cast' : 'Standby'}
              </span>
              {#if focusRun}
                <span class="obs-chip" style="color:{statusColor(focusRun.status)}">
                  <span
                    style="width:5px;height:5px;border-radius:50%;background:currentColor;box-shadow:0 0 6px currentColor"
                    aria-hidden="true"
                  ></span>
                  {statusLabel(focusRun.status)}
                </span>
                <span class="obs-chip">{focusRun.id.slice(-6)}</span>
                {#if focusRun.parent_run_id}
                  <span class="obs-chip">resumed</span>
                {/if}
              {:else}
                <span class="obs-chip">no run selected</span>
              {/if}
            </div>

            <h2 class="obs-hero-title">{focusRun?.target ?? 'The net is armed'}</h2>
            <p class="obs-hero-objective">{heroBody}</p>

            <div class="obs-hero-meta">
              {#if focusRun}
                <span class="obs-chip"><Icon name="target" size={11} />{target}</span>
                <span class="obs-chip">
                  <Icon name="clock" size={11} />
                  {live ? `${elapsed} elapsed` : `closed ${ago(focusRun.finished_at || focusRun.created_at)}`}
                </span>
                <span class="obs-chip"><Icon name="bot" size={11} />{agentsSeen} agents seen</span>
                <span class="obs-chip"><Icon name="database" size={11} />{viewCounts.endpoints ?? 0} endpoints</span>
              {:else}
                <span class="obs-chip"><Icon name="shield" size={11} />authorization required</span>
                <span class="obs-chip"><Icon name="terminal" size={11} />local control plane</span>
              {/if}
            </div>

            <div class="obs-hero-stats">
              <div class="obs-hero-stat"><span>Pages</span><strong>{viewCounts.pages ?? 0}</strong></div>
              <div class="obs-hero-stat"><span>Scripts</span><strong>{viewCounts.js_files ?? 0}</strong></div>
              <div class="obs-hero-stat"><span>Endpoints</span><strong>{viewCounts.endpoints ?? 0}</strong></div>
              <div class="obs-hero-stat">
                <span>Candidates</span>
                <strong class="gold">{rawSignals}<small> / {verified} proved</small></strong>
              </div>
            </div>

            <div class="obs-hero-actions">
              {#if focusRun}
                <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.watch(focusRun.id)}>
                  <Icon name={live ? 'activity' : 'eye'} size={13} />
                  {live ? 'Watch live' : 'Inspect operation'}
                </button>
                {#if reportAvailable}
                  <button class="obs-btn" type="button" onclick={() => store.watch(focusRun.id, 'report')}>
                    <Icon name="file" size={13} />
                    Open report
                  </button>
                {:else}
                  <button class="obs-btn" type="button" onclick={() => store.go('runs')}>
                    <Icon name="layers" size={13} />
                    Run ledger
                  </button>
                {/if}
              {:else}
                <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.go('new')}>
                  <Icon name="crosshair" size={13} />
                  Start your first cast
                </button>
                <button class="obs-btn" type="button" onclick={() => store.go('help')}>
                  <Icon name="terminal" size={13} />
                  Read the field guide
                </button>
              {/if}
              <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('new')}>
                <Icon name="plus" size={13} />
                New scan
              </button>
              <span class="obs-hero-elapsed">
                <span class="obs-status-dot" class:idle={!live} aria-hidden="true"></span>
                {#if live}
                  {stageLabel.toLowerCase()} - {elapsed}
                {:else if focusRun}
                  last event {events.length ? clock(events[events.length - 1].ts) : 'not recorded'}
                {:else}
                  waiting for a target
                {/if}
              </span>
            </div>
          </div>

          <aside class="obs-hero-side" aria-label="pipeline state">
            <div class="obs-ring" style="--p:{pipelinePct}">
              <div class="obs-ring-copy">
                <strong>{pipelinePct}<small>%</small></strong>
                <span>pipeline</span>
              </div>
            </div>
            <div class="obs-hero-side-meta">
              <strong>{focusRun ? stageLabel : 'STANDBY'}</strong>
              {events.length} events - {fleet.ok}/{fleet.total} replies
              <br />
              {runOptions.length ? runOptions.slice(0, 2).join(' - ') : 'no options recorded'}
            </div>
          </aside>
        </div>
      </section>

      <!-- agent fleet -->
      <section aria-label="agent fleet">
        <div class="obs-section-head">
          <div class="obs-section-title">
            <Icon name="bot" size={14} />
            Agent fleet
            <span class="obs-section-meta">{agentsSeen} seen - {roster.length} in roster</span>
          </div>
          <button class="obs-link" type="button" onclick={() => store.go('keys')}>
            Model mesh <Icon name="arrow-right" size={11} />
          </button>
        </div>
        <div class="obs-fleet">
          {#each agentRows.slice(0, 6) as agent (agent.key)}
            <article class="obs-agent" class:is-live={agent.live}>
              <div class="obs-agent-top">
                <span class="obs-agent-avatar">{agent.mark}</span>
                <div>
                  <div class="obs-agent-name">{agent.name}</div>
                  <div class="obs-agent-role">{agent.role}</div>
                </div>
                <span class="obs-agent-state">
                  <span
                    class="obs-status-dot"
                    class:idle={!agent.live && agent.events === 0}
                    class:violet={agent.events > 0 && !agent.live}
                    aria-hidden="true"
                  ></span>
                </span>
              </div>
              <div class="obs-agent-action">
                {#if agent.live}
                  Engaged in the {stageLabel.toLowerCase()} stage.
                {:else if agent.events}
                  {agent.events} events recorded in this cast.
                {:else}
                  No events recorded in this cast.
                {/if}
              </div>
              <div class="obs-agent-foot">
                <span>{agent.lastLabel}</span>
                <span class:acid={agent.live} class:violet={agent.events > 0 && !agent.live}>
                  {agent.events} ev{agent.stage ? ` - ${agent.stage}` : ''}
                </span>
              </div>
            </article>
          {/each}
        </div>
      </section>

      <!-- transmission -->
      <article class="obs-card obs-transmission" aria-label="agent transmission">
        <header class="obs-card-head">
          <div>
            <div class="obs-card-title"><Icon name="activity" size={13} />Agent transmission</div>
            <div class="obs-card-sub">Append-only event log - {events.length} frames on the wire</div>
          </div>
          <div class="obs-tabs" role="tablist" aria-label="transmission feed">
            {#each [
              ['think', 'thinking'],
              ['models', 'model calls'],
              ['signals', 'signals'],
              ['logs', 'logs']
            ] as [id, label] (id)}
              <button
                class="obs-tab"
                class:active={feedTab === id}
                type="button"
                role="tab"
                aria-selected={feedTab === id}
                onclick={() => (feedTab = id as typeof feedTab)}
              >
                {label}<b>{feedCounts[id as keyof typeof feedCounts] ?? 0}</b>
              </button>
            {/each}
          </div>
        </header>

        <div class="obs-feed">
          {#if events.length === 0}
            <div class="obs-empty">
              <span class="obs-empty-icon"><Icon name="terminal" size={18} /></span>
              <div class="obs-empty-title">No transmission yet</div>
              <p class="obs-empty-copy">
                {focusRun
                  ? 'This run did not leave a readable event trail. Open the inspector for whatever was persisted.'
                  : 'Start a cast and the agents will narrate what they read, what they suspect, and where they stop.'}
              </p>
              <button class="obs-btn" type="button" onclick={() => store.go(focusRun ? 'live' : 'new')}>
                {focusRun ? 'Open inspector' : 'Start a cast'}
              </button>
            </div>
          {:else if feedTab === 'think'}
            {#if thoughts.length === 0}
              <div class="obs-empty">
                <span class="obs-empty-icon"><Icon name="sparkles" size={18} /></span>
                <div class="obs-empty-title">{live ? 'Reasoning pending' : 'No reasoning recorded'}</div>
                <p class="obs-empty-copy">
                  {live
                    ? stageNow === 'crawl'
                      ? 'The crawl is still reading the surface. The first model call will narrate what it reads and where it stops.'
                      : 'The agents are between calls. Their reasoning will land here as soon as the next call returns.'
                    : 'This run left events but no model reasoning. Check the model calls and logs for what the agents were doing.'}
                </p>
                <button class="obs-btn" type="button" onclick={() => (focusRun ? store.watch(focusRun.id) : store.go('live'))}>
                  {live ? 'Watch the live cast' : 'Open inspector'}
                </button>
              </div>
            {:else}
              {#each thoughts.slice(-7).reverse() as thought, index (thought.seq)}
                <button
                  class="obs-thought"
                  class:is-live={live && index === 0}
                  type="button"
                  onclick={() => focusRun && store.watch(focusRun.id)}
                  title="open the full trace"
                >
                  <span class="obs-thought-meta" style="--agent:{agentColor(thought.agent)}">
                    <span class="lane" aria-hidden="true"></span>
                    <span class="agent">{thought.agent}</span>
                    <span class="time">{clock(thought.ts)}</span>
                  </span>
                  <span class="obs-thought-text">{thought.text}</span>
                </button>
              {/each}
            {/if}
          {:else if feedTab === 'models'}
            {#if calls.length === 0}
              <div class="obs-empty">
                <span class="obs-empty-icon"><Icon name="flow" size={18} /></span>
                <div class="obs-empty-title">{live ? 'No model calls yet' : 'No model calls'}</div>
                <p class="obs-empty-copy">
                  {live
                    ? 'The cast has not asked a model to read anything yet. Calls will appear here as each agent starts.'
                    : 'No model traffic was recorded in this run. Add a provider or test the current fleet before the next cast.'}
                </p>
                <button class="obs-btn" type="button" onclick={() => store.go('keys')}>Manage fleet</button>
              </div>
            {:else}
              {#each calls.slice(-10).reverse() as call (call.seq)}
                <div class="obs-call">
                  <span class="obs-call-dot" class:bad={!call.ok} aria-hidden="true"></span>
                  <span class="obs-call-name">{call.provider}/{call.model}</span>
                  <span class="obs-call-ms">{call.ms}ms</span>
                  <span class="obs-call-state" class:ok={call.ok} class:bad={!call.ok}>
                    {call.ok ? 'returned' : 'failed'}
                  </span>
                  {#if !call.ok && call.error}
                    <span class="obs-call-error" title={call.error}>{call.error}</span>
                  {/if}
                </div>
              {/each}
            {/if}
          {:else if feedTab === 'signals'}
            {#if signals.length === 0}
              <div class="obs-empty">
                <span class="obs-empty-icon"><Icon name="crosshair" size={18} /></span>
                <div class="obs-empty-title">{live ? 'No signals yet' : 'No signals'}</div>
                <p class="obs-empty-copy">
                  No raw candidate has surfaced in this cast. Values appear here only when the classifier can explain them.
                </p>
              </div>
            {:else}
              {#each signals.slice(-8).reverse() as signal (signal.seq)}
                <div class="obs-signal-row">
                  <span class="obs-signal-type">{signal.secret_type}</span>
                  <span class="obs-signal-value">{signal.value}</span>
                  <span class="obs-signal-state">{signal.status}</span>
                  <span class="obs-signal-detail" title={signal.detail}>{signal.detail}</span>
                </div>
              {/each}
            {/if}
          {:else}
            {#if logs.length === 0}
              <div class="obs-empty">
                <span class="obs-empty-icon"><Icon name="terminal" size={18} /></span>
                <div class="obs-empty-title">{live ? 'No log lines yet' : 'No logs'}</div>
                <p class="obs-empty-copy">No log lines were emitted in this run.</p>
              </div>
            {:else}
              {#each logs.slice(-12).reverse() as line (line.seq)}
                <div class="obs-log-row" class:is-error={line.level === 'error'}>
                  <span class="obs-log-time">{clock(line.ts)}</span>
                  <span class="obs-log-kind">{line.level === 'error' ? 'err' : 'log'}</span>
                  <span class="obs-log-text" title={line.text}>{line.text}</span>
                </div>
              {/each}
            {/if}
          {/if}
        </div>

        <footer class="obs-feed-foot">
          <span class="obs-pulse" class:live aria-hidden="true"></span>
          <span>{live ? 'streaming from the live cast' : 'replay of the last cast'}</span>
          <span class="spacer"></span>
          <span>{thoughts.length} thoughts - {calls.length} calls - {signals.length} signals</span>
          <button class="obs-btn obs-btn-sm obs-btn-ghost" type="button" onclick={toggleFollow}>
            {autoFollow ? 'Pause feed' : pausedCount ? `Resume - ${pausedCount}` : 'Resume feed'}
          </button>
        </footer>
      </article>

      <!-- findings -->
      <article class="obs-card obs-findings" aria-label="findings">
        <header class="obs-card-head">
          <div>
            <div class="obs-card-title"><Icon name="bug" size={13} />Findings in flight</div>
            <div class="obs-card-sub">
              {recent.length} persisted - {pendingCount} waiting - {confirmed} confirmed
            </div>
          </div>
          <button class="obs-link" type="button" onclick={() => store.go('findings')}>
            View all <Icon name="arrow-right" size={11} />
          </button>
        </header>

        {#if findingsPreview.length === 0}
          <div class="obs-empty-table">
            <span class="obs-empty-icon"><Icon name="shield" size={18} /></span>
            <div class="obs-empty-table-copy">
              <div class="obs-empty-table-title">Nothing persisted yet</div>
              <p>
                {focusRun
                  ? `The latest cast surfaced ${rawSignals} candidate${rawSignals === 1 ? '' : 's'} and proved ${verified}. A finding is written only after validation, so the proof trail stays clean.`
                  : 'No cast has run yet. When a candidate clears validation, its evidence and triage state land here.'}
              </p>
              <div class="obs-funnel-mini">
                <span class="obs-chip">surfaced {rawSignals}</span>
                <span class="obs-chip acid">proved {verified}</span>
                <span class="obs-chip">written {totals?.findings ?? 0}</span>
              </div>
            </div>
            <button
              class="obs-btn"
              type="button"
              onclick={() => (focusRun ? store.watch(focusRun.id) : store.go('new'))}
            >
              {focusRun ? 'Inspect the evidence' : 'Start a cast'}
            </button>
          </div>
        {:else}
          <div class="obs-table-wrap">
            <table class="obs-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Asset</th>
                  <th>Confidence</th>
                  <th>State</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {#each findingsPreview as finding (finding.id)}
                  <tr
                    role="link"
                    tabindex="0"
                    onclick={() => store.go('findings')}
                    onkeydown={(event) => {
                      if (event.key === 'Enter') store.go('findings');
                    }}
                  >
                    <td>
                      <span class="obs-chip" style="color:{sevColor(finding.severity)}">
                        <span
                          style="width:5px;height:5px;border-radius:50%;background:currentColor;box-shadow:0 0 5px currentColor"
                          aria-hidden="true"
                        ></span>
                        {finding.severity}
                      </span>
                    </td>
                    <td>
                      <div class="obs-finding-title">{finding.title}</div>
                      <div class="obs-finding-sub">
                        {finding.secret_type} - {ago(finding.created_at)}
                      </div>
                    </td>
                    <td class="obs-mono" style="font-size:8px;color:var(--obs-muted)">{findingSource(finding)}</td>
                    <td>
                      <div class="obs-conf">
                        <span class="obs-meter"><i style="width:{confidencePct(finding)}%"></i></span>
                        <span>{confidencePct(finding)}%</span>
                      </div>
                    </td>
                    <td><span class="obs-chip">{triageLabel(finding.triage_status)}</span></td>
                    <td><Icon name="arrow-right" size={12} class="obs-row-arrow" /></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </article>
    </div>

    <aside class="obs-command-rail">
      <!-- approvals -->
      <article class="obs-card obs-approvals" aria-label="approval queue">
        <header class="obs-card-head">
          <div>
            <div class="obs-card-title"><Icon name="lock" size={13} />Approval queue</div>
            <div class="obs-card-sub">{pendingCount} decision{pendingCount === 1 ? '' : 's'} need you</div>
          </div>
          <span class="obs-approval-count" class:is-zero={pendingCount === 0}>{pendingCount}</span>
        </header>

        {#if missionApprovals.length > 0}
          <div class="obs-approval-list">
            {#each missionApprovals.slice(0, 2) as approval (approval.id)}
              <div class="obs-approval" class:is-urgent={approval.risk === 'critical' || approval.risk === 'high'}>
                <div class="obs-approval-top">
                  <span class="obs-approval-agent">{approval.requested_by || 'agent'}</span>
                  <span class="obs-chip" style="color:{sevColor(approval.risk)}">{approval.risk} risk</span>
                </div>
                <div class="obs-approval-title">{approval.action}</div>
                <div class="obs-approval-why">
                  <strong>Why:</strong>
                  {approval.reason || 'An agent requested this action and the policy gate stopped it here.'}
                </div>
                <div class="obs-approval-meta">
                  {#if approval.mission_title}<span class="obs-chip">{approval.mission_title}</span>{/if}
                  {#if approval.run_id}<span class="obs-chip">{approval.run_id.slice(-6)}</span>{/if}
                  <span class="obs-chip violet">policy gate</span>
                </div>
                <div class="obs-approval-actions">
                  <button
                    class="obs-btn obs-btn-primary"
                    type="button"
                    disabled={reviewing === approval.id}
                    onclick={() => void decideApproval(approval, 'approved')}
                  >
                    Approve
                  </button>
                  <button
                    class="obs-btn obs-btn-ghost"
                    type="button"
                    disabled={reviewing === approval.id}
                    onclick={() => void decideApproval(approval, 'rejected')}
                  >
                    Reject
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {:else if pendingFindings.length > 0}
          <div class="obs-approval-list">
            {#each pendingFindings.slice(0, 2) as finding (finding.id)}
              <div class="obs-approval" class:is-urgent={finding.severity === 'critical' || finding.severity === 'high'}>
                <div class="obs-approval-top">
                  <span class="obs-approval-agent">{finding.secret_type}</span>
                  <span class="obs-chip" style="color:{sevColor(finding.severity)}">{finding.severity}</span>
                </div>
                <div class="obs-approval-title">{finding.title}</div>
                <div class="obs-approval-why">
                  <strong>Why:</strong>
                  {finding.impact || finding.evidence || 'A persisted finding is waiting for a human triage decision.'}
                </div>
                <div class="obs-approval-meta">
                  <span class="obs-chip">{findingSource(finding)}</span>
                  <span class="obs-chip">{confidencePct(finding)}% confidence</span>
                  <span class="obs-chip violet">needs review</span>
                </div>
                <div class="obs-approval-actions">
                  <button
                    class="obs-btn obs-btn-primary"
                    type="button"
                    disabled={reviewing === finding.id}
                    onclick={() => void review(finding, 'confirmed')}
                  >
                    Confirm
                  </button>
                  <button
                    class="obs-btn obs-btn-ghost"
                    type="button"
                    disabled={reviewing === finding.id}
                    onclick={() => void review(finding, 'rejected')}
                  >
                    Reject
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="obs-empty-approval">
            <span class="obs-empty-icon"><Icon name="shield" size={18} /></span>
            <div class="obs-empty-title">{recent.length ? 'Queue is clear' : 'No approval waiting'}</div>
            <p>
              {recent.length
                ? 'Every persisted finding has a triage decision and no agent is waiting on a policy gate.'
                : 'Human review opens when a finding is persisted or an agent requests a risky action. The gate cannot be skipped.'}
            </p>
            <button
              class="obs-btn obs-btn-sm"
              type="button"
              onclick={() => (focusRun ? store.watch(focusRun.id) : store.go('new'))}
            >
              {focusRun ? 'Inspect latest cast' : 'Start a cast'}
            </button>
          </div>
        {/if}
      </article>

      <!-- next moves -->
      <article class="obs-card" aria-label="next best actions">
        <header class="obs-card-head no-border">
          <div>
            <div class="obs-card-title"><Icon name="zap" size={13} />Next best actions</div>
            <div class="obs-card-sub">Ranked from this cast's evidence</div>
          </div>
          <span class="obs-chip">{nextActions.length}</span>
        </header>
        <div class="obs-next-list">
          {#each nextActions as action (action.id)}
            <button class="obs-next" type="button" onclick={action.go} style="--action:{action.color}">
              <span class="obs-next-icon" style="color:{action.color}">
                <Icon name={actionIcon(action.id)} size={13} />
              </span>
              <span class="obs-next-body">
                <span class="obs-next-title">{action.title}</span>
                <span class="obs-next-why">{action.body}</span>
                <span class="obs-next-cta">{action.cta} -></span>
              </span>
              <Icon name="arrow-right" size={11} />
            </button>
          {:else}
            <p style="padding:14px 16px;font-size:9.5px;color:var(--obs-faint)">
              The deck is clear. Cast a new target when you are ready.
            </p>
          {/each}
        </div>
      </article>

      <!-- scope -->
      <article class="obs-card" aria-label="scope and surface">
        <header class="obs-card-head">
          <div>
            <div class="obs-card-title"><Icon name="crosshair" size={13} />Scope &amp; surface</div>
            <div class="obs-card-sub">
              {focusRun ? `${focusRun.id.slice(-6)} - ${statusLabel(focusRun.status)}` : 'No cast recorded'}
            </div>
          </div>
          <span class="obs-chip" style="color:var(--obs-acid)">{Math.round(proofRate * 100)}% proof</span>
        </header>

        {#if focusRun}
          <div class="obs-scope-target">
            <Icon name="globe" size={13} />
            <strong>{target}</strong>
          </div>
          <div class="obs-scope-funnel">
            {#each surface.slice(0, 4) as row (row.key)}
              <div class="obs-scope-row">
                <span>{row.label}</span>
                <span class="obs-meter"><i style="width:{row.pct}%;background:{row.color}"></i></span>
                <strong>{row.value}</strong>
              </div>
            {/each}
          </div>
          {#if hosts.length}
            <div class="obs-hosts">
              {#each hosts.slice(0, 3) as host (host.host)}
                <div class="obs-host">
                  <span class="obs-provider-dot" class:ok={host.ok > 0} aria-hidden="true"></span>
                  <span class="obs-host-name" title={host.host}>{host.host}</span>
                  <span class="obs-provider-meta">{host.count}</span>
                </div>
              {/each}
            </div>
          {/if}
          <div class="obs-scope-chips">
            {#each runOptions as chip (chip)}
              <span class="obs-chip">{chip}</span>
            {:else}
              <span class="obs-chip">no options recorded</span>
            {/each}
          </div>
        {:else}
          <div class="obs-empty-approval" style="text-align:left;padding-top:14px">
            <p style="margin:0;max-width:none">
              No operation is loaded. Start a cast to map pages, scripts, endpoints and candidates here.
            </p>
          </div>
        {/if}

        <div class="obs-guardrail">
          <Icon name="shield" size={12} />
          <span>
            <strong>Operator responsibility.</strong> NetCast3r runs only where you point it. Confirm authorization and scope before starting a cast.
          </span>
        </div>
      </article>

      <!-- model mesh -->
      <article class="obs-card" aria-label="model mesh">
        <header class="obs-card-head">
          <div>
            <div class="obs-card-title"><Icon name="plug" size={13} />Model mesh</div>
            <div class="obs-card-sub">{providers.length} provider{providers.length === 1 ? '' : 's'} - {fleet.total} calls this cast</div>
          </div>
          <button class="obs-link" type="button" onclick={() => store.go('keys')}>
            Manage <Icon name="arrow-right" size={11} />
          </button>
        </header>

        {#if providers.length === 0}
          <div class="obs-empty-approval" style="padding-top:14px">
            <p style="margin:0 auto">No provider is configured. Add one to give the agents a model.</p>
            <button class="obs-btn obs-btn-sm" type="button" onclick={() => store.go('keys')}>Add provider</button>
          </div>
        {:else}
          {#each providers as provider (provider.id)}
            <div class="obs-provider">
              <span class="obs-provider-dot" class:ok={provider.healthy} aria-hidden="true"></span>
              <span class="obs-provider-name">{provider.name}</span>
              <span class="obs-provider-meta">
                {provider.models.length} models - {provider.key_set ? 'key set' : 'no key'}
              </span>
              <button
                class="obs-btn obs-btn-ghost"
                type="button"
                disabled={testing === provider.id || !provider.key_set}
                onclick={() => void testProvider(provider)}
              >
                {testing === provider.id ? '...' : 'test'}
              </button>
            </div>
          {/each}
        {/if}

        <footer class="obs-mesh-foot">
          <span>{fleet.ok}/{fleet.total} replies</span>
          <span style="margin-left:auto">{store.syncState === 'error' ? 'sync lost' : `synced ${syncLabel}`}</span>
        </footer>
      </article>
    </aside>
  </div>

  <!-- ledger -->
  <section class="obs-card obs-ledger" aria-label="run ledger">
    <header class="obs-card-head">
      <div>
        <div class="obs-card-title"><Icon name="layers" size={13} />Run ledger</div>
        <div class="obs-card-sub">Every cast, every return, every dead end</div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;margin-left:auto">
        <Sparkline values={runTrend} width={86} height={20} color="var(--obs-acid)" />
        <button class="obs-link" type="button" onclick={() => store.go('runs')}>
          History <Icon name="arrow-right" size={11} />
        </button>
      </div>
    </header>

    {#if store.runs.length === 0}
      <div class="obs-empty" style="min-height:150px">
        <span class="obs-empty-icon"><Icon name="layers" size={18} /></span>
        <div class="obs-empty-title">No casts in the ledger</div>
        <p class="obs-empty-copy">Start a scan and every run will appear here with its surface, signals and findings.</p>
        <button class="obs-btn" type="button" onclick={() => store.go('new')}>Start a cast</button>
      </div>
    {:else}
      <div class="obs-ledger-head" aria-hidden="true">
        <span>Operation</span>
        <span>Pages</span>
        <span>Scripts</span>
        <span>Endpoints</span>
        <span>Signals</span>
        <span>Findings</span>
        <span></span>
      </div>
      {#each store.runs.slice(0, 6) as run (run.id)}
        <button
          class="obs-ledger-row"
          class:is-current={run.id === focusRun?.id}
          type="button"
          onclick={() => store.watch(run.id)}
        >
          <span class="obs-ledger-main">
            <span class="obs-ledger-signal" style="background:{statusColor(run.status)}" aria-hidden="true"></span>
            <span style="min-width:0">
              <span class="obs-ledger-target">{run.target}</span>
              <span class="obs-ledger-sub">
                <span>{statusLabel(run.status)}</span>
                <span>-</span>
                <span>{duration(run)}</span>
                <span>-</span>
                <span>{ago(run.created_at)}</span>
              </span>
            </span>
          </span>
          <span class="obs-ledger-metric">{run.counts?.pages ?? 0}</span>
          <span class="obs-ledger-metric">{run.counts?.js_files ?? 0}</span>
          <span class="obs-ledger-metric">{run.counts?.endpoints ?? 0}</span>
          <span class="obs-ledger-metric" style="color:{(run.counts?.candidates ?? 0) > 0 ? 'var(--obs-violet)' : 'var(--obs-faint)'}">
            {run.counts?.candidates ?? 0}
          </span>
          <span class="obs-ledger-metric" style="color:{(run.counts?.findings ?? 0) > 0 ? 'var(--obs-acid)' : 'var(--obs-faint)'}">
            {run.counts?.findings ?? 0}
          </span>
          <Icon name="arrow-right" size={11} class="obs-ledger-go" />
        </button>
      {/each}
    {/if}
  </section>
</div>
