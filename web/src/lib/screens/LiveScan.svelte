<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import { api } from '../api';
  import { AGENT_COLORS, STAGES } from '../../tokens';
  import { clock, finishedThrough, isoMs, sevColor, sevShape, stageForAgent, statusColor, statusLabel, utcStamp } from '../format';
  import { renderMarkdown } from '../markdown';
  import { store } from '../state.svelte';
  import type { Run, RunDirective, RunEvent } from '../types';
  import Buffering from '../ui/Buffering.svelte';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import RunScope from '../ui/RunScope.svelte';
  import StageRail from '../ui/StageRail.svelte';
  import StageSignal from '../ui/StageSignal.svelte';
  import { countup, focusTrap, spotlight } from '../actions';

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
  const SOLVE_STAGES = [
    { key: 'reason', label: 'Reason', detail: 'The model proposes one action' },
    { key: 'act', label: 'Act', detail: 'Run it through the scoped tools' },
    { key: 'observe', label: 'Observe', detail: 'Feed the real result back' },
    { key: 'decide', label: 'Decide', detail: 'Stop, or take another step' }
  ];
  const OPERATOR_STAGES = [
    { key: 'reason', label: 'Reason', detail: 'Read memory and plan the next move' },
    { key: 'act', label: 'Act', detail: 'Execute one scoped tool call' },
    { key: 'observe', label: 'Observe', detail: 'Keep the real result as evidence' },
    { key: 'decide', label: 'Decide', detail: 'Reflect, replan, or finish' }
  ];
  const MESH_STAGES = [
    { key: 'reason', label: 'Strategise', detail: 'The strategist sets answerable objectives' },
    { key: 'act', label: 'Act', detail: 'A specialist runs one scoped call' },
    { key: 'observe', label: 'Validate', detail: 'An independent validator judges the observation' },
    { key: 'decide', label: 'Remember', detail: 'The scribe writes durable memory' }
  ];
  const MESH_ROLES = [
    { key: 'strategist', label: 'strategist', detail: 'plans', counter: 'strategist_calls', unit: 'calls' },
    { key: 'scout', label: 'scout', detail: 'maps', counter: 'scout_actions', unit: 'moves' },
    { key: 'attacker', label: 'attacker', detail: 'tests', counter: 'attacker_actions', unit: 'moves' },
    { key: 'validator', label: 'validator', detail: 'judges', counter: 'validator_calls', unit: 'calls' },
    { key: 'scribe', label: 'scribe', detail: 'remembers', counter: 'scribe_calls', unit: 'calls' }
  ];
  const TERMINAL = ['done', 'failed', 'stopped', 'interrupted'];
  const RESUMABLE = ['stopped', 'interrupted', 'failed'];
  const BUCKET_MS = 250;
  const BUCKETS = 96;
  const STREAM_CAP = 250;

  type StreamRow = {
    seq: number;
    ts: number;
    kind: string;
    agent: string;
    text: string;
    sub: string;
    tool?: string;
    url?: string;
    status?: number | string;
    ok?: boolean | null;
    model?: string;
    provider?: string;
    ms?: number;
    tokens?: number;
    detail?: string;
    stage?: string;
    repeat?: number;
  };

  type PlanTask = {
    id: string;
    owner: string;
    goal: string;
    hypothesis: string;
    status: string;
    round: number;
    critical: boolean;
    source: string;
    tool: string;
    verdict: string;
    reason: string;
  };

  type DirectiveRow = {
    id: string;
    text: string;
    kind: string;
    status: string;
    ts: number;
    owner: string;
    terms: string[];
    plan: string;
    matched: string;
    source: string;
  };

  const DIRECTIVE_KINDS: { id: 'auto' | 'skip' | 'focus'; label: string }[] = [
    { id: 'auto', label: 'auto' },
    { id: 'skip', label: 'skip' },
    { id: 'focus', label: 'focus' }
  ];

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
    { id: 'think', label: 'reasoning' },
    { id: 'tool', label: 'tools' },
    { id: 'http', label: 'http' },
    { id: 'model', label: 'models' },
    { id: 'log', label: 'logs' },
    { id: 'found', label: 'proof' },
    { id: 'err', label: 'errors' }
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
  const isSolve = $derived(runMode === 'solve');
  const isOperator = $derived(runMode === 'autopilot');
  const isMesh = $derived(runMode === 'swarm');
  const displayStages = $derived(isLab ? LAB_STAGES : isHunt ? HUNT_STAGES : isMesh ? MESH_STAGES : isOperator ? OPERATOR_STAGES : isSolve ? SOLVE_STAGES : stages);
  const displayTabs = $derived((isLab || isHunt || isSolve || isOperator || isMesh) ? TABS.filter((item) => item.id === 'feed' || item.id === 'report') : TABS);
  const operatorMission = $derived(String((run?.options as Record<string, unknown> | undefined)?.mission_id ?? ''));
  let events = $state<RunEvent[]>([]);
  let counts = $state<Record<string, number>>({});
  let landed = $state<{ id: number; status: string; secret_type: string; value: string; detail: string }[]>([]);
  let currentStage = $state('');
  let follow = $state(true);
  let unseen = $state(0);
  let seenStreamLen = 0;
  let filter = $state('all');
  let streamLimit = $state(STREAM_CAP);
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
  let agents = $state<Record<string, { lines: number; calls: number; tools: number; thoughts: number; lastTs: number; lastText: string; lastCall: string; lastCallOk: boolean | null; model: string; task: string }>>({});

  // live mission control: the current plan, its task board, and the operator
  // channel that can change both while the run is still executing.
  let planTasks = $state<PlanTask[]>([]);
  let planRound = $state(0);
  let planNote = $state('');
  let operatorDirectives = $state<DirectiveRow[]>([]);
  let directiveText = $state('');
  let directiveKind = $state<'auto' | 'skip' | 'focus'>('auto');
  let directiveBusy = $state(false);
  let directiveError = $state('');
  let directiveBox = $state<HTMLTextAreaElement | undefined>(undefined);

  // per run evidence, loaded on demand
  let inv = $state<Record<string, any[]>>({});
  let loadedInv = $state<Record<string, boolean>>({});
  let invBusy = $state('');
  const inflight = new Set<string>();
  let memory = $state<{ id: string; kind: string; title: string; body: string; created_at: string }[]>([]);

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
    if (!isLab && !isHunt && !isSolve && !isOperator && !isMesh) next.crawl = Math.max(next.crawl ?? 0, crawled);
    return next;
  });

  const KIND_META: Record<string, { label: string; color: string; icon: string }> = {
    think: { label: 'reason', color: 'var(--nc-bone-dust)', icon: '*' },
    act: { label: 'call', color: 'var(--nc-acid)', icon: '>' },
    tool: { label: 'result', color: 'var(--nc-acid)', icon: '<' },
    http: { label: 'http', color: 'var(--obs-violet-3)', icon: '~' },
    model: { label: 'model', color: 'var(--nc-gold, #efe4b1)', icon: '@' },
    note: { label: 'decide', color: 'var(--nc-slate-3, #8b8fa3)', icon: '#' },
    plan: { label: 'plan', color: 'var(--obs-text-2)', icon: '#' },
    directive: { label: 'operator', color: 'var(--obs-acid)', icon: '>' },
    log: { label: 'log', color: 'var(--nc-ash)', icon: '-' },
    err: { label: 'error', color: 'var(--nc-violet)', icon: '!' },
    found: { label: 'proof', color: 'var(--nc-gold, #efe4b1)', icon: '$' }
  };

  /** Heartbeat status pings emitted while a role waits on a model call. */
  const HEARTBEAT_RE = /^\s*(strategist|scout|attacker|validator|scribe) is reasoning\s*$/i;

  /** Append one model receipt. Consecutive failures for the same agent fuse
   *  into a counted row so a dead provider set does not flood the feed. */
  function pushModelRow(rows: StreamRow[], agent: string,
                        payload: Record<string, unknown>, seq: number, ts: number): void {
    const provider = String(payload.provider ?? '');
    const model = String(payload.model ?? '');
    const ok = !!payload.ok;
    const ms = Number(payload.ms ?? 0);
    const tokens = Number(payload.completion_tokens ?? payload.tokens ?? 0);
    const last = rows[rows.length - 1];
    if (!ok && last && last.kind === 'model' && last.agent === agent && last.ok === false) {
      last.repeat = (last.repeat ?? 1) + 1;
      last.seq = seq;
      last.ts = ts;
      last.text = `${provider}/${model}`;
      last.provider = provider;
      last.model = model;
      last.ms = ms;
      last.tokens = tokens;
      return;
    }
    rows.push({ seq, ts, kind: 'model', agent: String(payload.agent || agent),
                text: `${provider || '?'}/${model || '?'}`,
                sub: ok ? 'ok' : 'failed',
                provider, model, ms, tokens, ok, repeat: 1 });
  }

  /** One chronological stream: reasoning, tool calls, tool results, HTTP,
   *  model calls, decisions, and proof. Reasoning fragments from the same
   *  agent within 5s fuse into one row so the transmission reads as prose. */
  const streamAll = $derived.by<StreamRow[]>(() => {
    const rows: StreamRow[] = [];
    let think: StreamRow | null = null;
    for (const event of events) {
      if (event.type === 'lagged') continue;
      const payload = (event.payload ?? {}) as Record<string, unknown>;
      const agent = String(payload.agent || event.agent || 'run');
      if (event.type === 'log' || event.type === 'error') {
        const stage = String(event.stage || '');
        const text = String(payload.text ?? payload.error ?? '');
        // Heartbeat pings ("Scout is reasoning") only feed the live-agent lane;
        // they are not reasoning content and must not pollute the stream. The
        // flag is authoritative; the regex also cleans older recorded runs.
        if (payload.heartbeat || HEARTBEAT_RE.test(text)) continue;
        if (stage === 'reason' || (event.type === 'log' && !stage && payload.reasoning)) {
          const raw = text.trim();
          if (!raw) continue;
          if (think && think.agent === agent && event.ts - think.ts < 5000) {
            think.text = `${think.text} ${raw}`.replace(/\s+/g, ' ').slice(-2400);
            think.ts = event.ts;
            think.seq = event.seq;
          } else {
            think = { seq: event.seq, ts: event.ts, kind: 'think', agent,
                      text: raw.slice(0, 1200), sub: '', stage };
            rows.push(think);
          }
          continue;
        }
        think = null;
        if (stage === 'task') {
          // Task state feeds the mission-control board, not the transmission.
          continue;
        }
        if (stage === 'model') {
          pushModelRow(rows, agent, payload, event.seq, event.ts);
        } else if (stage === 'act') {
          rows.push({ seq: event.seq, ts: event.ts, kind: 'act', agent,
                      text: text || `calling ${String(payload.tool ?? '')}`,
                      sub: '', tool: String(payload.tool ?? ''), stage,
                      detail: JSON.stringify(payload.args ?? {}).slice(0, 1600) });
        } else if (stage === 'observe') {
          rows.push({ seq: event.seq, ts: event.ts, kind: 'tool', agent,
                      text, sub: '', tool: String(payload.tool ?? ''),
                      url: String(payload.url ?? ''),
                      status: (payload.status as number | string) ?? '',
                      ok: payload.ok === undefined ? null : !!payload.ok,
                      stage, detail: JSON.stringify(payload).slice(0, 1600) });
        } else if (stage === 'decide') {
          rows.push({ seq: event.seq, ts: event.ts, kind: 'note', agent,
                      text, sub: '', stage });
        } else if (stage === 'plan') {
          const objectives = Array.isArray(payload.objectives) ? payload.objectives : [];
          const skipped = Number(payload.skipped ?? 0);
          const focus = Number(payload.focus ?? 0);
          rows.push({ seq: event.seq, ts: event.ts, kind: 'plan',
                      agent: 'strategist',
                      text: `round ${payload.round ?? '?'}: ${objectives.length} task(s)`
                        + (skipped ? `, ${skipped} skipped` : '')
                        + (focus ? `, ${focus} from the operator` : ''),
                      sub: '', stage, detail: JSON.stringify(payload).slice(0, 1600) });
        } else if (stage === 'directive') {
          rows.push({ seq: event.seq, ts: event.ts, kind: 'directive',
                      agent: String(payload.source || 'operator'),
                      text: String(payload.text || payload.plan || 'operator directive'),
                      sub: `${payload.kind ?? ''} ${payload.status ?? ''}`.trim(),
                      stage, detail: JSON.stringify(payload).slice(0, 1600) });
        } else {
          rows.push({ seq: event.seq, ts: event.ts,
                      kind: event.type === 'error' ? 'err' : 'log', agent,
                      text, sub: '', stage });
        }
        continue;
      }
      if (event.type === 'reasoning' && payload.text) {
        const raw = String(payload.text).trim();
        if (!raw) continue;
        if (think && think.agent === agent && event.ts - think.ts < 5000) {
          think.text = `${think.text} ${raw}`.replace(/\s+/g, ' ').slice(-2400);
          think.ts = event.ts;
          think.seq = event.seq;
        } else {
          think = { seq: event.seq, ts: event.ts, kind: 'think', agent,
                    text: raw.slice(0, 1200), sub: '' };
          rows.push(think);
        }
        continue;
      }
      if (event.type === 'fetch' && payload.url) {
        if (String(payload.kind ?? '') === 'progress') continue;
        rows.push({ seq: event.seq, ts: event.ts, kind: 'http', agent,
                    text: String(payload.url), sub: '',
                    url: String(payload.url),
                    status: (payload.status as number | string) ?? '' });
        think = null;
        continue;
      }
      if (event.type === 'model' && payload.kind === 'done') {
        pushModelRow(rows, agent, payload, event.seq, event.ts);
        think = null;
        continue;
      }
      if (event.type === 'finding.created' && event.payload) {
        rows.push({ seq: event.seq, ts: event.ts, kind: 'found', agent,
                    text: `${String(payload.secret_type ?? 'secret')} / ${String(payload.value ?? '')}`,
                    sub: String(payload.status ?? '') });
        think = null;
      }
    }
    return rows;
  });

  /** Rows matching the active filter, before the render window is applied. */
  const streamBase = $derived.by(() => {
    if (filter === 'all') return streamAll;
    if (filter === 'http') {
      return streamAll.filter((row) => row.kind === 'http'
        || (row.kind === 'tool' && (!!row.url || /http|fetch|request/i.test(row.tool ?? ''))));
    }
    const want: Record<string, string[]> = {
      think: ['think'], tool: ['act', 'tool'], http: ['http'],
      model: ['model'], log: ['log', 'note', 'plan', 'directive'],
      found: ['found'], err: ['err']
    };
    const kinds = want[filter] ?? [filter];
    return streamAll.filter((row) => kinds.includes(row.kind));
  });
  const stream = $derived(streamBase.slice(-streamLimit));
  const olderRows = $derived(Math.max(0, streamBase.length - stream.length));
  const urlsSeen = $derived(new Set(
    streamAll.filter((row) => row.url && /^https?:/i.test(row.url)).map((row) => row.url)
  ).size);
  const lastSeq = $derived(stream.length ? stream[stream.length - 1].seq : 0);
  const reasoningCount = $derived(streamAll.filter((row) => row.kind === 'think').length);
  const toolCount = $derived(streamAll.filter((row) => row.kind === 'tool').length);
  const callCount = $derived(streamAll.filter((row) => row.kind === 'act').length);
  const modelCount = $derived(
    streamAll.filter((row) => row.kind === 'model')
      .reduce((total, row) => total + (row.repeat ?? 1), 0)
  );
  const agentList = $derived(
    Object.entries(agents)
      .map(([agent, stats]) => ({ agent, ...stats }))
      .filter((item) => item.lines > 0)
      .sort((a, b) => b.lastTs - a.lastTs)
  );

  const liveTask = $derived(
    planTasks.find((task) => task.status === 'running')
      ?? planTasks.find((task) => task.status === 'assigned')
      ?? null
  );
  const openTaskCount = $derived(
    planTasks.filter((task) => task.status === 'assigned' || task.status === 'running').length
  );
  const doneTaskCount = $derived(planTasks.filter((task) => task.status === 'done').length);
  const skippedTaskCount = $derived(planTasks.filter((task) => task.status === 'skipped').length);

  /** KPI values. The control plane reports some only at run end, so fall back
   *  to what the live stream already proves while the run is in flight. */
  function metric(key: string): number {
    const reported = counts[key];
    if (typeof reported === 'number' && reported > 0) return reported;
    if (key === 'agents') return agentList.length;
    if (key === 'moves' || key === 'actions') return callCount || toolCount;
    if (key === 'model_calls') return modelCount;
    if (key === 'findings') return landed.length;
    return 0;
  }
  /** Mesh role counter: reported totals win, then the live lane, so an
   *  in-flight run shows real moves instead of a flat zero. */
  function roleCount(counter: string): number {
    const reported = counts[counter];
    if (typeof reported === 'number' && reported > 0) return reported;
    const agent = counter.replace(/_(calls|actions)$/, '');
    return agents[agent]?.calls ?? 0;
  }
  function roundCount(): number {
    return (counts.rounds ?? 0) || planRound;
  }
  const spotlightRows = $derived(
    spotlightAgent ? streamAll.filter((row) => row.agent === spotlightAgent).slice(-400) : []
  );

  function metaOf(row: StreamRow): { label: string; color: string; icon: string } {
    return KIND_META[row.kind] ?? KIND_META.log;
  }

  function agentColor(agent: string): string {
    return (AGENT_COLORS as Record<string, string>)[agent] ?? 'var(--nc-bone-dust)';
  }

  function statusTone(status: number | string | undefined): string {
    const code = Number(status);
    if (!Number.isFinite(code) || code === 0) return 'var(--nc-ash)';
    if (code >= 200 && code < 300) return 'var(--nc-acid)';
    if (code >= 300 && code < 400) return 'var(--obs-violet-3)';
    if (code >= 400 && code < 500) return 'var(--nc-gold, #efe4b1)';
    return 'var(--nc-violet)';
  }

  let expanded = $state<Record<number, boolean>>({});

  function toggleRow(seq: number) {
    expanded = { ...expanded, [seq]: !expanded[seq] };
  }

  async function copyRow(row: StreamRow) {
    const text = row.detail || [row.tool, row.url, row.text].filter(Boolean).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      store.toast('ok', 'row copied');
    } catch {
      store.fail('clipboard is unavailable');
    }
  }

  /** One-line preview of a tool call's arguments so the move is readable
   *  without expanding the row. */
  function argPreview(row: StreamRow): string {
    if (!row.detail) return '';
    try {
      const obj = JSON.parse(row.detail) as Record<string, unknown>;
      return Object.entries(obj)
        .filter(([, value]) => value !== null && value !== undefined && value !== '')
        .map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`)
        .join(' ')
        .slice(0, 240);
    } catch {
      return '';
    }
  }

  // Agent theater status from recency of last activity.
  function laneStatus(lane: { lastTs: number }): { label: string; color: string } {
    if (!running) return { label: 'done', color: 'var(--nc-ash)' };
    const age = nowTick - lane.lastTs * (lane.lastTs < 1e12 ? 1000 : 1);
    if (age < 12000) return { label: 'working', color: 'var(--nc-acid)' };
    if (age < 60000) return { label: 'recent', color: 'var(--nc-gold, #efe4b1)' };
    return { label: 'idle', color: 'var(--nc-ash)' };
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
    const clean = String(text ?? '').replace(/\s+/g, ' ').trim();
    return clean.length > cap ? `${clean.slice(0, Math.max(0, cap - 3)).trimEnd()}...` : clean;
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
      const lane = agents[agent] ?? { lines: 0, calls: 0, tools: 0, thoughts: 0, lastTs: 0, lastText: '', lastCall: '', lastCallOk: null, model: '', task: '' };
      const updated = { ...lane, lines: lane.lines + 1 };
      if (event.type === 'log' || event.type === 'error') {
        const stage = String(event.stage || '');
        const text = String(event.payload?.text ?? event.payload?.error ?? '');
        updated.lastText = text;
        updated.lastTs = event.ts;
        if (stage === 'reason' && !event.payload?.heartbeat && !HEARTBEAT_RE.test(text)) {
          updated.thoughts = lane.thoughts + 1;
        }
        if (stage === 'act' || stage === 'observe') updated.tools = lane.tools + 1;
        if (stage === 'act') {
          updated.task = String(event.payload?.goal ?? event.payload?.task_id ?? '');
        }
      }
      if (event.type === 'reasoning' && event.payload?.text) {
        updated.lastText = String(event.payload.text);
        updated.lastTs = event.ts;
      }
      if (event.type === 'model' && event.payload?.kind === 'done') {
        updated.calls = lane.calls + 1;
        updated.lastCall = String(event.payload.model ?? '');
        updated.model = String(event.payload.model ?? '');
        updated.lastCallOk = !!event.payload.ok;
        updated.lastTs = event.ts;
      }
      agents = { ...agents, [agent]: updated };
    }
    if (event.type === 'log' && (stage === 'plan' || stage === 'task' || stage === 'directive')) {
      const payload = (event.payload ?? {}) as Record<string, any>;
      if (stage === 'plan') {
        const round = Number(payload.round ?? planRound ?? 0);
        planRound = round;
        planNote = String(payload.note ?? planNote ?? '');
        const objectives = Array.isArray(payload.objectives) ? payload.objectives
          : Array.isArray(payload.moves) ? payload.moves.map((item: Record<string, any>) => ({
              id: String(item.id ?? ''),
              owner: 'operator',
              goal: String(item.why ?? ''),
              hypothesis: '',
              critical: false,
              source: 'autopilot',
              tool: String(item.tool ?? '')
            })) : [];
        const planned: PlanTask[] = objectives.map((item: Record<string, any>) => ({
          id: String(item.id ?? ''),
          owner: String(item.owner ?? ''),
          goal: String(item.goal ?? ''),
          hypothesis: String(item.hypothesis ?? ''),
          status: 'assigned',
          round,
          critical: !!item.critical,
          source: String(item.source ?? 'strategist'),
          tool: String(item.tool ?? ''),
          verdict: '',
          reason: ''
        }));
        const plannedIds = new Set(planned.map((task) => task.id));
        const alreadySkipped = planTasks.filter(
          (task) => task.round === round && task.status === 'skipped' && !plannedIds.has(task.id)
        );
        planTasks = [...alreadySkipped, ...planned].slice(-24);
      } else if (stage === 'task') {
        const id = String(payload.task_id ?? '');
        if (id) {
          const round = Number(payload.round ?? planRound ?? 0);
          const row: PlanTask = {
            id,
            owner: String(payload.agent ?? ''),
            goal: String(payload.goal ?? ''),
            hypothesis: String(payload.hypothesis ?? ''),
            status: String(payload.status ?? 'assigned'),
            round,
            critical: !!payload.critical,
            source: String(payload.source ?? 'autopilot'),
            tool: String(payload.tool ?? ''),
            verdict: String(payload.verdict ?? ''),
            reason: String(payload.reason ?? '')
          };
          const index = planTasks.findIndex((task) => task.id === id && task.round === round);
          if (index >= 0) {
            planTasks = planTasks.map((task, at) => at === index
              ? { ...task, ...row, goal: row.goal || task.goal, hypothesis: row.hypothesis || task.hypothesis }
              : task);
          } else {
            planTasks = [...planTasks, row].slice(-24);
          }
        }
      } else {
        const id = String(payload.directive_id ?? '');
        if (id) {
          const row: DirectiveRow = {
            id,
            text: String(payload.text ?? ''),
            kind: String(payload.kind ?? 'focus'),
            status: String(payload.status ?? 'queued'),
            ts: event.ts,
            owner: String(payload.owner ?? ''),
            terms: Array.isArray(payload.terms) ? payload.terms.map(String) : [],
            plan: String(payload.plan ?? ''),
            matched: String(payload.matched_task ?? ''),
            source: String(payload.source ?? 'operator')
          };
          const index = operatorDirectives.findIndex((item) => item.id === id);
          if (index >= 0) {
            operatorDirectives = operatorDirectives.map((item, at) => at === index
              ? { ...item, ...row, text: row.text || item.text }
              : item);
          } else {
            operatorDirectives = [...operatorDirectives, row].slice(-60);
          }
        }
      }
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
    follow = streamBox.scrollTop + streamBox.clientHeight >= streamBox.scrollHeight - 48;
    if (follow) { unseen = 0; seenStreamLen = stream.length; }
  }

  function jumpToLatest() {
    follow = true;
    unseen = 0;
    seenStreamLen = stream.length;
    void tick().then(() => { if (streamBox) streamBox.scrollTop = streamBox.scrollHeight; });
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
    // A cast only writes a report when it has something to report. Ask the
    // API only when the run says one exists, so the tab does not log a 404.
    if (!counts.report) {
      report = '';
      reportErr = '';
      return;
    }
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
    memory = [];
    planTasks = [];
    planRound = 0;
    planNote = '';
    operatorDirectives = [];
    directiveText = '';
    directiveError = '';
    directiveBusy = false;
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
      const options = (run.options ?? {}) as Record<string, unknown>;
      if (String(options.mode ?? '') === 'autopilot' || String(options.mode ?? '') === 'swarm') {
        if (options.mission_id) {
          try {
            memory = (await api.missionNotes(String(options.mission_id))).items ?? [];
          } catch {
            /* the transcript still renders without the memory panel */
          }
        }
        try {
          mergeDirectives((await api.directives(run.id)).items ?? []);
        } catch {
          /* the stream already carries the live directive events */
        }
      }
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
      store.toast('warn', `stopping the operation on ${run.target}`);
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
      store.toast('ok', `continuing the operation on ${fresh.target} where it stopped`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not continue the run');
    } finally {
      continuing = false;
    }
  }

  function mergeDirectives(items: RunDirective[]) {
    const known = new Map(operatorDirectives.map((item) => [item.id, item]));
    for (const item of items) {
      if (!item || !item.id) continue;
      if (known.has(item.id)) continue;
      const stamp = Date.parse(item.created_at || '');
      known.set(item.id, {
        id: item.id,
        text: item.text || '',
        kind: item.kind || 'focus',
        status: item.status || 'queued',
        ts: Number.isFinite(stamp) ? stamp / 1000 : Date.now() / 1000,
        owner: '',
        terms: item.terms ?? [],
        plan: '',
        matched: '',
        source: item.source || 'operator'
      });
    }
    operatorDirectives = [...known.values()].sort((a, b) => a.ts - b.ts).slice(-60);
  }

  async function sendDirective(kindOverride: 'auto' | 'skip' | 'focus' = directiveKind,
                               targetOverride = '') {
    if (!run || directiveBusy) return;
    const text = directiveText.trim();
    if (!text) return;
    directiveBusy = true;
    directiveError = '';
    try {
      // A target id means "this exact task". Only a board action supplies
      // one; typed instructions stay subject-based so they cannot be
      // misread as a narrow skip of whatever task happens to be running.
      const result = await api.directive(run.id, text, kindOverride, targetOverride);
      mergeDirectives([result.directive]);
      directiveText = '';
      directiveKind = 'auto';
      store.toast('ok', `directive queued for ${run.target}`);
    } catch (exc) {
      directiveError = exc instanceof Error ? exc.message : 'could not send the directive';
    } finally {
      directiveBusy = false;
    }
  }

  // Quick actions only prepare a directive. They never send one: a stray click
  // must not skip a live task or redirect a running hunt.
  function skipCurrent() {
    const goal = liveTask?.goal || '';
    directiveText = goal ? `Skip this task: ${goal}` : 'Skip this task for now';
    directiveKind = 'skip';
    directiveBox?.focus();
  }

  function checkAuthFlow() {
    directiveText = 'Check the login and reset flow for an authentication bypass';
    directiveKind = 'focus';
    directiveBox?.focus();
  }

  function wrapUp() {
    directiveText = 'Focus on closing the strongest open lead and stop exploring side paths';
    directiveKind = 'focus';
    directiveBox?.focus();
  }

  function onDirectiveKey(event: KeyboardEvent) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void sendDirective();
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
    const len = stream.length;
    if (follow) { seenStreamLen = len; if (unseen) unseen = 0; }
    else if (len > seenStreamLen) unseen = len - seenStreamLen;
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
        body="Start an operation and it appears here live: the stage rail, a verbose transmission of every agent line, and inspectable evidence for each run - assets, endpoints, scripts, secrets, findings and the report."
        action="engage a target"
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
                <span class="min-w-0 flex-1 truncate text-sm text-bone" title={item.target}>{item.target}</span>
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
          <h1 class="truncate font-mono text-lg text-bone" title={run.target}>{run.target}</h1>
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
            {running ? `${(displayStages.find((s) => s.key === currentStage)?.label || displayStages[0]?.label || 'live').toLowerCase()} // live` : statusLabel(run.status)}
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
            <p class="num mt-0.5 text-[15px] text-bone"><span use:countup={Math.max(urlCount, urlsSeen)}>0</span></p>
          </div>
          <div>
            <p class="eyebrow">elapsed</p>
            <p class="num mt-0.5 text-[15px] text-bone">{elapsed}</p>
          </div>
        </div>
      </div>
    </section>

    <section class="grid grid-cols-2 gap-3 sm:grid-cols-4" aria-label="counters">
      {#if isSolve}
        {#each [['steps', 'steps'], ['actions', 'actions'], ['model calls', 'model_calls'], ['findings', 'findings']] as [label, key] (key)}
          <div class="obs-card obs-kpi is-dense">
            <p class="obs-kpi-label">{label}</p>
            <p class="obs-kpi-value" use:countup={counts[key] ?? 0}>0</p>
          </div>
        {/each}
      {:else if isMesh}
        {#each [['moves', 'actions'], ['model calls', 'model_calls'], ['agents', 'agents'], ['findings', 'findings']] as [label, key] (key)}
          <div class="obs-card obs-kpi is-dense">
            <p class="obs-kpi-label">{label}</p>
            <p class="obs-kpi-value" use:countup={metric(key)}>0</p>
          </div>
        {/each}
      {:else if isOperator}
        {#each [['moves', 'actions'], ['model calls', 'model_calls'], ['hypotheses', 'hypotheses'], ['findings', 'findings']] as [label, key] (key)}
          <div class="obs-card obs-kpi is-dense">
            <p class="obs-kpi-label">{label}</p>
            <p class="obs-kpi-value" use:countup={counts[key] ?? 0}>0</p>
          </div>
        {/each}
      {:else if isHunt}
        {#each [['pages', 'pages'], ['endpoints', 'endpoints'], ['techniques', 'techniques'], ['hypotheses', 'leads']] as [label, key] (key)}
          <div class="obs-card obs-kpi is-dense">
            <p class="obs-kpi-label">{label}</p>
            <p class="obs-kpi-value" use:countup={counts[key] ?? 0}>0</p>
          </div>
        {/each}
      {:else if isLab}
        {#each [['steps', 'steps'], ['http calls', 'http_calls'], ['solved', 'solved'], ['lesson', 'lesson_id']] as [label, key] (key)}
          <div class="obs-card obs-kpi is-dense">
            <p class="obs-kpi-label">{label}</p>
            <p class="obs-kpi-value">
              {key === 'solved' ? (counts.solved ? 'yes' : 'no') : key === 'lesson_id' ? (counts.lesson_id ? 'yes' : 'no') : (counts[key] ?? 0)}
            </p>
          </div>
        {/each}
      {:else}
        {#each [['pages', 'pages'], ['js files', 'js_files'], ['endpoints', 'endpoints'], ['candidates', 'candidates'], ['verified', 'verified'], ['findings', 'findings'], ['not confirmed', 'unverified'], ['weak points', 'review_loopholes']] as [label, key] (key)}
          <div class="obs-card obs-kpi is-dense">
            <p class="obs-kpi-label">{label}</p>
            <p class="obs-kpi-value" use:countup={counts[key] ?? 0}>0</p>
          </div>
        {/each}
      {/if}
    </section>

    {#if isMesh || isOperator}
      <section class="panel mc-panel" aria-label="mission control">
        <header class="mc-head">
          <div class="min-w-0">
            <p class="eyebrow">mission control</p>
            <h2 class="mc-title">{isMesh ? 'live brain loop' : 'live operator loop'}</h2>
          </div>
          <div class="mc-stats">
            <span class="mc-stat"><b>{planRound}</b> round</span>
            <span class="mc-stat"><b>{openTaskCount}</b> open</span>
            <span class="mc-stat"><b>{doneTaskCount}</b> done</span>
            <span class="mc-stat"><b>{skippedTaskCount}</b> skipped</span>
            <span class="mc-live" class:on={running}><i></i>{running ? 'live' : 'idle'}</span>
          </div>
        </header>
        {#if planNote}
          <p class="mc-note"><span class="mc-note-tag">brain</span>{formatText(planNote, 380)}</p>
        {/if}
        {#if liveTask}
          <p class="mc-now">
            <span class="mc-note-tag">now</span>
            <span class="mono" style="color:{agentColor(liveTask.owner)}">{liveTask.owner}</span>
            <span class="mc-now-sep">::</span>
            <span>{formatText(liveTask.goal, 300)}</span>
          </p>
        {/if}
        <div class="mc-grid">
          <div class="mc-board">
            <div class="mc-section-head">
              <p class="eyebrow">{isMesh ? 'plan / task board' : 'current plan'}</p>
              <span class="num text-xs text-ash">{planTasks.length}</span>
            </div>
            {#if planTasks.length === 0}
              <p class="mc-empty">
                {running ? 'The strategist is forming the first plan.' : 'No plan was recorded on this run.'}
              </p>
            {:else}
              <ul class="mc-tasks">
                {#each planTasks as task (task.id + ':' + task.round)}
                  <li class="mc-task" data-status={task.status} data-source={task.source}>
                    <span class="mc-task-bar" style="background:{agentColor(task.owner)}" aria-hidden="true"></span>
                    <div class="mc-task-body">
                      <div class="mc-task-top">
                        <span class="mc-owner" style="color:{agentColor(task.owner)}">{task.owner || 'operator'}</span>
                        {#if task.source === 'operator'}<span class="mc-tag operator">operator</span>{/if}
                        {#if task.critical}<span class="mc-tag critical">critical</span>{/if}
                        {#if task.tool}<code class="mc-tool">{task.tool}</code>{/if}
                        <span class="mc-status" data-status={task.status}>{task.status}</span>
                      </div>
                      <p class="mc-goal" title={task.goal}>{task.goal}</p>
                      {#if task.verdict}<span class="mc-verdict">{task.verdict}</span>{/if}
                      {#if task.reason}<span class="mc-reason">{task.reason}</span>{/if}
                    </div>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
          <div class="mc-channel">
            <div class="mc-section-head">
              <p class="eyebrow">operator channel</p>
              <span class="mono text-[10px] text-ash">two-way</span>
            </div>
            <p class="mc-help">
              Tell the brain what to skip, or what to check next. It becomes a live task,
              not a note on the side.
            </p>
            <textarea
              bind:this={directiveBox}
              bind:value={directiveText}
              class="mc-input"
              rows="3"
              maxlength="2000"
              aria-label="instruction to the brain"
              placeholder="e.g. skip the port scan for now, or check the login flow for auth bypass"
              onkeydown={onDirectiveKey}
            ></textarea>
            <div class="mc-actions">
              <div class="mc-kinds" role="group" aria-label="directive kind">
                {#each DIRECTIVE_KINDS as item (item.id)}
                  <button
                    class="mc-kind"
                    class:active={directiveKind === item.id}
                    type="button"
                    onclick={() => (directiveKind = item.id)}
                  >
                    {item.label}
                  </button>
                {/each}
              </div>
              <button
                class="btn btn-acid"
                type="button"
                onclick={() => sendDirective()}
                disabled={directiveBusy || !directiveText.trim()}
              >
                {directiveBusy ? 'sending...' : 'send to brain'}
              </button>
            </div>
            <div class="mc-quick">
              <button type="button" onclick={skipCurrent}>skip current task</button>
              <button type="button" onclick={checkAuthFlow}>check auth flow</button>
              <button type="button" onclick={wrapUp}>wrap up</button>
            </div>
            {#if directiveError}<p class="mc-error">{directiveError}</p>{/if}
            <div class="mc-directives">
              {#if operatorDirectives.length === 0}
                <p class="mc-empty">No operator instructions yet. The channel is open.</p>
              {:else}
                {#each operatorDirectives.slice(-8).reverse() as item (item.id)}
                  <div class="mc-directive" data-status={item.status} data-kind={item.kind}>
                    <div class="mc-directive-top">
                      <span class="mc-directive-kind" data-kind={item.kind}>{item.kind}</span>
                      <span class="mc-directive-status" data-status={item.status}>{item.status}</span>
                      <span class="mc-directive-time">{clock(item.ts)}</span>
                    </div>
                    <p class="mc-directive-text" title={item.text}>{formatText(item.text, 240)}</p>
                    {#if item.plan}<p class="mc-directive-plan">{formatText(item.plan, 170)}</p>{/if}
                  </div>
                {/each}
              {/if}
            </div>
          </div>
        </div>
      </section>
    {/if}

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
        <div class="grid min-w-0 lg:grid-cols-[1.7fr_1fr]">
          <div class="flex min-h-[460px] min-w-0 flex-col border-b border-indigo-deep lg:border-b-0 lg:border-r">
            <div class="obs-live-filter-bar flex flex-wrap items-center gap-2 px-4 py-2">
              {#each FILTERS as item (item.id)}
                <button
                  class="live-filter"
                  class:active={filter === item.id}
                  type="button"
                  onclick={() => { filter = item.id; streamLimit = STREAM_CAP; }}
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
                {follow ? 'following live' : unseen ? `${unseen} new` : 'jump to latest'}
              </button>
            </div>
            <div class="obs-live-legend" aria-label="stream legend">
              <span class="lg-think"><i></i>reasoning</span>
              <span class="lg-tool"><i></i>tool call</span>
              <span class="lg-evidence"><i></i>proof / evidence</span>
              <span class="lg-log"><i></i>log</span>
              <span style="margin-left:auto">{stream.length} {stream.length === 1 ? 'row' : 'rows'} - {reasoningCount} reasoning - {toolCount} {toolCount === 1 ? 'tool' : 'tools'} - {modelCount} {modelCount === 1 ? 'call' : 'calls'}</span>
            </div>
            <div
              class="mono flex-1 overflow-y-auto px-4 pb-3 text-[12px] leading-relaxed"
              style="max-height:min(58vh,560px);min-height:200px"
              data-transmission="1"
              class:is-live={running}
              bind:this={streamBox}
              onscroll={onStreamScroll}
            >
              {#if stream.length === 0}
                {#if running}
                  <div style="padding:10px 0"><Buffering variant="block" label="Waiting for first line" detail="Agents are waking up on {run.target}. Thinking, tool calls and proof will stream here." /></div>
                {:else}
                  <p class="py-2 text-slate">{filter === 'all' ? 'Nothing was transmitted on this run.' : `No ${filter} rows on this run.`}</p>
                {/if}
              {/if}
              {#if olderRows > 0}
                <div class="trace-older">
                  <button type="button" onclick={() => (streamLimit += STREAM_CAP)}>
                    load {Math.min(olderRows, STREAM_CAP)} older ({olderRows} hidden)
                  </button>
                </div>
              {/if}
              {#each stream as row (row.seq)}
                {@const meta = metaOf(row)}
                <div
                  class="trace-row"
                  class:trace-live={running && row.seq === lastSeq}
                  class:trace-think={row.kind === 'think'}
                  data-kind={row.kind}
                >
                  <button class="trace-main" type="button" onclick={() => toggleRow(row.seq)}>
                    <span class="trace-gutter" style="--agent:{agentColor(row.agent)}">
                      <i class="trace-icon" style="color:{meta.color}">{meta.icon}</i>
                      <span class="trace-time" title={utcStamp(row.ts)}>{clock(row.ts)}</span>
                    </span>
                    <span class="trace-kind" style="color:{meta.color}">{meta.label}</span>
                    <span class="trace-agent" style="color:{agentColor(row.agent)}">{row.agent}</span>
                    <span class="trace-body">
                      {#if row.kind === 'act' || row.kind === 'tool'}
                        <code class="trace-tool">{row.tool || row.text}</code>
                        {#if row.url}<span class="trace-url">{row.url}</span>{/if}
                        {#if row.kind === 'tool' && row.status !== '' && row.status !== undefined}
                          <span class="trace-status" style="color:{statusTone(row.status)}">{row.status}</span>
                        {/if}
                        {#if row.kind === 'tool'}
                          <span class="trace-ok" class:no={row.ok === false}>{row.ok === false ? 'failed' : 'ok'}</span>
                          {#if row.text}
                            <span class="trace-note">{formatText(row.text, 220)}</span>
                          {/if}
                        {/if}
                        {#if row.kind === 'act'}
                          {@const args = argPreview(row)}
                          {#if args}
                            <code class="trace-args">{args}</code>
                          {/if}
                          {#if row.text && row.text !== `calling ${row.tool}`}
                            <span class="trace-note">{formatText(row.text, 240)}</span>
                          {/if}
                        {/if}
                      {:else if row.kind === 'model'}
                        <code class="trace-tool">{row.text}</code>
                        <span class="trace-ok" class:no={row.ok === false}>{row.ok === false ? 'failed' : 'ok'}</span>
                        {#if (row.repeat ?? 1) > 1}
                          <span class="trace-repeat">x{row.repeat}</span>
                        {/if}
                        <span class="trace-note">{row.ms ?? 0}ms{row.tokens ? ` - ${row.tokens} tok` : ''}</span>
                      {:else if row.kind === 'http'}
                        <span class="trace-url">{row.url || row.text}</span>
                        {#if row.status !== '' && row.status !== undefined}
                          <span class="trace-status" style="color:{statusTone(row.status)}">{row.status}</span>
                        {/if}
                      {:else if row.kind === 'found'}
                        <Chip label={row.sub} color={sevColor(row.sub)} shape={sevShape(row.sub)} />
                        <span class="trace-note">{formatText(row.text, 900)}</span>
                      {:else if row.kind === 'directive'}
                        <span class="trace-text">{formatText(row.text, 600)}</span>
                        {#if row.sub}<span class="trace-note trace-directive-state">{row.sub}</span>{/if}
                      {:else if row.kind === 'plan'}
                        <span class="trace-text">{formatText(row.text, 300)}</span>
                      {:else}
                        <span class="trace-text">{formatText(row.text, row.kind === 'think' ? 1400 : 600)}</span>
                      {/if}
                    </span>
                  </button>
                  {#if expanded[row.seq] && row.detail}
                    <div class="trace-detail-wrap">
                      <button class="trace-copy" type="button" onclick={() => void copyRow(row)}>copy</button>
                      <pre class="trace-detail">{row.detail}</pre>
                    </div>
                  {/if}
                </div>
              {/each}
              {#if !follow && unseen > 0}
                <div class="obs-jump-latest"><button type="button" onclick={jumpToLatest}>{unseen} new - jump to latest</button></div>
              {/if}
            </div>
          </div>

          <div class="flex min-w-0 flex-col">
            <div class="border-b border-indigo-deep trace-agents">
              <div class="flex items-center justify-between px-4 py-2.5">
                <p class="eyebrow">live agents</p>
                <span class="num text-xs text-ash">{agentList.length}</span>
              </div>
              {#if agentList.length === 0}
                <p class="px-4 pb-3 text-sm text-bone-dust">Waiting for the first agent to speak.</p>
              {:else}
                <ul class="max-h-[280px] overflow-y-auto">
                  {#each agentList.slice(0, 8) as lane (lane.agent)}
                    {@const tone = laneStatus(lane)}
                    <li class="trace-agent-card" data-agent={lane.agent}>
                      <div class="flex items-center gap-2">
                        <span class="lane-led" style="--agent:{agentColor(lane.agent)}" aria-hidden="true"></span>
                        <span class="mono text-[11px]" style="color:{agentColor(lane.agent)}">{lane.agent}</span>
                        <span class="mono ml-auto text-[9px] uppercase tracking-[0.1em]" style="color:{tone.color}">{tone.label}</span>
                      </div>
                      {#if lane.task}
                        <p class="trace-agent-task" title={lane.task}>{formatText(lane.task, 140)}</p>
                      {/if}
                      <p class="trace-agent-thought" title={lane.lastText}>{formatText(lane.lastText, 160)}</p>
                      <div class="flex items-center gap-3 text-[9px] uppercase tracking-[0.1em] text-ash">
                        {#if lane.model}<span class="truncate">model {lane.model}</span>{/if}
                        <span>{lane.thoughts} think</span>
                        <span>{lane.tools} tool</span>
                        <span>{lane.calls} call</span>
                      </div>
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
            {#if isOperator || isMesh}
              <div class="border-b border-indigo-deep">
                <div class="flex items-center justify-between px-4 py-2.5">
                  <p class="eyebrow">{isMesh ? 'mesh memory' : 'operator memory'}</p>
                  <span class="num text-xs text-ash">{memory.length}</span>
                </div>
                {#if isMesh}
                  <ul data-mesh="1">
                    {#each MESH_ROLES as role (role.key)}
                      {@const color = (AGENT_COLORS as Record<string, string>)[role.key] ?? 'var(--nc-bone-dust)'}
                      <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-1.5 last:border-0">
                        <span class="lane-led" style="--agent:{color}" aria-hidden="true"></span>
                        <span class="mono w-[74px] shrink-0 text-[11px]" style="color:{color}">{role.label}</span>
                        <span class="text-[11px] text-bone-dust">{role.detail}</span>
                        <span class="num ml-auto text-[11px] text-ash">{roleCount(role.counter)} <span class="text-[9px] uppercase tracking-[0.08em] text-bone-dust">{role.unit}</span></span>
                      </li>
                    {/each}
                  </ul>
                  <div class="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-indigo-deep/60 px-4 py-2">
                    <span class="mono text-[9px] uppercase tracking-[0.12em]" style="color:var(--nc-acid)">supports {counts.supports ?? 0}</span>
                    <span class="mono text-[9px] uppercase tracking-[0.12em]" style="color:var(--nc-violet)">refutes {counts.refuted ?? 0}</span>
                    <span class="mono text-[9px] uppercase tracking-[0.12em] text-ash">inconclusive {counts.inconclusive ?? 0}</span>
                    <span class="mono ml-auto text-[9px] text-bone-dust">{roundCount()} round(s) - {counts.corroborated ?? 0} corroborated / {counts.contested ?? 0} contested</span>
                  </div>
                {/if}
                {#if memory.length === 0}
                  <p class="px-4 pb-4 text-sm text-bone-dust">No notes written yet.</p>
                {:else}
                  <ul class="max-h-[520px] overflow-y-auto" data-memory="1">
                    {#each memory.slice(-12).reverse() as note (note.id)}
                      <li class="border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                        <div class="flex items-center gap-2">
                          <span class="mono text-[9px] uppercase tracking-[0.14em] text-acid">{note.kind}</span>
                          <span class="mono text-[10px] text-slate">{clock(note.created_at)}</span>
                        </div>
                        <p class="mt-0.5 text-xs text-bone">{note.title}</p>
                      </li>
                    {/each}
                  </ul>
                {/if}
              </div>
            {:else}
            {#if !isLab && !isHunt && !isSolve}
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
                <p class="eyebrow">agent theater - who is doing what</p>
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
                    {@const status = laneStatus(lane)}
                    <li class="border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                      <div class="flex items-center gap-3">
                        <span class="lane-led" style="--agent:{color}" aria-hidden="true"></span>
                        <span class="mono w-[86px] shrink-0 truncate text-xs" style="color:{color}">{lane.agent}</span>
                        <span class="mono shrink-0 text-[9px] uppercase tracking-[0.1em]" style="color:{status.color}">{status.label}</span>
                        <span class="num shrink-0 text-[11px] text-ash">{lane.lines} lines{lane.calls ? ` - ${lane.calls} calls` : ''}</span>
                        <span class="mono ml-auto shrink-0 text-[10px] text-slate">{clock(lane.lastTs)}</span>
                        <button class="shrink-0 text-[10px] tracking-[0.12em] text-acid opacity-70 transition-opacity hover:opacity-100" type="button" onclick={() => openSpotlight(lane.agent)}>WATCH &gt;</button>
                      </div>
                      {#if lane.task}
                        <p class="mt-1 truncate pl-[22px] text-[11px] text-bone" title={lane.task}>{formatText(lane.task, 150)}</p>
                      {/if}
                      {#if lane.lastText}
                        <p class="mt-1 truncate pl-[22px] text-[11px] text-bone-dust" title={lane.lastText}>{formatText(lane.lastText, 160)}</p>
                      {:else if lane.lastCall}
                        <p class="mt-1 truncate pl-[22px] mono text-[11px]" style="color:{lane.lastCallOk === false ? 'var(--nc-violet)' : 'var(--nc-ash)'}">last model: {lane.lastCall}</p>
                      {/if}
                    </li>
                  {/each}
                </ul>
              {/if}
            </div>
            {/if}
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
              <p class="px-4 pb-4 text-sm text-bone-dust">No pages were mapped on this run.</p>
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
            <article class="report-prose max-w-[860px]">{@html renderMarkdown(report)}</article><!-- codeaudit: ignore svelte-html -- renderMarkdown escapes every character before rebuilding markup -->
          {:else}
            <p class="text-sm text-slate">
              {running
                ? 'the report is written when the run finishes - this preview will refresh on its own.'
                : counts.report
                  ? 'loading the report...'
                  : 'this cast did not write a report.'}
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
      class="palette-panel panel-raised panel-hud obs-spotlight mx-auto mt-[7vh] flex w-[min(880px,94vw)] flex-col overflow-hidden"
      style="max-height:80vh"
      role="dialog"
      aria-modal="true"
      aria-label="{spotlightAgent} live thinking"
      tabindex="-1"
      bind:this={panelEl}
      use:focusTrap
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          spotlightAgent = '';
        }
        event.stopPropagation();
      }}
    >
      <header class="obs-spot-head">
        <span class="lane-led" style="--agent:{color}" aria-hidden="true"></span>
        <div class="obs-spot-title">
          <p class="obs-eyebrow"><span class="tick"></span>live model spotlight</p>
          <h2 class="obs-spot-agent" style="color:{color}">{spotlightAgent}</h2>
        </div>
        <div class="obs-spot-tools">
          <span class="obs-spot-count">{spotlightRows.length} rows</span>
          <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => (spotlightAgent = '')}>
            close
          </button>
        </div>
      </header>
      <div
        class="think-stream obs-spot-stream"
        data-spotlight="1"
        bind:this={spotlightEl}
        onscroll={onSpotlightScroll}
      >
        {#if spotlightRows.length === 0}
          <p class="obs-spot-empty">
            {running
              ? `waiting for ${spotlightAgent} to speak...`
              : `no activity recorded for ${spotlightAgent} on this run`}
          </p>
        {/if}
        {#each spotlightRows as row, i (row.seq)}
          {@const badge = metaOf(row)}
          <p class="think-line obs-spot-line" style="--i:{Math.min(i, 14)}">
            <span class="obs-spot-t">{clock(row.ts)}</span>
            <span class="obs-spot-b" style="color:{badge.color}">{badge.label}</span>
            <span class="obs-spot-m" style="color:var(--obs-text-2)"
              >{formatText(row.text, 900)}{#if running && i === spotlightRows.length - 1}<span
                  class="caret"
                  aria-hidden="true"
                ></span>{/if}</span
            >
            {#if row.sub}<span class="obs-spot-s">{row.sub}</span>{/if}
          </p>
        {/each}
      </div>
      <footer class="obs-spot-foot">
        {#if running}
          <span class="pulse-live obs-spot-dot" aria-hidden="true"></span>
          <span class="obs-spot-note">streaming // press esc to close</span>
        {:else}
          <span class="obs-spot-note">{run ? statusLabel(run.status) : 'closed'} // press esc to close</span>
        {/if}
      </footer>
    </div>
  </div>
{/if}

{#if stopOpen && run}
  <Confirm
    title="Stop the operation on {run.target}?"
    body="The run stops at the next safe point and keeps everything it found so far. Partial results are written to disk, and you can continue the operation later from where it stopped. This cannot be undone."
    confirmLabel="stop this scan"
    danger
    onConfirm={confirmStop}
    onCancel={() => (stopOpen = false)}
  />
{/if}
