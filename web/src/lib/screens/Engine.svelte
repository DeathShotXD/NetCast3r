<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { AGENT_COLORS, AGENT_STAGE, STAGES } from '../../tokens';
  import { clock, isoMs, stageForAgent, statusColor, statusLabel } from '../format';
  import { store } from '../state.svelte';
  import type { Run, RunEvent } from '../types';
  import { countup } from '../actions';
  import RunScope from '../ui/RunScope.svelte';
  import StageSignal from '../ui/StageSignal.svelte';

  const stages = STAGES as unknown as { key: string; label: string; agent: string }[];

  const LANE_AGENTS = ['recon', 'exegete', 'prospector', 'classifier', 'assayer', 'chainer', 'scribe'];
  const BUCKETS = 96;
  const BUCKET_MS = 250;
  const FEED_CAP = 400;
  const FEED_AGENT_CAP = 60;
  const FETCH_CAP = 80;

  type Lane = {
    agent: string;
    lines: number;
    lastText: string;
    lastTs: number;
    lastCall: string;
    lastCallOk: boolean | null;
    calls: number;
    currentStage: string;
  };
  type FeedItem = { seq: number; agent: string; kind: 'reasoning' | 'log' | 'model'; text: string };
  type FetchRow = { seq: number; kind: string; url: string; status: number };

  let run = $state<Run | null>(null);
  let lanes = $state<Record<string, Lane>>({});
  let lastAt = $state<Record<string, number>>({});
  let feed = $state<FeedItem[]>([]);
  let fetches = $state<FetchRow[]>([]);
  let eventCount = $state(0);
  let urlCount = $state(0);
  let stageCounts = $state<Record<string, number>>({});
  let crawled = $state(0);
  let buckets = $state<number[]>(new Array(BUCKETS).fill(0));
  let nowTick = $state(Date.now());
  let picked = $state('');
  let spotlightAgent = $state('');

  let pending = 0;

  const running = $derived(!!run && (run.status === 'running' || run.status === 'queued'));
  const laneList = $derived(
    LANE_AGENTS.map((agent) => lanes[agent] ?? fresh(agent)).filter((lane) => lane.lines > 0)
  );
  const currentStage = $derived.by(() => {
    if (!running) return '';
    let at = -1;
    stages.forEach((stage, i) => {
      if ((stageCounts[stage.key] ?? 0) > 0) at = Math.max(at, i);
    });
    return at < 0 ? stages[0].key : stages[at].key;
  });
  const stageCount = $derived.by(() => {
    const counts: Record<string, number> = {};
    for (const stage of stages) counts[stage.key] = stageCounts[stage.key] ?? 0;
    counts.crawl = Math.max(crawled, counts.crawl ?? 0);
    return counts;
  });
  const rate = $derived.by(() => {
    const win = buckets.slice(-8);
    const total = win.reduce((sum, value) => sum + value, 0);
    return total / ((win.length * BUCKET_MS) / 1000);
  });
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
  const reasoningLines = $derived(feed.filter((item) => item.kind === 'reasoning'));
  const spotlightItems = $derived.by(() => {
    if (!spotlightAgent) return [];
    return feed.filter((item) => item.agent === spotlightAgent).slice().reverse();
  });
  const spotlightLane = $derived(lanes[spotlightAgent] ?? null);
  const spotlightStage = $derived.by(() => {
    const key = stageForAgent(spotlightAgent);
    return stages.find((stage) => stage.key === key)?.label ?? '';
  });
  const liveStage = $derived(stages.find((stage) => stage.key === currentStage) ?? null);

  function fresh(agent: string): Lane {
    return {
      agent,
      lines: 0,
      lastText: '',
      lastTs: 0,
      lastCall: '',
      lastCallOk: null,
      calls: 0,
      currentStage: (AGENT_STAGE as Record<string, string>)[agent] ?? ''
    };
  }

  const seen = new Set<number>();
  let queue: RunEvent[] = [];
  let scheduled = false;
  let rafId = 0;
  let timerId = 0;

  function push(event: RunEvent) {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    if (seen.size > 20000) {
      const stale = seen.values();
      for (let k = 0; k < 5000; k += 1) {
        const next = stale.next();
        if (next.done) break;
        seen.delete(next.value);
      }
    }
    queue.push(event);
    if (!scheduled) {
      scheduled = true;
      rafId = requestAnimationFrame(() => flush());
      timerId = window.setTimeout(() => flush(), 350);
    }
  }

  function flush() {
    scheduled = false;
    cancelAnimationFrame(rafId);
    window.clearTimeout(timerId);
    const batch = queue;
    queue = [];
    if (batch.length) applyBatch(batch);
  }

  function trimFeed(items: FeedItem[]): FeedItem[] {
    const perAgent: Record<string, number> = {};
    const kept: FeedItem[] = [];
    for (const item of items) {
      const n = (perAgent[item.agent] = (perAgent[item.agent] ?? 0) + 1);
      if (n > FEED_AGENT_CAP) continue;
      kept.push(item);
      if (kept.length >= FEED_CAP) break;
    }
    return kept;
  }

  /** One path for history and live events: everything downstream reads it. */
  function applyBatch(batch: RunEvent[]) {
    const next = { ...lanes };
    const at = { ...lastAt };
    const incoming: FeedItem[] = [];
    const arrived: FetchRow[] = [];
    const nextStage = { ...stageCounts };
    let nextCrawled = crawled;
    let nextRun = run;
    let addedEvents = 0;
    for (const event of batch) {
      if (event.type === 'lagged') continue;
      addedEvents += 1;
      pending += 1;
      if (event.type === 'run.state' && nextRun) {
        const status = String(event.payload?.status ?? '');
        const settled = ['done', 'failed', 'stopped', 'interrupted'].includes(nextRun.status);
        if (status && !settled) nextRun = { ...nextRun, status: status as Run['status'] };
        const counts = event.payload?.counts ?? event.payload?.summary;
        if (counts && typeof counts === 'object') {
          nextRun = { ...nextRun, counts: { ...nextRun.counts, ...(counts as Record<string, number>) } };
        }
      }
      if (event.type === 'run.finished' && nextRun) {
        const counts = event.payload?.counts;
        nextRun = {
          ...nextRun,
          status: 'done',
          counts: counts && typeof counts === 'object'
            ? { ...nextRun.counts, ...(counts as Record<string, number>) }
            : nextRun.counts
        };
      }
      const crawledValue = Number(event.progress?.crawled ?? 0);
      if (crawledValue > 0) nextCrawled = Math.max(nextCrawled, crawledValue);
      const stage = event.stage || stageForAgent(event.agent);
      if (stage) nextStage[stage] = (nextStage[stage] ?? 0) + 1;
      const agent = event.agent || '';
      if (agent && LANE_AGENTS.includes(agent)) {
        const lane = next[agent] ?? fresh(agent);
        const updated = { ...lane, lines: lane.lines + 1 };
        if (event.type === 'log' || event.type === 'error') {
          updated.lastText = String(event.payload?.text ?? event.payload?.error ?? '');
          updated.lastTs = event.ts;
          if (updated.lastText) incoming.push({ seq: event.seq, agent, kind: 'log', text: updated.lastText });
        }
        if (event.type === 'reasoning' && event.payload?.text) {
          updated.lastText = String(event.payload.text);
          updated.lastTs = event.ts;
          incoming.push({ seq: event.seq, agent, kind: 'reasoning', text: String(event.payload.text) });
        }
        if (event.type === 'model' && event.payload?.kind === 'done') {
          updated.calls = lane.calls + 1;
          updated.lastCall = String(event.payload.model ?? '');
          updated.lastCallOk = !!event.payload.ok;
          const ms = Number(event.payload.ms ?? 0);
          incoming.push({
            seq: event.seq,
            agent,
            kind: 'model',
            text: `${String(event.payload.provider ?? '')}/${updated.lastCall} ${updated.lastCallOk ? 'ok' : 'failed'} ${ms}ms`
          });
        }
        at[agent] = Date.now();
        next[agent] = updated;
      }
      if (event.type === 'fetch' && event.payload?.url) {
        const kind = String(event.payload.kind ?? '');
        if (kind !== 'progress') {
          arrived.push({
            seq: event.seq,
            kind,
            url: String(event.payload.url),
            status: Number(event.payload.status ?? 0)
          });
        }
      }
    }
    if (arrived.length) {
      urlCount += arrived.length;
      fetches = [...arrived.reverse(), ...fetches].slice(0, FETCH_CAP);
    }
    if (incoming.length) feed = trimFeed([...incoming.reverse(), ...feed]);
    lanes = next;
    lastAt = at;
    stageCounts = nextStage;
    crawled = nextCrawled;
    if (nextRun !== run) {
      run = nextRun;
      if (nextRun && nextRun.status !== 'running' && nextRun.status !== 'queued') {
        void store.refreshRuns();
      }
    }
    eventCount += addedEvents;
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

  async function load() {
    if (!store.activeRunId) return;
    cancelAnimationFrame(rafId);
    window.clearTimeout(timerId);
    scheduled = false;
    queue = [];
    try {
      run = await api.run(store.activeRunId);
      lanes = {};
      lastAt = {};
      feed = [];
      fetches = [];
      eventCount = 0;
      urlCount = 0;
      stageCounts = {};
      crawled = 0;
      buckets = new Array(BUCKETS).fill(0);
      pending = 0;
      nowTick = Date.now();
      seen.clear();
      picked = '';
      spotlightAgent = '';
      if (!run) return;
      const page = await api.runEvents(run.id);
      const items = (page.items ?? []) as RunEvent[];
      for (const item of items) seen.add(item.id);
      if (items.length) applyBatch(items);
      seedBuckets(items);
      pending = 0;
    } catch (exc) {
      run = null;
      store.fail(exc instanceof Error ? exc.message : 'could not load the run');
    }
  }

  let loadedId = $state('');
  let destroyed = false;

  async function start() {
    const id = store.activeRunId;
    source?.close();
    source = undefined;
    await load();
    if (destroyed || id !== store.activeRunId) return;
    connect();
  }

  let source: EventSource | undefined;

  function connect() {
    if (!store.activeRunId || !running) return;
    const wanted = store.activeRunId;
    source = new EventSource(api.eventsUrl(wanted));
    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as RunEvent;
        if (event.run_id && event.run_id !== wanted) return;
        push(event);
      } catch {
        /* ignore a malformed frame */
      }
    };
    source.onerror = () => {
      void refreshStatus(wanted);
    };
  }

  async function refreshStatus(id: string) {
    try {
      const fresh = await api.run(id);
      if (fresh && id === store.activeRunId) run = fresh;
    } catch {
      /* the stream will retry; a missed poll must not blank the screen */
    }
  }

  function openSpotlight(agent: string) {
    spotlightStick = true;
    spotlightAgent = agent;
  }

  function pickDefault(): void {
    if (store.activeRunId) return;
    const openRun = store.runs.find((item) => item.status === 'running');
    const latest = store.runs[0];
    const pick = openRun ?? latest;
    if (pick) store.select(pick.id);
  }

  function kindBadge(kind: string): { text: string; color: string } {
    if (kind === 'js') return { text: 'JS', color: 'var(--nc-violet)' };
    if (kind === 'page') return { text: 'HTML', color: 'var(--nc-acid)' };
    if (kind === 'skip') return { text: 'SKIP', color: 'var(--nc-slate)' };
    return { text: (kind || 'get').toUpperCase(), color: 'var(--nc-ash)' };
  }

  function countLabel(n: number): string {
    return `${n} ${n === 1 ? 'line' : 'lines'}`;
  }

  let spotlightStick = $state(true);
  let spotlightEl = $state<HTMLDivElement | undefined>(undefined);
  let panelEl = $state<HTMLElement | undefined>(undefined);

  function onSpotlightScroll() {
    if (!spotlightEl) return;
    spotlightStick = spotlightEl.scrollHeight - spotlightEl.scrollTop - spotlightEl.clientHeight < 48;
  }

  $effect(() => {
    spotlightItems.length;
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

  // One 250ms clock drives the scope bar, the hot-lane decay and elapsed.
  $effect(() => {
    if (!running) return;
    const tick = window.setInterval(() => {
      nowTick = Date.now();
      buckets = [...buckets.slice(1), pending];
      pending = 0;
    }, BUCKET_MS);
    return () => window.clearInterval(tick);
  });

  $effect(() => {
    const id = store.activeRunId;
    if (id === loadedId) return;
    loadedId = id;
    void start();
  });

  $effect(() => {
    if (!running) source?.close();
  });

  onMount(async () => {
    if (store.runs.length === 0) await store.refreshRuns();
    pickDefault();
  });

  onDestroy(() => {
    destroyed = true;
    source?.close();
    cancelAnimationFrame(rafId);
    window.clearTimeout(timerId);
  });
</script>

{#if !store.activeRunId || !run}
  <div class="stagger mx-auto max-w-[980px]">
    <section class="panel p-8 text-center">
      <p class="eyebrow">engine room</p>
      <h1 class="mt-2 text-xl text-bone">No run on the floor</h1>
      <p class="mx-auto mt-3 max-w-[460px] text-sm leading-relaxed text-bone-dust">
        The engine room shows every agent as a live lane: what each one is saying right now,
        how hard it is working, and where the run stands. Start a scan and the lanes wake up.
      </p>
      <button class="btn btn-acid mt-5" type="button" onclick={() => store.go('new')}>
        start a scan
      </button>
      {#if store.runs.length > 0}
        <div class="mx-auto mt-6 w-full max-w-[420px] border-t border-indigo-deep pt-4 text-left">
          <p class="eyebrow mb-2">or open a run</p>
          {#each store.runs.slice(0, 6) as item (item.id)}
            <button
              class="row-link flex w-full items-center gap-3 rounded px-3 py-2 text-left"
              type="button"
              onclick={() => store.select(item.id)}
            >
              <span class="min-w-0 flex-1 truncate text-sm text-bone">{item.target}</span>
              <span class="mono text-xs text-ash">{item.status}</span>
            </button>
          {/each}
        </div>
      {/if}
    </section>
  </div>
{:else}
  {@const activeRun = run as Run}
  <div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
    <section class="panel panel-hud flex flex-wrap items-center gap-3 p-5">
      <span class="lane-led" style="--agent:{statusColor(run.status)}" aria-hidden="true"></span>
      <div class="min-w-0">
        <p class="eyebrow">engine room // run {run.id.slice(-6)}</p>
        <h1 class="truncate font-mono text-lg text-bone">{run.target}</h1>
      </div>
      <span
        class="chip"
        style="color:{statusColor(run.status)}"
        title={run.error || ''}
      >
        {statusLabel(run.status)}
      </span>
      <span class="num ml-auto text-sm text-ash"><span use:countup={eventCount}>0</span> events</span>
      {#if store.runs.length > 1 || !store.runs.some((item) => item.id === activeRun.id)}
        <label class="flex items-center gap-2">
          <span class="eyebrow">scan</span>
          <select
            class="field py-1! text-xs"
            value={store.activeRunId}
            onchange={(event) => store.select((event.currentTarget as HTMLSelectElement).value)}
          >
            {#if !store.runs.some((item) => item.id === activeRun.id)}
              <option value={activeRun.id}>{activeRun.target} / {activeRun.status}</option>
            {/if}
            {#each store.runs as item (item.id)}
              <option value={item.id}>{item.target} / {item.status}</option>
            {/each}
          </select>
        </label>
      {/if}
    </section>

    <section class="grid gap-3 lg:grid-cols-[1.35fr_1fr]">
      <div class="panel panel-hud flex flex-col justify-center gap-3 px-4 py-3">
        <div class="flex items-center justify-between">
          <p class="eyebrow">stage signal</p>
          <span
            class="mono text-[10px] tracking-[0.14em]"
            style="color:{running ? 'var(--nc-acid)' : 'var(--nc-ash)'}"
          >
            {running ? `${(liveStage?.agent ?? 'run').toLowerCase()} // live` : statusLabel(run.status)}
          </span>
        </div>
        <StageSignal stages={stages} counts={stageCount} current={currentStage} {running} />
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

    <section class="grid gap-5 lg:grid-cols-[1.3fr_1fr]">
      <!-- the crawler: every URL as it lands, split html/js -->
      <div class="panel flex min-h-[280px] flex-col overflow-hidden">
        <div class="flex items-center justify-between border-b border-indigo-deep px-4 py-2.5">
          <p class="eyebrow">crawler feed</p>
          <span class="flex items-center gap-2">
            {#if running}
              <span class="pulse-live h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
            {/if}
            <span class="mono num text-xs text-ash">{urlCount} urls</span>
          </span>
        </div>
        <div class="relative flex-1 overflow-hidden">
          {#if running}
            <span class="scan-sweep" aria-hidden="true"></span>
          {/if}
          <div
            class="mono h-full overflow-y-auto px-4 py-2 text-[12px] leading-relaxed"
            data-feed="1"
          >
            {#if fetches.length === 0}
              <p class="text-slate">
                {running
                  ? `waiting for the first response from ${run.target}...`
                  : 'The crawler feed fills as the run works.'}
              </p>
            {/if}
            {#each fetches as row, i (row.seq)}
              {@const badge = kindBadge(row.kind)}
              <p class="flex items-center gap-2 py-0.5" class:line-arrive={i === 0 && running}>
                <span
                  class="w-[40px] shrink-0 text-[10px] tracking-[0.08em]"
                  style="color:{badge.color}"
                >
                  {badge.text}
                </span>
                <span
                  class="num w-[28px] shrink-0 text-[10px]"
                  style="color:{row.status >= 400
                    ? 'var(--nc-violet)'
                    : row.status === 0
                      ? 'var(--nc-slate)'
                      : 'var(--nc-bone-dust)'}"
                >
                  {row.status || '--'}
                </span>
                <span
                  class="min-w-0 flex-1 truncate {row.kind === 'skip' ? 'text-slate' : 'text-bone-dust'}"
                  title={row.url}
                >
                  {row.url}
                </span>
              </p>
            {/each}
          </div>
        </div>
      </div>

      <!-- what the models are saying right now -->
      <div class="panel flex min-h-[280px] flex-col overflow-hidden">
        <div class="flex items-center justify-between border-b border-indigo-deep px-4 py-2.5">
          <p class="eyebrow">thinking now</p>
          <span class="mono num text-xs text-ash">{countLabel(reasoningLines.length)}</span>
        </div>
        <div class="flex-1 overflow-y-auto px-4 py-2" data-think="1">
          {#if reasoningLines.length === 0}
            {#if running}
              <p class="flex items-center gap-2 text-xs text-slate">
                <span class="pulse-live h-1.5 w-1.5 shrink-0 rounded-full bg-acid"></span>
                <span>
                  {liveStage ? `${liveStage.agent} is ${liveStage.key === 'crawl' ? 'crawling' : 'working'}` : 'the agents are working'} &mdash;
                  model voice lands here the moment it answers.
                </span>
              </p>
            {:else}
              <p class="text-xs text-slate">No model reasoning on this run.</p>
            {/if}
          {/if}
          {#each reasoningLines.slice(0, 200) as block, i (block.seq)}
            {@const color = (AGENT_COLORS as Record<string, string>)[block.agent] ?? 'var(--nc-bone-dust)'}
            <p
              class="mono border-l-2 py-1 pl-2 text-[11px] leading-relaxed text-bone-dust"
              style="border-color:{color}"
              class:line-arrive={i === 0 && running}
            >
              <span style="color:{color}">{block.agent}</span>
              <span class="text-slate"> // </span>
              {block.text.slice(0, 200)}
            </p>
          {/each}
        </div>
      </div>
    </section>

    <section class="flex flex-col gap-2.5">
      {#each laneList as lane (lane.agent)}
        {@const color = (AGENT_COLORS as Record<string, string>)[lane.agent] ?? 'var(--nc-bone-dust)'}
        {@const hot = running && (lastAt[lane.agent] ?? 0) > nowTick - 1600}
        <div class="lane panel w-full" class:lane-hot={hot} style="--agent:{color}">
          <div class="flex items-center gap-3 px-4 py-2.5">
            <span class="lane-led" aria-hidden="true"></span>
            <button
              class="flex min-w-0 flex-1 items-center gap-3 text-left"
              type="button"
              aria-expanded={picked === lane.agent}
              onclick={() => (picked = picked === lane.agent ? '' : lane.agent)}
            >
              <span class="mono w-[96px] min-w-0 shrink truncate text-sm" style="color:{color}">
                {lane.agent}
              </span>
              <span class="lane-meter" aria-hidden="true">
                <i style="width:{Math.min(100, lane.lines * 4)}%"></i>
              </span>
              <span class="num shrink-0 text-xs text-ash">{countLabel(lane.lines)}</span>
              {#if lane.lastCall}
                <span
                  class="mono hidden shrink-0 text-[11px] sm:block"
                  style="color:{lane.lastCallOk === false ? 'var(--nc-violet)' : 'var(--nc-ash)'}"
                >
                  {lane.lastCall}
                </span>
              {/if}
            </button>
            {#if lane.lastTs > 0}
              <span class="mono hidden shrink-0 text-[10px] text-slate md:block">{clock(lane.lastTs)}</span>
            {/if}
            <button
              class="shrink-0 text-[10px] tracking-[0.12em] text-acid opacity-70 transition-opacity hover:opacity-100"
              type="button"
              onclick={() => openSpotlight(lane.agent)}
            >
              WATCH &gt;
            </button>
          </div>
          {#if lane.lastText && picked === lane.agent}
            <p class="mono whitespace-pre-wrap border-t border-indigo-deep/70 px-4 py-2.5 text-xs leading-relaxed text-bone-dust">
              <span style="color:{color}">&gt;</span>
              {lane.lastText}
            </p>
          {/if}
        </div>
      {/each}
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
        {#if spotlightStage}
          <span class="chip text-ash">{spotlightStage}</span>
        {/if}
        <div class="ml-auto flex items-center gap-3">
          {#if spotlightLane}
            <span class="num text-xs text-ash">{countLabel(spotlightItems.length)}</span>
            {#if spotlightLane.lastCall}
              <span class="mono hidden text-[11px] text-ash sm:block">{spotlightLane.lastCall}</span>
            {/if}
          {/if}
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
        {#if spotlightItems.length === 0}
          <p class="mono text-xs text-slate">
            {running
              ? `waiting for ${spotlightAgent} to speak...`
              : `no activity recorded for ${spotlightAgent} on this run`}
          </p>
          {#if running}
            <p class="mono mt-2 text-[11px] text-slate opacity-70">
              crawls, calls and reasoning all land here the moment they happen.
            </p>
          {/if}
        {/if}
        {#each spotlightItems as item, i (item.seq)}
          {#if item.kind === 'model'}
            <p class="think-line mono text-[11px] text-ash opacity-80">&middot;&middot;&middot; {item.text}</p>
          {:else}
            <p class="think-line mono whitespace-pre-wrap">
              <span style="color:{color}">{item.kind === 'reasoning' ? '>' : '\u00b7'}</span>
              {item.text}
              {#if running && i === spotlightItems.length - 1}
                <span class="caret" aria-hidden="true"></span>
              {/if}
            </p>
          {/if}
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
