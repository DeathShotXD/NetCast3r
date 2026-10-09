<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { AGENT_COLORS, AGENT_STAGE, STAGES } from '../../tokens';
  import { clock, stageForAgent } from '../format';
  import { store } from '../state.svelte';
  import type { Run, RunEvent } from '../types';
  import { countup } from '../actions';

  const stages = STAGES as unknown as { key: string; label: string }[];

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

  let run = $state<Run | null>(null);
  let lanes = $state<Record<string, Lane>>({});
  let totalLines = $state(0);
  let pulses = $state<Record<string, number>>({});
  let picked = $state('');

  const LANE_AGENTS = ['recon', 'exegete', 'prospector', 'classifier', 'assayer', 'chainer', 'scribe'];
  const CAP = 200;

  const running = $derived(!!run && (run.status === 'running' || run.status === 'queued'));
  const laneList = $derived(
    LANE_AGENTS.map((agent) => lanes[agent] ?? fresh(agent)).filter((lane) => lane.lines > 0)
  );
  const stageNow = $derived.by(() => {
    let current = '';
    for (const lane of laneList) {
      const key = stageForAgent(lane.agent);
      if (key) current = key;
    }
    return current;
  });

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

  function push(event: RunEvent) {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    queue.push(event);
    if (!scheduled) {
      scheduled = true;
      requestAnimationFrame(() => void flush());
      window.setTimeout(() => void flush(), 400);
    }
  }

  async function flush() {
    scheduled = false;
    const batch = queue;
    queue = [];
    if (batch.length === 0) return;
    const next = { ...lanes };
    for (const event of batch) {
      const agent = event.agent || (event.type === 'log' ? 'run' : '');
      if (agent && LANE_AGENTS.includes(agent)) {
        const lane = next[agent] ?? fresh(agent);
        lane.lines += 1;
        if (event.type === 'log' || event.type === 'error') {
          lane.lastText = String(event.payload?.text ?? event.payload?.error ?? '');
          lane.lastTs = event.ts;
        }
        pulses = { ...pulses, [agent]: (pulses[agent] ?? 0) + 1 };
        next[agent] = { ...lane };
      }
      if (event.type === 'model' && event.agent && event.payload?.kind === 'done') {
        const lane = next[event.agent] ?? fresh(event.agent);
        lane.calls += 1;
        lane.lastCall = String(event.payload.model ?? '');
        lane.lastCallOk = !!event.payload.ok;
        next[event.agent] = { ...lane };
      }
      totalLines += 1;
    }
    lanes = next;
  }

  async function load() {
    if (!store.activeRunId) return;
    run = await api.run(store.activeRunId);
    lanes = {};
    totalLines = 0;
    seen.clear();
    if (!run) return;
    const page = await api.runEvents(run.id);
    for (const item of page.items.slice(-CAP)) {
      seen.add(item.id);
      apply(item);
    }
  }

  function apply(event: RunEvent) {
    const agent = event.agent || '';
    if (agent && LANE_AGENTS.includes(agent)) {
      const lane = lanes[agent] ?? fresh(agent);
      const updated = { ...lane, lines: lane.lines + 1 };
      if (event.type === 'log' || event.type === 'error') {
        updated.lastText = String(event.payload?.text ?? event.payload?.error ?? '');
        updated.lastTs = event.ts;
      }
      lanes = { ...lanes, [agent]: updated };
      totalLines += 1;
    }
  }

  let source: EventSource | undefined;

  function connect() {
    if (!store.activeRunId || !running) return;
    source = new EventSource(api.eventsUrl(store.activeRunId));
    source.onmessage = (message) => {
      try {
        push(JSON.parse(message.data) as RunEvent);
      } catch {
        /* ignore a malformed frame */
      }
    };
  }

  function pickDefault(): void {
    if (store.activeRunId) return;
    const running = store.runs.find((item) => item.status === 'running');
    const latest = store.runs[0];
    const pick = running ?? latest;
    if (pick) store.activeRunId = pick.id;
  }

  onMount(async () => {
    if (store.runs.length === 0) await store.refreshRuns();
    pickDefault();
    await load();
    connect();
  });

  onDestroy(() => {
    source?.close();
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
    </section>
  </div>
{:else}
  <div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
    <section class="panel panel-hud flex flex-wrap items-center gap-3 p-5">
      <div class="min-w-0">
        <p class="eyebrow">engine room // run {run.id.slice(-6)}</p>
        <h1 class="truncate font-mono text-lg text-bone">{run.target}</h1>
      </div>
      <span class="num ml-auto text-sm text-ash">{totalLines} events</span>
    </section>

    <section class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {#each stages as stage (stage.key)}
        {@const lane = laneList.find((l) => l.currentStage === stage.key)}
        {@const live = stageNow === stage.key}
        <div
          class="panel kpi px-4 py-3"
          class:border-acid={live}
          style={live ? 'box-shadow:0 0 22px -6px rgba(200,248,26,0.35)' : ''}
        >
          <p class="eyebrow">{stage.label}</p>
          <p class="num mt-1 text-xl" style="color:{live ? 'var(--nc-acid)' : 'var(--nc-bone-dust)'}">
            {lane ? lane.lines : 0}
          </p>
        </div>
      {/each}
    </section>

    <section class="flex flex-col gap-2.5">
      {#each laneList as lane (lane.agent)}
        {@const color = (AGENT_COLORS as Record<string, string>)[lane.agent] ?? 'var(--nc-bone-dust)'}
        {@const hot = pulses[lane.agent] ?? 0}
        <button
          class="lane panel w-full p-0 text-left"
          class:lane-hot={hot > 0}
          type="button"
          style="--agent:{color}"
          onclick={() => (picked = picked === lane.agent ? '' : lane.agent)}
        >
          <div class="flex items-center gap-3 px-4 py-2.5">
            <span class="lane-led" aria-hidden="true"></span>
            <span class="mono w-[104px] shrink-0 text-sm" style="color:{color}">{lane.agent}</span>
            <span class="lane-meter" aria-hidden="true"><i style="width:{Math.min(100, lane.lines * 4)}%"></i></span>
            <span class="num shrink-0 text-xs text-ash">{lane.lines} lines</span>
            {#if lane.lastCall}
              <span
                class="mono hidden shrink-0 text-[11px] sm:block"
                style="color:{lane.lastCallOk === false ? 'var(--nc-violet)' : 'var(--nc-ash)'}"
              >
                {lane.lastCall}
              </span>
            {/if}
            <span class="mono ml-auto hidden shrink-0 text-xs text-slate md:block">{clock(lane.lastTs)}</span>
          </div>
          {#if lane.lastText && picked === lane.agent}
            <p class="mono border-t border-indigo-deep/70 px-4 py-2.5 text-xs leading-relaxed text-bone-dust">
              <span style="color:{color}">&gt;</span>
              {lane.lastText}
            </p>
          {/if}
        </button>
      {/each}
    </section>
  </div>
{/if}
