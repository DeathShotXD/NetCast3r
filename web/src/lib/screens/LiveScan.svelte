<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import { api } from '../api';
  import { AGENT_COLORS, STAGES } from '../../tokens';
  import { clock, finishedThrough, isoMs, sevColor, sevShape, stageForAgent, statusColor, statusLabel } from '../format';
  import { store } from '../state.svelte';
  import type { Run, RunEvent } from '../types';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import StageRail from '../ui/StageRail.svelte';
  import { countup } from '../actions';

  const stages = STAGES as unknown as { key: string; label: string }[];
  const TERMINAL = ['done', 'failed', 'stopped', 'interrupted'];

  let run = $state<Run | null>(null);
  let events = $state<RunEvent[]>([]);
  let counts = $state<Record<string, number>>({});
  let landed = $state<{ status: string; secret_type: string; value: string; detail: string }[]>([]);
  let currentStage = $state('');
  let elapsed = $state(0);
  let follow = $state(true);
  let stopOpen = $state(false);
  let stop = $state<() => void>(() => {});
  let logBox: HTMLDivElement | undefined = $state();
  let thinkBox: HTMLDivElement | undefined = $state();
  let thinkFollow = $state(true);
  let thinking = $state<{ seq: number; ts: number; agent: string; text: string }[]>([]);
  let calls = $state<{
    seq: number; ts: number; agent: string; provider: string; model: string;
    pending: boolean; ok: boolean; ms: number; error: string;
  }[]>([]);

  const lines = $derived(
    events
      .filter((event) => event.type === 'log' || event.type === 'error')
      .map((event) => ({
        seq: event.seq,
        ts: event.ts,
        agent: event.agent || 'run',
        text: String(event.payload?.text ?? event.payload?.error ?? ''),
        bad: event.type === 'error'
      }))
  );
  const finished = $derived(!!run && TERMINAL.includes(run.status));
  const running = $derived(!!run && (run.status === 'running' || run.status === 'queued'));
  const pendingCalls = $derived(calls.filter((row) => row.pending).length);
  const usedEndpoints = $derived(new Set(calls.map((row) => row.provider)).size);

  const seen = new Set<number>();

  function push(event: RunEvent) {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    events = [...events, event].slice(-1500);
    if (event.progress) counts = { ...counts, ...event.progress };
    if (event.type === 'finding.created' && event.payload) {
      landed = [
        { status: event.payload.status, secret_type: event.payload.secret_type, value: event.payload.value, detail: event.payload.detail },
        ...landed
      ];
    }
    if (event.type === 'reasoning' && event.payload?.text) {
      thinking = [
        ...thinking,
        { seq: event.seq, ts: event.ts, agent: event.agent || 'model', text: String(event.payload.text) }
      ].slice(-400);
      if (thinkFollow) void scrollThinking();
    }
    if (event.type === 'model' && event.payload) {
      const payload = event.payload;
      const provider = String(payload.provider ?? '?');
      const model = String(payload.model ?? '?');
      const agent = event.agent || '';
      if (payload.kind === 'call') {
        calls = [
          { seq: event.seq, ts: event.ts, agent, provider, model, pending: true, ok: false, ms: 0, error: '' },
          ...calls
        ].slice(0, 80);
      } else if (payload.kind === 'done') {
        let updated = false;
        calls = calls.map((row) => {
          if (!updated && row.pending && row.provider === provider && row.model === model && row.agent === agent) {
            updated = true;
            return {
              ...row, pending: false, ok: !!payload.ok,
              ms: Number(payload.ms ?? 0), error: String(payload.error ?? '')
            };
          }
          return row;
        });
      }
    }
    const agentStage = stageForAgent(event.agent);
    if (agentStage) currentStage = agentStage;
    if (event.stage) currentStage = event.stage;
    if (event.type === 'run.state' && event.payload?.status && !TERMINAL.includes(run?.status ?? '')) {
      run = run ? { ...run, status: event.payload.status } : run;
    }
    if (follow) void scrollToLatest();
  }

  async function scrollToLatest() {
    await tick();
    if (logBox) logBox.scrollTop = logBox.scrollHeight;
  }

  async function scrollThinking() {
    await tick();
    if (thinkBox) thinkBox.scrollTop = thinkBox.scrollHeight;
  }

  function onThinkScroll() {
    if (!thinkBox) return;
    thinkFollow = thinkBox.scrollTop + thinkBox.clientHeight >= thinkBox.scrollHeight - 32;
  }

  function onLogScroll() {
    if (!logBox) return;
    follow = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 32;
  }

  async function load() {
    if (!store.activeRunId) return;
    run = await api.run(store.activeRunId);
    events = [];
    seen.clear();
    landed = [];
    thinking = [];
    calls = [];
    counts = run?.counts ?? {};
    currentStage = '';
    if (run) {
      const page = await api.runEvents(run.id);
      for (const event of page.items) push(event);
      counts = { ...counts, ...(run.counts ?? {}) };
      if (finished) currentStage = '';
    }
    await scrollToLatest();
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
    const fresh = await api.run(store.activeRunId);
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

  function elapsedText(): string {
    if (!run) return '00:00';
    const start = isoMs(run.started_at || run.created_at);
    const end = run.finished_at ? isoMs(run.finished_at) : Date.now();
    if (!Number.isFinite(start) || !Number.isFinite(end)) return '00:00';
    const seconds = Math.max(0, Math.floor((end - start) / 1000));
    const mm = String(Math.floor(seconds / 60)).padStart(2, '0');
    const ss = String(seconds % 60).padStart(2, '0');
    return `${mm}:${ss}`;
  }

  let timer: number | undefined;
  let poller: number | undefined;

  $effect(() => {
    if (finished) {
      currentStage = '';
      stop();
    }
  });

  onMount(async () => {
    await load();
    if (!finished) connect();
    timer = window.setInterval(() => {
      if (running) elapsed += 1;
    }, 1000);
    poller = window.setInterval(() => void poll(), 2000);
    void scrollToLatest();
    void scrollThinking();
  });

  onDestroy(() => {
    stop();
    if (timer) window.clearInterval(timer);
    if (poller) window.clearInterval(poller);
  });
</script>

{#if !store.activeRunId}
  <div class="fade-rise mx-auto max-w-[720px]">
    <div class="panel overflow-hidden">
      <EmptyState
        eyebrow="live runs"
        title="No run selected"
        body="Start a scan and it appears here with a live stage rail, running counters, and every line the agents print as they work."
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
  <div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
    <section class="panel panel-hud p-5" class:finish-glow={finished}>
      <div class="flex flex-wrap items-center gap-3">
        <div class="min-w-0">
          <p class="eyebrow">run {run.id.slice(-6)}</p>
          <h1 class="truncate font-mono text-lg text-bone">{run.target}</h1>
        </div>
        <span class="chip" style="color:{statusColor(run.status)}">
          <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
            <circle cx="4" cy="4" r="3.4" />
          </svg>
          {statusLabel(run.status)}
        </span>
        <span class="num text-sm text-ash">{elapsedText()}</span>
        <div class="ml-auto flex gap-2">
          {#if running}
            <button class="btn btn-danger" type="button" onclick={requestStop}>stop scan</button>
          {:else}
            <button class="btn" type="button" onclick={rerun}>rerun</button>
          {/if}
          <button class="btn btn-quiet" type="button" onclick={() => store.go('home')}>close</button>
        </div>
      </div>
      <div class="mt-4">
        <StageRail current={currentStage} finished={finished ? stages.map((s) => s.key) : finishedThrough(currentStage)} />
      </div>
    </section>

    <section class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6" aria-label="counters">
      {#each [['pages', 'pages'], ['js files', 'js_files'], ['endpoints', 'endpoints'], ['candidates', 'candidates'], ['verified', 'verified'], ['findings', 'findings']] as [label, key] (key)}
        <div class="panel kpi px-4 py-3">
          <p class="eyebrow">{label}</p>
          <p class="num mt-1 text-xl text-bone" use:countup={counts[key] ?? 0}>0</p>
        </div>
      {/each}
    </section>

    <section class="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
      <div class="panel flex min-h-[420px] flex-col overflow-hidden">
        <div class="flex items-center justify-between border-b border-indigo-deep px-4 py-2.5">
          <p class="eyebrow">agent log</p>
          <button
            class="btn btn-quiet px-2! py-1! text-xs"
            type="button"
            onclick={() => {
              follow = true;
              void scrollToLatest();
            }}
          >
            {follow ? 'following' : 'jump to latest'}
          </button>
        </div>
        <div
          class="mono flex-1 overflow-y-auto px-4 py-3 text-[13px] leading-relaxed"
          data-log="1"
          bind:this={logBox}
          onscroll={onLogScroll}
        >
          {#if lines.length === 0}
            <p class="text-slate">waiting for the first line...</p>
          {/if}
          {#each lines as line (line.seq)}
            <p class="fade-rise flex gap-2" class:text-violet={line.bad}>
              <span class="shrink-0 text-slate">{clock(line.ts)}</span>
              <span class="w-[92px] shrink-0 truncate" style="color:{(AGENT_COLORS as Record<string, string>)[line.agent] ?? 'var(--nc-bone-dust)'}">
                {line.agent}
              </span>
              <span class="min-w-0 break-words" class:text-bone={!line.bad}>{line.text}</span>
            </p>
          {/each}
        </div>
      </div>

      <div class="flex flex-col gap-5">
        <div class="panel overflow-hidden">
          <div class="flex items-center justify-between border-b border-indigo-deep px-4 py-2.5">
            <p class="eyebrow">credentials caught</p>
            <span class="num text-xs text-ash">{landed.length}</span>
          </div>
          {#if landed.length === 0}
            <p class="px-4 py-5 text-sm text-bone-dust">
              {finished
                ? 'Nothing was caught on this pass.'
                : 'Candidates land here the moment one is validated.'}
            </p>
          {:else}
            <ul class="max-h-[300px] overflow-y-auto">
              {#each landed as item, i (i)}
                <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-2.5 last:border-0">
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

        <div class="panel p-4">
          <p class="eyebrow">what happens next</p>
          <ol class="mt-2 flex flex-col gap-2">
            {#each stages as stage, i (stage.key)}
              <li class="flex items-center gap-3 text-sm">
                <span class="num w-6 text-xs text-slate">{String(i + 1).padStart(2, '0')}</span>
                <span class="mono {currentStage === stage.key ? 'text-acid' : 'text-bone-dust'}">
                  {stage.label}
                </span>
                {#if currentStage === stage.key}
                  <span class="pulse-live ml-auto h-1.5 w-1.5 rounded-full bg-acid"></span>
                {/if}
              </li>
            {/each}
          </ol>
          <p class="mt-3 border-t border-indigo-deep pt-3 text-xs leading-relaxed text-ash">
            Every report file lands in your own results folder when the run finishes.
          </p>
        </div>
      </div>
    </section>

    <section class="panel overflow-hidden" data-thinking="1">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-indigo-deep px-4 py-2.5">
        <div class="flex items-center gap-3">
          <p class="eyebrow">model activity</p>
          {#if pendingCalls > 0}
            <span class="chip text-acid">
              <span class="pulse-live h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
              working
            </span>
          {/if}
        </div>
        <span class="mono text-xs text-ash">
          {calls.length} calls / {usedEndpoints} endpoints / {thinking.length} reasoning lines
        </span>
      </div>
      <div class="grid md:grid-cols-2">
        <div class="border-b border-indigo-deep md:border-b-0 md:border-r">
          <div class="flex items-center justify-between px-4 py-2">
            <p class="eyebrow">reasoning stream</p>
            <button
              class="btn btn-quiet px-2! py-1! text-xs"
              type="button"
              onclick={() => {
                thinkFollow = true;
                void scrollThinking();
              }}
            >
              {thinkFollow ? 'following' : 'jump to latest'}
            </button>
          </div>
          <div
            class="mono h-[300px] overflow-y-auto px-4 pb-3 text-xs leading-relaxed"
            data-reasoning="1"
            bind:this={thinkBox}
            onscroll={onThinkScroll}
          >
            {#if thinking.length === 0}
              <p class="text-slate">
                {finished
                  ? 'No model reasoning on this run.'
                  : 'Waiting for the first reasoning line...'}
              </p>
            {/if}
            {#each thinking as line (line.seq)}
              <p class="fade-rise flex gap-2">
                <span class="shrink-0 text-slate">{clock(line.ts)}</span>
                <span
                  class="w-[92px] shrink-0 truncate"
                  style="color:{(AGENT_COLORS as Record<string, string>)[line.agent] ?? 'var(--nc-bone-dust)'}"
                >
                  {line.agent}
                </span>
                <span class="min-w-0 break-words text-bone-dust">{line.text}</span>
              </p>
            {/each}
          </div>
        </div>
        <div>
          <div class="flex items-center justify-between px-4 py-2">
            <p class="eyebrow">call timeline</p>
            <span class="mono text-[11px] text-ash">{calls.length} total</span>
          </div>
          <ul class="h-[300px] overflow-y-auto" data-calls="1">
            {#if calls.length === 0}
              <li class="px-4 py-2 text-xs text-slate">
                {finished
                  ? 'No model calls on this run.'
                  : 'Calls appear here the moment an agent asks the model something.'}
              </li>
            {/if}
            {#each calls as row (row.seq)}
              <li class="flex items-center gap-3 border-b border-indigo-deep/60 px-4 py-2 last:border-0">
                <span
                  class="h-2 w-2 shrink-0 rounded-full"
                  class:bg-acid={!row.pending && row.ok}
                  class:bg-violet={!row.pending && !row.ok}
                  class:bg-slate={row.pending}
                  aria-hidden="true"
                ></span>
                <span class="mono min-w-0 flex-1 truncate text-xs text-bone">
                  {row.provider}<span class="text-slate">/{row.model}</span>
                </span>
                <span
                  class="mono hidden shrink-0 text-[11px] sm:block"
                  style="color:{(AGENT_COLORS as Record<string, string>)[row.agent] ?? 'var(--nc-ash)'}"
                >
                  {row.agent}
                </span>
                <span class="mono num shrink-0 text-[11px] text-ash">
                  {row.pending ? '...' : `${row.ms} ms`}
                </span>
                {#if row.error}
                  <span class="mono max-w-[140px] shrink-0 truncate text-[11px] text-violet" title={row.error}>
                    {row.error}
                  </span>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      </div>
    </section>
  </div>
{/if}

{#if stopOpen && run}
  <Confirm
    title="Stop the scan of {run.target}?"
    body="The run stops at the next safe point and keeps everything it found so far. Partial results are written to disk. This cannot be undone, but you can rerun the target later."
    confirmLabel="stop this scan"
    danger
    onConfirm={confirmStop}
    onCancel={() => (stopOpen = false)}
  />
{/if}
