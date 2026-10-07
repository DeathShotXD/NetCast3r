<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import { api } from '../api';
  import { AGENT_COLORS, STAGES } from '../../tokens';
  import { clock, finishedThrough, isoMs, sevColor, sevShape, stageForAgent, statusColor, statusLabel } from '../format';
  import { store } from '../state.svelte';
  import type { Run, RunEvent } from '../types';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import StageRail from '../ui/StageRail.svelte';

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

  const seen = new Set<number>();

  function push(event: RunEvent) {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    events = [...events, event].slice(-600);
    if (event.progress) counts = { ...counts, ...event.progress };
    if (event.type === 'finding.created' && event.payload) {
      landed = [
        { status: event.payload.status, secret_type: event.payload.secret_type, value: event.payload.value, detail: event.payload.detail },
        ...landed
      ];
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
  });

  onDestroy(() => {
    stop();
    if (timer) window.clearInterval(timer);
    if (poller) window.clearInterval(poller);
  });
</script>

{#if !store.activeRunId}
  <div class="fade-rise mx-auto max-w-[720px]">
    <div class="panel p-8 text-center">
      <p class="eyebrow">live runs</p>
      <h1 class="mt-2 text-xl text-bone">No run selected</h1>
      <p class="mx-auto mt-3 max-w-[46ch] text-sm leading-relaxed text-bone-dust">
        Start a scan and it appears here with a live stage rail, running counters, and every line
        the agents print as they work.
      </p>
      <button class="btn btn-acid mt-6" type="button" onclick={() => store.go('new')}>
        start a scan
      </button>
      {#if store.runs.length > 0}
        <div class="mx-auto mt-8 max-w-[420px] border-t border-indigo-deep pt-4 text-left">
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
    </div>
  </div>
{:else if run}
  <div class="fade-rise mx-auto flex max-w-[1180px] flex-col gap-5">
    <section class="panel p-5" class:finish-glow={finished}>
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
        <div class="panel px-4 py-3">
          <p class="eyebrow">{label}</p>
          <p class="num mt-1 text-xl text-bone">{counts[key] ?? 0}</p>
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
