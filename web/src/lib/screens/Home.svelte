<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { ago, finishedThrough, sevColor, sevShape, stageForAgent, statusColor, statusLabel, triageLabel } from '../format';
  import { store } from '../state.svelte';
  import { STAGES } from '../../tokens';
  import { countup, pauseOffscreen, spotlight } from '../actions';
  import HeroArt from '../ui/HeroArt.svelte';
  import StageRail from '../ui/StageRail.svelte';
  import Chip from '../ui/Chip.svelte';

  let stage = $state<{ current: string; finished: string[] }>({ current: '', finished: [] });
  let recent = $state<Awaited<ReturnType<typeof api.findings>>['items']>([]);
  let tail = $state<{ seq: number; text: string; error: boolean }[]>([]);
  const stages = STAGES as unknown as { key: string }[];

  const totals = $derived(store.totals);
  const lastRun = $derived(totals?.last_run ?? null);
  const count = (key: string) => totals?.triage?.[key] ?? 0;
  const openFindings = $derived(count('new') + count('in_progress'));
  const confirmed = $derived(count('confirmed'));
  const escalated = $derived(count('escalated'));

  const triageTotal = $derived(
    Object.values(totals?.triage ?? {}).reduce((sum, n) => sum + n, 0)
  );
  const share = (n: number) => (triageTotal > 0 ? Math.min(1, n / triageTotal) : 0);
  const endpointsRead = $derived(
    (lastRun?.counts?.endpoints ?? 0) + (lastRun?.counts?.js_files ?? 0)
  );

  const hero = $derived.by(() => {
    if (store.runs.some((run) => run.status === 'running')) {
      const run = store.runs.find((r) => r.status === 'running')!;
      return {
        eyebrow: 'live',
        title: `Scanning ${run.target}`,
        body: 'The pipeline is working right now. Watch each stage as it happens.',
        action: 'watch live',
        go: () => store.watch(run.id),
        color: 'var(--nc-acid)'
      };
    }
    if (confirmed > 0 || escalated > 0) {
      const n = confirmed + escalated;
      return {
        eyebrow: 'attention',
        title: `${n} ${n === 1 ? 'finding is' : 'findings are'} marked confirmed`,
        body: 'You marked these as real during triage. Reopen them to escalate or reject, or start a new scan.',
        action: 'review findings',
        go: () => store.go('findings'),
        color: 'var(--nc-gold)'
      };
    }
    if (openFindings > 0) {
      return {
        eyebrow: 'to review',
        title: `${openFindings} ${openFindings === 1 ? 'candidate needs' : 'candidates need'} a look`,
        body: 'Nothing is confirmed yet. Open the candidates, read the evidence, then confirm or reject each one.',
        action: 'review findings',
        go: () => store.go('findings'),
        color: 'var(--nc-bone)'
      };
    }
    if ((totals?.runs ?? 0) === 0) {
      return {
        eyebrow: 'ready',
        title: 'Point it at a target',
        body: 'NetCast3r crawls a site, reads its JavaScript, hunts for credentials, and validates what it catches against the provider that issued it. Nothing is sent anywhere until you start.',
        action: 'start your first scan',
        go: () => store.go('new'),
        color: 'var(--nc-acid)'
      };
    }
    return {
      eyebrow: 'all clear',
      title: 'No open findings',
      body: 'Every scan so far came back with nothing to triage. Run another target, or widen the depth if the last pass was shallow.',
      action: 'start a scan',
      go: () => store.go('new'),
      color: 'var(--nc-bone)'
    };
  });

  const kpis = $derived([
    { label: 'confirmed', value: confirmed, note: 'validated access', color: sevColor('critical'), meter: share(confirmed) },
    { label: 'needs review', value: openFindings, note: 'candidates waiting', color: 'var(--nc-gold)', meter: share(openFindings) },
    {
      label: 'escalate-ready',
      value: escalated,
      note: 'highest proven impact',
      color: 'var(--nc-violet)',
      meter: share(escalated)
    },
    {
      label: 'coverage',
      value: totals?.findings ?? 0,
      note: `${endpointsRead} endpoints read`,
      color: 'var(--nc-bone)',
      meter: endpointsRead > 0 ? Math.min(1, (totals?.findings ?? 0) / endpointsRead) : 0
    }
  ]);

  const action = $derived.by(() => {
    if (store.runs.some((run) => run.status === 'running')) return null;
    if (confirmed + escalated > 0) return `triage ${confirmed + escalated} confirmed findings`;
    if (openFindings > 0) return `open ${openFindings} candidates`;
    if ((totals?.runs ?? 0) === 0) return 'run your first scan';
    return 'pick a new target';
  });

  onMount(() => {
    store.refreshTotals();
    store.refreshRuns();
    void (async () => {
      try {
        recent = (await api.findings('?size=5')).items;
        const run = store.totals?.last_run;
        if (!run) return;
        const events = await api.runEvents(run.id);
        if (['done', 'failed', 'stopped'].includes(run.status)) {
          stage = { current: '', finished: stages.map((s) => s.key) };
        } else {
          let current = '';
          for (const event of events.items) {
            const key = stageForAgent(event.agent) || event.stage;
            if (key) current = key;
          }
          stage = { current, finished: finishedThrough(current) };
        }
        tail = events.items
          .filter(
            (event) =>
              (event.type === 'log' || event.type === 'error') &&
              (event.payload?.text || event.payload?.error)
          )
          .slice(-4)
          .map((event) => ({
            seq: event.seq,
            text: String(event.payload?.text ?? event.payload?.error ?? ''),
            error: event.type === 'error'
          }));
      } catch {
        /* the home cards simply stay empty when a fetch fails */
      }
    })();
  });
</script>

<div class="stagger mx-auto flex max-w-[1180px] flex-col gap-6">
  <!-- Hero -->
  <section
    class="caster-vignette panel-raised panel-hud relative min-h-[340px] overflow-hidden p-6 sm:min-h-[360px] sm:p-8"
    use:pauseOffscreen
  >
    <HeroArt
      class="caster-layer pointer-events-none absolute inset-0 h-full w-full opacity-50 sm:opacity-95"
      live={store.runs.some((run) => run.status === 'running')}
    />
    <div class="relative z-[2] max-w-[520px]">
      <p class="eyebrow" style="color:{hero.color}">{hero.eyebrow}</p>
      <h1 class="mt-2 text-2xl font-semibold leading-tight text-bone sm:text-[31px]">
        {hero.title}
      </h1>
      <p class="mt-3 text-sm leading-relaxed text-bone-dust sm:text-base">{hero.body}</p>
      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button class="btn btn-acid" type="button" onclick={hero.go}>{hero.action}</button>
        {#if action}
          <span class="mono text-xs text-ash">next: {action}</span>
        {/if}
      </div>
    </div>
  </section>

  <!-- KPIs -->
  <section class="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="summary">
    {#each kpis as kpi, i (kpi.label)}
      <div class="panel kpi flex flex-col gap-1 p-4" use:spotlight>
        <p class="eyebrow">{kpi.label}</p>
        <p class="num relative z-[1] text-[31px] leading-none" style="color:{kpi.color}" use:countup={kpi.value}>0</p>
        <p class="relative z-[1] text-xs text-bone-dust">{kpi.note}</p>
        <span class="meter relative z-[1] mt-1" style="--m:{kpi.meter};--m-color:{kpi.color}" aria-hidden="true"
          ><i style="animation-delay:{i * 90}ms"></i
        ></span>
      </div>
    {/each}
  </section>

  <!-- Last run -->
  {#if lastRun}
    <section class="panel panel-hud p-5" use:pauseOffscreen>
      <div class="mb-4 flex flex-wrap items-center gap-3">
        <p class="eyebrow">last run</p>
        <button
          class="mono text-sm text-bone underline decoration-indigo underline-offset-4 transition-colors hover:text-acid"
          type="button"
          onclick={() => store.watch(lastRun.id)}
        >
          {lastRun.target}
        </button>
        <span class="chip" style="color:{statusColor(lastRun.status)}">
          <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
            <circle cx="4" cy="4" r="3.4" />
          </svg>
          {statusLabel(lastRun.status)}
        </span>
        <span class="mono ml-auto text-xs text-ash">{ago(lastRun.created_at)}</span>
      </div>
      <StageRail current={stage.current} finished={stage.finished} />
      <div class="mt-4 grid grid-cols-2 gap-3 border-t border-indigo-deep pt-4 sm:grid-cols-4">
        {#each [['pages', lastRun.counts?.pages], ['js files', lastRun.counts?.js_files], ['endpoints', lastRun.counts?.endpoints], ['candidates', lastRun.counts?.candidates]] as [label, value] (label)}
          <div>
            <p class="eyebrow">{label}</p>
            <p class="num mt-1 text-lg text-bone">{value ?? 0}</p>
          </div>
        {/each}
      </div>
      {#if tail.length > 0}
        <div
          class="mono mt-4 max-h-[124px] overflow-hidden rounded-lg border border-indigo-deep bg-void px-3 py-2 text-xs leading-relaxed"
          aria-label="last lines from the run"
        >
          <div class="flex items-center gap-2 pb-1">
            <p class="eyebrow">stream</p>
            {#if lastRun.status === 'running'}
              <span class="chip ml-auto" style="color:var(--nc-acid)">
                <span class="pulse-live h-[7px] w-[7px] rounded-full bg-acid" aria-hidden="true"></span>
                live
              </span>
            {/if}
          </div>
          {#each tail as line (line.seq)}
            <p class="stream-line truncate" class:text-violet={line.error} class:text-bone-dust={!line.error}>
              <span class="text-acid" aria-hidden="true">&gt;</span>
              {line.text}
            </p>
          {/each}
          {#if lastRun.status === 'running'}
            <p class="text-bone-dust" aria-hidden="true">
              <span class="text-acid">&gt;</span>
              <span class="term-cursor ml-1 inline-block h-[10px] w-[6px] bg-acid align-[-1px]"></span>
            </p>
          {/if}
        </div>
      {/if}
    </section>
  {/if}

  <!-- Recent findings + runs -->
  <section class="grid gap-4 lg:grid-cols-2">
    <div class="panel panel-hover overflow-hidden">
      <div class="flex items-center justify-between border-b border-indigo-deep px-5 py-3">
        <p class="eyebrow">recent findings</p>
        <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => store.go('findings')}>
          view all
        </button>
      </div>
      {#if recent.length === 0}
        <p class="px-5 py-6 text-sm text-bone-dust">
          Nothing caught yet. Findings appear here the moment a run validates one.
        </p>
      {:else}
        <ul>
          {#each recent as finding (finding.id)}
            {@const sev = finding.severity_override || finding.severity}
            <li
              class="row-link flex items-center gap-3 border-b border-indigo-deep/60 px-5 py-3 last:border-0"
              style="--row-accent:{sevColor(sev)}"
            >
              <Chip label={sev} color={sevColor(sev)} shape={sevShape(sev)} />
              <span class="min-w-0 flex-1 truncate text-sm text-bone">{finding.title}</span>
              <span
                class="meter conf hidden sm:block"
                style="--m:{Math.min(1, finding.confidence ?? 0)};--m-color:{sevColor(sev)}"
                aria-hidden="true"><i></i
              ></span>
              <span class="num hidden shrink-0 text-xs text-ash sm:inline"
                >{Math.round((finding.confidence ?? 0) * 100)}%</span
              >
              <span class="mono hidden shrink-0 text-xs text-ash md:inline"
                >{triageLabel(finding.triage_status)}</span
              >
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    <div class="panel panel-hover overflow-hidden">
      <div class="flex items-center justify-between border-b border-indigo-deep px-5 py-3">
        <p class="eyebrow">recent runs</p>
        <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => store.go('runs')}>
          history
        </button>
      </div>
      {#if store.runs.length === 0}
        <p class="px-5 py-6 text-sm text-bone-dust">No scans yet.</p>
      {:else}
        <ul>
          {#each store.runs.slice(0, 5) as run (run.id)}
            <li>
              <button
                class="row-link flex w-full items-center gap-3 border-b border-indigo-deep/60 px-5 py-3 text-left last:border-0"
                type="button"
                onclick={() => store.watch(run.id)}
              >
                <span
                  class="h-2 w-2 shrink-0 rounded-full"
                  style="background:{statusColor(run.status)}"
                  aria-hidden="true"
                ></span>
                <span class="min-w-0 flex-1 truncate text-sm text-bone">{run.target}</span>
                <span
                  class="num shrink-0 text-xs"
                  style="color:{(run.counts?.findings ?? 0) > 0 ? 'var(--nc-acid)' : 'var(--nc-ash)'}"
                  >{run.counts?.findings ?? 0} fnd</span
                >
                <span class="mono shrink-0 text-xs text-ash">{ago(run.created_at)}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </section>
</div>
