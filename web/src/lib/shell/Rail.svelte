<script lang="ts">
  import { store } from '../state.svelte';
  import type { Screen } from '../types';
  import { countup } from '../actions';
  import Mark from '../ui/Mark.svelte';
  import NetScope from '../ui/NetScope.svelte';

  let {
    open = false,
    onNavigate = () => {}
  }: { open?: boolean; onNavigate?: () => void } = $props();

  const items: { id: Screen; label: string; glyph: string; hint: string }[] = [
    { id: 'home', label: 'Home', glyph: '#', hint: 'what we found, what to do' },
    { id: 'new', label: 'New scan', glyph: '>', hint: 'point the tool at a target' },
    { id: 'live', label: 'Live runs', glyph: '[*]', hint: 'watch a scan as it works' },
    { id: 'engine', label: 'Engine', glyph: '{i}', hint: 'the agents, thinking live' },
    { id: 'findings', label: 'Findings', glyph: '*', hint: 'triage what came back' },
    { id: 'runs', label: 'Runs', glyph: '//', hint: 'history, rerun, delete' },
    { id: 'keys', label: 'Providers', glyph: '^', hint: 'paste a key, test a provider' },
    { id: 'help', label: 'Help', glyph: '?', hint: 'what every state means' }
  ];

  const isActive = (id: Screen) =>
    id === store.screen || (id === 'live' && store.screen === 'live');

  const running = $derived(
    store.runs.find((run) => run.status === 'running') ?? store.liveRun ?? null
  );

  const openCount = $derived(
    (store.totals?.triage?.new ?? 0) + (store.totals?.triage?.in_progress ?? 0)
  );
  const findingCount = $derived(store.totals?.findings ?? 0);

  function go(id: Screen) {
    store.go(id);
    onNavigate();
  }

  let prevFindings = $state<number | null>(null);
  let pop = $state(false);
  $effect(() => {
    if (prevFindings === null) {
      prevFindings = findingCount;
      return;
    }
    if (findingCount !== prevFindings) {
      prevFindings = findingCount;
      pop = false;
      requestAnimationFrame(() => (pop = true));
      window.setTimeout(() => (pop = false), 500);
    }
  });
</script>

{#if open}
  <button
    class="fixed inset-0 z-30 bg-black/60 lg:hidden"
    aria-label="close navigation"
    onclick={onNavigate}
  ></button>
{/if}

<aside
  class="fixed inset-y-0 left-0 z-40 flex w-[248px] flex-col border-r border-indigo-deep bg-void-soft px-3 py-4 transition-transform duration-300 lg:translate-x-0 {open
    ? 'translate-x-0'
    : '-translate-x-full'}"
>
  <div class="flex items-center gap-3 px-2">
    <Mark class="h-9 w-9 shrink-0" live={!!running} />
    <div class="leading-tight">
      <p class="font-mono text-sm tracking-[0.2em] text-bone">NETCAST3R</p>
      <p class="eyebrow tracking-[0.24em]!">dashboard</p>
    </div>
  </div>

  <nav class="mt-6 flex flex-col gap-1" aria-label="main">
    {#each items as item (item.id)}
      <button
        type="button"
        class="nav-item"
        class:active={isActive(item.id)}
        onclick={() => go(item.id)}
        aria-current={isActive(item.id) ? 'page' : undefined}
        title={item.hint}
      >
        <span class="nav-glyph" aria-hidden="true">{item.glyph}</span>
        <span>{item.label}</span>
        {#if item.id === 'findings' && findingCount > 0}
          <span class="nav-badge" class:hot={openCount > 0} class:badge-pop={pop} title="{findingCount} findings"
            >{findingCount}</span
          >
        {/if}
        {#if item.id === 'live' && store.runs.some((run) => run.status === 'running')}
          <span class="pulse-live ml-auto h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
        {/if}
      </button>
    {/each}
  </nav>

  <!-- status module: the rail's midsection earns its keep -->
  <div class="mt-auto hidden min-h-0 flex-1 flex-col gap-3 pt-4 [@media(min-height:680px)]:flex">
    <div class="panel panel-hud relative min-h-[200px] flex-1 overflow-hidden p-3">
      <div class="relative z-[1] flex h-full flex-col gap-2">
        <div class="flex items-center justify-between gap-2">
          <p class="eyebrow">net status</p>
          {#if running}
            <span class="chip" style="color:var(--nc-acid)">
              <span class="pulse-live h-[7px] w-[7px] rounded-full bg-acid" aria-hidden="true"></span>
              {running.status === 'queued' ? 'queued' : 'casting'}
            </span>
          {:else}
            <span class="chip" style="color:var(--nc-ash)">standby</span>
          {/if}
        </div>
        {#if running}
          <p class="mono truncate text-xs text-acid">{running.target}</p>
        {/if}

        <!-- scope: the instrument well -->
        <div
          class="scope-well relative min-h-[92px] flex-1 overflow-hidden rounded-md border bg-void transition-colors duration-300"
          class:border-acid={!!running}
          class:border-indigo-deep={!running}
          aria-hidden="true"
        >
          <NetScope class="absolute inset-0 h-full w-full" active={!!running} />
          <div class="pointer-events-none absolute inset-x-0 bottom-1.5 text-center">
            {#if running}
              <span class="mono text-[10px] tracking-[0.08em] text-acid">casting // mesh live</span>
            {:else}
              <span class="mono text-[10px] tracking-[0.08em] text-slate">idle // no scan running</span>
              <span class="term-cursor ml-1 inline-block h-[9px] w-[5px] bg-acid align-[-1px]" aria-hidden="true"
              ></span>
            {/if}
          </div>
        </div>

        <div class="grid grid-cols-2 gap-2 border-t border-indigo-deep pt-2.5">
          <div>
            <p class="eyebrow">runs</p>
            <p class="num mt-0.5 text-sm text-bone" use:countup={store.totals?.runs ?? 0}>0</p>
          </div>
          <div class="border-l border-indigo-deep pl-2">
            <p class="eyebrow">findings</p>
            <p class="num mt-0.5 text-sm text-acid" use:countup={store.totals?.findings ?? 0}>0</p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="mt-auto space-y-3 px-2 pt-4 [@media(min-height:680px)]:mt-0">
    <button class="btn btn-acid w-full" type="button" onclick={() => go('new')}>
      cast a net
    </button>
    <p class="border-t border-indigo-deep pt-3 text-[11px] leading-relaxed text-ash">
      Authorized testing only. Point this at systems you are allowed to test.
    </p>
    <p class="mono text-[11px] text-slate">v{store.meta?.version ?? '0.0.0'}</p>
  </div>
</aside>
