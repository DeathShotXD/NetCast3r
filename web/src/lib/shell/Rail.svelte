<script lang="ts">
  import { store } from '../state.svelte';
  import type { Screen } from '../types';

  let {
    open = false,
    onNavigate = () => {}
  }: { open?: boolean; onNavigate?: () => void } = $props();

  const items: { id: Screen; label: string; glyph: string; hint: string }[] = [
    { id: 'home', label: 'Home', glyph: '#', hint: 'what we found, what to do' },
    { id: 'new', label: 'New scan', glyph: '>', hint: 'point the tool at a target' },
    { id: 'live', label: 'Live runs', glyph: '[*]', hint: 'watch a scan as it works' },
    { id: 'findings', label: 'Findings', glyph: '*', hint: 'triage what came back' },
    { id: 'runs', label: 'Runs', glyph: '//', hint: 'history, rerun, delete' },
    { id: 'keys', label: 'Providers', glyph: '^', hint: 'paste a key, test a provider' },
    { id: 'help', label: 'Help', glyph: '?', hint: 'what every state means' }
  ];

  const isActive = (id: Screen) =>
    id === store.screen || (id === 'live' && store.screen === 'live');

  function go(id: Screen) {
    store.go(id);
    onNavigate();
  }
</script>

{#if open}
  <button
    class="fixed inset-0 z-30 bg-black/60 lg:hidden"
    aria-label="close navigation"
    onclick={onNavigate}
  ></button>
{/if}

<aside
  class="fixed inset-y-0 left-0 z-40 flex w-[248px] flex-col border-r border-indigo-deep bg-void-soft px-3 py-4 transition-transform duration-300 lg:static lg:z-auto lg:translate-x-0 {open
    ? 'translate-x-0'
    : '-translate-x-full'}"
>
  <div class="flex items-center gap-3 px-2">
    <svg viewBox="0 0 32 32" class="h-7 w-7" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="var(--nc-void)" stroke="var(--nc-indigo)" />
      <path
        d="M7 21 L16 9 L25 21 M7 24 L25 24 M11 24 L16 15 L21 24"
        stroke="var(--nc-acid)"
        stroke-width="1.5"
        fill="none"
      />
    </svg>
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
        {#if item.id === 'live' && store.runs.some((run) => run.status === 'running')}
          <span class="pulse-live ml-auto h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
        {/if}
      </button>
    {/each}
  </nav>

  <div class="mt-auto space-y-3 px-2 pt-4">
    <p class="border-t border-indigo-deep pt-3 text-[11px] leading-relaxed text-ash">
      Authorized testing only. Point this at systems you are allowed to test.
    </p>
    <p class="mono text-[11px] text-slate">v{store.meta?.version ?? '0.0.0'}</p>
  </div>
</aside>
