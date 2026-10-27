<script lang="ts">
  import { store } from '../state.svelte';
  import { isoMs, statusColor, statusLabel } from '../format';
  import { STAGES } from '../../tokens';

  let {
    onMenu = () => {}
  }: { onMenu?: () => void } = $props();

  let search = $state('');
  let searchFocused = $state(false);

  const labels: Record<string, string> = {
    home: 'home',
    new: 'new scan',
    live: 'live run',
    findings: 'findings',
    runs: 'runs',
    keys: 'providers and keys',
    help: 'help'
  };

  const running = $derived(
    store.runs.find((run) => run.status === 'running' || run.status === 'queued') ?? store.liveRun ?? null
  );
  const status = $derived(running?.status ?? '');
  const scanActive = $derived(status === 'running' || status === 'queued');
  const active = $derived(store.runs.find((run) => run.id === store.activeRunId) ?? store.liveRun ?? null);
  const crumb = $derived(
    store.screen === 'live' && active ? active.target : labels[store.screen] ?? ''
  );
  const stageName = $derived(
    (STAGES as unknown as { key: string; label: string }[]).find((stage) => stage.key === store.liveStage)?.label ??
      (store.liveStage ? store.liveStage.toUpperCase() : 'WARMING UP')
  );
  const elapsed = $derived.by(() => {
    if (!running || !scanActive) return '';
    const start = isoMs(running.started_at || running.created_at);
    if (!Number.isFinite(start)) return '';
    const seconds = Math.max(0, Math.floor((Date.now() - start) / 1000));
    return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
  });
  const syncLabel = $derived(
    store.syncState === 'error' ? 'sync lost' : store.syncState === 'syncing' ? 'syncing' : 'synced'
  );

  function submit(event: SubmitEvent) {
    event.preventDefault();
    store.query = search.trim();
    store.go('findings');
  }
</script>

<header
  class="sticky top-0 z-20 flex items-center gap-3 border-b border-indigo-deep bg-void/95 px-4 py-3 sm:px-6"
  class:run-line={scanActive}
>
  <button
    class="btn btn-quiet shrink-0 px-2! lg:hidden"
    type="button"
    onclick={onMenu}
    aria-label="open navigation"
  >
    <span aria-hidden="true">=</span>
  </button>

  <p class="mono flex min-w-0 items-center gap-2 truncate text-sm text-bone-dust" title={crumb}>
    <span class="hidden text-slate sm:inline">netcast3r</span>
    <span class="hidden text-slate sm:inline"> / </span>
    <span class="truncate text-bone">{crumb}</span>
  </p>

  {#if scanActive && running}
    <span class="chip live-capsule ml-1 hidden shrink-0 sm:inline-flex" role="status" aria-live="polite">
      <span class="pulse-live h-[7px] w-[7px] rounded-full bg-acid" aria-hidden="true"></span>
      live
    </span>
    <span class="mono hidden max-w-[190px] shrink-0 truncate text-xs text-bone lg:inline">{running.target}</span>
    <span class="mono hidden shrink-0 text-[10px] tracking-[0.06em] text-ash xl:inline">{stageName} · {elapsed}</span>
  {:else}
    <span
      class="chip ml-1 hidden shrink-0 sm:inline-flex"
      style="color:{statusColor(status)}"
      role="status"
      aria-live="polite"
    >
      <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
        <circle cx="4" cy="4" r="3.4" />
      </svg>
      {status ? statusLabel(status) : 'idle'}
    </span>
  {/if}

  <span class="ml-auto hidden shrink-0 items-center gap-1.5 md:flex" title="control-plane freshness">
    <span class="sync-dot" class:live={scanActive} class:error={store.syncState === 'error'} aria-hidden="true"></span>
    <span class="mono text-[10px] tracking-[0.1em]" style="color:{store.syncState === 'error' ? 'var(--nc-violet)' : 'var(--nc-ash)'}">
      {syncLabel}
    </span>
  </span>

  <form class="flex shrink-0 items-center gap-2 md:ml-0 ml-auto" onsubmit={submit} role="search">
    <span class="relative inline-flex">
      <input
        class="field w-[clamp(108px,30vw,260px)]! py-1.5! text-sm!"
        type="search"
        placeholder="search findings"
        aria-label="search findings"
        data-search
        bind:value={search}
        onfocus={() => (searchFocused = true)}
        onblur={() => (searchFocused = false)}
      />
      {#if !search && !searchFocused}
        <span
          class="kbd pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 sm:inline-flex"
          aria-hidden="true"
          >/</span
        >
      {/if}
    </span>
    <button class="btn hidden shrink-0 px-3! py-1.5! sm:inline-flex" type="submit" aria-label="search"
      >go</button
    >
  </form>

  <button
    class="kbd hidden shrink-0 cursor-pointer transition-colors hover:border-violet-deep hover:text-bone sm:inline-flex"
    type="button"
    onclick={() => (store.palette = true)}
    title="open the command palette"
    aria-label="open command palette"
  >
    ctrl k
  </button>

  <button
    class="btn btn-acid shrink-0 py-1.5!"
    type="button"
    onclick={() => store.go('new')}
    title="start a scan"
  >
    new scan
  </button>
</header>
