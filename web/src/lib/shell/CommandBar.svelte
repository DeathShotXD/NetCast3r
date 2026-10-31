<script lang="ts">
  import { store } from '../state.svelte';
  import { isoMs, statusLabel } from '../format';
  import { STAGES } from '../../tokens';
  import Icon from '../ui/Icon.svelte';

  let {
    onMenu = () => {}
  }: { onMenu?: () => void } = $props();

  let search = $state('');
  let searchFocused = $state(false);

  const labels: Record<string, string> = {
    home: 'Command Center',
    missions: 'Missions',
    new: 'New scan',
    live: 'Live run',
    findings: 'Findings',
    runs: 'Cast history',
    reveng: 'Reverse Lab',
    reports: 'Reports',
    agent: 'Agent Studio',
    connect: 'Connect',
    keys: 'Providers',
    help: 'Field guide'
  };

  const running = $derived(
    store.runs.find((run) => run.status === 'running' || run.status === 'queued') ?? store.liveRun ?? null
  );
  const status = $derived(running?.status ?? '');
  const scanActive = $derived(status === 'running' || status === 'queued');
  const active = $derived(store.runs.find((run) => run.id === store.activeRunId) ?? store.liveRun ?? null);
  const crumb = $derived(
    store.screen === 'live' && active ? active.target : (labels[store.screen] ?? '')
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

<header class="obs-topbar">
  <button class="obs-menu" type="button" onclick={onMenu} aria-label="open navigation">
    <Icon name="grid" size={15} />
  </button>

  <div class="obs-crumbs" title={crumb}>
    <span class="hidden sm:inline">NetCast3r</span>
    <span class="slash hidden sm:inline">/</span>
    <strong>{crumb}</strong>
    {#if scanActive && running}
      <span class="obs-chip acid" style="margin-left:2px">
        <span class="obs-pulse" aria-hidden="true"></span>
        live
      </span>
    {/if}
  </div>

  <form class="obs-search" onsubmit={submit} role="search">
    <Icon name="search" size={14} />
    <input
      type="search"
      placeholder="Search findings..."
      aria-label="search findings"
      data-search
      bind:value={search}
      onfocus={() => (searchFocused = true)}
      onblur={() => (searchFocused = false)}
    />
    {#if !search && !searchFocused}
      <span class="obs-kbd" aria-hidden="true">/</span>
    {/if}
  </form>

  <span class="obs-sync" title="control-plane freshness">
    <span class="obs-sync-dot" class:error={store.syncState === 'error'} aria-hidden="true"></span>
    {syncLabel}
  </span>

  <button
    class="obs-icon-btn obs-search-icon"
    type="button"
    onclick={() => store.go('findings')}
    aria-label="search findings"
    title="search findings"
  >
    <Icon name="search" size={14} />
  </button>

  {#if scanActive && running}
    <span class="obs-status acid" role="status" aria-live="polite" title="{running.target} - {stageName}">
      <span class="obs-pulse" aria-hidden="true"></span>
      <span class="hidden xl:inline">{running.target}</span>
      <span class="hidden lg:inline">{elapsed}</span>
    </span>
  {:else}
    <span class="obs-status" role="status" aria-live="polite">
      <span class="obs-status-dot idle" style="width:5px;height:5px;box-shadow:none" aria-hidden="true"></span>
      {status ? statusLabel(status) : 'standby'}
    </span>
  {/if}

  <button
    class="obs-net-toggle"
    class:on={store.netCursor}
    type="button"
    aria-pressed={store.netCursor}
    title={store.netCursor ? 'net cursor on: it casts a web when it hunts' : 'net cursor off'}
    aria-label="toggle the net cursor"
    onclick={() => store.setNetCursor(!store.netCursor)}
  >
    <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true">
      <path
        d="M8 1v14M1 8h14M3 3l10 10M13 3L3 13"
        fill="none"
        stroke="currentColor"
        stroke-width=".8"
        stroke-opacity=".8"
      />
      <circle cx="8" cy="8" r="3.1" fill="none" stroke="currentColor" stroke-width=".9" />
      <circle cx="8" cy="8" r="1.1" fill="currentColor" />
    </svg>
    <span class="hidden sm:inline">Net</span>
  </button>

  <button
    class="obs-palette-btn obs-kbd"
    type="button"
    onclick={() => (store.palette = true)}
    title="open the command palette"
    aria-label="open command palette"
  >
    Ctrl K
  </button>

  <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.go('new')} title="start a scan">
    <Icon name="plus" size={13} />
    <span class="hidden sm:inline">New scan</span>
  </button>
</header>
