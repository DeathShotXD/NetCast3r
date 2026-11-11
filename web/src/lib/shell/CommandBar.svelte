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
  let castMenu = $state(false);
  const casts = $derived(store.activeCasts);

  const labels: Record<string, string> = {
    home: 'Command Center',
    missions: 'Missions',
    new: 'Engage target',
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
    store.runs.find(
      (run) =>
        run.id === store.activeRunId &&
        (run.status === 'running' || run.status === 'queued')
    ) ??
      store.runs.find((run) => run.status === 'running' || run.status === 'queued') ??
      store.liveRun ??
      null
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
    <span
      class="obs-status acid"
      role="status"
      aria-live="polite"
      title="{running.target} - {stageName} - {elapsed}"
    >
      <span class="obs-status-live" aria-hidden="true"></span>
      <span class="obs-status-target hidden md:inline">{running.target}</span>
      <span class="obs-status-sep hidden md:inline" aria-hidden="true"></span>
      <span class="obs-status-stage hidden lg:inline">{stageName}</span>
      <span class="obs-status-sep hidden lg:inline" aria-hidden="true"></span>
      <span class="obs-status-clock">{elapsed || '--:--'}</span>
    </span>
  {:else}
    <span class="obs-status" role="status" aria-live="polite">
      <span class="obs-status-dot idle" aria-hidden="true"></span>
      {status ? statusLabel(status) : 'standby'}
    </span>
  {/if}

  {#if casts.length > 1}
    <div class="obs-castbar">
      <button
        class="obs-castbar-btn"
        type="button"
        aria-haspopup="menu"
        aria-expanded={castMenu}
        title="{casts.length} casts in flight"
        onclick={() => (castMenu = !castMenu)}
      >
        <span class="obs-castbar-signal" aria-hidden="true"></span>
        <span class="obs-castbar-count">{casts.length}</span>
        <span class="obs-castbar-label">live</span>
      </button>
      {#if castMenu}
        <button
          class="obs-castbar-veil"
          type="button"
          tabindex="-1"
          aria-label="close cast menu"
          onclick={() => (castMenu = false)}
        ></button>
        <div class="obs-castbar-menu" role="menu" aria-label="casts in flight">
          <div class="obs-castbar-head">Casts in flight</div>
          {#each casts as cast (cast.id)}
            <button
              class="obs-castbar-item"
              class:on={cast.id === store.activeRunId}
              type="button"
              role="menuitem"
              onclick={() => {
                castMenu = false;
                store.watch(cast.id);
              }}
            >
              <span class="obs-castbar-target" title={cast.target}>{cast.target}</span>
              <em>{cast.id.slice(-6)}</em>
            </button>
          {/each}
        </div>
      {/if}
    </div>
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
    class="obs-icon-btn"
    type="button"
    class:on={store.brainDock}
    aria-pressed={store.brainDock}
    title="Helix - hunt steward (B)"
    aria-label="toggle Helix"
    onclick={() => (store.brainDock = !store.brainDock)}
  >
    <Icon name="sparkles" size={14} />
  </button>

  <button
    class="obs-palette-btn obs-kbd"
    type="button"
    onclick={() => (store.palette = true)}
    title="open the command palette"
    aria-label="command palette (Ctrl K)"
  >
    Ctrl K
  </button>
  <button
    class="obs-palette-glyph"
    type="button"
    onclick={() => (store.palette = true)}
    title="open the command palette"
    aria-label="open command palette"
  >
    <Icon name="terminal" size={13} />
  </button>

  <button
    class="obs-icon-btn"
    type="button"
    class:on={store.focusMode}
    aria-pressed={store.focusMode}
    title={store.focusMode ? 'leave focus mode (F)' : 'focus mode - hide the sidebar (F)'}
    aria-label="toggle focus mode"
    onclick={() => store.setFocusMode(!store.focusMode)}
  >
    <Icon name="layers" size={14} />
  </button>

  <button
    class="obs-icon-btn"
    type="button"
    title="keyboard shortcuts (?)"
    aria-label="keyboard shortcuts"
    onclick={() => (store.shortcuts = true)}
  >
    <Icon name="scroll" size={14} />
  </button>

  <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.go('new')} title="engage a target - one seed starts the full hunt">
    <Icon name="crosshair" size={13} />
    <span class="hidden sm:inline">Engage</span>
  </button>
</header>
