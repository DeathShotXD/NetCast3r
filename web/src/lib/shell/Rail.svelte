<script lang="ts">
  import { store } from '../state.svelte';
  import { ago, isoMs } from '../format';
  import { STAGES } from '../../tokens';
  import type { Screen } from '../types';
  import Icon from '../ui/Icon.svelte';

  let {
    open = false,
    onNavigate = () => {}
  }: { open?: boolean; onNavigate?: () => void } = $props();

  type NavItem = { id: Screen; label: string; icon: string; hint: string };

  const groups: { label: string; items: NavItem[] }[] = [
    {
      label: 'Command',
      items: [
        { id: 'home', label: 'Command Center', icon: 'grid', hint: 'what happened, what needs you' },
        { id: 'missions', label: 'Missions', icon: 'crosshair', hint: 'scoped objectives and their runs' },
        { id: 'new', label: 'New Scan', icon: 'target', hint: 'point the net at a target' },
        { id: 'live', label: 'Live Runs', icon: 'activity', hint: 'watch a cast, inspect everything it found' },
        { id: 'findings', label: 'Findings', icon: 'bug', hint: 'triage what came back' }
      ]
    },
    {
      label: 'Intelligence',
      items: [
        { id: 'runs', label: 'Run Ledger', icon: 'layers', hint: 'history, rerun, delete' },
        { id: 'reports', label: 'Reports', icon: 'file', hint: 'submissions, outcomes, payouts' },
        { id: 'agent', label: 'Agent Studio', icon: 'bot', hint: 'MCP tools, policy, audit' },
        { id: 'keys', label: 'Providers', icon: 'plug', hint: 'keys, models, health' }
      ]
    },
    {
      label: 'Reference',
      items: [{ id: 'help', label: 'Field Guide', icon: 'terminal', hint: 'what every state means' }]
    }
  ];

  const isActive = (id: Screen) => id === store.screen;

  const running = $derived(
    store.runs.find((run) => run.status === 'running' || run.status === 'queued') ??
      (store.liveRun && ['running', 'queued'].includes(store.liveRun.status) ? store.liveRun : null)
  );

  const openCount = $derived(
    (store.totals?.triage?.new ?? 0) + (store.totals?.triage?.in_progress ?? 0)
  );
  const findingCount = $derived(store.totals?.findings ?? 0);
  const missionCount = $derived(store.totals?.missions ?? 0);
  const pendingApprovals = $derived(store.totals?.pending_approvals ?? 0);
  const lastRun = $derived(store.totals?.last_run ?? store.runs[0] ?? null);
  const stageName = $derived(
    (STAGES as unknown as { key: string; label: string }[]).find((stage) => stage.key === store.liveStage)?.label ??
      (store.liveStage ? store.liveStage.toUpperCase() : 'WARMING UP')
  );
  const elapsed = $derived.by(() => {
    if (!running) return '';
    const start = isoMs(running.started_at || running.created_at);
    if (!Number.isFinite(start)) return '';
    const seconds = Math.max(0, Math.floor((Date.now() - start) / 1000));
    return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
  });
  const syncLabel = $derived(
    store.syncState === 'error' ? 'sync lost' : store.syncState === 'syncing' ? 'syncing' : 'synced'
  );

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
  <button class="obs-scrim" aria-label="close navigation" onclick={onNavigate}></button>
{/if}

<aside class="obs-sidebar" class:is-open={open} aria-label="primary navigation">
  <div class="obs-brand">
    <div class="obs-brand-mark" aria-hidden="true">
      <svg viewBox="0 0 28 28" fill="none">
        <path
          d="M14 2.5 24.5 8.6v10.8L14 25.5 3.5 19.4V8.6z"
          stroke="url(#obs-brand-gradient)"
          stroke-width="1.3"
        />
        <path
          d="M14 7.2 20 10.7v6.6L14 20.8l-6-3.5v-6.6z"
          stroke="#C8F81A"
          stroke-opacity=".55"
          stroke-width=".9"
        />
        <circle cx="14" cy="14" r="2.1" fill="#C8F81A" />
        <path
          d="M14 7.2v4.7M20 10.7l-3.9 2.2M20 17.3l-3.9-2.2M14 20.8v-4.7M8 17.3l3.9-2.2M8 10.7l3.9 2.2"
          stroke="#C8F81A"
          stroke-opacity=".42"
          stroke-width=".75"
        />
      </svg>
    </div>
    <div>
      <div class="obs-brand-name">NETCAST3R</div>
      <div class="obs-brand-sub">Agentic security OS</div>
    </div>
  </div>

  <div class="obs-workspace">
    <span class="obs-workspace-avatar">NC</span>
    <span class="obs-workspace-copy">
      <span class="obs-workspace-name">Local control plane</span>
      <span class="obs-workspace-plan">single operator · SQLite</span>
    </span>
    <Icon name="lock" size={12} />
  </div>

  <nav class="obs-nav">
    {#each groups as group (group.label)}
      <div class="obs-nav-group">
        <div class="obs-nav-label">{group.label}</div>
        {#each group.items as item (item.id)}
          <button
            type="button"
            class="obs-nav-item"
            class:active={isActive(item.id)}
            onclick={() => go(item.id)}
            aria-current={isActive(item.id) ? 'page' : undefined}
            title={item.hint}
          >
            <Icon name={item.icon} size={15} />
            <span>{item.label}</span>
            {#if item.id === 'findings' && findingCount > 0}
              <span class="obs-nav-badge" class:hot={openCount > 0} class:badge-pop={pop} title="{findingCount} findings">
                {findingCount}
              </span>
            {/if}
            {#if item.id === 'missions' && missionCount > 0}
              <span class="obs-nav-badge" class:hot={pendingApprovals > 0} title="{missionCount} missions">
                {missionCount}
              </span>
            {/if}
            {#if item.id === 'home' && pendingApprovals > 0}
              <span class="obs-nav-badge hot" title="{pendingApprovals} approvals waiting">{pendingApprovals}</span>
            {/if}
            {#if item.id === 'live' && running}
              <span class="obs-nav-live" aria-hidden="true"></span>
            {/if}
          </button>
        {/each}
      </div>
    {/each}
  </nav>

  {#if store.runs.length > 0}
    <div class="obs-sidebar-recent">
      <div class="obs-nav-label">Recent casts</div>
      {#each store.runs.slice(0, 5) as run (run.id)}
        <button class="obs-sidebar-run" type="button" onclick={() => store.watch(run.id)} title={run.target}>
          <span class="obs-sidebar-run-dot" style="background:{run.id === store.activeRunId ? 'var(--obs-acid)' : 'var(--obs-faint)'}" aria-hidden="true"></span>
          <span class="obs-sidebar-run-copy">
            <span class="obs-sidebar-run-target">{run.target}</span>
            <span class="obs-sidebar-run-meta">{run.status} · {ago(run.created_at)}</span>
          </span>
          <Icon name="arrow-right" size={10} />
        </button>
      {/each}
    </div>
  {/if}

  <div class="obs-sidebar-stats">
    <div><span>runs</span><strong>{store.totals?.runs ?? 0}</strong></div>
    <div><span>findings</span><strong>{store.totals?.findings ?? 0}</strong></div>
    <div><span>queue</span><strong class:hot={openCount > 0}>{openCount}</strong></div>
  </div>

  <div class="obs-sidebar-foot">
    <div class="obs-system-card">
      <div class="obs-system-line">
        <span class="obs-status-dot" class:idle={!running} class:violet={store.syncState === 'error'} aria-hidden="true"></span>
        {#if running}
          {stageName.toLowerCase()} · {elapsed}
        {:else}
          Control plane ready
        {/if}
      </div>
      <div class="obs-system-meta">
        {#if running}
          {running.target}<br />
        {:else if lastRun}
          last cast {ago(lastRun.created_at)}<br />
        {:else}
          no casts recorded<br />
        {/if}
        {syncLabel} · v{store.meta?.version ?? '0.0.0'}
      </div>
    </div>

    <button class="obs-btn obs-btn-primary" type="button" onclick={() => go('new')} style="width:100%">
      <Icon name="crosshair" size={13} />
      Cast a net
    </button>

    <p class="obs-sidebar-legal">
      Authorized testing only. You are responsible for the scope you point this at.
    </p>
    <p class="obs-sidebar-version">
      {store.totals?.runs ?? 0} casts · {store.totals?.findings ?? 0} findings
    </p>
  </div>
</aside>
