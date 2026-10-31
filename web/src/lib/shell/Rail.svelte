<script lang="ts">
  import { store } from '../state.svelte';
  import { isoMs } from '../format';
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
        { id: 'runs', label: 'Cast History', icon: 'layers', hint: 'every cast, its results, and a rerun' },
        { id: 'reveng', label: 'Reverse Lab', icon: 'code', hint: 'source, APK, contracts, drivers' },
        { id: 'reports', label: 'Reports', icon: 'file', hint: 'submissions, outcomes, payouts' },
        { id: 'agent', label: 'Agent Studio', icon: 'bot', hint: 'MCP tools, policy, audit' },
        { id: 'connect', label: 'Connect', icon: 'network', hint: 'OpenCode, Hermes, DeepSeek, Agent Zero' },
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
  const queuedCount = $derived(store.runs.filter((run) => run.status === 'queued').length);

  /* rolling 24-hour cast heartbeat: a real readout of the plane's recent signal. */
  const pulse = $derived.by(() => {
    const bins = new Array(24).fill(0) as number[];
    const now = Date.now();
    for (const run of store.runs) {
      const stamp = isoMs(run.created_at);
      if (!Number.isFinite(stamp)) continue;
      const age = Math.floor((now - stamp) / 3600000);
      if (age >= 0 && age < bins.length) bins[bins.length - 1 - age] += 1;
    }
    return bins;
  });

  const scope = $derived.by(() => {
    const w = 168;
    const h = 26;
    const pad = 2;
    const max = Math.max(1, ...pulse);
    const step = (w - pad * 2) / Math.max(1, pulse.length - 1);
    const pts = pulse.map((value, index) => {
      const x = pad + index * step;
      const y = h - pad - (value / max) * (h - pad * 2);
      return [x, y] as const;
    });
    let d = `M ${pts[0][0]} ${pts[0][1]}`;
    for (let i = 1; i < pts.length; i += 1) {
      const [x0, y0] = pts[i - 1];
      const [x1, y1] = pts[i];
      const mid = (x0 + x1) / 2;
      d += ` C ${mid} ${y0}, ${mid} ${y1}, ${x1} ${y1}`;
    }
    const area = `${d} L ${w - pad} ${h} L ${pad} ${h} Z`;
    return { d, area, last: pts[pts.length - 1] };
  });

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

  <div class="obs-plane" class:is-live={!!running} aria-label="local control plane">
    <div class="obs-plane-top">
      <span class="obs-plane-kicker">
        <span class="obs-plane-tick" aria-hidden="true"></span>
        control plane
      </span>
      <span class="obs-plane-pill" class:live={!!running}>
        <span class="obs-plane-led" class:live={!!running} aria-hidden="true"></span>
        {running ? `${stageName.toLowerCase()} ${elapsed}` : 'ready'}
      </span>
    </div>

    <div class="obs-plane-meta">
      <span>loopback</span>
      <span class="obs-plane-sep" aria-hidden="true"></span>
      <span>supervised</span>
      <span class="obs-plane-sep" aria-hidden="true"></span>
      <span>24h</span>
    </div>

    <div class="obs-plane-scope" aria-hidden="true">
      <svg viewBox="0 0 168 26" preserveAspectRatio="none">
        <defs>
          <linearGradient id="obs-plane-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#c8f81a" stop-opacity="0.22" />
            <stop offset="100%" stop-color="#c8f81a" stop-opacity="0" />
          </linearGradient>
        </defs>
        <path class="obs-plane-area" d={scope.area} />
        <path class="obs-plane-line" d={scope.d} />
        <circle class="obs-plane-node" cx={scope.last[0]} cy={scope.last[1]} r="1.9" />
      </svg>
    </div>

    <div class="obs-plane-grid">
      <div><span>casts</span><strong>{store.totals?.runs ?? 0}</strong></div>
      <div><span>queue</span><strong class:hot={queuedCount > 0}>{queuedCount}</strong></div>
      <div><span>findings</span><strong>{findingCount}</strong></div>
    </div>
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

  <div class="obs-sidebar-foot">
    <button class="obs-btn obs-btn-primary" type="button" onclick={() => go('new')} style="width:100%">
      <Icon name="crosshair" size={13} />
      New scan
    </button>

    <div class="obs-sidebar-sys">
      <span
        class="obs-status-dot"
        class:idle={!running}
        class:violet={store.syncState === 'error'}
        aria-hidden="true"
      ></span>
      {syncLabel} &middot; v{store.meta?.version ?? '0.0.0'}
    </div>

    <p class="obs-sidebar-legal">
      Authorized testing only. You are responsible for the scope you point this at.
    </p>
    <p class="obs-sidebar-version">
      {store.totals?.runs ?? 0} casts - {store.totals?.findings ?? 0} findings
    </p>
  </div>
</aside>
