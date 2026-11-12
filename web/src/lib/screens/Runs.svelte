<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { ago, statusColor, statusLabel, utcStamp } from '../format';
  import { store } from '../state.svelte';
  import Buffering from '../ui/Buffering.svelte';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import ReportView from '../ui/ReportView.svelte';
  import Sparkline from '../ui/Sparkline.svelte';
  import type { Run } from '../types';

  let runs = $state<Run[]>([]);
  let total = $state(0);
  let loading = $state(true);
  let error = $state('');
  let query = $state('');
  let statusFilter = $state('all');
  let sortBy = $state('newest');
  let pendingDelete = $state<string | null>(null);
  let pendingLive = $state<{ id: string; target: string; kind: 'rerun' | 'continue' } | null>(null);
  let reportRun = $state<string | null>(null);

  // The ledger can hold thousands of casts. Keep every row in memory for the
  // KPIs and the activity chart, but only paint a window of them at a time:
  // rendering ~1,200 rows at once froze the screen and produced a 84,000px
  // page. "load more" extends the window without another API round-trip.
  const PAGE_SIZE = 120;
  let visibleCount = $state(PAGE_SIZE);

  const TONES: Record<string, string> = {
    running: 'running',
    queued: 'queued',
    done: 'done',
    failed: 'failed',
    stopped: 'muted',
    interrupted: 'muted'
  };
  const tone = (status: string) => TONES[status] ?? 'muted';

  const MIX = [
    { key: 'running', label: 'running', color: 'var(--obs-acid)' },
    { key: 'queued', label: 'queued', color: 'var(--obs-orange)' },
    { key: 'done', label: 'complete', color: 'var(--obs-green)' },
    { key: 'failed', label: 'failed', color: 'var(--obs-fault)' },
    { key: 'interrupted', label: 'interrupted', color: 'var(--obs-faint)' },
    { key: 'stopped', label: 'stopped', color: 'var(--obs-muted)' }
  ];

  function ms(iso?: string): number {
    if (!iso) return Number.NaN;
    const z = iso.endsWith('Z') || /[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`;
    return new Date(z).getTime();
  }

  function modeOf(run: Run): string {
    const mode = String((run.options as Record<string, unknown> | undefined)?.mode ?? 'scan');
    return mode === 'scan' ? 'cast' : mode;
  }

  function durationText(run: Run): string {
    const start = ms(run.started_at || run.created_at);
    if (!Number.isFinite(start)) return '';
    const end = ms(run.finished_at) || Date.now();
    const secs = Math.max(0, Math.round((end - start) / 1000));
    if (secs < 60) return `${secs}s`;
    const minutes = Math.floor(secs / 60);
    if (minutes < 60) return `${minutes}m ${secs % 60}s`;
    return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  }

  function dayLabel(iso?: string): string {
    const stamp = ms(iso);
    if (!Number.isFinite(stamp)) return 'Unknown';
    const day = new Date(stamp);
    const now = new Date();
    const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const startDay = new Date(day.getFullYear(), day.getMonth(), day.getDate()).getTime();
    const diff = Math.round((startToday - startDay) / 86400000);
    if (diff <= 0) return 'Today';
    if (diff === 1) return 'Yesterday';
    if (diff < 7) return `${diff} days ago`;
    return day.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  }

  async function load() {
    loading = true;
    error = '';
    try {
      // The KPI row and the 14-day activity chart must describe the whole
      // history, not just the first page, so walk every page the control plane
      // reports. A generous guard keeps a runaway total from looping forever.
      const first = await api.runs('?size=200');
      const all = [...first.items];
      total = first.total ?? first.items.length;
      let guard = 0;
      while (all.length < total && guard < 40) {
        const next = await api.runs(`?size=200&offset=${all.length}`);
        if (!next.items.length) break;
        all.push(...next.items);
        guard += 1;
      }
      runs = all;
      visibleCount = PAGE_SIZE;
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not load the cast history';
    } finally {
      loading = false;
    }
  }

  async function remove(id: string) {
    try {
      await api.deleteRun(id);
      runs = runs.filter((run) => run.id !== id);
      store.runs = store.runs.filter((run) => run.id !== id);
      if (store.activeRunId === id) store.activeRunId = '';
      store.toast('ok', 'run deleted');
      void store.refreshTotals();
      total = Math.max(0, total - 1);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not delete the run');
    } finally {
      pendingDelete = null;
    }
  }

  async function rerun(id: string) {
    try {
      const fresh = await api.rerun(id);
      runs = [fresh, ...runs];
      store.runs = [fresh, ...store.runs];
      store.watch(fresh.id);
      store.toast('ok', `rerunning ${fresh.target}`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not rerun');
    }
  }

  async function resume(id: string) {
    try {
      const fresh = await api.resumeRun(id);
      runs = [fresh, ...runs.filter((item) => item.id !== fresh.id)];
      store.runs = [fresh, ...store.runs.filter((item) => item.id !== fresh.id)];
      store.watch(fresh.id);
      store.toast('ok', `continuing the operation on ${fresh.target} where it stopped`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not continue the run');
    }
  }

  const counts = $derived.by(() => {
    const by: Record<string, number> = {};
    for (const run of runs) by[run.status] = (by[run.status] ?? 0) + 1;
    return by;
  });
  const liveCount = $derived((counts.running ?? 0) + (counts.queued ?? 0));
  const findingCount = (run: Run) => run.finding_count ?? run.counts?.findings ?? 0;
  const findingTotal = $derived(Math.max(
    runs.reduce((n, run) => n + (run.finding_count ?? run.counts?.findings ?? 0), 0),
    store.totals?.findings ?? 0
  ));
  const endpointTotal = $derived(runs.reduce((n, run) => n + (run.counts?.endpoints ?? 0), 0));

  const mix = $derived(
    MIX.map((item) => ({ ...item, count: counts[item.key] ?? 0 })).filter((item) => item.count > 0)
  );
  const mixTotal = $derived(mix.reduce((sum, item) => sum + item.count, 0));

  const activity = $derived.by(() => {
    const days: { label: string; short: string; count: number; findings: number }[] = [];
    const now = new Date();
    for (let offset = 13; offset >= 0; offset -= 1) {
      const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - offset);
      const end = new Date(start.getTime() + 86400000);
      const inDay = runs.filter((run) => {
        const stamp = ms(run.created_at);
        return stamp >= start.getTime() && stamp < end.getTime();
      });
      days.push({
        label: start.toLocaleDateString([], { month: 'short', day: 'numeric' }),
        short: String(start.getDate()),
        count: inDay.length,
        findings: inDay.reduce((n, run) => n + findingCount(run), 0)
      });
    }
    return days;
  });
  const activityMax = $derived(Math.max(1, ...activity.map((day) => day.count)));
  const activityValues = $derived(activity.map((day) => day.count));

  const filters = $derived([
    { key: 'all', label: 'all', count: runs.length },
    { key: 'running', label: 'live', count: (counts.running ?? 0) + (counts.queued ?? 0) },
    { key: 'done', label: 'complete', count: counts.done ?? 0 },
    { key: 'failed', label: 'failed', count: counts.failed ?? 0 },
    { key: 'interrupted', label: 'interrupted', count: (counts.interrupted ?? 0) + (counts.stopped ?? 0) }
  ]);

  const filtered = $derived.by(() => {
    let list = runs.slice();
    if (statusFilter === 'running') list = list.filter((run) => run.status === 'running' || run.status === 'queued');
    else if (statusFilter === 'interrupted') list = list.filter((run) => run.status === 'interrupted' || run.status === 'stopped');
    else if (statusFilter !== 'all') list = list.filter((run) => run.status === statusFilter);
    const needle = query.trim().toLowerCase();
    if (needle) {
      list = list.filter(
        (run) => run.target.toLowerCase().includes(needle) || run.id.toLowerCase().includes(needle)
      );
    }
    if (sortBy === 'findings') list.sort((a, b) => findingCount(b) - findingCount(a));
    else if (sortBy === 'target') list.sort((a, b) => a.target.localeCompare(b.target));
    else list.sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')));
    return list;
  });

  const visible = $derived(filtered.slice(0, visibleCount));
  const hidden = $derived(Math.max(0, filtered.length - visible.length));

  const grouped = $derived.by(() => {
    const groups: { label: string; runs: Run[] }[] = [];
    for (const run of visible) {
      const label = dayLabel(run.created_at);
      const last = groups[groups.length - 1];
      if (last && last.label === label) last.runs.push(run);
      else groups.push({ label, runs: [run] });
    }
    return groups;
  });

  onMount(load);
</script>

<div class="obs-page obs-page-narrow">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Operations / Cast history</div>
      <h1>Cast history</h1>
      <p class="obs-page-sub">
        Every operation the plane has run, grouped by day. {total} casts recorded{liveCount
          ? ` / ${liveCount} live now`
          : ''}.
      </p>
    </div>
    <div class="obs-page-actions">
      <button class="obs-btn obs-btn-sm" type="button" onclick={() => void load()}>refresh</button>
      <button class="obs-btn obs-btn-sm obs-btn-primary" type="button" onclick={() => store.go('new')}>
        new scan
      </button>
    </div>
  </header>

  <section class="obs-kpis cols-4" aria-label="cast summary">
    <article class="obs-card obs-kpi">
      <p class="obs-kpi-label">casts</p>
      <p class="obs-kpi-value">{total}</p>
      <div class="obs-kpi-foot">
        <span>last 14 days</span>
        <Sparkline values={activityValues} width={52} height={17} />
      </div>
    </article>
    <article class="obs-card obs-kpi {liveCount > 0 ? 'acid' : ''}">
      <p class="obs-kpi-label">live now</p>
      <p class="obs-kpi-value">{liveCount}</p>
      <p class="obs-kpi-foot">{liveCount > 0 ? 'casting in the background' : 'idle'}</p>
    </article>
    <article class="obs-card obs-kpi {findingTotal > 0 ? 'acid' : ''}">
      <p class="obs-kpi-label">findings</p>
      <p class="obs-kpi-value">{findingTotal}</p>
      <p class="obs-kpi-foot">across all casts</p>
    </article>
    <article class="obs-card obs-kpi">
      <p class="obs-kpi-label">endpoints</p>
      <p class="obs-kpi-value">{endpointTotal}</p>
      <p class="obs-kpi-foot">{runs.length} casts scanned</p>
    </article>
  </section>

  <section class="obs-card">
    <div class="obs-card-head">
      <div>
        <div class="obs-card-title">Activity</div>
        <div class="obs-card-sub">casts per day - last 14 days</div>
      </div>
      <span class="obs-hist-band-total">
        {activity.reduce((n, day) => n + day.count, 0)} casts &middot; peak {activityMax}/day
      </span>
    </div>
    <div class="obs-hist-band">
      <div class="obs-hist-chart">
        <div class="obs-hist-grid" aria-hidden="true">
          <span></span><span></span><span></span><span></span>
        </div>
        <div class="obs-hist-bars" role="img" aria-label="casts per day over the last 14 days">
          {#each activity as day, i (day.label)}
            <div
              class="obs-hist-bar"
              class:has-runs={day.count > 0}
              class:is-today={i === activity.length - 1}
              title="{day.label}: {day.count} casts, {day.findings} findings"
            >
              <span class="obs-hist-bar-fill" style="height:{day.count ? Math.max(10, (day.count / activityMax) * 100) : 4}%"></span>
              <span class="obs-hist-bar-day">{day.short}</span>
            </div>
          {/each}
        </div>
      </div>
      <div class="obs-hist-mix">
        {#if mix.length}
          {#each mix as item (item.key)}
            <span
              class="obs-hist-mix-seg"
              style="flex:{item.count};background:{item.color}"
              title="{item.label}: {item.count}"
            ></span>
          {/each}
        {:else}
          <span class="obs-hist-mix-seg" style="flex:1;background:var(--obs-panel-4)"></span>
        {/if}
      </div>
      <div class="obs-hist-legend">
        {#each mix as item (item.key)}
          <span class="obs-hist-legend-item">
            <i style="background:{item.color}"></i>{item.label}
            <b>{item.count}</b>
          </span>
        {/each}
        {#if !mix.length}
          <span class="obs-hist-legend-item muted">no casts in the loaded set</span>
        {/if}
        {#if mixTotal}
          <span class="obs-hist-legend-item muted">{Math.round(((counts.done ?? 0) / mixTotal) * 100)}% complete</span>
        {/if}
      </div>
    </div>
  </section>

  <section class="obs-hist-toolbar">
    <label class="obs-hist-search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
        <circle cx="10.5" cy="10.5" r="6.2" />
        <path d="M15.2 15.2 L20.4 20.4" />
      </svg>
      <input type="search" placeholder="search target or run id" bind:value={query} oninput={() => (visibleCount = PAGE_SIZE)} aria-label="search casts" />
    </label>
    <div class="obs-hist-filters" role="group" aria-label="filter by status">
      {#each filters as item (item.key)}
        <button
          class="obs-hist-filter"
          class:active={statusFilter === item.key}
          type="button"
          onclick={() => {
            statusFilter = item.key;
            visibleCount = PAGE_SIZE;
          }}
        >
          {item.label}<span>{item.count}</span>
        </button>
      {/each}
    </div>
    <label class="obs-hist-sort">
      <span>sort</span>
      <select bind:value={sortBy} onchange={() => (visibleCount = PAGE_SIZE)} aria-label="sort casts">
        <option value="newest">newest</option>
        <option value="findings">findings</option>
        <option value="target">target</option>
      </select>
    </label>
  </section>

  {#if error && runs.length > 0}
    <p class="obs-alert" role="alert">
      {error} - showing the last history the control plane returned.
      <button class="obs-link" type="button" onclick={() => void load()}>Retry</button>
    </p>
  {/if}

  {#if loading && runs.length === 0}
    <section class="obs-card obs-empty" style="min-height:280px; gap:14px">
      <Buffering
        variant="block"
        tone="quiet"
        label="Loading casts"
        detail="Reading operation history from the control plane."
      />
    </section>
  {:else if error && runs.length === 0}
    <section class="obs-card">
      <EmptyState
        eyebrow="control plane"
        tone="error"
        title="Could not load the cast history"
        body={error}
        action="Try again"
        onAction={() => void load()}
        secondaryAction="Engage a target"
        onSecondaryAction={() => store.go('new')}
      />
    </section>
  {:else if runs.length === 0}
    <section class="obs-card">
      <EmptyState
        eyebrow="empty"
        title="No operations yet"
        body="Your cast history collects here: every target, when it ran, what it caught, and a rerun button for the next pass."
        action="start your first scan"
        onAction={() => store.go('new')}
        hint="> reports are also written to your results folder"
      />
    </section>
  {:else if filtered.length === 0}
    <section class="obs-card px-5 py-8 text-sm text-ash">No cast matches this filter.</section>
  {:else}
    {#each grouped as group (group.label)}
      <section class="obs-hist-group">
        <div class="obs-hist-group-head">
          <span class="obs-hist-group-label">{group.label}</span>
          <span class="obs-hist-group-line"></span>
          <span class="obs-hist-group-count">{group.runs.length}</span>
        </div>
        <div class="obs-hist-list">
          {#each group.runs as run (run.id)}
            <article class="obs-hist-run tone-{tone(run.status)}" class:is-live={run.status === 'running' || run.status === 'queued'}>
              <span class="obs-hist-run-rail" aria-hidden="true"></span>
              <div class="obs-hist-run-main">
                <div class="obs-hist-run-top">
                  {#if run.status === 'running'}
                    <span class="pulse-live"><Chip label={statusLabel(run.status)} color={statusColor(run.status)} /></span>
                  {:else}
                    <Chip label={statusLabel(run.status)} color={statusColor(run.status)} />
                  {/if}
                  <span class="obs-hist-run-mode">{modeOf(run)}</span>
                  <button class="obs-hist-run-target" type="button" onclick={() => store.watch(run.id)} title={run.target}>
                    {run.target}
                  </button>
                  <span class="obs-hist-run-time" title={utcStamp(run.created_at)}>{ago(run.created_at)}</span>
                </div>
                <div class="obs-hist-run-stats">
                  <span class:pulse={findingCount(run) > 0}>
                    <b>{findingCount(run)}</b> findings
                  </span>
                  <span><b>{run.counts?.endpoints ?? 0}</b> endpoints</span>
                  <span><b>{run.counts?.pages ?? 0}</b> pages</span>
                  <span><b>{run.counts?.js_files ?? 0}</b> js</span>
                  <span class="obs-hist-run-dur">{durationText(run)}</span>
                  {#if run.error}
                    <span class="obs-hist-run-error" title={run.error}>error</span>
                  {/if}
                </div>
                {#if run.status === 'running' || run.status === 'queued'}
                  <div class="obs-hist-progress" aria-hidden="true"><i></i></div>
                {/if}
              </div>
              <div class="obs-hist-run-actions">
                <button class="obs-hist-act primary" type="button" onclick={() => store.watch(run.id)}>open</button>
                {#if run.status === 'stopped' || run.status === 'interrupted' || run.status === 'failed'}
                  <button class="obs-hist-act" type="button" onclick={() => (pendingLive = { id: run.id, target: run.target, kind: 'continue' })}>continue</button>
                {/if}
                <button class="obs-hist-act" type="button" onclick={() => (pendingLive = { id: run.id, target: run.target, kind: 'rerun' })}>rerun</button>
                <button class="obs-hist-act" type="button" onclick={() => (reportRun = run.id)}>report</button>
                <button class="obs-hist-act danger" type="button" onclick={() => (pendingDelete = run.id)}>delete</button>
              </div>
            </article>
          {/each}
        </div>
      </section>
    {/each}
    {#if filtered.length > PAGE_SIZE}
      <div class="obs-hist-more">
        <span>{visible.length} of {filtered.length} casts</span>
        {#if hidden > 0}
          <button class="obs-btn obs-btn-sm" type="button" onclick={() => (visibleCount += PAGE_SIZE)}>
            load {Math.min(PAGE_SIZE, hidden)} more
          </button>
        {/if}
      </div>
    {/if}
  {/if}
</div>

{#if pendingLive}
  <Confirm
    title={pendingLive.kind === 'continue' ? 'Continue this operation?' : 'Rerun this cast?'}
    body={pendingLive.kind === 'continue'
      ? `Resuming picks up where the cast on ${pendingLive.target} stopped. It runs live under the current scope and writes to the audit trail.`
      : `A fresh cast starts against ${pendingLive.target}, live under the current scope, and writes to the audit trail.`}
    confirmLabel={pendingLive.kind === 'continue' ? 'continue cast' : 'rerun cast'}
    onConfirm={() => {
      const job = pendingLive;
      pendingLive = null;
      if (job) {
        if (job.kind === 'continue') void resume(job.id);
        else void rerun(job.id);
      }
    }}
    onCancel={() => (pendingLive = null)}
  />
{/if}

{#if pendingDelete}
  <Confirm
    title="Delete this cast?"
    body="The ledger row and its indexed events are removed. The report files on disk are not touched."
    confirmLabel="delete cast"
    danger={true}
    onConfirm={() => void remove(pendingDelete as string)}
    onCancel={() => (pendingDelete = null)}
  />
{/if}

{#if reportRun}
  <ReportView runId={reportRun} onClose={() => (reportRun = null)} />
{/if}