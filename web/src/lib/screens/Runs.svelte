<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { ago, statusColor, statusLabel } from '../format';
  import { store } from '../state.svelte';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import ReportView from '../ui/ReportView.svelte';
  import Sparkline from '../ui/Sparkline.svelte';
  import type { Run } from '../types';

  let runs = $state<Run[]>([]);
  let total = $state(0);
  let loading = $state(true);
  let query = $state('');
  let statusFilter = $state('all');
  let sortBy = $state('newest');
  let pendingDelete = $state<string | null>(null);
  let reportRun = $state<string | null>(null);

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
    { key: 'failed', label: 'failed', color: 'var(--obs-red)' },
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
    try {
      const page = await api.runs('?size=200');
      runs = page.items;
      total = page.total ?? page.items.length;
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not load the cast history');
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
      store.toast('ok', `continuing the scan of ${fresh.target} where it stopped`);
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
  const findingTotal = $derived(runs.reduce((n, run) => n + (run.counts?.findings ?? 0), 0));
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
        findings: inDay.reduce((n, run) => n + (run.counts?.findings ?? 0), 0)
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
    if (sortBy === 'findings') list.sort((a, b) => (b.counts?.findings ?? 0) - (a.counts?.findings ?? 0));
    else if (sortBy === 'target') list.sort((a, b) => a.target.localeCompare(b.target));
    else list.sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')));
    return list;
  });

  const grouped = $derived.by(() => {
    const groups: { label: string; runs: Run[] }[] = [];
    for (const run of filtered) {
      const label = dayLabel(run.created_at);
      const last = groups[groups.length - 1];
      if (last && last.label === label) last.runs.push(run);
      else groups.push({ label, runs: [run] });
    }
    return groups;
  });

  onMount(load);
</script>

<div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
  <section class="flex flex-wrap items-end gap-3">
    <div class="mr-auto">
      <p class="eyebrow">history</p>
      <h1 class="mt-1 text-xl text-bone">Cast history</h1>
      <p class="mt-1 text-sm text-ash">
        {total} casts recorded{liveCount ? ` / ${liveCount} live now` : ''}
      </p>
    </div>
    <button class="btn btn-quiet" type="button" onclick={() => void load()}>refresh</button>
    <button class="btn btn-acid" type="button" onclick={() => store.go('new')}>new scan</button>
  </section>

  <section class="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="cast summary">
    <div class="obs-hist-kpi">
      <p class="eyebrow">casts</p>
      <p class="num mt-1 text-xl text-bone">{total}</p>
      <Sparkline values={activityValues} width={150} height={26} class="mt-2 w-full" />
    </div>
    <div class="obs-hist-kpi" class:is-live={liveCount > 0}>
      <p class="eyebrow">live now</p>
      <p class="num mt-1 text-xl" style="color:{liveCount > 0 ? 'var(--obs-acid)' : 'var(--obs-text)'}">
        {liveCount}
      </p>
      <p class="obs-hist-kpi-note">{liveCount > 0 ? 'casting in the background' : 'idle'}</p>
    </div>
    <div class="obs-hist-kpi">
      <p class="eyebrow">findings</p>
      <p class="num mt-1 text-xl" style="color:{findingTotal > 0 ? 'var(--obs-acid)' : 'var(--obs-text)'}">
        {findingTotal}
      </p>
      <p class="obs-hist-kpi-note">across the loaded casts</p>
    </div>
    <div class="obs-hist-kpi">
      <p class="eyebrow">endpoints</p>
      <p class="num mt-1 text-xl text-bone">{endpointTotal}</p>
      <p class="obs-hist-kpi-note">{runs.length} casts scanned</p>
    </div>
  </section>

  <section class="panel obs-hist-band">
    <div class="obs-hist-band-head">
      <p class="eyebrow">activity &middot; last 14 days</p>
      <span class="obs-hist-band-total">{activity.reduce((n, day) => n + day.count, 0)} casts</span>
    </div>
    <div class="obs-hist-bars" role="img" aria-label="casts per day over the last 14 days">
      {#each activity as day (day.label)}
        <div
          class="obs-hist-bar"
          class:has-runs={day.count > 0}
          title="{day.label}: {day.count} casts, {day.findings} findings"
        >
          <span class="obs-hist-bar-fill" style="height:{day.count ? Math.max(8, (day.count / activityMax) * 100) : 3}%"></span>
          <span class="obs-hist-bar-day">{day.short}</span>
        </div>
      {/each}
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
  </section>

  <section class="obs-hist-toolbar">
    <label class="obs-hist-search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
        <circle cx="10.5" cy="10.5" r="6.2" />
        <path d="M15.2 15.2 L20.4 20.4" />
      </svg>
      <input type="search" placeholder="search target or run id" bind:value={query} aria-label="search casts" />
    </label>
    <div class="obs-hist-filters" role="group" aria-label="filter by status">
      {#each filters as item (item.key)}
        <button
          class="obs-hist-filter"
          class:active={statusFilter === item.key}
          type="button"
          onclick={() => (statusFilter = item.key)}
        >
          {item.label}<span>{item.count}</span>
        </button>
      {/each}
    </div>
    <label class="obs-hist-sort">
      <span>sort</span>
      <select bind:value={sortBy} aria-label="sort casts">
        <option value="newest">newest</option>
        <option value="findings">findings</option>
        <option value="target">target</option>
      </select>
    </label>
  </section>

  {#if loading && runs.length === 0}
    <section class="panel px-5 py-8 text-sm text-ash">loading casts...</section>
  {:else if runs.length === 0}
    <section class="panel">
      <EmptyState
        eyebrow="empty"
        title="No scans yet"
        body="Your cast history collects here: every target, when it ran, what it caught, and a rerun button for the next pass."
        action="start your first scan"
        onAction={() => store.go('new')}
        hint="> reports are also written to your results folder"
      />
    </section>
  {:else if filtered.length === 0}
    <section class="panel px-5 py-8 text-sm text-ash">No cast matches this filter.</section>
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
                  <span class="obs-hist-run-time">{ago(run.created_at)}</span>
                </div>
                <div class="obs-hist-run-stats">
                  <span class:pulse={((run.counts?.findings ?? 0) as number) > 0}>
                    <b>{run.counts?.findings ?? 0}</b> findings
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
                  <button class="obs-hist-act" type="button" onclick={() => void resume(run.id)}>continue</button>
                {/if}
                <button class="obs-hist-act" type="button" onclick={() => void rerun(run.id)}>rerun</button>
                <button class="obs-hist-act" type="button" onclick={() => (reportRun = run.id)}>report</button>
                <button class="obs-hist-act danger" type="button" onclick={() => (pendingDelete = run.id)}>delete</button>
              </div>
            </article>
          {/each}
        </div>
      </section>
    {/each}
  {/if}
</div>

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