<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { ago } from '../format';
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';
  import type {
    DirectorLogEntry,
    McpInfo,
    SelfAudit,
    SelfGap,
    SelfGaps,
    SelfModel,
    Upgrade
  } from '../types';

  let model = $state<SelfModel | null>(null);
  let gaps = $state<SelfGaps | null>(null);
  let audit = $state<SelfAudit | null>(null);
  let upgrades = $state<Upgrade[]>([]);
  let mcp = $state<McpInfo | null>(null);
  let boot = $state<DirectorLogEntry | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let error = $state('');

  const dimensions = $derived(
    [...(model?.dimensions ?? [])].sort((a, b) => a.score - b.score)
  );
  const proposed = $derived(upgrades.filter((u) => (u.status || '') === 'proposed'));
  const counts = $derived(model?.counts ?? {});

  function levelTone(score: number): 'acid' | 'violet' | 'muted' {
    if (score >= 60) return 'acid';
    if (score >= 25) return 'violet';
    return 'muted';
  }

  async function load(silent = false) {
    if (silent && (refreshing || loading)) return;
    if (silent) refreshing = true;
    else { loading = true; error = ''; }
    try {
      const [sm, sg, sa, up, info, log] = await Promise.all([
        api.selfModel(),
        api.selfGaps().catch(() => null),
        api.selfAudit().catch(() => null),
        api.upgrades().catch(() => ({ items: [], total: 0 })),
        api.mcpInfo().catch(() => null),
        api.directorLog(40).catch(() => ({ items: [] }))
      ]);
      model = sm;
      gaps = sg;
      audit = sa;
      upgrades = up.items;
      mcp = info;
      boot = log.items.find((entry) => entry.kind === 'boot' &&
        entry.message.startsWith('continuity')) ?? null;
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not read the self-model';
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  onMount(() => void load());
</script>

<section class="flex flex-wrap items-end gap-3">
  <div class="mr-auto">
    <p class="eyebrow">introspection</p>
    <h1 class="mt-1 text-xl text-bone">Core</h1>
    <p class="mt-1 text-sm text-ash">
      The framework's own view of itself: maturity, capability gaps, local integrity,
      upgrade proposals, and what it was doing when it last went down.
    </p>
  </div>
  <button class="btn btn-quiet" type="button" disabled={loading} onclick={() => void load(true)}>
    {loading ? 'Reading...' : 'Refresh'}
  </button>
</section>

{#if error && model}
  <div class="obs-agent-note is-warn" role="status">
    Refresh failed: {error}. Showing the last self-model the plane returned.
  </div>
{/if}

{#if loading && !model}
  <div class="obs-card obs-empty" style="min-height:300px">
    <Buffering variant="block" tone="quiet" label="Reading the self-model"
      detail="Maturity, gaps, integrity, and continuity from the local control plane." />
  </div>
{:else if error && !model}
  <div class="obs-card obs-empty" style="min-height:260px">
    <span class="obs-empty-icon"><Icon name="x" size={18} /></span>
    <div class="obs-empty-title">Could not read the self-model</div>
    <p class="obs-empty-copy">{error}</p>
    <button class="obs-btn" type="button" onclick={() => void load()}>Try again</button>
  </div>
{:else if model}
  <section class="obs-core-stats" aria-label="self summary">
    <article class="obs-card">
      <span>Maturity</span>
      <strong class:acid={model.overall >= 60} class:violet={levelTone(model.overall) === 'violet'}>
        {model.overall}
      </strong>
      <small>{model.level}</small>
    </article>
    <article class="obs-card">
      <span>Integrity</span>
      <strong class:acid={(audit?.score ?? 0) >= 90}>{audit ? `${audit.grade} / ${audit.score}` : '-'}</strong>
      <small>local posture</small>
    </article>
    <article class="obs-card">
      <span>Capability gaps</span>
      <strong>{gaps?.items.length ?? 0}</strong>
      <small>ranked next moves</small>
    </article>
    <article class="obs-card">
      <span>Upgrades</span>
      <strong class:violet={proposed.length > 0}>{proposed.length}</strong>
      <small>awaiting review</small>
    </article>
    <article class="obs-card">
      <span>Tools</span>
      <strong>{mcp?.tools.length ?? 0}</strong>
      <small>typed contracts</small>
    </article>
    <article class="obs-card">
      <span>What it knows</span>
      <strong>{counts.techniques ?? 0}</strong>
      <small>{counts.skills ?? 0} skills, {counts.hypotheses ?? 0} leads</small>
    </article>
  </section>

  {#if boot}
    <section class="panel p-4 obs-continuity" aria-label="continuity">
      <div class="flex items-center gap-2">
        <span class="obs-continuity-dot" aria-hidden="true"></span>
        <span class="eyebrow">continuity</span>
        <span class="text-xs text-bone-dust">{boot.message}</span>
        <span class="ml-auto text-xs text-faint">{boot.ts ? ago(boot.ts) : ''}</span>
      </div>
    </section>
  {/if}

  <div class="obs-core-grid">
    <section class="obs-card" aria-label="maturity dimensions">
      <header class="obs-card-head">
        <div>
          <div class="obs-card-title"><Icon name="graph" size={13} />Maturity</div>
          <div class="obs-card-sub">
            A live read of what the framework can do, least developed first. A low score is
            a place to grow, not a defect.
          </div>
        </div>
      </header>
      <div class="obs-card-body">
        <div class="obs-core-dims">
          {#each dimensions as dim (dim.dimension)}
            <div class="obs-core-dim">
              <div class="obs-core-dim-top">
                <span class="obs-core-dim-label">{dim.label}</span>
                <span class="obs-core-dim-score {levelTone(dim.score)}">{dim.score}</span>
              </div>
              <div class="obs-core-bar" role="img" aria-label="{dim.label} maturity {dim.score} of 100">
                <span class="obs-core-bar-fill {levelTone(dim.score)}" style="width:{Math.max(2, Math.min(100, dim.score))}%"></span>
              </div>
              <div class="obs-core-dim-meta">
                <span>{dim.level}</span>
                <span>{dim.skills.length} skill{dim.skills.length === 1 ? '' : 's'}</span>
                <span>{dim.techniques} technique{dim.techniques === 1 ? '' : 's'}</span>
                {#if dim.training_total}<span>{dim.training_solved}/{dim.training_total} labs</span>{/if}
                {#if dim.findings}<span>{dim.findings} finding{dim.findings === 1 ? '' : 's'}</span>{/if}
              </div>
            </div>
          {/each}
        </div>
      </div>
    </section>

    <section class="obs-card" aria-label="capability gaps">
      <header class="obs-card-head">
        <div>
          <div class="obs-card-title"><Icon name="target" size={13} />What to grow next</div>
          <div class="obs-card-sub">
            The ranked gaps with the exact call that closes each one.
          </div>
        </div>
      </header>
      <div class="obs-card-body">
        {#if gaps?.items.length}
          <ul class="obs-core-gaps">
            {#each gaps.items as gap (gap.dimension)}
              <li>
                <div class="obs-core-gap-top">
                  <span class="obs-core-gap-label">{gap.label}</span>
                  <span class="obs-core-gap-score {levelTone(gap.score)}">{gap.score}</span>
                </div>
                <p class="obs-core-gap-gap">{gap.gap}</p>
                <p class="obs-core-gap-action">{gap.action}</p>
                <code class="obs-core-gap-tool">{gap.tool}</code>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="obs-detail-note">No stored gaps. The self-model is current.</p>
        {/if}
        <p class="obs-agent-fine">{model.note}</p>
      </div>
    </section>
  </div>

  <section class="obs-card" aria-label="upgrade proposals">
    <header class="obs-card-head">
      <div>
        <div class="obs-card-title"><Icon name="sparkles" size={13} />Upgrade proposals</div>
        <div class="obs-card-sub">
          Improvements the framework proposed from its own gaps and labs. Each is
          human-gated: nothing is applied until an operator approves it.
        </div>
      </div>
    </header>
    <div class="obs-card-body">
      {#if upgrades.length}
        <div class="obs-core-upgrades">
          {#each upgrades as up (up.id)}
            <div class="obs-core-upgrade">
              <div class="obs-core-upgrade-top">
                <span class="obs-core-prio" data-prio={up.priority}>{up.priority}</span>
                <span class="obs-core-upgrade-title">{up.title}</span>
                <span class="obs-core-upgrade-area">{up.area}</span>
                <span class="obs-core-upgrade-status" data-status={up.status}>{up.status}</span>
              </div>
              <p class="obs-core-upgrade-why">{up.rationale}</p>
              {#if up.evidence}<p class="obs-core-upgrade-evidence">{up.evidence}</p>{/if}
            </div>
          {/each}
        </div>
      {:else}
        <p class="obs-detail-note">No upgrade proposals yet.</p>
      {/if}
    </div>
  </section>

  {#if audit}
    <section class="panel p-4" aria-label="local integrity">
      <div class="flex flex-wrap items-center gap-3">
        <span class="eyebrow">local integrity</span>
        <span class="chip" class:text-acid={audit.score >= 90} class:text-violet={audit.score < 90}>
          {audit.grade} / {audit.score}
        </span>
        <span class="text-xs text-bone-dust">{audit.note}</span>
      </div>
    </section>
  {/if}
{/if}
