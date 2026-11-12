<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { ago } from '../format';
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';
  import type {
    Continuity,
    McpInfo,
    SelfAudit,
    SelfGaps,
    SelfModel,
    Upgrade
  } from '../types';

  let model = $state<SelfModel | null>(null);
  let gaps = $state<SelfGaps | null>(null);
  let audit = $state<SelfAudit | null>(null);
  let upgrades = $state<Upgrade[]>([]);
  let mcp = $state<McpInfo | null>(null);
  let continuity = $state<Continuity | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let error = $state('');

  const boot = $derived(continuity?.last_boot ?? null);

  const dimensions = $derived(
    [...(model?.dimensions ?? [])].sort((a, b) => a.score - b.score)
  );
  const proposed = $derived(upgrades.filter((u) => (u.status || '') === 'proposed'));
  const counts = $derived(model?.counts ?? {});

  const kpis = $derived([
    { key: 'maturity', label: 'Maturity', icon: 'graph', value: model?.overall ?? 0,
      note: model?.level ?? '', tone: (model?.overall ?? 0) >= 60 ? 'acid' : '' },
    { key: 'integrity', label: 'Integrity', icon: 'shield', value: audit?.score ?? 0,
      note: audit ? `grade ${audit.grade} - local posture` : 'not read',
      tone: (audit?.score ?? 0) >= 90 ? 'acid' : '' },
    { key: 'gaps', label: 'Gaps', icon: 'target', value: gaps?.items.length ?? 0,
      note: 'ranked next moves', tone: '' },
    { key: 'upgrades', label: 'Upgrades', icon: 'arrow-up', value: proposed.length,
      note: 'awaiting review', tone: proposed.length > 0 ? 'violet' : '' },
    { key: 'knowledge', label: 'Knowledge', icon: 'database', value: counts.techniques ?? 0,
      note: `${counts.skills ?? 0} skills - ${counts.hypotheses ?? 0} leads`, tone: '' }
  ]);

  type Tone = 'acid' | 'violet' | 'muted';
  function tone(score: number): Tone {
    if (score >= 60) return 'acid';
    if (score >= 25) return 'violet';
    return 'muted';
  }

  async function load(silent = false) {
    if (silent && (refreshing || loading)) return;
    if (silent) refreshing = true;
    else { loading = true; error = ''; }
    try {
      const [sm, sg, sa, up, info, nextContinuity] = await Promise.all([
        api.selfModel(),
        api.selfGaps().catch(() => null),
        api.selfAudit().catch(() => null),
        api.upgrades().catch(() => ({ items: [], total: 0 })),
        api.mcpInfo().catch(() => null),
        api.continuity().catch(() => null)
      ]);
      model = sm;
      gaps = sg;
      audit = sa;
      upgrades = up.items;
      mcp = info;
      continuity = nextContinuity;
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not read the self-model';
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  onMount(() => void load());
</script>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Introspection / Core</div>
      <h1>Core</h1>
      <p class="obs-page-sub">
        The framework's own view of itself: what it can do, where it is thin, whether
        its local posture is clean, what it proposes to grow, and what it was reading
        the last time the process went down.
      </p>
    </div>
    <div class="obs-page-actions">
      <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('agent')}>
        <Icon name="bot" size={13} />
        Agent studio
      </button>
      <button class="obs-btn obs-btn-primary" type="button" disabled={loading || refreshing}
        onclick={() => void load(true)}>
        <Icon name="refresh" size={13} />
        {loading ? 'Reading...' : refreshing ? 'Refreshing...' : 'Refresh'}
      </button>
    </div>
  </header>

  {#if error && model}
    <div class="obs-agent-note is-warn" role="status">
      Refresh failed: {error}. Showing the last self-model the plane returned.
    </div>
  {/if}

  {#if loading && !model}
    <div class="obs-card obs-empty" style="min-height:320px">
      <Buffering variant="block" tone="quiet" label="Reading the self-model"
        detail="Maturity, gaps, integrity, and continuity from the local control plane." />
    </div>
  {:else if error && !model}
    <div class="obs-card obs-empty" style="min-height:280px">
      <span class="obs-empty-icon"><Icon name="x" size={18} /></span>
      <div class="obs-empty-title">Could not read the self-model</div>
      <p class="obs-empty-copy">{error}</p>
      <button class="obs-btn" type="button" onclick={() => void load()}>Try again</button>
    </div>
  {:else if model}
    <section class="obs-kpis obs-core-kpis" aria-label="self summary">
      {#each kpis as kpi (kpi.key)}
        <article class="obs-card obs-kpi {kpi.tone}">
          <div class="obs-kpi-label"><Icon name={kpi.icon} size={12} />{kpi.label}</div>
          <div class="obs-kpi-value"><span>{kpi.value}</span></div>
          <div class="obs-kpi-foot"><span>{kpi.note}</span></div>
          <span class="obs-kpi-glyph" aria-hidden="true"><Icon name={kpi.icon} size={42} /></span>
        </article>
      {/each}
    </section>

    <section class="obs-card obs-core-boot" aria-label="continuity">
      <div class="obs-core-boot-row">
        <span class="obs-core-boot-dot" aria-hidden="true"></span>
        <div class="obs-core-boot-body">
          <p class="eyebrow">continuity</p>
          <p class="obs-core-boot-msg">
            {boot ? boot.message : 'First boot on this record. A restarted swarm resumes the same run id from its checkpoint.'}
          </p>
        </div>
        <div class="obs-core-boot-side">
          {#if continuity?.current?.pid}
            <span class="obs-core-chip">process {continuity.current.pid}</span>
          {/if}
          <span class="obs-core-chip">{mcp?.tools.length ?? 0} tools</span>
          {#if boot?.ts}<span class="obs-core-boot-ts">{ago(boot.ts)}</span>{/if}
        </div>
      </div>
    </section>

    <div class="obs-core-grid">
      <section class="obs-card obs-core-panel" aria-label="maturity dimensions">
        <header class="obs-core-head">
          <div>
            <p class="eyebrow">maturity</p>
            <p class="obs-core-sub">
              A live read of what the framework can do, least developed first. A low
              score is a place to grow, not a defect.
            </p>
          </div>
        </header>
        <div class="obs-core-dims">
          {#each dimensions as dim (dim.dimension)}
            <div class="obs-core-dim">
              <div class="obs-core-dim-top">
                <span class="obs-core-dim-label">{dim.label}</span>
                <span class="obs-core-dim-score {tone(dim.score)}">{dim.score}</span>
              </div>
              <div class="obs-meter" role="img" aria-label="{dim.label} maturity {dim.score} of 100">
                <i class:is-violet={tone(dim.score) === 'violet'}
                   class:is-muted={tone(dim.score) === 'muted'}
                   style="width:{Math.max(3, Math.min(100, dim.score))}%"></i>
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
      </section>

      <section class="obs-card obs-core-panel" aria-label="capability gaps">
        <header class="obs-core-head">
          <div>
            <p class="eyebrow">what to grow next</p>
            <p class="obs-core-sub">The ranked gaps with the exact call that closes each one.</p>
          </div>
        </header>
        {#if gaps?.items.length}
          <ul class="obs-core-gaps">
            {#each gaps.items as gap (gap.dimension)}
              <li>
                <div class="obs-core-gap-top">
                  <span class="obs-core-gap-label">{gap.label}</span>
                  <span class="obs-core-gap-score {tone(gap.score)}">{gap.score}</span>
                </div>
                <p class="obs-core-gap-gap">{gap.gap}</p>
                <p class="obs-core-gap-action">{gap.action}</p>
                <code class="obs-core-tool">{gap.tool}</code>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="obs-detail-note">No stored gaps. The self-model is current.</p>
        {/if}
        <p class="obs-core-fine">{model.note}</p>
      </section>
    </div>

    <section class="obs-card obs-core-panel" aria-label="upgrade proposals">
      <header class="obs-core-head">
        <div>
          <p class="eyebrow">upgrade proposals</p>
          <p class="obs-core-sub">
            Improvements the framework proposed from its own gaps and labs. Each is
            human-gated: nothing is applied until an operator approves it.
          </p>
        </div>
      </header>
      {#if upgrades.length}
        <div class="obs-core-upgrades">
          {#each upgrades as up (up.id)}
            <article class="obs-core-upgrade">
              <div class="obs-core-upgrade-top">
                <span class="obs-core-prio" data-prio={up.priority}>{up.priority}</span>
                <span class="obs-core-upgrade-title">{up.title}</span>
                <span class="obs-core-upgrade-area">{up.area}</span>
                <span class="obs-core-status" data-status={up.status}>{up.status}</span>
              </div>
              <p class="obs-core-upgrade-why">{up.rationale}</p>
              {#if up.evidence}
                <p class="obs-core-upgrade-evidence"><span>evidence</span>{up.evidence}</p>
              {/if}
            </article>
          {/each}
        </div>
      {:else}
        <p class="obs-detail-note">No upgrade proposals yet.</p>
      {/if}
    </section>

    {#if audit}
      <p class="obs-core-fine" aria-label="local integrity">
        {audit.note} Local integrity read {audit.grade} / {audit.score}.
      </p>
    {/if}
  {/if}
</div>
