<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { ago, sevColor, statusLabel } from '../format';
  import type { AgentStatus, Approval, Autonomy, Mission, MissionAgent, MissionStatus } from '../types';
  import Icon from '../ui/Icon.svelte';
  import Sparkline from '../ui/Sparkline.svelte';

  type Filter = 'all' | MissionStatus;

  let missions = $state<Mission[]>([]);
  let approvals = $state<Approval[]>([]);
  let selected = $state<Mission | null>(null);
  let agent = $state<MissionAgent | null>(null);
  let agentLoading = $state(false);
  let agentBusy = $state('');
  let agentModel = $state(false);
  let loading = $state(true);
  let error = $state('');
  let filter = $state<Filter>('all');
  let detailTab = $state<'overview' | 'runs' | 'approvals' | 'agent'>('overview');
  let composer = $state(false);
  let busy = $state('');
  let form = $state({
    title: '',
    target: '',
    objective: '',
    autonomy: 'supervised' as Autonomy,
    budget: '',
    scope: ''
  });

  const statusOrder: MissionStatus[] = ['active', 'paused', 'draft', 'done', 'archived'];
  const statusCopy: Record<MissionStatus, string> = {
    draft: 'Draft',
    active: 'In pursuit',
    paused: 'Paused',
    done: 'Closed',
    archived: 'Archived'
  };
  const autonomyCopy: Record<Autonomy, string> = {
    manual: 'Manual',
    supervised: 'Supervised',
    autonomous: 'Autonomous'
  };
  const agentCopy: Record<AgentStatus, string> = {
    idle: 'Idle',
    planning: 'Planning',
    running: 'Running',
    paused: 'Paused',
    stopping: 'Stopping',
    stopped: 'Stopped',
    done: 'Done',
    error: 'Error',
    interrupted: 'Interrupted'
  };

  const filtered = $derived(
    filter === 'all' ? missions : missions.filter((mission) => mission.status === filter)
  );
  const activeCount = $derived(missions.filter((mission) => mission.status === 'active').length);
  const pendingApprovals = $derived(approvals.filter((approval) => approval.status === 'pending'));
  const selectedApprovals = $derived(
    selected ? approvals.filter((approval) => approval.mission_id === selected?.id) : []
  );
  const missionStats = $derived({
    total: missions.length,
    active: activeCount,
    pending: pendingApprovals.length,
    findings: missions.reduce((sum, mission) => sum + mission.finding_count, 0)
  });
  const runTrend = $derived(
    [...missions]
      .slice(0, 10)
      .reverse()
      .map((mission) => mission.run_count)
  );

  async function load() {
    loading = true;
    error = '';
    try {
      const [missionPage, approvalPage] = await Promise.all([
        api.missions('?size=100'),
        api.approvals('?size=100')
      ]);
      missions = missionPage.items;
      approvals = approvalPage.items;
      if (selected) {
        const fresh = missions.find((mission) => mission.id === selected?.id);
        if (fresh) await open(fresh, false, true);
        else selected = null;
      }
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not load missions';
    } finally {
      loading = false;
    }
  }

  async function open(mission: Mission, scroll = true, preserveTab = false) {
    busy = `open:${mission.id}`;
    const tab = detailTab;
    try {
      selected = await api.mission(mission.id);
      agent = null;
      detailTab = preserveTab ? tab : 'overview';
      if (preserveTab && tab === 'agent') void loadAgent();
      if (scroll && window.innerWidth < 1180) {
        requestAnimationFrame(() => document.querySelector('.obs-mission-detail')?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
      }
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not open the mission');
    } finally {
      busy = '';
    }
  }

  async function loadAgent(silent = false) {
    if (!selected) return;
    const missionId = selected.id;
    if (!silent) agentLoading = true;
    try {
      const data = await api.missionAgent(missionId);
      if (selected?.id === missionId) agent = data;
    } catch (exc) {
      if (!silent) store.fail(exc instanceof Error ? exc.message : 'could not read the mission agent');
    } finally {
      if (!silent) agentLoading = false;
    }
  }

  async function startAgent() {
    if (!selected) return;
    agentBusy = 'start';
    try {
      agent = await api.startMissionAgent(selected.id, {
        use_model: agentModel,
        role: selected.training ? 'training' : 'recon',
        restart: agent?.status === 'interrupted'
      });
      if (selected.status === 'draft' || selected.status === 'paused') {
        selected = { ...selected, status: 'active' };
        missions = missions.map((mission) =>
          mission.id === selected?.id ? { ...mission, status: 'active' } : mission
        );
      }
      store.toast('ok', 'mission agent planned and started');
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start the mission agent');
    } finally {
      agentBusy = '';
    }
  }

  async function runNextLab() {
    if (!selected) return;
    agentBusy = 'lab';
    try {
      const run = await api.startLabRun({ slug: 'auto', mission_id: selected.id });
      store.toast('ok', 'lab run started');
      store.watch(run.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start the lab runner');
    } finally {
      agentBusy = '';
    }
  }

  async function controlAgent(action: 'pause' | 'resume' | 'stop') {
    if (!selected) return;
    agentBusy = action;
    try {
      const call = action === 'pause'
        ? api.pauseMissionAgent
        : action === 'resume'
          ? api.resumeMissionAgent
          : api.stopMissionAgent;
      agent = await call(selected.id);
      store.toast('ok', `mission agent ${action === 'pause' ? 'paused' : action === 'resume' ? 'resumed' : 'stopped'}`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : `could not ${action} the mission agent`);
    } finally {
      agentBusy = '';
    }
  }

  function selectTab(tab: typeof detailTab) {
    detailTab = tab;
    if (tab === 'agent') void loadAgent();
  }

  function formatCost(cents: number | null): string {
    if (cents == null) return 'not reported';
    return `$${(cents / 100).toFixed(4)}`;
  }

  function agentPercent(value: number, cap: number): number {
    if (!cap || cap <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round((value / cap) * 100)));
  }

  function resetForm() {
    form = { title: '', target: '', objective: '', autonomy: 'supervised', budget: '', scope: '' };
  }

  function startComposer() {
    resetForm();
    composer = true;
  }

  async function createMission() {
    if (!form.title.trim() || !form.target.trim()) {
      store.toast('warn', 'a mission needs a title and a target');
      return;
    }
    const cap = Number(form.budget);
    busy = 'create';
    try {
      const mission = await api.createMission({
        title: form.title.trim(),
        target: form.target.trim(),
        objective: form.objective.trim(),
        autonomy: form.autonomy,
        status: 'draft',
        budget: Number.isFinite(cap) && cap > 0 ? { max_usd: cap } : {},
        scope: form.scope
          .split(/[\n,]/)
          .map((item) => item.trim())
          .filter(Boolean)
      });
      composer = false;
      resetForm();
      store.toast('ok', 'mission saved as a draft');
      await load();
      await open(mission);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not create the mission');
    } finally {
      busy = '';
    }
  }

  async function launch() {
    if (!selected) return;
    busy = 'launch';
    try {
      const result = await api.startMissionRun(selected.id, {});
      store.toast('ok', `cast started for ${selected.title}`);
      selected = result.mission;
      await load();
      store.watch(result.run.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start the cast');
    } finally {
      busy = '';
    }
  }

  async function transition(status: MissionStatus) {
    if (!selected) return;
    busy = `status:${status}`;
    try {
      const updated = await api.patchMission(selected.id, { status });
      store.toast('ok', `mission ${statusCopy[status].toLowerCase()}`);
      selected = updated;
      missions = missions.map((mission) => (mission.id === updated.id ? { ...mission, ...updated } : mission));
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not change the mission state');
    } finally {
      busy = '';
    }
  }

  async function decide(approval: Approval, decision: 'approved' | 'rejected') {
    busy = `approval:${approval.id}`;
    try {
      const updated = await api.decideApproval(approval.id, { decision, decided_by: 'operator' });
      approvals = approvals.map((item) => (item.id === updated.id ? updated : item));
      if (selected) selected = (await api.mission(selected.id)) as Mission;
      store.toast('ok', decision === 'approved' ? 'approval granted' : 'approval rejected');
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not record the decision');
    } finally {
      busy = '';
    }
  }

  function budgetLabel(mission: Mission): string {
    const cap = Number(mission.budget?.max_usd ?? 0);
    return cap > 0 ? `$${cap.toLocaleString()}` : 'no cap';
  }

  function statusClass(status: MissionStatus): string {
    return status === 'active'
      ? 'is-live'
      : status === 'paused'
        ? 'is-paused'
        : status === 'done'
          ? 'is-done'
          : status === 'archived'
            ? 'is-archived'
            : 'is-draft';
  }

  onMount(() => {
    void load();
    void store.refreshTotals();
    const poll = window.setInterval(() => {
      if (detailTab !== 'agent' || !selected || !agent) return;
      if (['planning', 'running', 'paused', 'stopping'].includes(agent.status)) {
        void loadAgent(true);
      }
    }, 1200);
    return () => window.clearInterval(poll);
  });
</script>

<svelte:window
  onkeydown={(event) => {
    if (event.key === 'Escape' && composer) {
      composer = false;
      event.preventDefault();
    }
  }}
/>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Operations / Missions</div>
      <h1>Missions</h1>
      <p class="obs-page-sub">
        Objectives with a target, a scope, an autonomy level, and every run attached to them. The mission is the unit of accountability; a cast is just one move inside it.
      </p>
    </div>
    <div class="obs-page-actions">
      <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('findings')}>
        <Icon name="bug" size={13} />
        Findings
      </button>
      <button class="obs-btn obs-btn-primary" type="button" onclick={startComposer}>
        <Icon name="plus" size={13} />
        New mission
      </button>
    </div>
  </header>

  <section class="obs-mission-stats" aria-label="mission portfolio summary">
    <article class="obs-card">
      <span>Portfolio</span>
      <strong>{missionStats.total}</strong>
      <small>mission{missionStats.total === 1 ? '' : 's'}</small>
      <Sparkline values={runTrend} width={72} height={19} color="var(--obs-acid)" />
    </article>
    <article class="obs-card">
      <span>In pursuit</span>
      <strong class="acid">{missionStats.active}</strong>
      <small>active</small>
    </article>
    <article class="obs-card">
      <span>Approvals</span>
      <strong class={missionStats.pending > 0 ? 'violet' : ''}>{missionStats.pending}</strong>
      <small>waiting</small>
    </article>
    <article class="obs-card">
      <span>Findings</span>
      <strong>{missionStats.findings}</strong>
      <small>across missions</small>
    </article>
  </section>

  <div class="obs-filter-bar" role="tablist" aria-label="mission filters">
    <button class="obs-filter" class:active={filter === 'all'} type="button" onclick={() => (filter = 'all')}>
      All <span>{missions.length}</span>
    </button>
    {#each statusOrder as status (status)}
      <button class="obs-filter" class:active={filter === status} type="button" onclick={() => (filter = status)}>
        {statusCopy[status]} <span>{missions.filter((mission) => mission.status === status).length}</span>
      </button>
    {/each}
    <span class="obs-filter-spacer"></span>
    <button class="obs-btn obs-btn-sm obs-btn-ghost" type="button" onclick={() => void load()}>
      <Icon name="refresh" size={12} />
      Refresh
    </button>
  </div>

  {#if loading && missions.length === 0}
    <div class="obs-card obs-empty" style="min-height:360px">
      <span class="obs-empty-icon"><Icon name="crosshair" size={18} /></span>
      <div class="obs-empty-title">Loading the portfolio</div>
      <p class="obs-empty-copy">Reading missions and their approval state from the control plane.</p>
    </div>
  {:else if error}
    <div class="obs-card obs-empty" style="min-height:320px">
      <span class="obs-empty-icon"><Icon name="x" size={18} /></span>
      <div class="obs-empty-title">Could not load missions</div>
      <p class="obs-empty-copy">{error}</p>
      <button class="obs-btn" type="button" onclick={() => void load()}>Try again</button>
    </div>
  {:else if missions.length === 0}
    <div class="obs-card obs-empty" style="min-height:390px">
      <span class="obs-empty-icon"><Icon name="crosshair" size={19} /></span>
      <div class="obs-empty-title">No missions yet</div>
      <p class="obs-empty-copy">
        A mission captures why a target matters, what is in scope, and how much autonomy the fleet has. Casts attach to it instead of disappearing into a run list.
      </p>
      <button class="obs-btn obs-btn-primary" type="button" onclick={startComposer}>
        <Icon name="plus" size={13} />
        Compose the first mission
      </button>
    </div>
  {:else}
    <div class="obs-missions-layout">
      <div class="obs-mission-grid">
        {#each filtered as mission (mission.id)}
          <button
            class="obs-mission-card {statusClass(mission.status)}"
            class:selected={selected?.id === mission.id}
            type="button"
            onclick={() => void open(mission)}
          >
            <div class="obs-mission-top">
              <span class="obs-mission-state {statusClass(mission.status)}">
                <span class="obs-pulse" aria-hidden="true"></span>
                {statusCopy[mission.status]}
              </span>
              <span class="obs-chip">{autonomyCopy[mission.autonomy]}</span>
              {#if mission.training}
                <span class="obs-chip acid">training</span>
              {/if}
              {#if mission.pending_approvals > 0}
                <span class="obs-chip violet" style="margin-left:auto">{mission.pending_approvals} approval{mission.pending_approvals === 1 ? '' : 's'}</span>
              {/if}
            </div>

            <h3 class="obs-mission-title">{mission.title}</h3>
            <div class="obs-mission-target">
              <Icon name="globe" size={11} />
              <span>{mission.target}</span>
            </div>
            <p class="obs-mission-objective">
              {mission.objective || 'No objective written yet. Open the mission to add the reason this target matters.'}
            </p>

            <div class="obs-mission-stats-row">
              <div><span>Runs</span><strong>{mission.run_count}</strong></div>
              <div><span>Findings</span><strong class={mission.finding_count > 0 ? 'acid' : ''}>{mission.finding_count}</strong></div>
              <div><span>Scope</span><strong>{mission.scope.length}</strong></div>
              <div><span>Budget</span><strong>{budgetLabel(mission)}</strong></div>
            </div>

            <div class="obs-mission-foot">
              <span class="obs-mission-updated">updated {ago(mission.updated_at)}</span>
              <span class="obs-mission-open">
                Open <Icon name="arrow-right" size={12} />
              </span>
            </div>
          </button>
        {:else}
          <div class="obs-card obs-empty" style="grid-column:1/-1;min-height:260px">
            <span class="obs-empty-icon"><Icon name="filter" size={18} /></span>
            <div class="obs-empty-title">No mission in this state</div>
            <p class="obs-empty-copy">Change the filter or compose a new mission.</p>
            <button class="obs-btn" type="button" onclick={() => (filter = 'all')}>Show all</button>
          </div>
        {/each}
      </div>

      {#if selected}
        <aside class="obs-card obs-mission-detail" aria-label="mission detail">
          <header class="obs-mission-detail-head">
            <div class="obs-mission-top">
              <span class="obs-mission-state {statusClass(selected.status)}">
                <span class="obs-pulse" aria-hidden="true"></span>
                {statusCopy[selected.status]}
              </span>
              <span class="obs-chip">{autonomyCopy[selected.autonomy]}</span>
              {#if selected.training}
                <span class="obs-chip acid">training</span>
              {/if}
              <button class="obs-icon-btn" type="button" aria-label="close mission" onclick={() => { selected = null; agent = null; }} style="margin-left:auto">
                <Icon name="x" size={13} />
              </button>
            </div>
            <h2 class="obs-mission-detail-title">{selected.title}</h2>
            <div class="obs-mission-target">
              <Icon name="target" size={11} />
              <span>{selected.target}</span>
            </div>
            <p class="obs-mission-detail-objective">
              {selected.objective || 'No objective written yet. Edit the mission to describe what proof would count as success.'}
            </p>
            <div class="obs-mission-detail-actions">
              {#if selected.status !== 'done' && selected.status !== 'archived'}
                {#if selected.training}
                  <button class="obs-btn obs-btn-primary" type="button" disabled={agentBusy === 'start'} onclick={() => void startAgent()}>
                    <Icon name="activity" size={13} />
                    {agentBusy === 'start' ? 'Planning...' : 'Continue training'}
                  </button>
                  <button class="obs-btn" type="button" disabled={agentBusy === 'lab'} onclick={() => void runNextLab()}>
                    <Icon name="crosshair" size={13} />
                    {agentBusy === 'lab' ? 'Starting...' : 'Run next lab'}
                  </button>
                {:else}
                  <button class="obs-btn obs-btn-primary" type="button" disabled={busy === 'launch'} onclick={() => void launch()}>
                    <Icon name="activity" size={13} />
                    {busy === 'launch' ? 'Starting...' : 'Launch cast'}
                  </button>
                {/if}
              {/if}
              {#if selected.status === 'draft' || selected.status === 'paused'}
                <button class="obs-btn" type="button" disabled={busy.startsWith('status:')} onclick={() => void transition('active')}>
                  <Icon name="play" size={12} />
                  {selected.status === 'paused' ? 'Resume' : 'Activate'}
                </button>
              {:else if selected.status === 'active'}
                <button class="obs-btn" type="button" disabled={busy.startsWith('status:')} onclick={() => void transition('paused')}>
                  <Icon name="pause" size={12} />
                  Pause
                </button>
              {/if}
              {#if selected.status !== 'done' && selected.status !== 'archived'}
                <button class="obs-btn obs-btn-ghost" type="button" disabled={busy.startsWith('status:')} onclick={() => void transition('done')}>
                  <Icon name="check" size={12} />
                  Close
                </button>
              {/if}
            </div>
          </header>

          <div class="obs-detail-tabs" role="tablist" aria-label="mission detail tabs">
            {#each [
              ['overview', 'Overview'],
              ['runs', `Runs ${selected.run_count}`],
              ['approvals', `Approvals ${selected.pending_approvals}`],
              ['agent', `Agent${agent && ['planning', 'running', 'paused', 'stopping'].includes(agent.status) ? ' *' : ''}`]
            ] as [id, label] (id)}
              <button
                class="obs-detail-tab"
                class:active={detailTab === id}
                type="button"
                role="tab"
                aria-selected={detailTab === id}
                onclick={() => selectTab(id as typeof detailTab)}
              >
                {label}
              </button>
            {/each}
          </div>

          <div class="obs-mission-detail-body">
            {#if detailTab === 'overview'}
              <section class="obs-detail-section">
                <h3>Scope</h3>
                {#if selected.scope.length}
                  <div class="obs-scope-chips" style="padding:0;border:0">
                    {#each selected.scope as item (item)}
                      <span class="obs-chip">{item}</span>
                    {/each}
                  </div>
                {:else}
                  <p>No scope entries recorded. The target is the only declared boundary.</p>
                {/if}
              </section>
              <section class="obs-detail-section">
                <h3>Guardrails</h3>
                <div class="obs-detail-grid">
                  <div><span>Autonomy</span><strong>{autonomyCopy[selected.autonomy]}</strong></div>
                  <div><span>Budget cap</span><strong>{budgetLabel(selected)}</strong></div>
                  <div><span>Runs</span><strong>{selected.run_count}</strong></div>
                  <div><span>Findings</span><strong>{selected.finding_count}</strong></div>
                </div>
                <p style="margin-top:7px">
                  The mission agent enforces these as runtime caps: a scope check, a task cap, a wall-clock cap, and a model-call cap. It never runs a destructive tool, creates a finding, or spends an approval.
                </p>
              </section>
              <section class="obs-detail-section">
                <h3>Plan</h3>
                <p>
                  {selected.training
                    ? 'This is a training mission. Starting it selects the next labs, matches public-research techniques, reads capability gaps, and verifies the session. It does not crawl the target or mark a lab solved; solved labs still need evidence and a lesson.'
                    : selected.plan.length
                      ? 'A plan is attached to this mission. Starting the agent stores its own bounded task plan and verifier alongside it.'
                      : 'The agent builds the plan when you start it: scope check, one live probe, a read-only inventory, an optional advisory analysis, and an independent verifier. The tasks and their evidence are kept on the mission.'}
                </p>
              </section>
              <section class="obs-detail-section">
                <h3>Timeline</h3>
                <div class="obs-detail-grid">
                  <div><span>Created</span><strong>{ago(selected.created_at)}</strong></div>
                  <div><span>Updated</span><strong>{ago(selected.updated_at)}</strong></div>
                  <div><span>Started</span><strong>{selected.started_at ? ago(selected.started_at) : 'not started'}</strong></div>
                  <div><span>Finished</span><strong>{selected.finished_at ? ago(selected.finished_at) : 'open'}</strong></div>
                </div>
              </section>
            {:else if detailTab === 'runs'}
              {#if selected.runs && selected.runs.length}
                <div class="obs-detail-runs">
                  {#each selected.runs as run (run.id)}
                    <button class="obs-detail-run" type="button" onclick={() => store.watch(run.id)}>
                      <span class="obs-ledger-signal" style="background:{run.status === 'done' ? 'var(--obs-acid)' : 'var(--obs-violet)'}" aria-hidden="true"></span>
                      <span>
                        <span class="obs-ledger-target">{run.target}</span>
                        <span class="obs-ledger-sub">
                          <span>{statusLabel(run.status)}</span>
                          <span>-</span>
                          <span>{run.counts?.pages ?? 0} pages</span>
                          <span>-</span>
                          <span>{run.counts?.candidates ?? 0} signals</span>
                        </span>
                      </span>
                      <Icon name="arrow-right" size={11} />
                    </button>
                  {/each}
                </div>
              {:else}
                <div class="obs-empty" style="min-height:170px">
                  <span class="obs-empty-icon"><Icon name="activity" size={18} /></span>
                  <div class="obs-empty-title">{selected.training ? 'No training session yet' : 'No run attached'}</div>
                  <p class="obs-empty-copy">
                    {selected.training
                      ? 'A training session selects the next labs, matches research techniques, and reads the capability gaps. It does not crawl the target.'
                      : "Launching a cast starts a real scan with this mission's target and links it here."}
                  </p>
                  <button class="obs-btn" type="button" onclick={() => selected?.training ? void startAgent() : void launch()}>
                    {selected.training ? 'Plan the next session' : 'Launch the first cast'}
                  </button>
                </div>
              {/if}
            {:else if detailTab === 'agent'}
              <section class="obs-detail-section">
                <div class="obs-mission-agent-head">
                  <span class="obs-mission-agent-state is-{agent?.status ?? 'idle'}">
                    <span class="obs-pulse" aria-hidden="true"></span>
                    {agentCopy[agent?.status ?? 'idle']}
                  </span>
                  {#if agent?.live}<span class="obs-chip acid">live</span>{/if}
                  {#if agent?.phase && ['scope', 'probe', 'inventory', 'analysis', 'verify'].includes(agent.phase)}
                    <span class="obs-chip">{agent.phase}</span>
                  {/if}
                  {#if agent?.stale}<span class="obs-chip violet">orphaned thread</span>{/if}
                </div>
                <p class="obs-mission-agent-summary">
                  {#if agentLoading}
                    Reading the runtime state...
                  {:else if agent}
                    {agent.summary || agent.last_error || 'No summary yet. Start the agent to run the bounded plan.'}
                  {:else}
                    No runtime state yet. The agent plans, executes, and verifies on this mission only.
                  {/if}
                </p>
                <div class="obs-mission-agent-controls">
                  {#if !agent || ['idle', 'stopped', 'error', 'interrupted', 'done'].includes(agent.status)}
                    <button class="obs-btn obs-btn-primary" type="button" disabled={agentBusy === 'start'} onclick={() => void startAgent()}>
                      <Icon name="play" size={12} />
                      {agentBusy === 'start' ? 'Planning...' : agent?.status === 'done' ? (selected.training ? 'Plan another session' : 'Run again') : (selected.training ? 'Plan a training session' : 'Start agent')}
                    </button>
                  {:else if agent.status === 'paused'}
                    <button class="obs-btn obs-btn-primary" type="button" disabled={agentBusy === 'resume'} onclick={() => void controlAgent('resume')}>
                      <Icon name="play" size={12} />
                      {agentBusy === 'resume' ? 'Resuming...' : 'Resume'}
                    </button>
                    <button class="obs-btn obs-btn-ghost" type="button" disabled={agentBusy === 'stop'} onclick={() => void controlAgent('stop')}>
                      <Icon name="stop" size={11} />
                      Stop
                    </button>
                  {:else if agent.status === 'running' || agent.status === 'planning'}
                    <button class="obs-btn" type="button" disabled={agentBusy === 'pause'} onclick={() => void controlAgent('pause')}>
                      <Icon name="pause" size={12} />
                      {agentBusy === 'pause' ? 'Pausing...' : 'Pause'}
                    </button>
                    <button class="obs-btn obs-btn-ghost" type="button" disabled={agentBusy === 'stop'} onclick={() => void controlAgent('stop')}>
                      <Icon name="stop" size={11} />
                      Stop
                    </button>
                  {:else if agent.status === 'stopping'}
                    <span class="obs-chip">stopping after the current task...</span>
                  {/if}
                  <button class="obs-btn obs-btn-ghost" type="button" disabled={agentLoading} onclick={() => void loadAgent()}>
                    <Icon name="refresh" size={11} />
                    Refresh
                  </button>
                </div>
                {#if !agent || ['idle', 'done', 'stopped', 'error'].includes(agent.status)}
                  <label class="obs-mission-agent-model">
                    <input type="checkbox" bind:checked={agentModel} />
                    <span>Ask a model for one advisory analysis. It sees the evidence and cannot change it.</span>
                  </label>
                {/if}
              </section>

              {#if agent}
                <section class="obs-detail-section">
                  <h3>Budget</h3>
                  <div class="obs-mission-agent-meters">
                    <div>
                      <div class="obs-mission-agent-meter-label"><span>Tasks</span><strong>{agent.usage.tasks_done}/{agent.budget.max_tasks}</strong></div>
                      <div class="obs-mission-agent-meter"><span style="width:{agentPercent(agent.usage.tasks_done, agent.budget.max_tasks)}%"></span></div>
                    </div>
                    <div>
                      <div class="obs-mission-agent-meter-label"><span>Wall clock</span><strong>{agent.usage.elapsed_seconds}s / {agent.budget.max_seconds}s</strong></div>
                      <div class="obs-mission-agent-meter"><span style="width:{agentPercent(agent.usage.elapsed_seconds, agent.budget.max_seconds)}%"></span></div>
                    </div>
                    <div>
                      <div class="obs-mission-agent-meter-label"><span>Model calls</span><strong>{agent.usage.calls}/{agent.budget.max_model_calls}</strong></div>
                      <div class="obs-mission-agent-meter"><span style="width:{agentPercent(agent.usage.calls, agent.budget.max_model_calls)}%"></span></div>
                    </div>
                  </div>
                  <div class="obs-mission-agent-spend">
                    <span>Recorded spend</span>
                    <strong>{agent.usage.cost_reported ? formatCost(agent.usage.cost_cents) : 'not reported'}</strong>
                    <small>
                      {agent.budget.max_usd ? `Mission cap $${agent.budget.max_usd.toLocaleString()}. ` : ''}
                      {agent.usage.cost_reported
                        ? 'Price reported by the provider.'
                        : 'Providers returned no price. Token counts are recorded; no cost is invented.'}
                    </small>
                  </div>
                </section>

                <section class="obs-detail-section">
                  <h3>Task timeline</h3>
                  <ol class="obs-mission-agent-tasks">
                    {#each agent.tasks as task (task.id)}
                      <li class="obs-mission-agent-task is-{task.status}">
                        <span class="obs-mission-agent-seq">{task.seq + 1}</span>
                        <div class="obs-mission-agent-task-copy">
                          <div class="obs-mission-agent-task-title">{task.title}</div>
                          <div class="obs-mission-agent-task-meta">
                            <span>{task.kind}</span>
                            <span>-</span>
                            <span>{task.risk}</span>
                            {#if task.tool}<span>-</span><span>{task.tool}</span>{/if}
                            <span>-</span>
                            <span>{task.status}</span>
                          </div>
                          {#if task.verifier_notes}<p>{task.verifier_notes}</p>{/if}
                          {#if task.kind === 'analysis' && typeof task.result.advisory === 'string'}
                            <blockquote>{task.result.advisory}</blockquote>
                          {/if}
                        </div>
                        <span
                          class="obs-chip obs-mission-agent-verdict"
                          class:acid={task.verification === 'verified'}
                          class:violet={task.verification === 'advisory'}
                          style={task.status === 'failed' ? 'color:var(--obs-red)' : ''}
                        >
                          {task.verification || task.status}
                        </span>
                      </li>
                    {/each}
                  </ol>
                </section>

                {#if agent.model_calls.length}
                  <section class="obs-detail-section">
                    <h3>Model calls</h3>
                    <div class="obs-mission-agent-calls">
                      {#each agent.model_calls as call (call.id)}
                        <div class="obs-mission-agent-call">
                          <span class="obs-ledger-signal" style="background:{call.status === 'ok' ? 'var(--obs-acid)' : 'var(--obs-red)'}" aria-hidden="true"></span>
                          <div>
                            <strong>{call.provider || 'no provider'} / {call.model || 'none'}</strong>
                            <small>{call.status} - {call.prompt_tokens ?? '?'} in - {call.completion_tokens ?? '?'} out - {formatCost(call.cost_cents)}</small>
                          </div>
                        </div>
                      {/each}
                    </div>
                  </section>
                {/if}

                <p class="obs-mission-agent-note">
                  Every task above is one typed tool call or one recorded model call. The verifier is independent of the executor: reachability is not a finding, and the runtime never writes one.
                </p>
              {/if}
            {:else}
              {#if selectedApprovals.length}
                <div class="obs-detail-approvals">
                  {#each selectedApprovals as approval (approval.id)}
                    <div class="obs-detail-approval">
                      <div class="obs-approval-top">
                        <span class="obs-approval-agent">{approval.requested_by || 'agent'}</span>
                        <span class="obs-chip" style="color:{sevColor(approval.risk)}">{approval.risk}</span>
                        <span class="obs-chip" style="margin-left:auto">{approval.status}</span>
                      </div>
                      <div class="obs-approval-title">{approval.action}</div>
                      <div class="obs-approval-why">{approval.reason || 'No reason recorded.'}</div>
                      {#if approval.status === 'pending'}
                        <div class="obs-approval-actions">
                          <button class="obs-btn obs-btn-primary" type="button" disabled={busy === `approval:${approval.id}`} onclick={() => void decide(approval, 'approved')}>
                            Approve
                          </button>
                          <button class="obs-btn obs-btn-ghost" type="button" disabled={busy === `approval:${approval.id}`} onclick={() => void decide(approval, 'rejected')}>
                            Reject
                          </button>
                        </div>
                      {:else}
                        <div class="obs-approval-meta">
                          <span class="obs-chip">decided {approval.decided_at ? ago(approval.decided_at) : ''}</span>
                        </div>
                      {/if}
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="obs-empty" style="min-height:190px">
                  <span class="obs-empty-icon"><Icon name="shield" size={18} /></span>
                  <div class="obs-empty-title">No approval requested</div>
                  <p class="obs-empty-copy">
                    This queue only fills when an agent asks for a risky action. Nothing is fabricated to make the gate look busy.
                  </p>
                </div>
              {/if}
            {/if}
          </div>
        </aside>
      {/if}
    </div>
  {/if}
</div>

{#if composer}
  <div
    class="obs-modal-veil"
    role="presentation"
    onclick={() => (composer = false)}
    onkeydown={(event) => {
      if (event.key === 'Escape') composer = false;
    }}
  >
    <div
      class="obs-modal"
      role="dialog"
      aria-modal="true"
      aria-label="new mission"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <header class="obs-modal-head">
        <div>
          <div class="obs-eyebrow"><span class="tick"></span> Mission composer</div>
          <h2>Frame the work before the fleet moves.</h2>
          <p>The mission holds the objective, the boundary, and the autonomy level. A cast is launched separately.</p>
        </div>
        <button class="obs-icon-btn" type="button" aria-label="close composer" onclick={() => (composer = false)}>
          <Icon name="x" size={14} />
        </button>
      </header>

      <div class="obs-modal-body">
        <label class="obs-field">
          <span>Mission title</span>
          <input bind:value={form.title} placeholder="Operation Nightfall" />
        </label>
        <label class="obs-field">
          <span>Target</span>
          <input bind:value={form.target} placeholder="app.example.com" />
          <small>Only targets you are authorized to test.</small>
        </label>
        <label class="obs-field">
          <span>Objective</span>
          <textarea bind:value={form.objective} rows="3" placeholder="What proof would count as success? What is explicitly out of bounds?"></textarea>
        </label>

        <div class="obs-field">
          <span>Autonomy</span>
          <div class="obs-autonomy">
            {#each [
              ['manual', 'Manual', 'Every action needs a human.'],
              ['supervised', 'Supervised', 'Low-risk steps run; risky actions gate.'],
              ['autonomous', 'Autonomous', 'Agent plans and executes within policy.']
            ] as [id, label, hint] (id)}
              <button
                class="obs-autonomy-option"
                class:active={form.autonomy === id}
                type="button"
                onclick={() => (form.autonomy = id as Autonomy)}
              >
                <strong>{label}</strong>
                <span>{hint}</span>
              </button>
            {/each}
          </div>
        </div>

        <div class="obs-form-row">
          <label class="obs-field">
            <span>Budget cap (USD)</span>
            <input bind:value={form.budget} type="number" min="0" step="1" placeholder="No cap" />
            <small>A guardrail, not a spend estimate.</small>
          </label>
          <label class="obs-field">
            <span>Scope entries</span>
            <textarea bind:value={form.scope} rows="3" placeholder="One host or URL per line"></textarea>
          </label>
        </div>
      </div>

      <footer class="obs-modal-foot">
        <span class="obs-modal-note">The mission agent enforces scope, task count, wall clock, and model-call caps. The USD figure is a recorded ceiling, not a spend estimate.</span>
        <button class="obs-btn obs-btn-ghost" type="button" onclick={() => (composer = false)}>Cancel</button>
        <button class="obs-btn obs-btn-primary" type="button" disabled={busy === 'create'} onclick={() => void createMission()}>
          <Icon name="plus" size={13} />
          {busy === 'create' ? 'Saving...' : 'Save mission'}
        </button>
      </footer>
    </div>
  </div>
{/if}
