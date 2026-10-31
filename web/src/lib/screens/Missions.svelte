<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { ago, sevColor, statusLabel } from '../format';
  import type { AgentStatus, Approval, Autonomy, Campaign, Direction, ExploitPlan, GraphNode, GraphPath, Mission, MissionAgent, MissionGraph, MissionStatus, ToolCall } from '../types';
  import Icon from '../ui/Icon.svelte';
  import Sparkline from '../ui/Sparkline.svelte';

  type Filter = 'all' | MissionStatus;

  // Evidence graph: layout layers and ink per node kind, kept deterministic
  // so the same graph always draws the same way.
  const GRAPH_LAYERS = ['target', 'host', 'ip', 'endpoint', 'technology',
    'service', 'identity', 'credential', 'hypothesis', 'finding'];
  const GRAPH_COLORS: Record<string, string> = {
    target: 'var(--obs-acid)',
    host: 'var(--obs-violet-3)',
    ip: 'var(--obs-violet-3)',
    endpoint: 'var(--obs-text-2)',
    technology: 'var(--obs-gold)',
    service: 'var(--obs-gold)',
    identity: 'var(--obs-violet)',
    credential: 'var(--obs-red)',
    hypothesis: 'var(--obs-violet-3)',
    finding: 'var(--obs-red)'
  };
  const PATH_COLORS: Record<string, string> = {
    verified: 'var(--obs-acid)',
    refuted: 'var(--obs-red)',
    partial: 'var(--obs-orange)',
    blocked: 'var(--obs-red)',
    verifying: 'var(--obs-violet-3)',
    candidate: 'var(--obs-muted)',
    inconclusive: 'var(--obs-muted)'
  };

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
  let detailTab = $state<'overview' | 'runs' | 'approvals' | 'graph' | 'exploits' | 'console' | 'tools' | 'agent'>('overview');
  let graph = $state<MissionGraph | null>(null);
  let graphBusy = $state('');
  let campaign = $state<Campaign | null>(null);
  let directions = $state<Direction[]>([]);
  let toolCalls = $state<ToolCall[]>([]);
  let directionText = $state('');
  let exploitPlan = $state<ExploitPlan | null>(null);
  let exploitBusy = $state('');
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
      graph = null;
      directions = [];
      toolCalls = [];
      exploitPlan = null;
      detailTab = preserveTab ? tab : 'overview';
      void loadCampaign();
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

  async function runSolve() {
    if (!selected) return;
    busy = 'solve';
    try {
      const run = await api.startMissionSolve(selected.id, { max_steps: 3 });
      store.toast('ok', 'bounded model loop started');
      store.watch(run.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start the model loop');
    } finally {
      busy = '';
    }
  }

  async function runAutopilot() {
    if (!selected) return;
    busy = 'autopilot';
    try {
      const run = await api.startMissionAutopilot(selected.id, {
        max_steps: 8,
        max_seconds: 600,
        max_model_calls: 4
      });
      store.toast('ok', 'native operator started: it will plan, act, and reflect on its own');
      store.watch(run.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start the native operator');
    } finally {
      busy = '';
    }
  }

  async function runSwarm() {
    if (!selected) return;
    busy = 'swarm';
    try {
      const run = await api.startMissionSwarm(selected.id, {
        max_steps: 10,
        max_seconds: 600,
        max_model_calls: 12
      });
      store.toast('ok', 'intelligence mesh started: five roles will plan, act, validate, and remember');
      store.watch(run.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not convene the intelligence mesh');
    } finally {
      busy = '';
    }
  }

  async function runHunt() {
    if (!selected) return;
    busy = 'hunt';
    try {
      const run = await api.startMissionHunt(selected.id);
      store.toast('ok', 'hunt started');
      store.watch(run.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start the hunt');
    } finally {
      busy = '';
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
  }

  // Load a tab's data once per (mission, tab), so switching tabs or missions
  // never shows stale data or races the mission fetch.
  let loadedKey = '';
  $effect(() => {
    const id = selected?.id ?? '';
    if (!id) return;
    const key = `${id}:${detailTab}`;
    if (key === loadedKey) return;
    loadedKey = key;
    if (detailTab === 'graph') void loadGraph();
    else if (detailTab === 'exploits') void loadExploits();
    else if (detailTab === 'console') void loadDirections();
    else if (detailTab === 'tools') void loadTools();
    else if (detailTab === 'agent') void loadAgent();
  });

  async function loadExploits() {
    if (!selected) return;
    exploitBusy = 'load';
    try {
      exploitPlan = await api.exploitPlan(selected.id, 12);
    } catch {
      exploitPlan = null;
    } finally {
      exploitBusy = '';
    }
  }

  async function planExploitLeads() {
    if (!selected) return;
    exploitBusy = 'build';
    try {
      const result = await api.buildExploitLeads(selected.id, 5);
      store.toast('ok', `planned ${result.count} exploit lead(s)`);
      await loadExploits();
      await loadCampaign();
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not plan exploit leads');
    } finally {
      exploitBusy = '';
    }
  }

  function riskColor(risk: string): string {
    return risk === 'critical' ? 'var(--obs-red)'
      : risk === 'high' ? 'var(--obs-orange)'
      : risk === 'medium' ? 'var(--obs-violet-3)' : 'var(--obs-muted)';
  }

  async function loadCampaign() {
    if (!selected) return;
    try {
      campaign = await api.campaign(selected.id);
    } catch {
      campaign = null;
    }
  }

  async function loadDirections() {
    if (!selected) return;
    try {
      directions = (await api.directions(selected.id)).items ?? [];
    } catch {
      directions = [];
    }
  }

  async function queueDirection() {
    if (!selected || !directionText.trim()) return;
    busy = 'direction';
    try {
      await api.queueDirection(selected.id, { body: directionText.trim() });
      directionText = '';
      await loadDirections();
      store.toast('ok', 'direction queued');
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not queue the direction');
    } finally {
      busy = '';
    }
  }

  async function loadTools() {
    if (!selected) return;
    try {
      toolCalls = (await api.toolCalls(`?mission_id=${selected.id}&limit=60`)).items ?? [];
    } catch {
      toolCalls = [];
    }
  }

  async function loadGraph() {
    if (!selected) return;
    graphBusy = 'load';
    try {
      graph = await api.missionGraph(selected.id);
    } catch {
      graph = null;
    } finally {
      graphBusy = '';
    }
  }

  async function buildGraph() {
    if (!selected) return;
    graphBusy = 'build';
    try {
      const summary = await api.buildMissionGraph(selected.id);
      graph = await api.missionGraph(selected.id);
      store.toast('ok', `graph: ${summary.nodes} nodes, ${summary.edges} edges, ${summary.paths} path(s)`);
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not build the graph');
    } finally {
      graphBusy = '';
    }
  }

  async function verifyPath(path: GraphPath) {
    graphBusy = path.id;
    try {
      const run = await api.verifyPath(path.id, {});
      store.toast('ok', 'path verification started');
      store.watch(run.id);
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not verify the path');
    } finally {
      graphBusy = '';
    }
  }

  const graphLayout = $derived.by(() => {
    const nodes = graph?.nodes ?? [];
    const edges = graph?.edges ?? [];
    const buckets = new Map<string, GraphNode[]>();
    for (const node of nodes) {
      const list = buckets.get(node.kind) ?? [];
      list.push(node);
      buckets.set(node.kind, list);
    }
    const layers = GRAPH_LAYERS.filter((kind) => (buckets.get(kind)?.length ?? 0) > 0);
    const W = 640;
    const H = 300;
    const pos = new Map<string, { x: number; y: number }>();
    layers.forEach((kind, li) => {
      const list = buckets.get(kind) ?? [];
      const x = layers.length === 1 ? W / 2 : 46 + li * ((W - 92) / (layers.length - 1));
      list.forEach((node, ni) => {
        const y = 28 + ((ni + 0.5) * (H - 56)) / list.length;
        pos.set(node.id, { x, y });
      });
    });
    const lines: Array<{ id: string; x1: number; y1: number; x2: number; y2: number; kind: string }> = [];
    for (const edge of edges) {
      const a = pos.get(edge.src);
      const b = pos.get(edge.dst);
      if (a && b) lines.push({ id: edge.id, x1: a.x, y1: a.y, x2: b.x, y2: b.y, kind: edge.kind });
    }
    const dots: Array<{ id: string; x: number; y: number; kind: string; label: string; color: string; severity: string; layerCount: number }> = [];
    for (const node of nodes) {
      const p = pos.get(node.id);
      const layerCount = (buckets.get(node.kind) ?? []).length;
      if (p) dots.push({
        id: node.id, x: p.x, y: p.y, kind: node.kind,
        label: node.label || node.key,
        color: GRAPH_COLORS[node.kind] ?? 'var(--obs-muted)',
        severity: node.severity, layerCount
      });
    }
    return { W, H, lines, dots, layers };
  });

  function pathStateColor(state: string): string {
    return PATH_COLORS[state] ?? 'var(--obs-muted)';
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
                  <button class="obs-btn obs-btn-primary" type="button" disabled={busy === 'hunt'} onclick={() => void runHunt()}>
                    <Icon name="crosshair" size={13} />
                    {busy === 'hunt' ? 'Hunting...' : 'Hunt now'}
                  </button>
                  <button class="obs-btn obs-btn-autopilot" type="button" disabled={busy === 'autopilot'} onclick={() => void runAutopilot()}>
                    <Icon name="bot" size={13} />
                    {busy === 'autopilot' ? 'Thinking...' : 'Autopilot'}
                  </button>
                  <button class="obs-btn obs-btn-swarm" type="button" disabled={busy === 'swarm'} onclick={() => void runSwarm()}>
                    <Icon name="activity" size={13} />
                    {busy === 'swarm' ? 'Convening...' : 'Swarm'}
                  </button>
                  <button class="obs-btn" type="button" disabled={busy === 'solve'} onclick={() => void runSolve()}>
                    <Icon name="bot" size={13} />
                    {busy === 'solve' ? 'Solving...' : 'Model loop'}
                  </button>
                  <button class="obs-btn" type="button" disabled={busy === 'launch'} onclick={() => void launch()}>
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
              ['graph', 'Graph'],
              ['exploits', 'Exploits'],
              ['console', 'Console'],
              ['tools', 'Tools'],
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
            {:else if detailTab === 'graph'}
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Attack graph</h3>
                    <p class="obs-graph-copy">
                      Nodes and edges are derived from real evidence, and every edge carries its provenance. Verification runs each step through the same scoped, risk-gated tools and never creates a finding.
                    </p>
                  </div>
                  <button class="obs-btn" type="button" disabled={graphBusy !== ''} onclick={() => void buildGraph()}>
                    <Icon name="activity" size={12} />
                    {graphBusy === 'build' ? 'Building...' : 'Build graph'}
                  </button>
                </div>
                {#if graph && graph.nodes.length}
                  <div class="obs-graph-chips">
                    <span class="obs-chip">{graph.nodes.length} nodes</span>
                    <span class="obs-chip">{graph.edges.length} edges</span>
                    <span class="obs-chip">{graph.paths.length} path{graph.paths.length === 1 ? '' : 's'}</span>
                  </div>
                  <svg class="obs-graph-svg" viewBox="0 0 {graphLayout.W} {graphLayout.H}" role="img" aria-label="mission attack graph">
                    {#each graphLayout.lines as line (line.id)}
                      <line x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2} stroke="var(--obs-line-strong)" stroke-width="1" />
                    {/each}
                    {#each graphLayout.dots as dot (dot.id)}
                      <g>
                        <title>{dot.kind}: {dot.label}{dot.severity ? ` (${dot.severity})` : ''}</title>
                        <circle cx={dot.x} cy={dot.y} r="6" fill={dot.color} fill-opacity="0.16" stroke={dot.color} stroke-width="1.3" />
                        {#if dot.layerCount <= 6}
                          <text x={dot.x} y={dot.y + 18} text-anchor="middle" class="obs-graph-label" style="fill:{dot.color}">{dot.label.length > 16 ? `${dot.label.slice(0, 15)}...` : dot.label}</text>
                        {/if}
                      </g>
                    {/each}
                  </svg>
                {:else}
                  <div class="obs-empty" style="min-height:130px">
                    <span class="obs-empty-icon"><Icon name="activity" size={16} /></span>
                    <div class="obs-empty-title">No graph yet</div>
                    <p class="obs-empty-copy">
                      Build the graph to derive the surface, the open leads, and the findings for this mission.
                    </p>
                  </div>
                {/if}
                <h3 style="margin-top:14px">Candidate paths</h3>
                {#if graph && graph.paths.length}
                  <ul class="obs-graph-paths">
                    {#each graph.paths as path (path.id)}
                      <li>
                        <div class="obs-graph-path-head">
                          <span class="obs-chip" style="color:{pathStateColor(path.state)}">{path.state}</span>
                          <span class="obs-graph-path-title">{path.title}</span>
                          <button class="obs-btn obs-btn-ghost" type="button" disabled={graphBusy !== ''} onclick={() => void verifyPath(path)}>
                            {graphBusy === path.id ? 'Starting...' : 'Verify'}
                          </button>
                        </div>
                        <p class="obs-graph-path-steps">
                          {path.steps.map((step) => step.goal || step.kind || 'step').join(' -> ')}
                        </p>
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <p class="obs-detail-note">
                    No candidate path yet. Record a falsifiable lead with hypothesis_create, then rebuild the graph.
                  </p>
                {/if}
              </section>
            {:else if detailTab === 'exploits'}
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Exploit modules</h3>
                    <p class="obs-graph-copy">
                      The catalog matched to what this mission actually observed. A module is a test to run, not a finding; a ready module became a falsifiable lead.
                    </p>
                  </div>
                  <button class="obs-btn obs-btn-primary" type="button" disabled={exploitBusy !== ''} onclick={() => void planExploitLeads()}>
                    <Icon name="crosshair" size={12} />
                    {exploitBusy === 'build' ? 'Planning...' : 'Plan leads'}
                  </button>
                </div>
                {#if exploitPlan}
                  <div class="obs-graph-chips">
                    <span class="obs-chip">{exploitPlan.proposals.filter((p) => p.ready).length} ready</span>
                    <span class="obs-chip">{exploitPlan.proposals.length} matched</span>
                    <span class="obs-chip">{exploitPlan.endpoints} endpoints</span>
                    <span class="obs-chip">{exploitPlan.open_leads} open lead(s)</span>
                    {#if exploitPlan.tech.length}
                      <span class="obs-chip">tech: {exploitPlan.tech.slice(0, 4).join(', ')}</span>
                    {/if}
                  </div>
                  <ul class="obs-graph-paths">
                    {#each exploitPlan.proposals as module (module.id)}
                      <li>
                        <div class="obs-graph-path-head">
                          <span class="obs-chip" style="color:{module.ready ? 'var(--obs-acid)' : 'var(--obs-muted)'}">{module.ready ? 'ready' : 'blocked'}</span>
                          <span class="obs-chip" style="color:{riskColor(module.risk)}">{module.risk}</span>
                          <span class="obs-graph-path-title">{module.name}</span>
                          <span class="obs-chip">{module.category}</span>
                        </div>
                        <p class="obs-graph-path-steps">
                          {module.evidence}
                          {#if module.blocked_reason} - {module.blocked_reason}{/if}
                        </p>
                        {#if module.steps.length}
                          <p class="obs-graph-path-steps">steps: {module.steps.map((s) => s.tool).join(' -> ')}</p>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <div class="obs-empty" style="min-height:120px">
                    <span class="obs-empty-icon"><Icon name="crosshair" size={16} /></span>
                    <div class="obs-empty-title">No plan yet</div>
                    <p class="obs-empty-copy">Load the exploit plan to match the catalog to this mission's technology and leads.</p>
                  </div>
                {/if}
              </section>
            {:else if detailTab === 'console'}
              <section class="obs-detail-section">
                <h3>Operator console</h3>
                {#if campaign}
                  <div class="obs-graph-chips">
                    <span class="obs-chip" style="color:var(--obs-acid)">{campaign.stage}</span>
                    <span class="obs-chip">{campaign.mode}</span>
                    <span class="obs-chip">{campaign.endpoints} endpoints</span>
                    <span class="obs-chip">{campaign.open_leads} open lead(s)</span>
                  </div>
                  <p class="obs-detail-note">{campaign.reason}</p>
                {/if}
                <p class="obs-detail-note">
                  Queue a direction. The director hands the next run the first queued direction, and every brain reads it in its brief. Mention a specific lead or finding with @lead:&lt;id&gt; or @finding:&lt;id&gt;.
                </p>
                <textarea
                  class="obs-input obs-console-input"
                  rows="2"
                  bind:value={directionText}
                  placeholder="e.g. focus the order API and test IDOR on /api/orders/7"
                ></textarea>
                <div class="obs-console-actions">
                  <button class="obs-btn obs-btn-primary" type="button" disabled={!directionText.trim() || busy === 'direction'} onclick={() => void queueDirection()}>
                    <Icon name="arrow-right" size={12} />
                    {busy === 'direction' ? 'Queueing...' : 'Queue direction'}
                  </button>
                  <button class="obs-btn obs-btn-ghost" type="button" disabled={busy === 'direction'} onclick={() => void loadDirections()}>
                    Refresh
                  </button>
                </div>
                {#if directions.length}
                  <ul class="obs-console-list">
                    {#each directions as direction (direction.id)}
                      <li>
                        <span class="obs-chip" style="color:{direction.status === 'queued' ? 'var(--obs-acid)' : 'var(--obs-muted)'}">{direction.status}</span>
                        <span class="obs-console-body">{direction.body}</span>
                        {#if direction.mentions.length}
                          <span class="obs-console-mentions">{direction.mentions.map((m) => `@${m.kind}:${m.id}`).join(' ')}</span>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <p class="obs-detail-note">Nothing queued for this mission.</p>
                {/if}
              </section>
            {:else if detailTab === 'tools'}
              <section class="obs-detail-section">
                <h3>Tool results</h3>
                <p class="obs-detail-note">
                  Every scoped call the harness made for this mission, newest first, with its status and duration. The full audit, not a summary.
                </p>
                {#if toolCalls.length}
                  <ul class="obs-tool-list">
                    {#each toolCalls as call (call.id)}
                      <li>
                        <span class="obs-chip" style="color:{call.status === 'ok' ? 'var(--obs-acid)' : call.status === 'denied' ? 'var(--obs-red)' : 'var(--obs-muted)'}">{call.tool}</span>
                        <span class="obs-tool-status">{call.status}{call.risk !== 'low' ? ` / ${call.risk}` : ''}</span>
                        <span class="obs-tool-target">{String(call.args?.target ?? call.args?.mission_id ?? '')}</span>
                        <span class="obs-tool-ms">{call.duration_ms} ms</span>
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <p class="obs-detail-note">No tool calls recorded yet.</p>
                {/if}
              </section>
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
