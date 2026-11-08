<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { ago, sevColor, statusLabel } from '../format';
  import type { AgentStatus, Approval, Autonomy, Campaign, Candidate, CoverageSummary, Direction, ExploitPlan, GraphNode, GraphPath, Hypothesis, HypothesisEvidence, Mission, MissionAgent, MissionGraph, MissionStatus, ProgramImport, ProgramPreview, ToolCall , ThreatMap } from '../types';
  import Buffering from '../ui/Buffering.svelte';
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
  let detailTab = $state<'overview' | 'runs' | 'approvals' | 'graph' | 'leads' | 'exploits' | 'candidates' | 'coverage' | 'program' | 'console' | 'tools' | 'agent'>('overview');
  let graph = $state<MissionGraph | null>(null);
  let threatMap = $state<ThreatMap | null>(null);
  let graphBusy = $state('');
  let hypotheses = $state<Hypothesis[]>([]);
  let hypothesisEvidence = $state<HypothesisEvidence | null>(null);
  let selectedHypothesis = $state('');
  let leadsBusy = $state('');
  let showArchivedLeads = $state(false);
  const visibleHypotheses = $derived(
    showArchivedLeads
      ? hypotheses
      : hypotheses.filter((item) => item.status !== 'archived' && item.technique !== 'observation')
  );
  let coverage = $state<CoverageSummary | null>(null);
  let coverageBusy = $state('');
  let programBrief = $state('');
  let programFilename = $state('');
  let programPlatform = $state('other');
  let programAllowExpand = $state(false);
  let programPreview = $state<ProgramPreview | null>(null);
  let programHistory = $state<ProgramImport[]>([]);
  let programBusy = $state('');
  let seedHosts = $state('');
  let seedBusy = $state(false);
  let seedResult = $state<{ accepted: number; hosts_live: number; hosts_unresolved: number; hosts_rejected: number; rejected: string[] } | null>(null);
  let campaign = $state<Campaign | null>(null);
  let directions = $state<Direction[]>([]);
  let toolCalls = $state<ToolCall[]>([]);
  let directionText = $state('');
  let exploitPlan = $state<ExploitPlan | null>(null);
  let exploitBusy = $state('');
  let candidates = $state<Candidate[]>([]);
  let candidateBusy = $state('');
  let composer = $state(false);
  let busy = $state('');
  let form = $state({
    title: '',
    target: '',
    objective: '',
    autonomy: 'autonomous' as Autonomy,
    unrestricted: true,
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
      const changedMission = selected?.id !== mission.id;
      selected = await api.mission(mission.id);
      if (changedMission) {
        programPreview = null;
        programBrief = '';
        coverage = null;
        hypotheses = [];
        hypothesisEvidence = null;
        selectedHypothesis = '';
      }
      agent = null;
      graph = null;
      threatMap = null;
      directions = [];
      toolCalls = [];
      exploitPlan = null;
      candidates = [];
      detailTab = preserveTab ? tab : 'overview';
      void loadCampaign();
      void loadGraph();
      void loadLeads();
      void loadThreatMap();
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
      const run = await api.startMissionAutopilot(selected.id, { endless: true });
      store.toast('ok', 'endless operator started: it plans, acts, and rotates techniques until you stop it');
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
      const run = await api.startMissionSwarm(selected.id, { endless: true });
      store.toast('ok', 'endless intelligence mesh started: five roles plan, act, validate, and rotate techniques until you stop it');
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
    else if (detailTab === 'leads') void loadLeads();
    else if (detailTab === 'exploits') void loadExploits();
    else if (detailTab === 'candidates') void loadCandidates();
    else if (detailTab === 'coverage') void loadCoverage();
    else if (detailTab === 'program') void loadProgramHistory();
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

  async function runModule(module: { id: string }) {
    if (!selected) return;
    exploitBusy = module.id;
    try {
      const run = await api.exploitRun(selected.id, module.id,
        selected.autonomy === 'autonomous' ? 'full' : 'supervised');
      store.toast('ok', `running ${module.id}`);
      store.watch(run.id);
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not run the module');
    } finally {
      exploitBusy = '';
    }
  }

  async function loadCandidates() {
    if (!selected) return;
    try {
      candidates = (await api.candidates(selected.id)).items ?? [];
    } catch {
      candidates = [];
    }
  }

  async function promoteCandidate(candidate: Candidate) {
    if (!selected) return;
    candidateBusy = candidate.id;
    try {
      const result = await api.promoteCandidate(candidate.id, {});
      store.toast('ok', `promoted to a ${result.finding.severity} finding`);
      await loadCandidates();
      void store.refreshTotals();
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not promote the candidate');
    } finally {
      candidateBusy = '';
    }
  }

  async function dismissCandidate(candidate: Candidate) {
    candidateBusy = candidate.id;
    try {
      await api.dismissCandidate(candidate.id);
      await loadCandidates();
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not dismiss the candidate');
    } finally {
      candidateBusy = '';
    }
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

  async function loadThreatMap() {
    if (!selected) return;
    try { threatMap = await api.threatMap(selected.id); } catch { threatMap = null; }
  }

  async function loadCoverage() {
    if (!selected) return;
    coverageBusy = 'load';
    try {
      coverage = await api.missionCoverage(selected.id);
    } catch {
      coverage = null;
    } finally {
      coverageBusy = '';
    }
  }

  async function loadProgramHistory() {
    if (!selected) return;
    try {
      programHistory = (await api.programImports(selected.id)).items;
    } catch {
      programHistory = [];
    }
  }

  function programBody() {
    return {
      brief: programBrief,
      filename: programFilename,
      platform: programPlatform,
      allow_expand: programAllowExpand
    };
  }

  async function loadLeads() {
    if (!selected) return;
    leadsBusy = 'load';
    try {
      hypotheses = (await api.hypotheses(selected.id)).items;
      const visible = hypotheses.filter((item) => item.status !== 'archived'
        && item.technique !== 'observation');
      const current = hypotheses.find((item) => item.id === selectedHypothesis);
      const first = current ?? visible.find((item) => item.status === 'open') ?? visible[0] ?? hypotheses[0];
      selectedHypothesis = first?.id ?? '';
      hypothesisEvidence = first ? await api.hypothesisEvidence(first.id) : null;
    } catch {
      hypotheses = [];
      hypothesisEvidence = null;
      selectedHypothesis = '';
    } finally {
      leadsBusy = '';
    }
  }

  async function syncLeads() {
    if (!selected) return;
    leadsBusy = 'sync';
    try {
      const result = await api.syncLeads(selected.id, 3);
      store.toast('ok', `${result.counts.created} new lead(s) from recorded observations`);
      await loadLeads();
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not sync leads');
    } finally {
      leadsBusy = '';
    }
  }

  async function openHypothesis(id: string) {
    selectedHypothesis = id;
    leadsBusy = id;
    try {
      hypothesisEvidence = await api.hypothesisEvidence(id);
    } catch {
      hypothesisEvidence = null;
    } finally {
      leadsBusy = '';
    }
  }

  function callDetail(call: ToolCall): string {
    const result = call.result as Record<string, unknown> | null;
    const status = result && typeof result === 'object' ? result.status : '';
    const target = String(call.args?.target || call.error || '');
    const method = String(call.args?.method || 'GET');
    return `${method} ${target}${status !== '' && status !== undefined ? ` -> HTTP ${status}` : ''}`;
  }

  const openLeads = $derived(
    hypotheses
      .filter((h) => h.status === 'open' && h.technique !== 'observation')
      .slice(0, 4)
  );
  const topPath = $derived(graph?.paths?.[0] ?? null);

  function leadStatusColor(status: string): string {
    if (status === 'supported' || status === 'promoted') return 'var(--obs-acid)';
    if (status === 'refuted') return 'var(--obs-red)';
    if (status === 'inconclusive') return 'var(--obs-orange)';
    return 'var(--obs-violet-3)';
  }

  function verdictColor(verdict: string): string {
    if (verdict === 'supported' || verdict === 'proven') return 'var(--obs-acid)';
    if (verdict === 'edge-blocked' || verdict === 'blocked') return 'var(--obs-orange)';
    if (verdict === 'redirect-only' || verdict === 'callback-seen') return 'var(--obs-cyan, #19d3da)';
    if (verdict === 'untested') return 'var(--obs-faint)';
    if (verdict === 'unavailable') return 'var(--obs-red)';
    return 'var(--obs-violet-3)';
  }

  async function previewProgram() {
    if (!selected) return;
    if (!programBrief.trim()) {
      store.toast('warn', 'paste a CSV, JSON export, or programme brief first');
      return;
    }
    programBusy = 'preview';
    try {
      programPreview = await api.programPreview(selected.id, programBody());
      const diff = programPreview.diff;
      store.toast('ok', `${diff.add_in_scope.length} in scope, ${diff.add_exclusions.length} exclusion(s)${diff.requires_allow_expand.length ? `, ${diff.requires_allow_expand.length} would expand` : ''}`);
    } catch (exc) {
      programPreview = null;
      void store.fail(exc instanceof Error ? exc.message : 'could not parse the brief');
    } finally {
      programBusy = '';
    }
  }

  async function importProgram() {
    if (!selected) return;
    if (!programBrief.trim()) {
      store.toast('warn', 'paste a CSV, JSON export, or programme brief first');
      return;
    }
    programBusy = 'apply';
    try {
      const result = await api.programImport(selected.id, programBody());
      programPreview = result;
      selected = await api.mission(selected.id);
      void loadProgramHistory();
      const added = result.applied?.added ?? 0;
      store.toast('ok', `scope updated: ${added} entr${added === 1 ? 'y' : 'ies'}`);
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not apply the brief');
    } finally {
      programBusy = '';
    }
  }

  async function seedSurface() {
    if (!selected) return;
    const hosts = Array.from(new Set(
      seedHosts.split(/[\s,;]+/).map((item) => item.trim()).filter(Boolean)
    )).slice(0, 500);
    if (!hosts.length) {
      store.toast('warn', 'paste at least one host from the programme or a CT export');
      return;
    }
    seedBusy = true;
    try {
      const result = await api.surfaceSeed(selected.id, hosts);
      seedResult = result;
      selected = await api.mission(selected.id);
      await Promise.all([loadGraph(), loadLeads()]);
      store.toast('ok', `${result.hosts_live} live of ${result.accepted} in scope${result.hosts_rejected ? `, ${result.hosts_rejected} out of scope` : ''}`);
    } catch (exc) {
      void store.fail(exc instanceof Error ? exc.message : 'could not seed the surface');
    } finally {
      seedBusy = false;
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
    form = { title: '', target: '', objective: '', autonomy: 'autonomous', unrestricted: true, budget: '', scope: '' };
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
        unrestricted: form.unrestricted,
        status: 'active',
        budget: Number.isFinite(cap) && cap > 0 ? { max_usd: cap } : {},
        scope: form.scope
          .split(/[\n,]/)
          .map((item) => item.trim())
          .filter(Boolean)
      });
      composer = false;
      resetForm();
      store.toast('ok', 'mission created and in pursuit');
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
      <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.go('new')}>
        <Icon name="crosshair" size={13} />
        Engage target
      </button>
      <button class="obs-btn obs-btn-ghost" type="button" onclick={startComposer} title="advanced draft without auto-engage">
        Draft only
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
    <div class="obs-card obs-empty" style="min-height:360px; gap:14px">
      <Buffering
        variant="block"
        tone="quiet"
        label="Loading portfolio"
        detail="Reading missions and approval state from the control plane."
      />
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

            <h3 class="obs-mission-title" title={mission.title}>{mission.title}</h3>
            <div class="obs-mission-target">
              <Icon name="globe" size={11} />
              <span title={mission.target}>{mission.target}</span>
            </div>
            <p
              class="obs-mission-objective"
              title={mission.objective || undefined}
            >
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
            <h2 class="obs-mission-detail-title" title={selected.title}>{selected.title}</h2>
            <div class="obs-mission-target">
              <Icon name="target" size={11} />
              <span title={selected.target}>{selected.target}</span>
            </div>
            <p class="obs-mission-detail-objective" title={selected.objective || undefined}>
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
                  <button
                    class="obs-btn obs-btn-primary"
                    class:is-busy={busy === 'hunt'}
                    type="button"
                    disabled={busy === 'hunt'}
                    aria-busy={busy === 'hunt'}
                    onclick={() => void runHunt()}
                  >
                    {#if busy !== 'hunt'}<Icon name="crosshair" size={13} />{/if}
                    {busy === 'hunt' ? 'Hunting' : 'Hunt now'}
                  </button>
                  <button
                    class="obs-btn obs-btn-autopilot"
                    class:is-busy={busy === 'autopilot'}
                    type="button"
                    disabled={busy === 'autopilot'}
                    aria-busy={busy === 'autopilot'}
                    onclick={() => void runAutopilot()}
                  >
                    {#if busy !== 'autopilot'}<Icon name="bot" size={13} />{/if}
                    {busy === 'autopilot' ? 'Thinking' : 'Autopilot'}
                  </button>
                  <button
                    class="obs-btn obs-btn-swarm"
                    class:is-busy={busy === 'swarm'}
                    type="button"
                    disabled={busy === 'swarm'}
                    aria-busy={busy === 'swarm'}
                    onclick={() => void runSwarm()}
                  >
                    {#if busy !== 'swarm'}<Icon name="activity" size={13} />{/if}
                    {busy === 'swarm' ? 'Convening' : 'Swarm'}
                  </button>
                  <button
                    class="obs-btn"
                    class:is-busy={busy === 'solve'}
                    type="button"
                    disabled={busy === 'solve'}
                    aria-busy={busy === 'solve'}
                    onclick={() => void runSolve()}
                  >
                    {#if busy !== 'solve'}<Icon name="bot" size={13} />{/if}
                    {busy === 'solve' ? 'Solving' : 'Model loop'}
                  </button>
                  <button
                    class="obs-btn"
                    class:is-busy={busy === 'launch'}
                    type="button"
                    disabled={busy === 'launch'}
                    aria-busy={busy === 'launch'}
                    onclick={() => void launch()}
                  >
                    {#if busy !== 'launch'}<Icon name="activity" size={13} />{/if}
                    {busy === 'launch' ? 'Starting' : 'Launch cast'}
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
              ['leads', 'Leads'],
              ['exploits', 'Exploits'],
              ['candidates', 'Candidates'],
              ['coverage', 'Coverage'],
              ['program', 'Program'],
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
              <section class="obs-detail-section obs-huntmap" aria-label="hunt map">
                <div class="obs-graph-head">
                  <div>
                    <h3>Hunt map</h3>
                    <p class="obs-graph-copy">Threat map from local evidence: surface, candidate attack paths, and the open leads that still need proof.</p>
                  </div>
                  <button class="obs-btn obs-btn-ghost" type="button" disabled={graphBusy !== ''} onclick={() => void buildGraph()}>{graphBusy === 'build' ? 'Building...' : 'Rebuild map'}</button>
                </div>
                {#if graph && graph.nodes.length}
                  <div class="obs-huntmap-strip">
                    <span><strong>{graph.nodes.length}</strong> nodes</span>
                    <span><strong>{graph.edges.length}</strong> edges</span>
                    <span><strong>{graph.paths.length}</strong> path{graph.paths.length === 1 ? '' : 's'}</span>
                    <span><strong>{openLeads.length}</strong> open lead{openLeads.length === 1 ? '' : 's'}</span>
                    <button class="obs-link" type="button" onclick={() => selectTab('graph')}>Open full graph</button>
                  </div>
                  {#if threatMap && threatMap.critical.length}
                    <ul class="obs-huntmap-leads" aria-label="critical weaknesses and APIs">
                      {#each threatMap.critical.slice(0, 4) as node (node.id)}
                        <li>
                          <span class="obs-huntmap-dot" style="background:var(--obs-red)" aria-hidden="true"></span>
                          <span style="flex:1;min-width:0"><strong style="display:block;font-size:12px;color:var(--obs-text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{node.label}</strong><small style="font-size:10.5px;color:var(--obs-faint)">{node.kind} - risk {node.risk_score} - {node.confidence}</small></span>
                          <span class="obs-chip" style="color:var(--obs-red)">{node.severity || 'critical'}</span>
                        </li>
                      {/each}
                    </ul>
                  {/if}
                  {#if topPath}
                    <div class="obs-huntmap-path">
                      <span class="obs-chip" style="color:{pathStateColor(topPath.state)}">{topPath.state}</span>
                      <span class="obs-huntmap-path-title">{topPath.title}</span>
                      <span class="obs-huntmap-steps">{topPath.steps.map((s) => s.goal || s.kind || 'step').join(' -> ')}</span>
                      <button class="obs-btn obs-btn-primary obs-btn-sm" type="button" disabled={graphBusy !== ''} onclick={() => void verifyPath(topPath)}>{graphBusy === topPath.id ? 'Starting...' : 'Verify path'}</button>
                    </div>
                  {/if}
                  {#if openLeads.length}
                    <ul class="obs-huntmap-leads">
                      {#each openLeads as lead (lead.id)}
                        <li>
                          <span class="obs-huntmap-dot" style="background:{leadStatusColor(lead.status)}" aria-hidden="true"></span>
                          <button type="button" onclick={() => { selectTab('leads'); void openHypothesis(lead.id); }}><strong>{lead.title}</strong><small>{lead.technique} - {lead.target}</small></button>
                          <span class="obs-chip">open lead</span>
                        </li>
                      {/each}
                    </ul>
                  {:else}
                    <p class="obs-detail-note">No open critical leads. Sync leads or record a falsifiable hypothesis to extend the map.</p>
                  {/if}
                {:else}
                  <p class="obs-detail-note">No hunt map built yet. Build it to derive weaknesses and critical APIs from recorded evidence - nothing is invented.</p>
                  <button class="obs-btn" type="button" disabled={graphBusy !== ''} onclick={() => void buildGraph()}>{graphBusy === 'build' ? 'Building...' : 'Build hunt map'}</button>
                {/if}
              </section>
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
                    ? 'This is a training mission. Starting it selects the next labs, matches public-research techniques, reads capability gaps, and verifies the session. It does not touch the target or mark a lab solved; solved labs still need evidence and a lesson.'
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
                      ? 'A training session selects the next labs, matches research techniques, and reads the capability gaps. It does not touch the target.'
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
            {:else if detailTab === 'leads'}
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Leads and hypotheses</h3>
                    <p class="obs-graph-copy">
                      A lead is a falsifiable question, not a finding. Open means the proof has not been recorded, even when an agent has already reasoned about it. This view collects the exact notes, tool calls, runs, and graph nodes that mention the lead.
                    </p>
                  </div>
                  <div class="flex flex-wrap items-center gap-2">
                    <button class="obs-btn obs-btn-ghost" type="button" onclick={() => (showArchivedLeads = !showArchivedLeads)}>
                      {showArchivedLeads ? 'Hide archived' : 'Show archived'}
                    </button>
                    <button class="obs-btn obs-btn-ghost" type="button" disabled={leadsBusy !== ''} onclick={() => void syncLeads()}>
                      {leadsBusy === 'sync' ? 'Syncing...' : 'Sync observations'}
                    </button>
                    <button class="obs-btn obs-btn-ghost" type="button" onclick={() => void loadLeads()}>
                      Refresh
                    </button>
                  </div>
                </div>
                {#if visibleHypotheses.length}
                  <div class="obs-leads-layout">
                    <div class="obs-leads-list">
                      {#each visibleHypotheses as item (item.id)}
                        <button
                          type="button"
                          class="obs-lead-card"
                          class:active={selectedHypothesis === item.id}
                          onclick={() => void openHypothesis(item.id)}
                        >
                          <span class="obs-lead-card-top">
                            <span class="obs-chip" style="color:{leadStatusColor(item.status)}">{item.status}</span>
                            {#if item.technique}<span class="obs-chip">{item.technique}</span>{/if}
                          </span>
                          <strong>{item.title}</strong>
                          <small>{item.target || 'no endpoint'} - {ago(item.created_at)}</small>
                          {#if item.rationale}<p>{item.rationale}</p>{/if}
                        </button>
                      {/each}
                    </div>
                    <div class="obs-lead-detail">
                      {#if hypothesisEvidence}
                        <div class="obs-lead-detail-head">
                          <div>
                            <span class="obs-eyebrow"><span class="tick"></span> Lead detail</span>
                            <h4>{hypothesisEvidence.hypothesis.title}</h4>
                          </div>
                          <span class="obs-chip" style="color:{leadStatusColor(hypothesisEvidence.hypothesis.status)}">{hypothesisEvidence.hypothesis.status}</span>
                        </div>
                        <p class="obs-lead-progress">{hypothesisEvidence.progress}</p>
                        {#if hypothesisEvidence.verdict}
                          <div class="obs-lead-verdict" data-verdict={hypothesisEvidence.verdict.verdict}>
                            <div class="obs-lead-verdict-head">
                              <span class="obs-chip" style="color:{verdictColor(hypothesisEvidence.verdict.verdict)}">
                                {hypothesisEvidence.verdict.verdict}
                              </span>
                              <span class="obs-chip">
                                {hypothesisEvidence.verdict.proves_technique ? 'proof recorded' : 'not proof'}
                              </span>
                              {#if hypothesisEvidence.verdict.related_technique}
                                <span class="obs-chip">{hypothesisEvidence.verdict.related_technique}</span>
                              {/if}
                            </div>
                            <p>{hypothesisEvidence.verdict.summary}</p>
                            <p class="obs-lead-verdict-next">
                              <strong>Next:</strong> {hypothesisEvidence.verdict.next_step}
                            </p>
                          </div>
                        {/if}
                        <div class="obs-lead-counts">
                          <span class="obs-chip">{hypothesisEvidence.counts.notes} note(s)</span>
                          <span class="obs-chip">{hypothesisEvidence.counts.tool_calls} call(s)</span>
                          <span class="obs-chip">{hypothesisEvidence.counts.runs} run(s)</span>
                          <span class="obs-chip">{hypothesisEvidence.counts.graph_nodes} node(s)</span>
                        </div>
                        <div class="obs-lead-section">
                          <h5>What would prove it</h5>
                          <p>{hypothesisEvidence.hypothesis.expected || 'No proof criterion recorded.'}</p>
                        </div>
                        {#if hypothesisEvidence.hypothesis.test || hypothesisEvidence.hypothesis.result}
                          <div class="obs-lead-section">
                            <h5>Recorded test</h5>
                            {#if hypothesisEvidence.hypothesis.test}<p>{hypothesisEvidence.hypothesis.test}</p>{/if}
                            {#if hypothesisEvidence.hypothesis.result}<p class="mono">{hypothesisEvidence.hypothesis.result}</p>{/if}
                          </div>
                        {/if}
                        {#if hypothesisEvidence.finding}
                          <div class="obs-lead-section">
                            <h5>Promoted finding</h5>
                            <p><span class="obs-chip" style="color:var(--obs-acid)">{hypothesisEvidence.finding.id}</span> {hypothesisEvidence.finding.title}</p>
                          </div>
                        {/if}
                        <div class="obs-lead-section">
                          <h5>Relevant tool calls</h5>
                          {#if hypothesisEvidence.tool_calls.length}
                            <ul class="obs-lead-evidence">
                              {#each hypothesisEvidence.tool_calls.slice(0, 12) as call (call.id)}
                                <li>
                                  <span class="obs-chip" style="color:{call.status === 'ok' ? 'var(--obs-acid)' : 'var(--obs-red)'}">{call.status}</span>
                                  <strong>{call.tool}</strong>
                                  <span class="mono">{callDetail(call)}</span>
                                  {#if call.matched_terms?.length}<span class="obs-chip">{call.matched_terms.join(', ')}</span>{/if}
                                  <small>{ago(call.created_at)}</small>
                                </li>
                              {/each}
                            </ul>
                          {:else}
                            <p class="obs-detail-note">No matching tool call is recorded for this lead.</p>
                          {/if}
                        </div>
                        <div class="obs-lead-section">
                          <h5>Recorded observations</h5>
                          {#if hypothesisEvidence.notes.length}
                            <ul class="obs-lead-evidence">
                              {#each hypothesisEvidence.notes.slice(-8).reverse() as note (note.id)}
                                <li>
                                  <span class="obs-chip">{note.kind}</span>
                                  <strong>{note.title}</strong>
                                  <p>{note.body}</p>
                                  <small>{ago(note.created_at)}</small>
                                </li>
                              {/each}
                            </ul>
                          {:else}
                            <p class="obs-detail-note">No observation is linked to this lead yet.</p>
                          {/if}
                        </div>
                        <div class="obs-lead-actions">
                          <a
                            class="obs-btn obs-btn-ghost"
                            href={`/api/v1/hypotheses/${hypothesisEvidence.hypothesis.id}/evidence.md`}
                            download={`${hypothesisEvidence.hypothesis.id}-evidence.md`}
                          >
                            <Icon name="download" size={12} />
                            Download brief
                          </a>
                          <button class="obs-btn obs-btn-ghost" type="button" onclick={() => selectTab('graph')}>
                            <Icon name="graph" size={12} />
                            Open graph
                          </button>
                          {#if hypothesisEvidence.hypothesis.finding_id}
                            <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('findings')}>
                              <Icon name="target" size={12} />
                              Open findings
                            </button>
                          {/if}
                        </div>
                      {:else if leadsBusy}
                        <p class="obs-detail-note">Reading the lead evidence...</p>
                      {:else}
                        <p class="obs-detail-note">Select a lead to see its evidence.</p>
                      {/if}
                    </div>
                  </div>
                {:else if leadsBusy}
                  <p class="obs-detail-note">Reading leads...</p>
                {:else}
                  <p class="obs-detail-note">No hypothesis has been recorded for this mission. A lead is created from a real observation, never to fill the screen.</p>
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
                          <button class="obs-btn obs-btn-ghost" type="button" disabled={!module.ready || exploitBusy !== ''} onclick={() => void runModule(module)}>
                            {exploitBusy === module.id ? 'Starting...' : 'Run'}
                          </button>
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
            {:else if detailTab === 'candidates'}
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Finding candidates</h3>
                    <p class="obs-graph-copy">
                      Reproducible differences an exploit test observed, with the raw evidence attached. A candidate is not a finding - promote it yourself when you have reproduced it.
                    </p>
                  </div>
                  <button class="obs-btn obs-btn-ghost" type="button" onclick={() => void loadCandidates()}>
                    Refresh
                  </button>
                </div>
                {#if candidates.length}
                  <ul class="obs-graph-paths">
                    {#each candidates as candidate (candidate.id)}
                      <li>
                        <div class="obs-graph-path-head">
                          <span class="obs-chip" style="color:{riskColor(candidate.severity)}">{candidate.severity}</span>
                          <span class="obs-chip" style="color:{candidate.status === 'candidate' ? 'var(--obs-acid)' : 'var(--obs-muted)'}">{candidate.status}</span>
                          <span class="obs-graph-path-title">{candidate.title}</span>
                          {#if candidate.status === 'candidate'}
                            <button class="obs-btn obs-btn-primary" type="button" disabled={candidateBusy !== ''} onclick={() => void promoteCandidate(candidate)}>
                              {candidateBusy === candidate.id ? 'Promoting...' : 'Promote'}
                            </button>
                            <button class="obs-btn obs-btn-ghost" type="button" disabled={candidateBusy !== ''} onclick={() => void dismissCandidate(candidate)}>
                              Dismiss
                            </button>
                          {:else if candidate.finding_id}
                            <span class="obs-chip">{candidate.finding_id}</span>
                          {/if}
                        </div>
                        <p class="obs-graph-path-steps">
                          {candidate.module_id || 'path'} - evidence: {JSON.stringify(candidate.evidence).slice(0, 220)}
                        </p>
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <p class="obs-detail-note">
                    No candidates yet. Run an exploit module; a supported step stages one here for review.
                  </p>
                {/if}
              </section>
            {:else if detailTab === 'coverage'}
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Coverage</h3>
                    <p class="obs-graph-copy">
                      The modern testing checklist for this mission: WSTG v4.2, the API Top 10, the LLM Top 10, the 2025 research classes, cloud, mobile, and supply chain. A module run moves its items; the brain can mark one with evidence. A vulnerable item is a lead, not a finding.
                    </p>
                  </div>
                  <button class="obs-btn obs-btn-ghost" type="button" onclick={() => void loadCoverage()}>
                    Refresh
                  </button>
                </div>
                {#if coverage}
                  <div class="obs-coverage-head">
                    <div class="obs-coverage-meter" style="--p:{coverage.percent}">
                      <span class="obs-coverage-pct">{coverage.percent}%</span>
                      <span class="obs-coverage-label">closed</span>
                    </div>
                    <div class="obs-coverage-counts">
                      <span class="obs-chip" style="color:var(--obs-acid)">covered {coverage.counts.covered}</span>
                      <span class="obs-chip" style="color:var(--obs-violet-3)">vulnerable {coverage.counts.vulnerable}</span>
                      <span class="obs-chip" style="color:var(--obs-orange)">in progress {coverage.counts.in_progress}</span>
                      <span class="obs-chip" style="color:var(--obs-red)">blocked {coverage.counts.blocked}</span>
                      <span class="obs-chip">untested {coverage.counts.untested}</span>
                      <span class="obs-chip">{coverage.total} items</span>
                    </div>
                  </div>
                  <div class="obs-coverage-grid">
                    {#each Object.entries(coverage.categories) as [name, bucket] (name)}
                      <div class="obs-coverage-cat">
                        <span class="obs-coverage-cat-name">{name}</span>
                        <span class="obs-coverage-cat-num">{bucket.covered + bucket.vulnerable}/{bucket.total}</span>
                        <span class="obs-coverage-cat-bar"><i style="width:{Math.round(((bucket.covered + bucket.vulnerable) / bucket.total) * 100)}%"></i></span>
                      </div>
                    {/each}
                  </div>
                  <h4 class="obs-coverage-next-title">Next highest-impact questions</h4>
                  {#if coverage.next.length}
                    <ul class="obs-graph-paths">
                      {#each coverage.next as item (item.id)}
                        <li>
                          <div class="obs-graph-path-head">
                            <span class="obs-chip" style="color:{riskColor(item.severity)}">{item.severity}</span>
                            <span class="obs-chip">{item.framework}</span>
                            <span class="obs-graph-path-title">{item.title}</span>
                            <span class="obs-chip">{item.id}</span>
                          </div>
                          <p class="obs-graph-path-steps">
                            {item.objective}
                            {#if item.modules.length}
                              <br />modules: {item.modules.join(', ')}
                            {/if}
                            {#if item.tools.length}
                              <br />tools: {item.tools.join(', ')}
                            {/if}
                          </p>
                        </li>
                      {/each}
                    </ul>
                  {:else}
                    <p class="obs-detail-note">Every item is closed. A new surface or a new programme adds fresh questions.</p>
                  {/if}
                {:else if coverageBusy}
                  <p class="obs-detail-note">Loading coverage...</p>
                {:else}
                  <p class="obs-detail-note">Coverage could not be loaded.</p>
                {/if}
              </section>
            {:else if detailTab === 'program'}
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Program scope</h3>
                    <p class="obs-graph-copy">
                      Paste a HackerOne, Bugcrowd, Intigriti, YesWeHack, or Immunefi CSV/JSON export, or a programme brief. The preview is read-only. Applying an exclusion is safe; a new in-scope asset that the mission does not already cover needs the explicit expansion flag.
                    </p>
                  </div>
                  {#if programPreview}
                    <button class="obs-btn obs-btn-ghost" type="button" onclick={() => (programPreview = null)}>
                      Clear
                    </button>
                  {/if}
                </div>
                <div class="obs-program-grid">
                  <div class="obs-program-form">
                    <label class="obs-field">
                      <span>Brief</span>
                      <textarea rows="10" bind:value={programBrief} placeholder="In scope&#10;- app.example.com&#10;&#10;Out of scope&#10;- staging.example.com"></textarea>
                    </label>
                    <div class="obs-form-row">
                      <label class="obs-field">
                        <span>Filename</span>
                        <input bind:value={programFilename} placeholder="hackerone_scope.csv" />
                      </label>
                      <label class="obs-field">
                        <span>Platform</span>
                        <select bind:value={programPlatform}>
                          <option value="other">Auto-detect</option>
                          <option value="hackerone">HackerOne</option>
                          <option value="bugcrowd">Bugcrowd</option>
                          <option value="intigriti">Intigriti</option>
                          <option value="yeswehack">YesWeHack</option>
                          <option value="immunefi">Immunefi</option>
                        </select>
                      </label>
                    </div>
                    <label class="obs-program-check">
                      <input type="checkbox" bind:checked={programAllowExpand} />
                      <span>Authorise new in-scope assets outside the current mission scope</span>
                    </label>
                    <div class="obs-program-actions">
                      <button class="obs-btn obs-btn-ghost" type="button" disabled={programBusy !== ''} onclick={() => void previewProgram()}>
                        {programBusy === 'preview' ? 'Parsing...' : 'Preview'}
                      </button>
                      <button class="obs-btn obs-btn-primary" type="button" disabled={programBusy !== ''} onclick={() => void importProgram()}>
                        {programBusy === 'apply' ? 'Applying...' : 'Apply to scope'}
                      </button>
                    </div>
                  </div>
                  <div class="obs-program-result">
                    {#if programPreview}
                      <div class="obs-program-counts">
                        <span class="obs-chip" style="color:var(--obs-acid)">{programPreview.parsed.counts.in_scope} in scope</span>
                        <span class="obs-chip" style="color:var(--obs-red)">{programPreview.parsed.counts.out_of_scope} excluded</span>
                        <span class="obs-chip">{programPreview.parsed.platform}</span>
                        <span class="obs-chip">{programPreview.parsed.source}</span>
                      </div>
                      {#if programPreview.parsed.rules.length}
                        <div class="obs-program-block">
                          <h4>Rules</h4>
                          <ul>
                            {#each programPreview.parsed.rules.slice(0, 6) as rule (rule)}
                              <li>{rule}</li>
                            {/each}
                          </ul>
                        </div>
                      {/if}
                      <div class="obs-program-block">
                        <h4>Scope diff</h4>
                        {#if programPreview.diff.add_in_scope.length}
                          <p class="obs-program-line"><span class="obs-chip" style="color:var(--obs-acid)">add</span> {programPreview.diff.add_in_scope.join(', ')}</p>
                        {/if}
                        {#if programPreview.diff.add_exclusions.length}
                          <p class="obs-program-line"><span class="obs-chip" style="color:var(--obs-red)">exclude</span> {programPreview.diff.add_exclusions.join(', ')}</p>
                        {/if}
                        {#if programPreview.diff.already_present.length}
                          <p class="obs-program-line"><span class="obs-chip">already present</span> {programPreview.diff.already_present.join(', ')}</p>
                        {/if}
                        {#if programPreview.diff.requires_allow_expand.length}
                          <p class="obs-program-line"><span class="obs-chip" style="color:var(--obs-orange)">needs expansion</span> {programPreview.diff.requires_allow_expand.join(', ')}</p>
                        {/if}
                        {#if !programPreview.diff.add_in_scope.length && !programPreview.diff.add_exclusions.length}
                          <p class="obs-detail-note">No scope change. The brief is already represented on this mission.</p>
                        {/if}
                      </div>
                    {:else}
                      <div class="obs-program-empty">
                        <span class="obs-eyebrow"><span class="tick"></span> Read-only preview</span>
                        <p>Parse a brief to see the exact in-scope additions, exclusions, and assets held back because they would widen authorisation.</p>
                      </div>
                    {/if}
                  </div>
                </div>
                {#if programHistory.length}
                  <div class="obs-program-history">
                    <h4>Applied briefs</h4>
                    <ul>
                      {#each programHistory as item (item.id)}
                        <li>
                          <span class="obs-chip">{item.platform}</span>
                          <strong>{item.name || item.handle || item.filename || item.id}</strong>
                          <span class="mono">{item.in_scope.length} in / {item.out_of_scope.length} out - {ago(item.created_at)}</span>
                          {#if item.actor}<span class="mono">{item.actor}</span>{/if}
                        </li>
                      {/each}
                    </ul>
                  </div>
                {/if}
              </section>
              <section class="obs-detail-section">
                <div class="obs-graph-head">
                  <div>
                    <h3>Surface seed</h3>
                    <p class="obs-graph-copy">
                      Paste hosts you already hold - a certificate-transparency export, a programme asset list, or the names in a wildcard scope. Every name is checked against mission scope; only in-scope names are resolved and probed. Observed hosts and endpoints reach the evidence graph, never the findings ledger.
                    </p>
                  </div>
                  {#if seedResult}
                    <span class="obs-chip" style="color:var(--obs-acid)">{seedResult.hosts_live} live / {seedResult.accepted} in scope</span>
                  {/if}
                </div>
                <div class="obs-program-grid">
                  <div class="obs-program-form">
                    <label class="obs-field">
                      <span>Hosts</span>
                      <textarea rows="7" bind:value={seedHosts} placeholder="api.example.gov.pk&#10;admin.example.gov.pk&#10;portal.example.gov.pk"></textarea>
                    </label>
                    <div class="obs-program-actions">
                      <button class="obs-btn obs-btn-primary" type="button" disabled={seedBusy} onclick={() => void seedSurface()}>
                        {seedBusy ? 'Probing...' : 'Seed and probe'}
                      </button>
                    </div>
                  </div>
                  <div class="obs-program-result">
                    {#if seedResult}
                      <div class="obs-program-counts">
                        <span class="obs-chip" style="color:var(--obs-acid)">{seedResult.hosts_live} live</span>
                        <span class="obs-chip">{seedResult.hosts_unresolved} unresolved</span>
                        <span class="obs-chip" style="color:var(--obs-red)">{seedResult.hosts_rejected} out of scope</span>
                      </div>
                      {#if seedResult.rejected.length}
                        <p class="obs-program-line mono">{seedResult.rejected.slice(0, 8).join(', ')}</p>
                      {/if}
                      <p class="obs-detail-note">The director can now plan against these hosts. Scope is unchanged.</p>
                    {:else}
                      <div class="obs-program-empty">
                        <span class="obs-eyebrow"><span class="tick"></span> Operator seed</span>
                        <p>Use this when passive sources are slow or blocked. Hosts are leads, not findings.</p>
                      </div>
                    {/if}
                  </div>
                </div>
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
                  <button
                    class="obs-btn obs-btn-primary"
                    class:is-busy={busy === 'direction'}
                    type="button"
                    disabled={!directionText.trim() || busy === 'direction'}
                    aria-busy={busy === 'direction'}
                    onclick={() => void queueDirection()}
                  >
                    {#if busy !== 'direction'}<Icon name="arrow-right" size={12} />{/if}
                    {busy === 'direction' ? 'Queueing' : 'Queue direction'}
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
                        <span class="obs-chip" style="color:{call.status === 'ok' ? 'var(--obs-acid)' : call.status === 'denied' ? 'var(--obs-red)' : 'var(--obs-muted)'}">tool - {call.tool}</span>
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
          <label class="obs-program-check">
            <input type="checkbox" bind:checked={form.unrestricted} />
            <span>Unrestricted: run host shell, host writes, and destructive steps without per-call approvals</span>
          </label>
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
        <button
          class="obs-btn obs-btn-primary"
          class:is-busy={busy === 'create'}
          type="button"
          disabled={busy === 'create'}
          aria-busy={busy === 'create'}
          onclick={() => void createMission()}
        >
          {#if busy !== 'create'}<Icon name="plus" size={13} />{/if}
          {busy === 'create' ? 'Saving' : 'Save mission'}
        </button>
      </footer>
    </div>
  </div>
{/if}
