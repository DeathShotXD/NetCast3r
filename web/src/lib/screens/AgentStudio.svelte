<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { ago } from '../format';
  import { store } from '../state.svelte';
  import type {
    Approval,
    McpInfo,
    McpTool,
    ToolCall,
    ToolCallStatus
  } from '../types';
  import Icon from '../ui/Icon.svelte';

  const statusOrder: ToolCallStatus[] = [
    'ok',
    'error',
    'denied',
    'approval_required',
    'confirm_required'
  ];
  const statusCopy: Record<ToolCallStatus, string> = {
    ok: 'ok',
    error: 'error',
    denied: 'denied',
    approval_required: 'approval held',
    confirm_required: 'confirm held'
  };
  const policyCopy: Record<string, string> = {
    readonly: 'Read-only traffic. Any mutation is refused before it reaches the control plane.',
    supervised: 'Reads and scoped work run; high-risk calls stop until a human spends one bound approval.',
    full: 'Everything is allowed, but deletes and decisions still require an explicit confirm=true.'
  };
  const categoryCopy: Record<string, string> = {
    workspace: 'Workspace',
    missions: 'Missions',
    runs: 'Runs and scans',
    findings: 'Findings',
    governance: 'Governance',
    providers: 'Providers',
    reports: 'Reports',
    scope: 'Scope',
    identity: 'Identity',
    callbacks: 'Callbacks',
    web: 'Authenticated web'
  };

  let info = $state<McpInfo | null>(null);
  let calls = $state<ToolCall[]>([]);
  let callTotal = $state(0);
  let approvals = $state<Approval[]>([]);
  let selectedTool = $state<McpTool | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let error = $state('');
  let toolQuery = $state('');
  let toolCategory = $state('all');
  let auditStatus = $state<'all' | ToolCallStatus>('all');
  let auditTool = $state('');
  let expanded = $state<string | null>(null);
  let busy = $state('');
  let timer: ReturnType<typeof setInterval> | null = null;

  const tools = $derived(info?.tools ?? []);
  const server = $derived(info?.server ?? null);
  const connected = $derived(Boolean(info?.connected));
  const policy = $derived(server?.policy ?? '');
  const pending = $derived(approvals.filter((approval) => approval.status === 'pending'));

  const categories = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const tool of tools) {
      counts.set(tool.category, (counts.get(tool.category) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  });

  const filteredTools = $derived.by(() => {
    const query = toolQuery.trim().toLowerCase();
    return tools.filter((tool) => {
      if (toolCategory !== 'all' && tool.category !== toolCategory) return false;
      if (!query) return true;
      return `${tool.name} ${tool.title} ${tool.description} ${tool.category}`
        .toLowerCase()
        .includes(query);
    });
  });

  const groupedTools = $derived.by(() => {
    const groups = new Map<string, McpTool[]>();
    for (const tool of filteredTools) {
      const items = groups.get(tool.category);
      if (items) items.push(tool);
      else groups.set(tool.category, [tool]);
    }
    return [...groups.entries()].map(([category, items]) => ({ category, items }));
  });

  const selectedArgs = $derived.by(() => {
    if (!selectedTool) return [];
    const schema = selectedTool.input_schema ?? { type: 'object' };
    const required = new Set(schema.required ?? []);
    return Object.entries(schema.properties ?? {}).map(([name, raw]) => {
      const value = raw as Record<string, unknown>;
      const bounds: string[] = [];
      if (value.enum) bounds.push(`one of ${(value.enum as unknown[]).map(String).join(', ')}`);
      if (value.minimum !== undefined) bounds.push(`min ${String(value.minimum)}`);
      if (value.maximum !== undefined) bounds.push(`max ${String(value.maximum)}`);
      if (value.default !== undefined) bounds.push(`default ${JSON.stringify(value.default)}`);
      return {
        name,
        type: String(value.type ?? 'any'),
        description: String(value.description ?? ''),
        required: required.has(name),
        bounds: bounds.join(' - ')
      };
    });
  });

  const rejectsUnknown = $derived(selectedTool?.input_schema?.additionalProperties === false);
  const clientLabel = $derived(
    server?.client?.name
      ? `${server.client.name}${server.client.version ? ` ${server.client.version}` : ''}`
      : 'none attached'
  );

  function auditQuery(): string {
    const params = new URLSearchParams({ size: '60' });
    if (auditStatus !== 'all') params.set('status', auditStatus);
    if (auditTool) params.set('tool', auditTool);
    return `?${params.toString()}`;
  }

  async function load(silent = false) {
    if (silent && (refreshing || loading)) return;
    if (silent) refreshing = true;
    else {
      loading = true;
      error = '';
    }
    try {
      const [nextInfo, audit, approvalPage] = await Promise.all([
        api.mcpInfo(),
        api.toolCalls(auditQuery()),
        api.approvals('?status=pending&size=50')
      ]);
      info = nextInfo;
      calls = audit.items;
      callTotal = audit.total;
      approvals = approvalPage.items;
      if (selectedTool) {
        selectedTool = nextInfo.tools.find((tool) => tool.name === selectedTool?.name) ?? null;
      }
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not read the agent control plane';
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  function openTool(tool: McpTool) {
    selectedTool = tool;
    if (window.innerWidth < 1180) {
      requestAnimationFrame(() =>
        document
          .querySelector('.obs-agent-rail')
          ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      );
    }
  }

  function riskClass(risk: string): string {
    return risk === 'high' ? 'is-high' : risk === 'medium' ? 'is-medium' : 'is-low';
  }

  function statusClass(status: ToolCallStatus): string {
    if (status === 'ok') return 'is-ok';
    if (status === 'error') return 'is-error';
    if (status === 'denied') return 'is-denied';
    return 'is-held';
  }

  function shortContext(call: ToolCall): string {
    if (call.mission_id) return call.mission_id;
    if (call.run_id) return call.run_id;
    return '-';
  }

  function pretty(value: unknown, limit = 3200): string {
    let text: string;
    try {
      text = JSON.stringify(value, null, 2) ?? String(value);
    } catch {
      text = String(value);
    }
    return text.length > limit ? `${text.slice(0, limit)}\n... truncated for display` : text;
  }

  function approvalTool(approval: Approval): string {
    const name = approval.payload?.tool;
    return typeof name === 'string' ? name : '';
  }

  function gateCopy(tool: McpTool): string {
    if (tool.operator_only) {
      return 'Operator-only. Denied under read-only and supervised policy; full policy still requires confirm=true.';
    }
    if (tool.destructive) {
      return 'High risk. Supervised policy spends one approved approval bound to the exact arguments; full policy requires confirm=true.';
    }
    if (tool.open_world) {
      return 'Sends traffic to a scoped target. It needs a mission or an explicit scope, and metadata or link-local addresses are always refused.';
    }
    if (tool.risk === 'medium') {
      return 'Medium risk. Allowed under supervised and full policy, refused under read-only, and audited either way.';
    }
    return 'Read-only. Allowed under every policy and still written to the audit trail.';
  }

  async function decide(approval: Approval, decision: 'approved' | 'rejected') {
    busy = `approval:${approval.id}`;
    try {
      await api.decideApproval(approval.id, { decision, decided_by: 'operator' });
      store.toast('ok', decision === 'approved' ? 'approval granted' : 'approval rejected');
      await load(true);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not record the decision');
    } finally {
      busy = '';
    }
  }

  async function selectStatus(status: 'all' | ToolCallStatus) {
    auditStatus = status;
    expanded = null;
    await load(true);
  }

  async function selectToolFilter(name: string) {
    auditTool = name;
    expanded = null;
    await load(true);
  }

  onMount(() => {
    void load();
    void store.refreshTotals();
    timer = setInterval(() => {
      if (document.visibilityState === 'visible') void load(true);
    }, 15000);
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });
</script>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Operations / Agent Studio</div>
      <h1>Agent Studio</h1>
      <p class="obs-page-sub">
        The control surface behind the MCP server: every tool an agent may call, the policy that gates it, and every call that actually ran. Connection state is read from the server heartbeat, never assumed.
      </p>
    </div>
    <div class="obs-page-actions">
      <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('runs')}>
        <Icon name="layers" size={13} />
        Run ledger
      </button>
      <button
        class="obs-btn obs-btn-primary"
        type="button"
        disabled={loading || refreshing}
        onclick={() => void load()}
      >
        <Icon name="refresh" size={13} />
        {loading ? 'Reading...' : 'Refresh'}
      </button>
    </div>
  </header>

  <section class="obs-agent-stats" aria-label="agent control summary">
    <article class="obs-card">
      <span>MCP link</span>
      <strong class:acid={connected} class:violet={!connected}>
        {connected ? 'live' : 'idle'}
      </strong>
      <small>{clientLabel}</small>
    </article>
    <article class="obs-card">
      <span>Policy</span>
      <strong class="acid">{policy || 'unknown'}</strong>
      <small>enforced per call</small>
    </article>
    <article class="obs-card">
      <span>Tools</span>
      <strong>{tools.length}</strong>
      <small>typed contracts</small>
    </article>
    <article class="obs-card">
      <span>Audit</span>
      <strong>{callTotal}</strong>
      <small>calls recorded</small>
    </article>
  </section>

  {#if error && info}
    <div class="obs-agent-note is-warn" role="status">
      Refresh failed: {error}. Showing the last data the control plane returned.
    </div>
  {/if}

  {#if loading && !info}
    <div class="obs-card obs-empty" style="min-height:360px">
      <span class="obs-empty-icon"><Icon name="plug" size={18} /></span>
      <div class="obs-empty-title">Reading the control surface</div>
      <p class="obs-empty-copy">Fetching the MCP heartbeat, tool catalogue, and audit trail from the local control plane.</p>
    </div>
  {:else if error && !info}
    <div class="obs-card obs-empty" style="min-height:320px">
      <span class="obs-empty-icon"><Icon name="x" size={18} /></span>
      <div class="obs-empty-title">Could not reach the control plane</div>
      <p class="obs-empty-copy">{error}</p>
      <button class="obs-btn" type="button" onclick={() => void load()}>Try again</button>
    </div>
  {:else}
    <div class="obs-agent-grid">
      <div class="obs-agent-main">
        <section class="obs-card" aria-label="MCP connection">
          <header class="obs-card-head">
            <div>
              <div class="obs-card-title"><Icon name="plug" size={13} />Control surface</div>
              <div class="obs-card-sub">
                Heartbeat published by the MCP process. A stale file is reported as idle, never as connected.
              </div>
            </div>
            <span class="obs-agent-link-state" class:is-live={connected}>
              <span class="obs-pulse" aria-hidden="true"></span>
              {connected ? 'connected' : 'idle'}
            </span>
          </header>
          <div class="obs-card-body">
            <div class="obs-agent-facts">
              <div><span>Client</span><strong title={clientLabel}>{clientLabel}</strong></div>
              <div><span>Policy</span><strong class="acid">{policy || '-'}</strong></div>
              <div><span>Transport</span><strong>{server?.transport ?? '-'}</strong></div>
              <div><span>Backend</span><strong>{server?.backend ?? '-'}</strong></div>
              <div><span>Protocol</span><strong>{server?.protocol_version ?? '-'}</strong></div>
              <div><span>Calls this process</span><strong>{server?.calls ?? 0}</strong></div>
              <div><span>Started</span><strong>{server?.started_at ? ago(server.started_at) : '-'}</strong></div>
              <div>
                <span>Last call</span>
                <strong>{server?.last_call_at ? ago(server.last_call_at) : 'no calls yet'}</strong>
              </div>
            </div>

            {#if connected}
              <p class="obs-agent-note is-live">
                A live heartbeat from {clientLabel} is attached over {server?.transport ?? 'stdio'}. The registry below is exactly what that client can call, and every request lands in the audit trail.
              </p>
            {:else}
              <p class="obs-agent-note is-idle">
                No MCP client heartbeat is present. The catalogue and audit stay readable, but idle is not connected: a client must initialize before it can drive a tool.
              </p>
            {/if}

            <div class="obs-agent-paths">
              {#if info?.control_plane?.url}
                <div>
                  Control plane
                  <code>{info.control_plane.url}</code>
                  <span class:obs-agent-down={!info.control_plane.alive}>
                    {info.control_plane.alive ? 'answering' : 'not answering'}
                  </span>
                </div>
              {/if}
              <div>State file <code>{info?.state_file ?? '-'}</code></div>
            </div>
          </div>
        </section>

        <section class="obs-card obs-agent-registry" aria-label="tool registry">
          <header class="obs-card-head">
            <div>
              <div class="obs-card-title"><Icon name="terminal" size={13} />Tool registry</div>
              <div class="obs-card-sub">
                {tools.length} typed tools with JSON schemas. Unknown arguments are rejected, not silently ignored.
              </div>
            </div>
            <label class="obs-agent-search">
              <Icon name="search" size={11} />
              <input bind:value={toolQuery} placeholder="filter tools" aria-label="filter tools" />
            </label>
          </header>

          <div class="obs-agent-cats" role="tablist" aria-label="tool categories">
            <button
              class="obs-filter"
              class:active={toolCategory === 'all'}
              type="button"
              onclick={() => (toolCategory = 'all')}
            >
              All <span>{tools.length}</span>
            </button>
            {#each categories as [category, count] (category)}
              <button
                class="obs-filter"
                class:active={toolCategory === category}
                type="button"
                onclick={() => (toolCategory = category)}
              >
                {categoryCopy[category] ?? category} <span>{count}</span>
              </button>
            {/each}
          </div>

          <div class="obs-agent-tools">
            {#each groupedTools as group (group.category)}
              <div class="obs-agent-tool-group">
                <div class="obs-agent-tool-cat">
                  {categoryCopy[group.category] ?? group.category}
                  <span>{group.items.length}</span>
                </div>
                {#each group.items as tool (tool.name)}
                  <button
                    class="obs-agent-tool"
                    class:selected={selectedTool?.name === tool.name}
                    type="button"
                    onclick={() => openTool(tool)}
                    title={tool.description}
                  >
                    <span class="obs-agent-risk {riskClass(tool.risk)}">{tool.risk}</span>
                    <span class="obs-agent-tool-copy">
                      <span class="obs-agent-tool-name">{tool.name}</span>
                      <span class="obs-agent-tool-title">{tool.title}</span>
                      <span class="obs-agent-tool-desc">{tool.description}</span>
                    </span>
                    <span class="obs-agent-tool-flags">
                      {#if tool.read_only}<span>RO</span>{/if}
                      {#if tool.destructive}<span class="is-danger">DEL</span>{/if}
                      {#if tool.open_world}<span class="is-open">NET</span>{/if}
                      {#if tool.operator_only}<span class="is-ops">OPS</span>{/if}
                    </span>
                  </button>
                {/each}
              </div>
            {:else}
              <div class="obs-empty" style="min-height:200px">
                <span class="obs-empty-icon"><Icon name="filter" size={17} /></span>
                <div class="obs-empty-title">No tool matches</div>
                <p class="obs-empty-copy">Clear the search or choose another category.</p>
                <button
                  class="obs-btn"
                  type="button"
                  onclick={() => {
                    toolQuery = '';
                    toolCategory = 'all';
                  }}
                >
                  Reset filters
                </button>
              </div>
            {/each}
          </div>
        </section>
      </div>

      <aside class="obs-agent-rail" aria-label="agent detail">
        {#if selectedTool}
          <section class="obs-card obs-agent-detail">
            <header class="obs-agent-detail-head">
              <div style="min-width:0;flex:1">
                <span class="obs-agent-risk {riskClass(selectedTool.risk)}">{selectedTool.risk} risk</span>
                <h2>{selectedTool.title}</h2>
                <div class="obs-agent-detail-name">{selectedTool.name}</div>
              </div>
              <button
                class="obs-icon-btn"
                type="button"
                aria-label="close tool detail"
                onclick={() => (selectedTool = null)}
              >
                <Icon name="x" size={13} />
              </button>
            </header>
            <div class="obs-agent-detail-body">
              <p>{selectedTool.description}</p>
              <div class="obs-agent-flags">
                <span>{categoryCopy[selectedTool.category] ?? selectedTool.category}</span>
                {#if selectedTool.read_only}<span class="acid">read-only</span>{/if}
                {#if selectedTool.destructive}<span class="red">destructive</span>{/if}
                {#if selectedTool.open_world}<span class="orange">open world</span>{/if}
                {#if selectedTool.operator_only}<span class="violet">operator only</span>{/if}
              </div>

              <section class="obs-detail-section">
                <h3>Arguments</h3>
                {#if selectedArgs.length}
                  <div class="obs-agent-schema">
                    {#each selectedArgs as arg (arg.name)}
                      <div class="obs-agent-arg">
                        <div class="obs-agent-arg-top">
                          <code>{arg.name}</code>
                          {#if arg.required}<span class="req">required</span>{/if}
                          <span class="type">{arg.type}</span>
                        </div>
                        {#if arg.description}<p>{arg.description}</p>{/if}
                        {#if arg.bounds}<div class="bounds">{arg.bounds}</div>{/if}
                      </div>
                    {/each}
                  </div>
                  {#if rejectsUnknown}
                    <p class="obs-agent-fine">additionalProperties is false: an unknown field is an error.</p>
                  {/if}
                {:else}
                  <p>No arguments. The tool runs with an empty object.</p>
                {/if}
              </section>

              <section class="obs-detail-section">
                <h3>Gate</h3>
                <p>{gateCopy(selectedTool)}</p>
              </section>
            </div>
          </section>
        {:else}
          <section class="obs-card obs-agent-policy" aria-label="risk policy">
            <header class="obs-card-head">
              <div>
                <div class="obs-card-title"><Icon name="shield" size={13} />Risk policy</div>
                <div class="obs-card-sub">The server enforces one policy for the life of the process.</div>
              </div>
              <span class="obs-chip acid">{policy || 'unknown'}</span>
            </header>
            <div class="obs-card-body" style="padding-top:0">
              <div class="obs-agent-policy-list">
                {#each ['readonly', 'supervised', 'full'] as name (name)}
                  <div class="obs-agent-policy-row" class:is-active={policy === name}>
                    <strong>{name}</strong>
                    <p>{policyCopy[name]}</p>
                  </div>
                {/each}
              </div>
              <ul class="obs-agent-rules">
                <li>Active tools need a mission or an explicit scope; a bare target is refused.</li>
                <li>Out-of-scope rules win. Metadata and link-local addresses are never in scope.</li>
                <li>An approval is bound to the tool and the SHA-256 of its arguments, and can be spent once.</li>
                <li>Every call, including denials and failures, is written to the audit.</li>
              </ul>
              <p class="obs-agent-fine">Select a tool for its schema and the exact gate it passes through.</p>
            </div>
          </section>
        {/if}

        <article class="obs-card obs-approvals" aria-label="approval queue">
          <header class="obs-card-head">
            <div>
              <div class="obs-card-title"><Icon name="lock" size={13} />Approval queue</div>
              <div class="obs-card-sub">
                {pending.length} decision{pending.length === 1 ? '' : 's'} need a human
              </div>
            </div>
            <span class="obs-approval-count" class:is-zero={pending.length === 0}>{pending.length}</span>
          </header>

          {#if pending.length}
            <div class="obs-approval-list">
              {#each pending as approval (approval.id)}
                <div class="obs-approval" class:is-urgent={approval.risk === 'high' || approval.risk === 'critical'}>
                  <div class="obs-approval-top">
                    <span class="obs-approval-agent">{approval.requested_by || 'agent'}</span>
                    <span class="obs-chip" style="color:{approval.risk === 'high' ? 'var(--obs-red)' : 'var(--obs-gold)'}">
                      {approval.risk} risk
                    </span>
                  </div>
                  <div class="obs-approval-title">{approval.action}</div>
                  <div class="obs-approval-why">
                    <strong>Why:</strong>
                    {approval.reason || 'An agent requested this action and the policy gate stopped it here.'}
                  </div>
                  <div class="obs-approval-meta">
                    {#if approval.mission_title}<span class="obs-chip">{approval.mission_title}</span>{/if}
                    {#if approvalTool(approval)}<span class="obs-chip violet">{approvalTool(approval)}</span>{/if}
                    <span class="obs-chip">{ago(approval.created_at)}</span>
                  </div>
                  <div class="obs-approval-actions">
                    <button
                      class="obs-btn obs-btn-primary"
                      type="button"
                      disabled={busy === `approval:${approval.id}`}
                      onclick={() => void decide(approval, 'approved')}
                    >
                      Approve
                    </button>
                    <button
                      class="obs-btn obs-btn-ghost"
                      type="button"
                      disabled={busy === `approval:${approval.id}`}
                      onclick={() => void decide(approval, 'rejected')}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              {/each}
            </div>
          {:else}
            <div class="obs-empty" style="min-height:150px">
              <span class="obs-empty-icon"><Icon name="shield" size={17} /></span>
              <div class="obs-empty-title">Nothing waiting</div>
              <p class="obs-empty-copy">
                No high-risk action is pending. This queue only fills when an agent asks for one.
              </p>
            </div>
          {/if}
        </article>
      </aside>
    </div>

    <section class="obs-card obs-audit" aria-label="tool call audit">
      <header class="obs-card-head">
        <div>
          <div class="obs-card-title"><Icon name="database" size={13} />Tool-call audit</div>
          <div class="obs-card-sub">
            Every MCP request, including denied and failed calls. Credential-shaped arguments are redacted before storage.
          </div>
        </div>
        <span class="obs-chip">{callTotal} call{callTotal === 1 ? '' : 's'}</span>
      </header>

      <div class="obs-audit-toolbar">
        <div class="obs-filter-bar" style="margin:0">
          <button
            class="obs-filter"
            class:active={auditStatus === 'all'}
            type="button"
            onclick={() => void selectStatus('all')}
          >
            All
          </button>
          {#each statusOrder as status (status)}
            <button
              class="obs-filter"
              class:active={auditStatus === status}
              type="button"
              onclick={() => void selectStatus(status)}
            >
              {statusCopy[status]}
            </button>
          {/each}
        </div>
        <label class="obs-agent-select">
          <span>tool</span>
          <select
            value={auditTool}
            onchange={(event) => void selectToolFilter((event.currentTarget as HTMLSelectElement).value)}
          >
            <option value="">all tools</option>
            {#each tools as tool (tool.name)}
              <option value={tool.name}>{tool.name}</option>
            {/each}
          </select>
        </label>
      </div>

      {#if calls.length === 0}
        <div class="obs-empty" style="min-height:190px">
          <span class="obs-empty-icon"><Icon name="database" size={17} /></span>
          <div class="obs-empty-title">
            {callTotal === 0 && auditStatus === 'all' && !auditTool
              ? 'No tool calls recorded yet'
              : 'No call matches these filters'}
          </div>
          <p class="obs-empty-copy">
            {callTotal === 0 && auditStatus === 'all' && !auditTool
              ? 'The audit starts with the first MCP request. It is never seeded with demo rows.'
              : 'Clear the status or tool filter to widen the view.'}
          </p>
        </div>
      {:else}
        <div class="obs-agent-table">
          <div class="obs-agent-table-head" aria-hidden="true">
            <span>when</span>
            <span>tool</span>
            <span>status</span>
            <span class="col-actor">actor</span>
            <span class="col-context">context</span>
            <span class="col-approval">approval</span>
            <span>ms</span>
            <span></span>
          </div>
          {#each calls as call (call.id)}
            <div class="obs-agent-call" class:is-open={expanded === call.id}>
              <button
                class="obs-agent-call-row"
                type="button"
                aria-expanded={expanded === call.id}
                onclick={() => (expanded = expanded === call.id ? null : call.id)}
              >
                <span class="obs-agent-call-when" title={call.created_at}>{ago(call.created_at)}</span>
                <span class="obs-agent-call-tool">{call.tool}</span>
                <span class="obs-call-status {statusClass(call.status)}">{statusCopy[call.status]}</span>
                <span class="obs-agent-call-actor col-actor" title={call.actor}>{call.actor || '-'}</span>
                <span class="obs-agent-call-context col-context" title={shortContext(call)}>{shortContext(call)}</span>
                <span class="obs-agent-call-approval col-approval">
                  {call.approval_id ? 'bound' : '-'}
                </span>
                <span class="obs-agent-call-ms">{call.duration_ms}</span>
                <span class="obs-agent-call-chevron" class:is-open={expanded === call.id}>
                  <Icon name="chevron-down" size={10} />
                </span>
              </button>
              {#if call.error}
                <p class="obs-agent-call-note">{call.error}</p>
              {/if}
              {#if expanded === call.id}
                <div class="obs-agent-call-detail">
                  <div>
                    <span>arguments</span>
                    <pre>{pretty(call.args)}</pre>
                  </div>
                  <div>
                    <span>result</span>
                    <pre>{pretty(call.result)}</pre>
                  </div>
                  {#if call.error}
                    <div class="is-error">
                      <span>error</span>
                      <pre>{call.error}</pre>
                    </div>
                  {/if}
                  <div>
                    <span>call id</span>
                    <pre>{call.id}{call.mission_id ? `\nmission ${call.mission_id}` : ''}{call.run_id ? `\nrun ${call.run_id}` : ''}{call.approval_id ? `\napproval ${call.approval_id}` : ''}</pre>
                  </div>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </section>
  {/if}
</div>
