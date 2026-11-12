<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';
  import type { ConnectInfo, McpInfo } from '../types';

  let info = $state<ConnectInfo | null>(null);
  let mcp = $state<McpInfo | null>(null);
  let loading = $state(true);
  let error = $state('');
  let toolQuery = $state('');
  let copied = $state('');

  let auth = $state<{ username: string; default: boolean; source: string } | null>(null);
  let credUser = $state('');
  let credPass = $state('');
  let credConfirm = $state('');
  let credBusy = $state(false);
  let credError = $state('');
  let credNote = $state('');

  async function saveCredentials(event: SubmitEvent) {
    event.preventDefault();
    if (credBusy) return;
    credError = '';
    credNote = '';
    if (!credUser.trim()) {
      credError = 'choose a username';
      return;
    }
    if (!credPass) {
      credError = 'choose a password';
      return;
    }
    if (credPass !== credConfirm) {
      credError = 'the two passwords do not match';
      return;
    }
    credBusy = true;
    try {
      const res = await api.changeCredentials(credUser.trim(), credPass);
      auth = { username: res.username, default: res.default, source: auth?.source ?? '' };
      credPass = '';
      credConfirm = '';
      credNote = `saved. sign in as ${res.username} from now on.`;
      store.toast('ok', 'dashboard login updated');
    } catch (exc) {
      credError = exc instanceof Error ? exc.message : 'could not update the login';
    } finally {
      credBusy = false;
    }
  }

  async function load() {
    loading = true;
    error = '';
    try {
      info = await api.connect();
      try {
        mcp = await api.mcpInfo();
      } catch {
        mcp = null;
      }
      try {
        auth = await api.authInfo();
        credUser = auth.username;
      } catch {
        auth = null;
      }
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not read the connection info';
    } finally {
      loading = false;
    }
  }

  async function copy(id: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand('copy');
      } catch {
        /* the copy is best effort */
      }
      document.body.removeChild(area);
    }
    copied = id;
    window.setTimeout(() => {
      if (copied === id) copied = '';
    }, 1400);
    store.toast('ok', 'copied to clipboard');
  }

  const tools = $derived.by(() => {
    if (!info) return [];
    const needle = toolQuery.trim().toLowerCase();
    if (!needle) return info.tools;
    return info.tools.filter(
      (tool) =>
        tool.name.toLowerCase().includes(needle) ||
        tool.title.toLowerCase().includes(needle) ||
        tool.category.toLowerCase().includes(needle)
    );
  });

  const categories = $derived.by(() => {
    if (!info) return [];
    const by = new Map<string, number>();
    for (const tool of info.tools) by.set(tool.category, (by.get(tool.category) ?? 0) + 1);
    return [...by.entries()].sort((a, b) => b[1] - a[1]);
  });

  onMount(load);
</script>

<div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
  <section class="flex flex-wrap items-end gap-3">
    <div class="mr-auto">
      <p class="eyebrow">integrations</p>
      <h1 class="mt-1 text-xl text-bone">Connect a harness</h1>
      <p class="mt-1 text-sm text-ash">One control plane. Every tool. Shared audit, in real time.</p>
    </div>
    <button class="btn btn-quiet" type="button" onclick={() => void load()}>refresh</button>
  </section>

  {#if error}
    <section class="panel px-5 py-4 text-sm" style="color:var(--obs-red)" role="alert">
      Could not read connection info: {error}
      <button class="obs-btn obs-btn-sm" type="button" style="margin-left:10px" onclick={() => void load()}>Try again</button>
    </section>
  {:else if loading || !info}
    <section class="obs-card obs-empty" style="min-height:220px; gap:14px">
      <Buffering
        variant="block"
        tone="quiet"
        label="Reading plane"
        detail="Enumerating harness endpoints, tools, and auth policy."
      />
    </section>
  {:else}
    <section class="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="connection summary">
      <div class="obs-hist-kpi">
        <p class="eyebrow">endpoint</p>
        <p class="obs-connect-value obs-connect-mono">{info.workspace.url}</p>
        <p class="obs-hist-kpi-note">loopback</p>
      </div>
      <div class="obs-hist-kpi">
        <p class="eyebrow">policy</p>
        <p class="obs-connect-value">{info.workspace.policy}</p>
        <p class="obs-hist-kpi-note">risk gates apply</p>
      </div>
      <div class="obs-hist-kpi">
        <p class="eyebrow">tools</p>
        <p class="obs-connect-value" style="color:var(--obs-acid)">{info.workspace.tools}</p>
        <p class="obs-hist-kpi-note">{categories.length} categories</p>
      </div>
      <div class="obs-hist-kpi">
        <p class="eyebrow">auth</p>
        <p class="obs-connect-value obs-connect-mono">{auth?.username ?? 'admin'}</p>
        <p class="obs-hist-kpi-note">{auth?.default ? 'default login - change it' : 'username + password'}</p>
      </div>
    </section>

    <section class="panel p-5" aria-label="live harness connection">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p class="eyebrow">live harness</p>
          <h2 class="obs-connect-name">MCP client connection</h2>
        </div>
        <span class="chip" class:text-acid={mcp?.connected} class:text-violet={!mcp?.connected}>
          <span class="h-2 w-2 rounded-full" class:bg-acid={mcp?.connected} class:bg-violet={!mcp?.connected}></span>
          {mcp?.connected ? 'connected' : 'no client'}
        </span>
      </div>
      {#if mcp?.server}
        <div class="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <div>
            <p class="eyebrow">client</p>
            <p class="obs-connect-mono text-sm text-bone">
              {mcp.server.client?.name || 'unknown'}{mcp.server.client?.version ? ` ${mcp.server.client.version}` : ''}
            </p>
          </div>
          <div>
            <p class="eyebrow">policy</p>
            <p class="obs-connect-mono text-sm text-bone">{mcp.server.policy ?? '-'}</p>
          </div>
          <div>
            <p class="eyebrow">transport</p>
            <p class="obs-connect-mono text-sm text-bone">
              {mcp.server.transport ?? '-'} / {mcp.server.protocol_version ?? '-'}
            </p>
          </div>
          <div>
            <p class="eyebrow">calls</p>
            <p class="obs-connect-mono text-sm text-bone">{mcp.server.calls ?? 0}</p>
          </div>
        </div>
        {#if mcp.server.client_capabilities?.length}
          <div class="mt-3 flex flex-wrap items-center gap-1.5">
            <span class="eyebrow mr-1">advertised</span>
            {#each mcp.server.client_capabilities as cap (cap)}
              <span class="mono rounded-[2px] border border-indigo-deep px-2 py-0.5 text-[11px] text-bone-dust">{cap}</span>
            {/each}
          </div>
        {/if}
        <p class="obs-connect-notes mt-3">
          A client that advertises <code>sampling</code> can run a completion on its own model;
          one that advertises <code>roots</code> bounds the host read, write, and list tools to
          the folders it hands over.
        </p>
      {:else}
        <p class="obs-connect-notes mt-3">
          No MCP client is connected. Register a config below and its name, policy, and
          advertised capabilities appear here in real time.
        </p>
      {/if}
    </section>

    <section class="panel obs-access" aria-label="dashboard access">
      <header class="obs-access-head">
        <div>
          <p class="eyebrow">dashboard access</p>
          <h2 class="obs-connect-name">Sign-in</h2>
        </div>
        {#if auth}
          <span class="obs-access-badge" class:is-default={auth.default}>
            {auth.default ? 'default login' : 'custom'}
          </span>
        {/if}
      </header>
      <p class="obs-access-copy">
        Signed in as <strong>{auth?.username ?? 'unknown'}</strong>.
        {#if auth?.default}
          The default login is <code>admin</code> / <code>123</code> - change it before you leave
          the dashboard open.
        {:else}
          A custom username and password protect this dashboard.
        {/if}
      </p>
      <form class="obs-access-form" onsubmit={saveCredentials}>
        <div class="obs-access-field">
          <label class="eyebrow" for="cred-user">username</label>
          <input
            id="cred-user"
            class="obs-field"
            type="text"
            autocomplete="username"
            spellcheck="false"
            bind:value={credUser}
          />
        </div>
        <div class="obs-access-field">
          <label class="eyebrow" for="cred-pass">new password</label>
          <input
            id="cred-pass"
            class="obs-field"
            type="password"
            autocomplete="new-password"
            bind:value={credPass}
          />
        </div>
        <div class="obs-access-field">
          <label class="eyebrow" for="cred-confirm">confirm password</label>
          <input
            id="cred-confirm"
            class="obs-field"
            type="password"
            autocomplete="new-password"
            bind:value={credConfirm}
          />
        </div>
        <div class="obs-access-actions">
          <button class="obs-btn obs-btn-primary" type="submit" disabled={credBusy}>
            {credBusy ? 'saving...' : 'save login'}
          </button>
          {#if credNote}<span class="obs-access-note">{credNote}</span>{/if}
          {#if credError}<span class="obs-access-error" role="alert">{credError}</span>{/if}
        </div>
      </form>
    </section>

    <section class="panel obs-connect-note">
      <Icon name="network" size={15} />
      <p>{info.note}</p>
    </section>

    <section class="grid gap-3 lg:grid-cols-2">
      {#each info.harnesses as harness (harness.id)}
        <article class="panel obs-connect-card">
          <header class="obs-connect-head">
            <div>
              <p class="eyebrow">{harness.transport}</p>
              <h2 class="obs-connect-name">{harness.name}</h2>
            </div>
            <button
              class="obs-connect-copy"
              class:copied={copied === harness.id}
              type="button"
              onclick={() => void copy(harness.id, JSON.stringify(harness.config, null, 2))}
            >
              {copied === harness.id ? 'copied' : 'copy config'}
            </button>
          </header>
          <p class="obs-connect-summary">{harness.summary}</p>
          <pre class="obs-connect-code">{JSON.stringify(harness.config, null, 2)}</pre>
          <p class="obs-connect-notes">{harness.notes}</p>
        </article>
      {/each}
    </section>

    <section class="panel obs-connect-tools">
      <header class="obs-connect-tools-head">
        <div class="mr-auto">
          <p class="eyebrow">tool surface</p>
          <h2 class="obs-connect-name">{info.tools.length} typed tools</h2>
        </div>
        <label class="obs-hist-search obs-connect-search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
            <circle cx="10.5" cy="10.5" r="6.2" />
            <path d="M15.2 15.2 L20.4 20.4" />
          </svg>
          <input type="search" placeholder="search tools" bind:value={toolQuery} aria-label="search tools" />
        </label>
      </header>
      <div class="obs-connect-cats">
        {#each categories as [name, count] (name)}
          <span class="obs-connect-cat">{name}<b>{count}</b></span>
        {/each}
      </div>
      <div class="obs-connect-toolgrid">
        {#each tools as tool (tool.name)}
          <div class="obs-connect-tool" class:high={tool.risk === 'high'}>
            <span class="obs-connect-tool-name">{tool.name}</span>
            <span class="obs-connect-tool-risk risk-{tool.risk}">{tool.risk}</span>
          </div>
        {/each}
        {#if tools.length === 0}
          <p class="obs-connect-notes">No tool matches "{toolQuery}". Clear the search to see all {info.tools.length} tools.</p>
        {/if}
      </div>
    </section>

    <section class="panel obs-connect-auth">
      <p class="eyebrow">auth</p>
      <p class="obs-connect-notes">{info.workspace.auth_note}</p>
      <dl class="obs-connect-dl">
        <dt>token file</dt><dd class="obs-connect-mono">{info.workspace.token_file}</dd>
        <dt>python</dt><dd class="obs-connect-mono">{info.workspace.python}</dd>
        <dt>repo</dt><dd class="obs-connect-mono">{info.workspace.repo}</dd>
        <dt>version</dt><dd class="obs-connect-mono">{info.workspace.version}</dd>
      </dl>
      <p class="obs-connect-notes">
        High-risk tools still need a human approval in supervised mode, whichever harness calls them.
      </p>
    </section>
  {/if}
</div>