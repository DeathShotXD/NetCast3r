<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import Icon from '../ui/Icon.svelte';
  import type { ConnectInfo } from '../types';

  let info = $state<ConnectInfo | null>(null);
  let loading = $state(true);
  let error = $state('');
  let toolQuery = $state('');
  let copied = $state('');

  async function load() {
    loading = true;
    error = '';
    try {
      info = await api.connect();
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
    <section class="panel px-5 py-4 text-sm" style="color:var(--obs-red)">{error}</section>
  {:else if loading || !info}
    <section class="panel px-5 py-8 text-sm text-ash">reading the control plane...</section>
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
        <p class="obs-connect-value obs-connect-mono">{info.workspace.token_header}</p>
        <p class="obs-hist-kpi-note">token in the 0600 state file</p>
      </div>
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
          <p class="obs-connect-notes">no tool matches that search.</p>
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