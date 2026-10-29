<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { sevColor, sevShape } from '../format';
  import { store } from '../state.svelte';
  import type { RevengKinds, RevengObservation, RevengResult } from '../types';
  import Chip from '../ui/Chip.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import Icon from '../ui/Icon.svelte';

  const EXAMPLES = [
    { kind: 'apk', path: '/path/to/app.apk', note: 'manifest, exported components, secrets, endpoints' },
    { kind: 'source', path: '/path/to/source-tree', note: 'routes, sinks, hardcoded credentials' },
    { kind: 'contract', path: '/path/to/contracts', note: 'tx.origin, delegatecall, selfdestruct' },
    { kind: 'binary', path: '/path/to/driver.sys', note: 'kernel imports, IOCTLs, hardening' }
  ];

  let kinds = $state<RevengKinds | null>(null);
  let kind = $state('auto');
  let path = $state('');
  let busy = $state(false);
  let error = $state('');
  let result = $state<RevengResult | null>(null);
  let expanded = $state<string>('');
  let saved = $state<Set<string>>(new Set());
  let saving = $state('');

  const severity = $derived(result?.summary.severity ?? {});
  const observations = $derived(result?.observations ?? []);
  const highCount = $derived((severity.critical ?? 0) + (severity.high ?? 0));
  const metaChips = $derived.by(() => {
    if (!result) return [] as { label: string; value: string }[];
    const summary = result.summary;
    const chips: { label: string; value: string }[] = [];
    for (const key of ['package', 'format', 'decompiler']) {
      const value = summary[key];
      if (typeof value === 'string' && value) chips.push({ label: key, value });
    }
    for (const key of ['files', 'components', 'functions', 'endpoints', 'secrets']) {
      const value = summary[key];
      if (typeof value === 'number') chips.push({ label: key, value: String(value) });
    }
    if (Array.isArray(summary.permissions) && summary.permissions.length) {
      chips.push({ label: 'permissions', value: String(summary.permissions.length) });
    }
    return chips;
  });

  async function loadKinds() {
    try {
      kinds = await api.revengKinds();
    } catch {
      kinds = null;
    }
  }

  async function analyze() {
    if (!path.trim()) {
      store.toast('warn', 'give the lab a file or directory to read');
      return;
    }
    busy = true;
    error = '';
    try {
      result = await api.revengAnalyze({ kind, path: path.trim(), markdown: true });
      expanded = '';
      saved = new Set();
      const total = result.summary.observations;
      store.toast(total > 0 ? 'ok' : 'info', `${total} observation${total === 1 ? '' : 's'} from ${result.kind} analysis`);
    } catch (exc) {
      result = null;
      error = exc instanceof Error ? exc.message : 'the analyzer could not read that artifact';
    } finally {
      busy = false;
    }
  }

  function toggle(item: RevengObservation) {
    expanded = expanded === item.id ? '' : item.id;
  }

  async function saveFinding(item: RevengObservation) {
    saving = item.id;
    const location = item.line ? `${item.file}:${item.line}` : item.file;
    try {
      const finding = await api.createFinding({
        title: item.title,
        severity: item.severity,
        impact: item.recommendation,
        evidence: `${location} — ${item.evidence}`,
        source: `reveng:${result?.kind ?? kind}`,
        secret_type: `reveng_${item.category}`,
        confidence: item.confidence,
        tags: ['reveng', result?.kind ?? kind, item.category],
        notes: `Artifact: ${result?.path ?? path}`
      });
      saved = new Set([...saved, item.id]);
      store.toast('ok', `recorded ${finding.id} in triage`);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not record the finding');
    } finally {
      saving = '';
    }
  }

  function useExample(example: (typeof EXAMPLES)[number]) {
    kind = example.kind;
    path = example.path;
  }

  onMount(() => {
    void loadKinds();
  });
</script>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Intelligence / Reverse Lab</div>
      <h1>Read the artifact</h1>
      <p class="obs-page-sub">
        Source trees, APKs, Solidity projects, and PE/ELF drivers. Analysis is local and
        read-only; nothing is uploaded or executed. Observations are leads, not findings:
        record one only after you confirm it against the live target.
      </p>
    </div>
    <div class="obs-page-actions">
      <span class="obs-page-time mono">local only</span>
    </div>
  </header>

  <section class="obs-card">
    <div class="obs-card-head">
      <div>
        <div class="obs-card-title">Artifact</div>
        <div class="obs-card-sub">Point the lab at something you are allowed to inspect.</div>
      </div>
      {#if kinds}
        <div class="flex flex-wrap items-center gap-2 text-[11px] text-ash">
          {#each Object.entries(kinds.decompilers) as [name, ready]}
            <span class="chip" style="color:{ready ? 'var(--ok)' : 'var(--ash)'}">
              {name} {ready ? 'ready' : 'missing'}
            </span>
          {/each}
        </div>
      {/if}
    </div>
    <div class="obs-card-body">
      <div class="flex flex-col gap-3 md:flex-row md:items-end">
        <label class="block w-full md:w-[190px]">
          <span class="obs-eyebrow">kind</span>
          <select class="obs-field mt-1 w-full" bind:value={kind}>
            {#each (kinds?.kinds ?? ['auto', 'source', 'apk', 'contract', 'binary']) as item}
              <option value={item}>{item}</option>
            {/each}
          </select>
        </label>
        <label class="block flex-1">
          <span class="obs-eyebrow">path</span>
          <input
            class="obs-field mt-1 w-full font-mono text-[12px]"
            placeholder="/home/you/targets/app.apk or ./source-tree"
            bind:value={path}
            onkeydown={(event) => {
              if (event.key === 'Enter') void analyze();
            }}
          />
        </label>
        <button class="obs-btn obs-btn-primary h-[38px]" type="button" onclick={() => void analyze()} disabled={busy}>
          <Icon name={busy ? 'refresh' : 'code'} size={13} />
          {busy ? 'reading…' : 'Analyze'}
        </button>
      </div>

      <div class="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-ash">
        <span class="mono">try:</span>
        {#each EXAMPLES as example}
          <button
            type="button"
            class="obs-btn obs-btn-ghost obs-btn-sm"
            title={example.note}
            onclick={() => useExample(example)}
          >
            {example.kind}
          </button>
        {/each}
      </div>

      {#if error}
        <p class="mt-3 text-[12px] text-danger">{error}</p>
      {/if}
    </div>
  </section>

  {#if result}
    <section class="grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="analysis totals">
      <article class="obs-card">
        <div class="obs-card-body">
          <span class="obs-eyebrow">observations</span>
          <strong class="mt-1 block text-2xl text-bone">{result.summary.observations}</strong>
          <small class="text-ash">{highCount} high or critical</small>
        </div>
      </article>
      <article class="obs-card">
        <div class="obs-card-body">
          <span class="obs-eyebrow">endpoints</span>
          <strong class="mt-1 block text-2xl text-bone">{result.summary.endpoints}</strong>
          <small class="text-ash">paths and hosts</small>
        </div>
      </article>
      <article class="obs-card">
        <div class="obs-card-body">
          <span class="obs-eyebrow">secrets</span>
          <strong class="mt-1 block text-2xl text-bone">{result.summary.secrets}</strong>
          <small class="text-ash">masked previews</small>
        </div>
      </article>
      <article class="obs-card">
        <div class="obs-card-body">
          <span class="obs-eyebrow">kind</span>
          <strong class="mt-1 block text-lg text-bone">{result.kind}</strong>
          <small class="truncate text-ash" title={result.path}>{result.path.split('/').pop()}</small>
        </div>
      </article>
    </section>

    <div class="flex flex-wrap gap-2">
      {#each metaChips as chip}
        <span class="chip" style="color:var(--ash)">
          <span class="text-ash/70">{chip.label}</span>
          <span class="mono text-bone">{chip.value}</span>
        </span>
      {/each}
    </div>

    <section class="obs-card">
      <div class="obs-card-head">
        <div>
          <div class="obs-card-title">Observations</div>
          <div class="obs-card-sub">Sorted by severity, then file and line. Values are masked.</div>
        </div>
      </div>
      <div class="obs-card-body">
        {#if observations.length === 0}
          <EmptyState
            eyebrow="clear"
            title="No observations"
            body="The analyzers did not find a lead in this artifact. Try a different kind or a wider path."
          />
        {:else}
          <div class="flex flex-col divide-y divide-line/60">
            {#each observations as item}
              <div class="py-2">
                <div
                  class="flex w-full cursor-pointer items-center gap-3 text-left"
                  role="button"
                  tabindex="0"
                  onclick={() => toggle(item)}
                  onkeydown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') toggle(item);
                  }}
                >
                  <Chip label={item.severity} color={sevColor(item.severity)} shape={sevShape(item.severity)} />
                  <span class="min-w-0 flex-1">
                    <span class="block truncate text-[13px] text-bone">{item.title}</span>
                    <span class="mono block truncate text-[10px] text-ash">
                      {item.file}{item.line ? `:${item.line}` : ''} · {item.category}
                    </span>
                  </span>
                  <span class="mono hidden text-[10px] text-ash sm:block">{Math.round(item.confidence * 100)}%</span>
                  <button
                    type="button"
                    class="obs-btn obs-btn-ghost obs-btn-sm"
                    disabled={saved.has(item.id) || saving === item.id}
                    onclick={(event) => {
                      event.stopPropagation();
                      void saveFinding(item);
                    }}
                  >
                    {saved.has(item.id) ? 'recorded' : saving === item.id ? 'saving…' : 'save'}
                  </button>
                </div>
                {#if expanded === item.id}
                  <div class="mt-2 rounded-sm border border-line/60 bg-ink/40 p-3">
                    <p class="mono break-words text-[11px] text-bone">{item.evidence}</p>
                    <p class="mt-2 text-[11px] text-ash">{item.recommendation}</p>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </section>

    {#if result.endpoints.length > 0}
      <section class="obs-card">
        <div class="obs-card-head">
          <div>
            <div class="obs-card-title">Endpoints</div>
            <div class="obs-card-sub">Paths and hosts extracted from the artifact.</div>
          </div>
        </div>
        <div class="obs-card-body">
          <div class="flex max-h-[280px] flex-col gap-1 overflow-auto">
            {#each result.endpoints.slice(0, 120) as endpoint}
              <div class="flex items-baseline gap-3">
                <span class="mono min-w-0 flex-1 break-all text-[11px] text-bone">{endpoint.url}</span>
                <span class="mono shrink-0 text-[10px] text-ash">{endpoint.file}:{endpoint.line}</span>
              </div>
            {/each}
          </div>
        </div>
      </section>
    {/if}

    {#if result.secrets.length > 0}
      <section class="obs-card">
        <div class="obs-card-head">
          <div>
            <div class="obs-card-title">Secret candidates</div>
            <div class="obs-card-sub">Masked. Open the file at the line to confirm the value.</div>
          </div>
        </div>
        <div class="obs-card-body">
          <div class="flex flex-col gap-1">
            {#each result.secrets.slice(0, 80) as secret}
              <div class="flex items-baseline gap-3">
                <span class="mono w-[150px] shrink-0 text-[11px] text-bone">{secret.type}</span>
                <span class="mono min-w-0 flex-1 break-all text-[11px] text-ash">{secret.preview}</span>
                <span class="mono shrink-0 text-[10px] text-ash">{secret.file}:{secret.line}</span>
              </div>
            {/each}
          </div>
        </div>
      </section>
    {/if}
  {/if}
</div>
