<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { ago, sevColor, sevShape, triageLabel } from '../format';
  import { store } from '../state.svelte';
  import { pauseOffscreen } from '../actions';
  import type { Finding } from '../types';
  import Chip from '../ui/Chip.svelte';
  import EmptyState from '../ui/EmptyState.svelte';

  let items = $state<Finding[]>([]);
  let total = $state(0);
  let q = $state(store.query);
  let severity = $state('');
  let triage = $state('');
  let selected = $state<Finding | null>(null);
  let notes = $state('');
  let busy = $state(false);
  let error = $state('');
  let seq = 0;
  let searchTimer: number | undefined;

  async function load() {
    const mine = ++seq;
    const params = new URLSearchParams({ size: '100' });
    if (q.trim()) params.set('q', q.trim());
    if (severity) params.set('severity', severity);
    if (triage) params.set('status', triage);
    try {
      const page = await api.findings('?' + params.toString());
      if (mine !== seq) return;
      items = page.items;
      total = page.total;
      error = '';
      store.query = q;
    } catch (exc) {
      if (mine !== seq) return;
      items = [];
      total = 0;
      error = exc instanceof Error ? exc.message : 'could not load findings';
    }
  }

  function debouncedLoad() {
    if (searchTimer) window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => void load(), 250);
  }

  $effect(() => {
    const incoming = store.query;
    if (incoming !== q) {
      q = incoming;
      void load();
    }
  });

  onDestroy(() => {
    if (searchTimer) window.clearTimeout(searchTimer);
  });

  function open(finding: Finding) {
    selected = finding;
    notes = finding.notes || '';
  }

  function close() {
    selected = null;
  }

  async function patch(body: Partial<Finding>, message: string) {
    if (!selected) return;
    busy = true;
    try {
      const updated = await api.patchFinding(selected.id, body);
      selected = updated;
      const at = items.findIndex((item) => item.id === updated.id);
      if (at >= 0) items = items.map((item, i) => (i === at ? updated : item));
      store.toast('ok', message);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not update the finding');
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
  <section class="flex flex-wrap items-end gap-4">
    <div class="mr-auto">
      <p class="eyebrow">findings</p>
      <h1 class="mt-1 text-xl text-bone">
        {total} {total === 1 ? 'finding' : 'findings'}
      </h1>
    </div>
    <div class="flex flex-wrap items-end gap-3">
      <label class="block">
        <span class="eyebrow">search</span>
        <input class="field mt-1 w-[220px]! py-1.5! text-sm!" type="search" bind:value={q} oninput={debouncedLoad} />
      </label>
      <label class="block">
        <span class="eyebrow">severity</span>
        <select class="field mt-1 w-[150px]! py-1.5! text-sm!" bind:value={severity} onchange={load}>
          <option value="">all</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
      </label>
      <label class="block">
        <span class="eyebrow">state</span>
        <select class="field mt-1 w-[170px]! py-1.5! text-sm!" bind:value={triage} onchange={load}>
          <option value="">all</option>
          <option value="new">needs review</option>
          <option value="confirmed">confirmed</option>
          <option value="escalated">escalate-ready</option>
          <option value="rejected">rejected</option>
        </select>
      </label>
    </div>
  </section>

  <section class="panel overflow-hidden" use:pauseOffscreen>
    {#if error}
      <p class="border-b border-violet-deep bg-violet-abyss px-4 py-3 text-sm text-bone">{error}</p>
    {/if}
    {#if items.length === 0}
      <EmptyState
        eyebrow="empty"
        title={q || severity || triage ? 'No findings match' : 'Nothing caught yet'}
        body={q || severity || triage
          ? 'No finding satisfies every filter at once. Clear one of the boxes above, or run another scan.'
          : 'Findings land here the moment a run validates a credential against the provider that issued it.'}
        action="start a scan"
        onAction={() => store.go('new')}
        hint={q || severity || triage ? '> tip: leave a filter blank to include everything' : ''}
      />
    {:else}
      <div class="max-h-[68vh] overflow-auto">
        <table class="sticky-head w-full min-w-[860px] border-collapse text-left">
          <thead>
            <tr class="border-b border-indigo-deep">
              <th class="eyebrow px-4 py-3">severity</th>
              <th class="eyebrow px-4 py-3">finding</th>
              <th class="eyebrow px-4 py-3">value</th>
              <th class="eyebrow px-4 py-3">confidence</th>
              <th class="eyebrow px-4 py-3">state</th>
              <th class="eyebrow px-4 py-3">seen</th>
            </tr>
          </thead>
          <tbody>
            {#each items as finding (finding.id)}
              {@const sev = finding.severity_override || finding.severity}
              <tr
                class="row-link cursor-pointer border-b border-indigo-deep/60 last:border-0"
                style="--row-accent:{sevColor(sev)}"
                onclick={() => open(finding)}
                onkeydown={(event) => event.key === 'Enter' && open(finding)}
                tabindex="0"
              >
                <td class="px-4 py-3">
                  <Chip label={sev} color={sevColor(sev)} shape={sevShape(sev)} />
                </td>
                <td class="max-w-[320px] px-4 py-3">
                  <span class="block truncate text-sm text-bone">{finding.title}</span>
                  <span class="mono block truncate text-xs text-bone-dust">{finding.secret_type}</span>
                </td>
                <td class="mono max-w-[220px] truncate px-4 py-3 text-xs text-bone-dust">
                  {finding.value}
                </td>
                <td class="px-4 py-3">
                  <span class="flex items-center gap-2">
                    <span class="num text-xs text-bone">{Math.round((finding.confidence ?? 0) * 100)}%</span>
                    <span
                      class="meter conf"
                      style="--m:{Math.min(1, finding.confidence ?? 0)};--m-color:{sevColor(sev)}"
                      aria-hidden="true"><i></i
                    ></span>
                  </span>
                </td>
                <td class="px-4 py-3 text-xs text-bone-dust">{triageLabel(finding.triage_status)}</td>
                <td class="mono whitespace-nowrap px-4 py-3 text-xs text-ash">{ago(finding.created_at)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

{#if selected}
  <button class="fixed inset-0 z-30 bg-black/60" aria-label="close detail" onclick={close}></button>
  <aside
    class="drawer fixed inset-y-0 right-0 z-40 flex w-[min(460px,100vw)] flex-col overflow-y-auto border-l border-indigo-deep bg-void-soft"
    aria-label="finding detail"
  >
    <div class="flex items-start gap-3 border-b border-indigo-deep px-5 py-4">
      <div class="min-w-0 flex-1">
        <p class="eyebrow">finding</p>
        <h2 class="mt-1 text-lg leading-snug text-bone">{selected.title}</h2>
      </div>
      <button class="btn btn-quiet px-2!" type="button" onclick={close} aria-label="close">x</button>
    </div>

    <div class="flex flex-col gap-5 px-5 py-5">
      <div class="flex flex-wrap gap-2">
        <Chip
          label={selected.severity_override || selected.severity}
          color={sevColor(selected.severity_override || selected.severity)}
          shape={sevShape(selected.severity_override || selected.severity)}
        />
        <Chip label={selected.status} color="var(--nc-gold)" shape="dot" />
        <Chip label={triageLabel(selected.triage_status)} color="var(--nc-violet)" shape="ring" />
      </div>

      <div>
        <p class="eyebrow">explain this finding</p>
        <p class="mt-2 text-sm leading-relaxed text-bone-dust">
          {selected.impact ||
            'A credential was recovered from this target and recognised as a real secret type. Open the evidence below before you decide what it means.'}
        </p>
      </div>

      <dl class="grid grid-cols-2 gap-3">
        <div class="panel px-3 py-2">
          <dt class="eyebrow">type</dt>
          <dd class="mono mt-1 text-sm text-bone">{selected.secret_type}</dd>
        </div>
        <div class="panel px-3 py-2">
          <dt class="eyebrow">confidence</dt>
          <dd class="mt-1 flex items-center gap-2">
            <span class="num text-sm text-bone">{Math.round((selected.confidence ?? 0) * 100)}%</span>
            <span
              class="meter flex-1"
              style="--m:{Math.min(1, selected.confidence ?? 0)};--m-color:{sevColor(selected.severity_override || selected.severity)}"
              aria-hidden="true"><i></i
            ></span>
          </dd>
        </div>
        <div class="panel col-span-2 px-3 py-2">
          <dt class="eyebrow">value (masked)</dt>
          <dd class="mono mt-1 break-all text-sm text-acid">{selected.value}</dd>
        </div>
        <div class="panel col-span-2 px-3 py-2">
          <dt class="eyebrow">source</dt>
          <dd class="mono mt-1 break-all text-xs text-bone-dust">{selected.source || '-'}</dd>
        </div>
      </dl>

      {#if selected.evidence}
        <div>
          <p class="eyebrow">evidence</p>
          <pre
            class="mono mt-2 max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-indigo-deep bg-void px-3 py-3 text-xs leading-relaxed text-bone-dust">{selected.evidence}</pre>
        </div>
      {/if}

      <div>
        <p class="eyebrow">triage</p>
        <div class="mt-2 flex flex-wrap gap-2">
          <button
            class="btn"
            type="button"
            disabled={busy}
            onclick={() => patch({ status: 'confirmed' }, 'marked as confirmed')}
            style="color:var(--nc-acid)">confirm</button
          >
          <button class="btn" type="button" disabled={busy} onclick={() => patch({ status: 'escalated' }, 'marked escalate-ready')}
            >escalate</button
          >
          <button
            class="btn btn-danger"
            type="button"
            disabled={busy}
            onclick={() => patch({ status: 'rejected' }, 'rejected')}>reject</button
          >
        </div>
        <label class="mt-3 block">
          <span class="eyebrow">notes</span>
          <textarea class="field mt-2 min-h-[90px] text-sm!" bind:value={notes} placeholder="why it matters, where it came from, what you did"></textarea>
        </label>
        <button class="btn mt-2" type="button" disabled={busy} onclick={() => patch({ notes }, 'notes saved')}>
          save notes
        </button>
      </div>
    </div>
  </aside>
{/if}
