<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { ago, sevColor, sevShape, triageLabel } from '../format';
  import { store } from '../state.svelte';
  import { pauseOffscreen } from '../actions';
  import type { Finding } from '../types';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import Icon from '../ui/Icon.svelte';

  let items = $state<Finding[]>([]);
  let total = $state(0);
  let q = $state(store.query);
  let severity = $state('');
  let triage = $state('');
  let selected = $state<Finding | null>(null);
  let notes = $state('');
  let busy = $state(false);
  let error = $state('');
  let pendingReject = $state<Finding | null>(null);
  let seq = 0;
  let searchTimer: number | undefined;

  function onWindowKey(event: KeyboardEvent) {
    if (event.key !== 'Escape') return;
    if (pendingReject) {
      pendingReject = null;
      return;
    }
    if (selected) selected = null;
  }

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

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Intelligence / Findings</div>
      <h1>{total} {total === 1 ? 'finding' : 'findings'}</h1>
      <p class="obs-page-sub">
        Triage validated credentials and exploit leads. Confirm what is real, escalate what is ready, reject noise.
      </p>
    </div>
    <div class="obs-page-actions">
      <button class="obs-btn obs-btn-primary" type="button" onclick={() => store.go('new')}>
        <Icon name="plus" size={13} />
        Engage target
      </button>
    </div>
  </header>

  <div class="obs-findings-tools" style="margin-bottom:14px">
    <label>
      <span class="obs-eyebrow">search</span>
      <input class="obs-field" style="width:min(240px,70vw);padding:8px 10px" type="search" bind:value={q} oninput={debouncedLoad} />
    </label>
    <label>
      <span class="obs-eyebrow">severity</span>
      <select class="obs-field" style="width:150px;padding:8px 10px" bind:value={severity} onchange={load}>
        <option value="">all</option>
        <option value="critical">critical</option>
        <option value="high">high</option>
        <option value="medium">medium</option>
        <option value="low">low</option>
        <option value="info">info</option>
      </select>
    </label>
    <label>
      <span class="obs-eyebrow">state</span>
      <select class="obs-field" style="width:170px;padding:8px 10px" bind:value={triage} onchange={load}>
        <option value="">all</option>
        <option value="new">needs review</option>
        <option value="confirmed">confirmed</option>
        <option value="escalated">escalate-ready</option>
        <option value="rejected">rejected</option>
      </select>
    </label>
  </div>

  <section class="obs-card" use:pauseOffscreen>
    {#if error}
      <p class="obs-alert" style="margin:12px 14px 0">{error}</p>
    {/if}
    {#if items.length === 0}
      <EmptyState
        eyebrow="empty"
        title={q || severity || triage ? 'No findings match' : 'Nothing caught yet'}
        body={q || severity || triage
          ? 'No finding satisfies every filter at once. Clear one of the boxes above, or run another scan.'
          : 'Findings land here the moment a run validates a credential against the provider that issued it.'}
        action="engage a target"
        onAction={() => store.go('new')}
        hint={q || severity || triage ? 'tip: leave a filter blank to include everything' : ''}
      />
    {:else}
      <div class="obs-findings-table-wrap">
        <table class="obs-findings-table">
          <thead>
            <tr>
              <th>severity</th>
              <th>finding</th>
              <th>value</th>
              <th>confidence</th>
              <th>state</th>
              <th>seen</th>
            </tr>
          </thead>
          <tbody>
            {#each items as finding (finding.id)}
              {@const sev = finding.severity_override || finding.severity}
              <tr
                style="--row-accent:{sevColor(sev)}"
                onclick={() => open(finding)}
                onkeydown={(event) => event.key === 'Enter' && open(finding)}
                tabindex="0"
              >
                <td>
                  <Chip label={sev} color={sevColor(sev)} shape={sevShape(sev)} />
                </td>
                <td style="max-width:320px">
                  <span style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12.5px;color:var(--obs-text)">{finding.title}</span>
                  <span class="obs-mono" style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px;color:var(--obs-muted)">{finding.secret_type}</span>
                </td>
                <td class="obs-mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--obs-muted)">
                  {finding.value}
                </td>
                <td>
                  <span style="display:inline-flex;align-items:center;gap:8px">
                    <span class="obs-mono" style="font-size:11px">{Math.round((finding.confidence ?? 0) * 100)}%</span>
                    <span
                      class="meter conf"
                      style="--m:{Math.min(1, finding.confidence ?? 0)};--m-color:{sevColor(sev)}"
                      aria-hidden="true"><i></i
                    ></span>
                  </span>
                </td>
                <td style="font-size:11.5px;color:var(--obs-muted)">{triageLabel(finding.triage_status)}</td>
                <td class="obs-mono" style="white-space:nowrap;font-size:11px;color:var(--obs-faint)">{ago(finding.created_at)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

{#if selected}
  <button class="obs-drawer-veil" aria-label="close detail" onclick={close}></button>
  <aside class="obs-drawer" aria-label="finding detail">
    <div class="obs-drawer-head">
      <div class="min-w-0 flex-1">
        <p class="obs-eyebrow"><span class="tick"></span>finding</p>
        <h2>{selected.title}</h2>
      </div>
      <button class="obs-icon-btn" type="button" onclick={close} aria-label="close">
        <Icon name="x" size={14} />
      </button>
    </div>

    <div class="obs-drawer-scroll">
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">
        <Chip
          label={selected.severity_override || selected.severity}
          color={sevColor(selected.severity_override || selected.severity)}
          shape={sevShape(selected.severity_override || selected.severity)}
        />
        <Chip label={selected.status} color="var(--nc-gold)" shape="dot" />
        <Chip label={triageLabel(selected.triage_status)} color="var(--nc-violet)" shape="ring" />
      </div>

      <div style="margin-bottom:16px">
        <p class="obs-eyebrow">explain this finding</p>
        <p style="margin:8px 0 0;font-size:12.5px;line-height:1.55;color:var(--obs-muted)">
          {selected.impact ||
            'A credential was recovered from this target and recognised as a real secret type. Open the evidence below before you decide what it means.'}
        </p>
      </div>

      <dl style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div class="obs-card" style="padding:10px 12px">
          <dt class="obs-eyebrow">type</dt>
          <dd class="obs-mono" style="margin-top:6px;font-size:12px">{selected.secret_type}</dd>
        </div>
        <div class="obs-card" style="padding:10px 12px">
          <dt class="obs-eyebrow">confidence</dt>
          <dd style="margin-top:6px;display:flex;align-items:center;gap:8px">
            <span class="obs-mono" style="font-size:12px">{Math.round((selected.confidence ?? 0) * 100)}%</span>
            <span
              class="meter flex-1"
              style="--m:{Math.min(1, selected.confidence ?? 0)};--m-color:{sevColor(selected.severity_override || selected.severity)}"
              aria-hidden="true"><i></i
            ></span>
          </dd>
        </div>
        <div class="obs-card" style="grid-column:1 / -1;padding:10px 12px">
          <dt class="obs-eyebrow">value (masked)</dt>
          <dd class="obs-mono" style="margin-top:6px;word-break:break-all;font-size:12px;color:var(--obs-acid)">{selected.value}</dd>
        </div>
        <div class="obs-card" style="grid-column:1 / -1;padding:10px 12px">
          <dt class="obs-eyebrow">source</dt>
          <dd class="obs-mono" style="margin-top:6px;word-break:break-all;font-size:11px;color:var(--obs-muted)">{selected.source || '-'}</dd>
        </div>
      </dl>

      {#if selected.evidence}
        <div style="margin-bottom:16px">
          <p class="obs-eyebrow">evidence</p>
          <pre
            class="obs-mono"
            style="margin-top:8px;max-height:220px;overflow:auto;white-space:pre-wrap;word-break:break-word;border:1px solid var(--obs-line);border-radius:9px;background:var(--obs-bg-2);padding:12px;font-size:11px;line-height:1.5;color:var(--obs-muted)">{selected.evidence}</pre>
        </div>
      {/if}

      <div>
        <p class="obs-eyebrow">triage</p>
        <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px">
          <button
            class="obs-btn obs-btn-swarm"
            class:is-busy={busy}
            type="button"
            disabled={busy}
            aria-busy={busy}
            onclick={() => patch({ status: 'confirmed' }, 'marked as confirmed')}
          >confirm</button>
          <button
            class="obs-btn"
            class:is-busy={busy}
            type="button"
            disabled={busy}
            aria-busy={busy}
            onclick={() => patch({ status: 'escalated' }, 'marked escalate-ready')}
          >escalate</button>
          <button
            class="obs-btn obs-btn-danger"
            type="button"
            disabled={busy}
            onclick={() => (pendingReject = selected)}
          >reject</button>
        </div>
        <label style="display:block;margin-top:14px">
          <span class="obs-eyebrow">notes</span>
          <textarea
            class="obs-field obs-field-area"
            style="margin-top:6px"
            bind:value={notes}
            placeholder="why it matters, where it came from, what you did"
          ></textarea>
        </label>
        <button
          class="obs-btn"
          class:is-busy={busy}
          type="button"
          style="margin-top:8px"
          disabled={busy}
          aria-busy={busy}
          onclick={() => patch({ notes }, 'notes saved')}
        >
          {busy ? 'Saving' : 'save notes'}
        </button>
      </div>
    </div>
  </aside>
{/if}

{#if pendingReject}
  <Confirm
    title="Reject this finding?"
    body="Rejecting marks it not an issue in the index. The report file is left alone and you can set it back to needs review later."
    confirmLabel="reject it"
    danger
    onConfirm={() => {
      patch({ status: 'rejected' }, 'rejected');
      pendingReject = null;
    }}
    onCancel={() => (pendingReject = null)}
  />
{/if}

<svelte:window onkeydown={onWindowKey} />
