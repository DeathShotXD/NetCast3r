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
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';

  let items = $state<Finding[]>([]);
  let total = $state(0);
  let q = $state(store.query);
  let severity = $state('');
  let triage = $state('');
  let selected = $state<Finding | null>(null);
  let notes = $state('');
  let busy = $state(false);
  let loading = $state(true);
  let quality = $state<{ score: number; grade: string; artifacts: number; note: string; checks: { name: string; points: number; ok: boolean; hint: string }[] } | null>(null);
  let qualityBusy = $state(false);
  let retesting = $state(false);
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
    loading = true;
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
    } finally {
      if (mine === seq) loading = false;
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
    quality = null;
  }

  // Verify = real evidence-quality score from the control plane.
  async function verifyFinding() {
    if (!selected || qualityBusy) return;
    qualityBusy = true;
    try {
      quality = await api.findingQuality(selected.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not score this finding');
    } finally { qualityBusy = false; }
  }

  // Retest = rerun the cast that produced this finding, then spectate it.
  async function retestFinding() {
    if (!selected?.run_id || retesting) return;
    retesting = true;
    try {
      const fresh = await api.rerun(selected.run_id);
      store.runs = [fresh, ...store.runs.filter((r) => r.id !== fresh.id)];
      store.toast('ok', `retest cast started for ${fresh.target} - spectating live`);
      store.watch(fresh.id);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not start a retest cast');
    } finally { retesting = false; }
  }

  const spine = $derived.by(() => {
    if (!selected) return [];
    const f = selected;
    return [
      { label: 'Observed', detail: f.source || 'source not recorded', ok: Boolean(f.source) },
      { label: 'Captured', detail: f.secret_type ? `${f.secret_type} value captured (masked in UI)` : 'value captured', ok: Boolean(f.value) },
      { label: 'Validated', detail: `${f.status} - ${Math.round((f.confidence ?? 0) * 100)}% confidence`, ok: f.status === 'confirmed' || (f.confidence ?? 0) >= 0.7 },
      { label: 'Evidence', detail: f.evidence ? `${f.evidence.length} chars of recorded evidence` : 'no evidence text attached yet', ok: Boolean(f.evidence) },
      { label: 'Triaged', detail: triageLabel(f.triage_status), ok: f.triage_status !== 'new' }
    ];
  });

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

  <div class="obs-findings-tools" data-nc-zone="findings-filters">
    <label>
      <span class="obs-eyebrow">search</span>
      <input class="obs-field" type="search" bind:value={q} oninput={debouncedLoad} placeholder="title, type, host..." aria-label="Search findings" />
    </label>
    <label>
      <span class="obs-eyebrow">severity</span>
      <select class="obs-field" bind:value={severity} onchange={load} aria-label="Filter by severity">
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
      <select class="obs-field" bind:value={triage} onchange={load} aria-label="Filter by triage state">
        <option value="">all</option>
        <option value="new">needs review</option>
        <option value="confirmed">confirmed</option>
        <option value="escalated">escalate-ready</option>
        <option value="rejected">rejected</option>
      </select>
    </label>
  </div>

  <section class="obs-card" use:pauseOffscreen>
    {#if loading && items.length === 0}
      <div style="padding:18px"><Buffering variant="skeleton" label="Loading findings" detail="Reading validated findings from the control plane." /></div>
    {:else if error && items.length === 0}
      <EmptyState eyebrow="control plane" tone="error" title="Could not load findings" body={error} action="Try again" onAction={() => void load()} secondaryAction="Engage a target" onSecondaryAction={() => store.go('new')} />
    {:else if items.length === 0}
      <EmptyState
        eyebrow="empty"
        title={q || severity || triage ? 'No findings match' : 'Nothing caught yet'}
        body={q || severity || triage
          ? 'No finding satisfies every filter at once. Clear one filter, or run another scan.'
          : 'Findings land here the moment a run validates a credential against the provider that issued it.'}
        action={q || severity || triage ? 'Clear filters' : 'Engage a target'}
        onAction={() => { if (q || severity || triage) { q = ''; severity = ''; triage = ''; void load(); } else store.go('new'); }}
        hint={q || severity || triage ? 'tip: leave a filter blank to include everything' : ''}
      />
    {:else}
      {#if error}<p class="obs-alert" style="margin:12px 14px 0" role="alert">{error} <button class="obs-link" type="button" onclick={() => void load()}>Retry</button></p>{/if}
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
                <td class="obs-findings-title">
                  <span class="obs-findings-title-text" title={finding.title}>{finding.title}</span>
                  <span class="obs-mono obs-findings-type" title={finding.secret_type || ''}>{finding.secret_type}</span>
                </td>
                <td class="obs-mono obs-findings-value" title={finding.value || ''}>
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

      <div style="margin-bottom:16px">
        <p class="obs-eyebrow">evidence spine</p>
        <ol class="obs-spine" aria-label="evidence chain">
          {#each spine as step (step.label)}
            <li class:ok={step.ok}><i aria-hidden="true"></i><span><strong>{step.label}</strong><small>{step.detail}</small></span></li>
          {/each}
        </ol>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">
          <button class="obs-btn obs-btn-primary" type="button" disabled={qualityBusy} onclick={() => void verifyFinding()}>{qualityBusy ? 'Scoring...' : 'Verify evidence'}</button>
          <button class="obs-btn" type="button" disabled={retesting || !selected.run_id} title={selected.run_id ? 'Rerun the cast that produced this finding' : 'No source run recorded'} onclick={() => void retestFinding()}>{retesting ? 'Starting retest...' : 'Retest via rerun'}</button>
        </div>
        {#if quality}
          <div class="obs-quality" role="status">
            <strong>Evidence score {quality.score}/100 - grade {quality.grade}</strong>
            <span>{quality.artifacts} artifact(s) attached. {quality.note}</span>
            <ul>{#each quality.checks as check (check.name)}<li class:ok={check.ok}>{check.ok ? 'pass' : 'gap'} - {check.name}{#if !check.ok && check.hint} - {check.hint}{/if}</li>{/each}</ul>
          </div>
        {/if}
      </div>

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
