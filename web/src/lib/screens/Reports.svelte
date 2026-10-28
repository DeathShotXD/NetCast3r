<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { ago, sevColor } from '../format';
  import { store } from '../state.svelte';
  import type {
    Mission,
    Submission,
    SubmissionPlatform,
    SubmissionStatus,
    SubmissionSummary
  } from '../types';
  import Icon from '../ui/Icon.svelte';

  type Filter = 'all' | 'open' | 'review' | 'accepted' | 'closed';

  const statusOrder: SubmissionStatus[] = [
    'draft',
    'ready',
    'submitted',
    'triaged',
    'accepted',
    'paid',
    'informative',
    'duplicate',
    'rejected',
    'withdrawn'
  ];
  const statusCopy: Record<SubmissionStatus, string> = {
    draft: 'Draft',
    ready: 'Ready',
    submitted: 'Submitted',
    triaged: 'Triaged',
    accepted: 'Accepted',
    paid: 'Paid',
    informative: 'Informative',
    duplicate: 'Duplicate',
    rejected: 'Rejected',
    withdrawn: 'Withdrawn'
  };
  const platformCopy: Record<SubmissionPlatform, string> = {
    hackerone: 'HackerOne',
    bugcrowd: 'Bugcrowd',
    intigriti: 'Intigriti',
    yeswehack: 'YesWeHack',
    immunefi: 'Immunefi',
    other: 'Other'
  };
  const filters: { id: Filter; label: string }[] = [
    { id: 'all', label: 'All' },
    { id: 'open', label: 'Not filed' },
    { id: 'review', label: 'In review' },
    { id: 'accepted', label: 'Accepted' },
    { id: 'closed', label: 'Closed' }
  ];
  const groupOf: Record<SubmissionStatus, Filter> = {
    draft: 'open',
    ready: 'open',
    submitted: 'review',
    triaged: 'review',
    accepted: 'accepted',
    paid: 'accepted',
    informative: 'closed',
    duplicate: 'closed',
    rejected: 'closed',
    withdrawn: 'closed'
  };
  const platforms: SubmissionPlatform[] = [
    'hackerone',
    'bugcrowd',
    'intigriti',
    'yeswehack',
    'immunefi',
    'other'
  ];
  const severities = ['critical', 'high', 'medium', 'low', 'info'];

  const emptySummary: SubmissionSummary = {
    total: 0,
    by_status: {},
    awaiting: 0,
    accepted: 0,
    paid: 0,
    by_currency: { USD: { awarded_cents: 0, paid_cents: 0 } }
  };

  let submissions = $state<Submission[]>([]);
  let summary = $state<SubmissionSummary>(emptySummary);
  let missions = $state<Mission[]>([]);
  let loading = $state(true);
  let refreshing = $state(false);
  let error = $state('');
  let filter = $state<Filter>('all');
  let composer = $state(false);
  let editing = $state<Submission | null>(null);
  let busy = $state('');
  let form = $state({
    title: '',
    target: '',
    platform: 'hackerone' as SubmissionPlatform,
    program: '',
    severity: 'medium',
    status: 'draft' as SubmissionStatus,
    mission_id: '',
    bounty: '',
    currency: 'USD',
    external_id: '',
    url: '',
    notes: ''
  });
  let edit = $state({
    status: 'draft' as SubmissionStatus,
    bounty: '',
    currency: 'USD',
    external_id: '',
    url: '',
    notes: ''
  });

  const paidUsd = $derived(summary.by_currency?.USD?.paid_cents ?? 0);
  const awardedUsd = $derived(summary.by_currency?.USD?.awarded_cents ?? 0);
  const otherCurrencies = $derived(
    Object.keys(summary.by_currency ?? {}).filter((code) => code !== 'USD')
  );
  const paidByCurrency = $derived(
    Object.entries(summary.by_currency ?? {})
      .filter(([, totals]) => (totals?.paid_cents ?? 0) > 0)
      .map(([code, totals]) => `${code} ${money(totals.paid_cents, code)}`)
  );
  const filtered = $derived.by(() => {
    if (filter === 'all') return submissions;
    return submissions.filter((item) => groupOf[item.status] === filter);
  });
  const hiddenCount = $derived(Math.max(0, summary.total - submissions.length));

  function groupCount(id: Filter): number {
    if (id === 'all') return summary.total;
    return statusOrder
      .filter((status) => groupOf[status] === id)
      .reduce((total, status) => total + (summary.by_status[status] ?? 0), 0);
  }

  function money(cents: number, currency = 'USD'): string {
    try {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency,
        maximumFractionDigits: 2
      }).format((cents || 0) / 100);
    } catch {
      return `${((cents || 0) / 100).toFixed(2)} ${currency}`;
    }
  }

  function toCents(value: string): number {
    const amount = Number.parseFloat(value.replace(/[^0-9.]/g, ''));
    return Number.isFinite(amount) && amount > 0 ? Math.round(amount * 100) : 0;
  }

  function toDollars(cents: number): string {
    return cents > 0 ? (cents / 100).toFixed(2) : '';
  }

  function statusClass(status: SubmissionStatus): string {
    return `is-${status}`;
  }

  function shortLink(item: Submission): string {
    return item.mission_title || item.run_target || item.target || 'unlinked';
  }

  async function load(silent = false) {
    if (silent && (refreshing || loading)) return;
    if (silent) refreshing = true;
    else {
      loading = true;
      error = '';
    }
    try {
      const [page, nextSummary, missionPage] = await Promise.all([
        api.submissions('?size=200'),
        api.submissionSummary(),
        api.missions('?size=100')
      ]);
      submissions = page.items;
      summary = nextSummary;
      missions = missionPage.items;
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not read the submission ledger';
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  function openComposer() {
    form = {
      title: '',
      target: '',
      platform: 'hackerone',
      program: '',
      severity: 'medium',
      status: 'draft',
      mission_id: '',
      bounty: '',
      currency: 'USD',
      external_id: '',
      url: '',
      notes: ''
    };
    composer = true;
  }

  function openSubmission(item: Submission) {
    editing = item;
    edit = {
      status: item.status,
      bounty: toDollars(item.bounty_cents),
      currency: item.currency || 'USD',
      external_id: item.external_id || '',
      url: item.url || '',
      notes: item.notes || ''
    };
  }

  async function createSubmission() {
    if (!form.title.trim()) {
      store.toast('warn', 'a report needs a title');
      return;
    }
    busy = 'create';
    try {
      await api.createSubmission({
        title: form.title.trim(),
        target: form.target.trim(),
        platform: form.platform,
        program: form.program.trim(),
        severity: form.severity,
        status: form.status,
        mission_id: form.mission_id,
        bounty_cents: toCents(form.bounty),
        currency: form.currency,
        external_id: form.external_id.trim(),
        url: form.url.trim(),
        notes: form.notes.trim()
      });
      composer = false;
      store.toast('ok', 'submission recorded in the ledger');
      await load(true);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not record the submission');
    } finally {
      busy = '';
    }
  }

  async function saveEdit() {
    if (!editing) return;
    busy = 'save';
    try {
      await api.patchSubmission(editing.id, {
        status: edit.status,
        bounty_cents: toCents(edit.bounty),
        currency: edit.currency,
        external_id: edit.external_id.trim(),
        url: edit.url.trim(),
        notes: edit.notes.trim()
      });
      store.toast('ok', 'submission updated');
      editing = null;
      await load(true);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not update the submission');
    } finally {
      busy = '';
    }
  }

  async function deleteEdit() {
    if (!editing) return;
    if (!window.confirm(`Delete "${editing.title}" from the ledger? The report file is not removed.`)) {
      return;
    }
    busy = 'delete';
    try {
      await api.deleteSubmission(editing.id);
      store.toast('ok', 'submission deleted from the ledger');
      editing = null;
      await load(true);
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not delete the submission');
    } finally {
      busy = '';
    }
  }

  onMount(() => {
    void load();
  });
</script>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Operations / Reports</div>
      <h1>Submission ledger</h1>
      <p class="obs-page-sub">
        Every report you actually filed, the platform's answer, and the money it paid. A row exists only because a human or an agent recorded it. Nothing here is estimated.
      </p>
    </div>
    <div class="obs-page-actions">
      <button class="obs-btn obs-btn-ghost" type="button" onclick={() => void load()}>
        <Icon name="refresh" size={13} />
        Refresh
      </button>
      <button class="obs-btn obs-btn-primary" type="button" onclick={openComposer}>
        <Icon name="plus" size={13} />
        Record submission
      </button>
    </div>
  </header>

  <section class="obs-sub-stats" aria-label="submission totals">
    <article class="obs-card">
      <span>In ledger</span>
      <strong>{summary.total}</strong>
      <small>reports recorded</small>
    </article>
    <article class="obs-card">
      <span>Awaiting</span>
      <strong class:violet={summary.awaiting > 0}>{summary.awaiting}</strong>
      <small>submitted or triaged</small>
    </article>
    <article class="obs-card">
      <span>Accepted</span>
      <strong class:acid={summary.accepted > 0}>{summary.accepted}</strong>
      <small>include paid</small>
    </article>
    <article class="obs-card">
      <span>Paid</span>
      <strong class:acid={paidUsd > 0}>{money(paidUsd, 'USD')}</strong>
      <small>
        {#if otherCurrencies.length}
          USD recorded · {otherCurrencies.join(', ')} kept separate
        {:else}
          USD recorded · awarded {money(awardedUsd, 'USD')}
        {/if}
      </small>
    </article>
  </section>

  {#if error}
    <div class="obs-agent-note is-warn" role="status">
      {error}. Showing the last data the control plane returned.
    </div>
  {/if}

  <div class="obs-filter-bar">
    {#each filters as item (item.id)}
      <button
        class="obs-filter"
        class:active={filter === item.id}
        type="button"
        onclick={() => (filter = item.id)}
      >
        {item.label} <span>{groupCount(item.id)}</span>
      </button>
    {/each}
    <span class="obs-sub-count">{filtered.length} shown</span>
  </div>

  {#if loading && submissions.length === 0}
    <div class="obs-card obs-empty" style="min-height:360px">
      <span class="obs-empty-icon"><Icon name="file" size={18} /></span>
      <div class="obs-empty-title">Reading the ledger</div>
      <p class="obs-empty-copy">Loading submissions, outcomes, and recorded payouts from the control plane.</p>
    </div>
  {:else if filtered.length === 0}
    <div class="obs-card obs-empty" style="min-height:340px">
      <span class="obs-empty-icon"><Icon name="file" size={18} /></span>
      <div class="obs-empty-title">
        {summary.total === 0 ? 'No submissions recorded' : 'Nothing in this view'}
      </div>
      <p class="obs-empty-copy">
        {summary.total === 0
          ? 'The ledger is empty. It stays empty until you file a report and record it. A finding is not a bounty, and a scan result is not a submission.'
          : 'Choose another filter, or record a report that is not in this group yet.'}
      </p>
      {#if summary.total === 0}
        <button class="obs-btn obs-btn-primary" type="button" onclick={openComposer}>
          <Icon name="plus" size={13} />
          Record the first submission
        </button>
      {/if}
    </div>
  {:else}
    <section class="obs-card obs-sub-table" aria-label="submissions">
      <div class="obs-sub-head" aria-hidden="true">
        <span>report</span>
        <span class="col-platform">platform</span>
        <span class="col-severity">severity</span>
        <span>status</span>
        <span class="col-award">award</span>
        <span class="col-updated">updated</span>
        <span></span>
      </div>
      {#each filtered as item (item.id)}
        <button class="obs-sub-row" type="button" onclick={() => openSubmission(item)}>
          <span class="obs-sub-report">
            <span class="obs-sub-title">{item.title}</span>
            <span class="obs-sub-target">{shortLink(item)}</span>
          </span>
          <span class="obs-sub-platform col-platform">
            <span>{platformCopy[item.platform] ?? item.platform}</span>
            {#if item.program}<small>{item.program}</small>{/if}
          </span>
          <span class="obs-sub-severity col-severity" style="color:{sevColor(item.severity)}">
            {item.severity}
          </span>
          <span class="obs-sub-status {statusClass(item.status)}">{statusCopy[item.status]}</span>
          <span class="obs-sub-award col-award">
            {#if item.bounty_cents > 0}
              {money(item.bounty_cents, item.currency)}
            {:else}
              <span class="is-empty">not recorded</span>
            {/if}
          </span>
          <span class="obs-sub-updated col-updated">{ago(item.updated_at)}</span>
          <span class="obs-sub-chevron"><Icon name="chevron-down" size={10} /></span>
        </button>
      {/each}
      {#if hiddenCount > 0}
        <p class="obs-sub-footnote">
          Showing the most recent {submissions.length} of {summary.total} rows. The summary uses every row.
        </p>
      {/if}
    </section>
  {/if}

  <section class="obs-sub-notes">
    <div>
      <Icon name="shield" size={13} />
      <strong>Only recorded outcomes count.</strong>
      <span>A submission starts as a draft. Filed, triaged, accepted, and paid are states you set when the platform tells you.</span>
    </div>
    <div>
      <Icon name="dollar" size={13} />
      <strong>Payouts are kept by currency.</strong>
      <span>
        {#if paidByCurrency.length}
          Paid to date: {paidByCurrency.join(' · ')}. Amounts are never converted or added across currencies.
        {:else}
          No payout recorded yet. USD is the default view. Other currencies are stored separately and never converted or added into the USD total.
        {/if}
      </span>
    </div>
  </section>
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
      aria-label="record submission"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <header class="obs-modal-head">
        <div>
          <div class="obs-eyebrow"><span class="tick"></span> Submission ledger</div>
          <h2>Record what you filed.</h2>
          <p>Draft first if the report is not filed yet. Set the outcome only when the platform tells you.</p>
        </div>
        <button class="obs-icon-btn" type="button" aria-label="close" onclick={() => (composer = false)}>
          <Icon name="x" size={14} />
        </button>
      </header>

      <div class="obs-modal-body">
        <label class="obs-field">
          <span>Report title</span>
          <input bind:value={form.title} placeholder="Stored XSS in the admin console" />
        </label>
        <div class="obs-form-row">
          <label class="obs-field">
            <span>Platform</span>
            <select bind:value={form.platform}>
              {#each platforms as platform (platform)}
                <option value={platform}>{platformCopy[platform]}</option>
              {/each}
            </select>
          </label>
          <label class="obs-field">
            <span>Program</span>
            <input bind:value={form.program} placeholder="acme" />
          </label>
        </div>
        <div class="obs-form-row">
          <label class="obs-field">
            <span>Severity</span>
            <select bind:value={form.severity}>
              {#each severities as severity (severity)}
                <option value={severity}>{severity}</option>
              {/each}
            </select>
          </label>
          <label class="obs-field">
            <span>Status</span>
            <select bind:value={form.status}>
              {#each statusOrder as status (status)}
                <option value={status}>{statusCopy[status]}</option>
              {/each}
            </select>
          </label>
        </div>
        <div class="obs-form-row">
          <label class="obs-field">
            <span>Affected target</span>
            <input bind:value={form.target} placeholder="app.example.com" />
          </label>
          <label class="obs-field">
            <span>Mission</span>
            <select bind:value={form.mission_id}>
              <option value="">No mission link</option>
              {#each missions as mission (mission.id)}
                <option value={mission.id}>{mission.title}</option>
              {/each}
            </select>
          </label>
        </div>
        <div class="obs-form-row">
          <label class="obs-field">
            <span>Recorded award</span>
            <input bind:value={form.bounty} type="number" min="0" step="0.01" placeholder="0.00" />
            <small>Leave blank until a number is real.</small>
          </label>
          <label class="obs-field">
            <span>Currency</span>
            <select bind:value={form.currency}>
              <option value="USD">USD</option>
              <option value="EUR">EUR</option>
              <option value="GBP">GBP</option>
              <option value="CAD">CAD</option>
              <option value="AUD">AUD</option>
            </select>
          </label>
        </div>
        <div class="obs-form-row">
          <label class="obs-field">
            <span>Platform report id</span>
            <input bind:value={form.external_id} placeholder="optional" />
          </label>
          <label class="obs-field">
            <span>Report URL</span>
            <input bind:value={form.url} placeholder="https://..." />
          </label>
        </div>
        <label class="obs-field">
          <span>Notes</span>
          <textarea bind:value={form.notes} rows="3" placeholder="Scope, duplicate check, reviewer, next step."></textarea>
        </label>
      </div>

      <footer class="obs-modal-foot">
        <span class="obs-modal-note">The ledger records what happened. It never estimates a bounty.</span>
        <button class="obs-btn obs-btn-ghost" type="button" onclick={() => (composer = false)}>Cancel</button>
        <button
          class="obs-btn obs-btn-primary"
          type="button"
          disabled={busy === 'create'}
          onclick={() => void createSubmission()}
        >
          <Icon name="plus" size={13} />
          {busy === 'create' ? 'Saving...' : 'Save submission'}
        </button>
      </footer>
    </div>
  </div>
{/if}

{#if editing}
  <div
    class="obs-modal-veil"
    role="presentation"
    onclick={() => (editing = null)}
    onkeydown={(event) => {
      if (event.key === 'Escape') editing = null;
    }}
  >
    <div
      class="obs-modal obs-sub-detail"
      role="dialog"
      aria-modal="true"
      aria-label="edit submission"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <header class="obs-modal-head">
        <div>
          <div class="obs-eyebrow"><span class="tick"></span> {platformCopy[editing.platform] ?? editing.platform}</div>
          <h2>{editing.title}</h2>
          <p>{editing.program || 'No program recorded'} · {editing.target || 'No target recorded'}</p>
        </div>
        <button class="obs-icon-btn" type="button" aria-label="close" onclick={() => (editing = null)}>
          <Icon name="x" size={14} />
        </button>
      </header>

      <div class="obs-modal-body">
        <div class="obs-sub-meta">
          <div><span>Recorded</span><strong>{ago(editing.created_at)}</strong></div>
          <div><span>Submitted</span><strong>{editing.submitted_at ? ago(editing.submitted_at) : 'not filed'}</strong></div>
          <div><span>Decided</span><strong>{editing.decided_at ? ago(editing.decided_at) : 'open'}</strong></div>
          <div><span>Paid</span><strong>{editing.paid_at ? ago(editing.paid_at) : 'not paid'}</strong></div>
        </div>

        {#if editing.mission_title || editing.finding_title || editing.run_target}
          <div class="obs-sub-links">
            {#if editing.mission_title}<span class="obs-chip">{editing.mission_title}</span>{/if}
            {#if editing.finding_title}<span class="obs-chip violet">{editing.finding_title}</span>{/if}
            {#if editing.run_target}<span class="obs-chip">{editing.run_target}</span>{/if}
          </div>
        {/if}

        <div class="obs-form-row">
          <label class="obs-field">
            <span>Status</span>
            <select bind:value={edit.status}>
              {#each statusOrder as status (status)}
                <option value={status}>{statusCopy[status]}</option>
              {/each}
            </select>
            <small>Entering submitted, an outcome, or paid stamps that time once.</small>
          </label>
          <label class="obs-field">
            <span>Recorded award</span>
            <input bind:value={edit.bounty} type="number" min="0" step="0.01" placeholder="0.00" />
          </label>
        </div>
        <div class="obs-form-row">
          <label class="obs-field">
            <span>Currency</span>
            <select bind:value={edit.currency}>
              <option value="USD">USD</option>
              <option value="EUR">EUR</option>
              <option value="GBP">GBP</option>
              <option value="CAD">CAD</option>
              <option value="AUD">AUD</option>
            </select>
          </label>
          <label class="obs-field">
            <span>Platform report id</span>
            <input bind:value={edit.external_id} placeholder="optional" />
          </label>
        </div>
        <label class="obs-field">
          <span>Report URL</span>
          <input bind:value={edit.url} placeholder="https://..." />
        </label>
        <label class="obs-field">
          <span>Notes</span>
          <textarea bind:value={edit.notes} rows="4"></textarea>
        </label>
        {#if editing.url}
          <a class="obs-sub-external" href={editing.url} target="_blank" rel="noreferrer noopener">
            <Icon name="external" size={12} />
            Open the platform report
          </a>
        {/if}
      </div>

      <footer class="obs-modal-foot">
        <button
          class="obs-btn obs-sub-delete"
          type="button"
          disabled={busy === 'delete'}
          onclick={() => void deleteEdit()}
        >
          Delete from ledger
        </button>
        <span class="obs-modal-note">Deleting a row does not delete the report file.</span>
        <button class="obs-btn obs-btn-ghost" type="button" onclick={() => (editing = null)}>Cancel</button>
        <button
          class="obs-btn obs-btn-primary"
          type="button"
          disabled={busy === 'save'}
          onclick={() => void saveEdit()}
        >
          {busy === 'save' ? 'Saving...' : 'Save changes'}
        </button>
      </footer>
    </div>
  </div>
{/if}
