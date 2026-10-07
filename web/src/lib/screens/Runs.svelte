<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { ago, statusColor, statusLabel } from '../format';
  import { store } from '../state.svelte';
  import Chip from '../ui/Chip.svelte';
  import Confirm from '../ui/Confirm.svelte';
  import EmptyState from '../ui/EmptyState.svelte';

  let pendingDelete = $state<string | null>(null);

  async function remove(id: string) {
    try {
      await api.deleteRun(id);
      store.runs = store.runs.filter((run) => run.id !== id);
      if (store.activeRunId === id) store.activeRunId = '';
      store.toast('ok', 'run deleted');
      void store.refreshTotals();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not delete the run');
    } finally {
      pendingDelete = null;
    }
  }

  async function rerun(id: string) {
    try {
      const fresh = await api.rerun(id);
      store.runs = [fresh, ...store.runs];
      store.watch(fresh.id);
      store.toast('ok', `rerunning ${fresh.target}`);
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'could not rerun');
    }
  }

  onMount(() => store.refreshRuns());
</script>

<div class="stagger mx-auto flex max-w-[1180px] flex-col gap-5">
  <section class="flex flex-wrap items-end gap-4">
    <div class="mr-auto">
      <p class="eyebrow">history</p>
      <h1 class="mt-1 text-xl text-bone">{store.runs.length} runs</h1>
    </div>
    <button class="btn btn-acid" type="button" onclick={() => store.go('new')}>new scan</button>
  </section>

  <section class="panel overflow-hidden">
    {#if store.runs.length === 0}
      <EmptyState
        eyebrow="empty"
        title="No scans yet"
        body="Your run history collects here: every target, when it ran, what it caught, and a rerun button for the next pass."
        action="start your first scan"
        onAction={() => store.go('new')}
        hint="> reports are also written to your results folder"
      />
    {:else}
      <div class="overflow-x-auto">
        <table class="w-full min-w-[720px] border-collapse text-left">
          <thead>
            <tr class="border-b border-indigo-deep">
              <th class="eyebrow px-4 py-3">status</th>
              <th class="eyebrow px-4 py-3">target</th>
              <th class="eyebrow px-4 py-3">results</th>
              <th class="eyebrow px-4 py-3">started</th>
              <th class="eyebrow px-4 py-3 text-right">actions</th>
            </tr>
          </thead>
          <tbody>
            {#each store.runs as run (run.id)}
              <tr class="row-link border-b border-indigo-deep/60 last:border-0">
                <td class="px-4 py-3">
                  <Chip label={statusLabel(run.status)} color={statusColor(run.status)} shape="dot" />
                </td>
                <td class="max-w-[300px] px-4 py-3">
                  <button
                    class="mono block w-full truncate text-left text-sm text-bone underline decoration-indigo underline-offset-4 hover:text-acid"
                    type="button"
                    onclick={() => store.watch(run.id)}
                  >
                    {run.target}
                  </button>
                </td>
                <td class="num px-4 py-3 text-xs text-bone-dust">
                  {run.counts?.findings ?? 0} findings / {run.counts?.endpoints ?? 0} endpoints
                </td>
                <td class="mono whitespace-nowrap px-4 py-3 text-xs text-ash">{ago(run.created_at)}</td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => store.watch(run.id)}>
                      open
                    </button>
                    <button class="btn btn-quiet px-2! py-1! text-xs" type="button" onclick={() => rerun(run.id)}>
                      rerun
                    </button>
                    <button
                      class="btn btn-quiet btn-danger px-2! py-1! text-xs"
                      type="button"
                      onclick={() => (pendingDelete = run.id)}
                    >
                      delete
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

{#if pendingDelete}
  <Confirm
    title="Delete this run?"
    body="Run {pendingDelete.slice(-6)} and every event recorded for it are removed from the index. The report files already written to your results folder are kept."
    confirmLabel="delete run"
    danger
    onConfirm={() => remove(pendingDelete!)}
    onCancel={() => (pendingDelete = null)}
  />
{/if}
