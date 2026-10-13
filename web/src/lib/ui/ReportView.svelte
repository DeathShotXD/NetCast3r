<script lang="ts">
  import { api } from '../api';

  let {
    runId = '',
    onClose = () => {}
  }: { runId?: string; onClose?: () => void } = $props();

  let dialog: HTMLDialogElement | undefined = $state();
  let text = $state('');
  let error = $state('');
  let loading = $state(true);

  $effect(() => {
    dialog?.showModal();
  });

  $effect(() => {
    if (!runId) return;
    loading = true;
    error = '';
    api
      .runReport(runId)
      .then((body) => {
        text = body;
      })
      .catch((exc) => {
        error = exc instanceof Error ? exc.message : 'could not load the report';
      })
      .finally(() => {
        loading = false;
      });
  });

  function close() {
    dialog?.close();
    onClose();
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
    }
  }
</script>

<dialog
  bind:this={dialog}
  class="m-auto w-[min(920px,95vw)] rounded-xl border border-indigo-deep bg-void-soft p-0 text-bone backdrop:bg-black/70"
  oncancel={(event) => {
    event.preventDefault();
    close();
  }}
  {onkeydown}
>
  <div class="flex max-h-[88vh] flex-col">
    <header class="flex items-center gap-3 border-b border-indigo-deep px-5 py-3">
      <p class="eyebrow">report // run {runId.slice(-6)}</p>
      <button class="btn btn-quiet ml-auto px-2! py-1! text-xs" type="button" onclick={close}>close</button>
    </header>
    <div class="overflow-y-auto px-5 py-4">
      {#if loading}
        <p class="mono text-xs text-slate">loading the report...</p>
      {:else if error}
        <p class="text-sm text-violet">{error}</p>
      {:else}
        <pre class="mono whitespace-pre-wrap break-words text-[12px] leading-relaxed text-bone-dust">{text}</pre>
      {/if}
    </div>
  </div>
</dialog>
