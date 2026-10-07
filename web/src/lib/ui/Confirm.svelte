<script lang="ts">
  let {
    title,
    body,
    confirmLabel = 'confirm',
    danger = false,
    onConfirm = () => {},
    onCancel = () => {}
  }: {
    title: string;
    body: string;
    confirmLabel?: string;
    danger?: boolean;
    onConfirm?: () => void;
    onCancel?: () => void;
  } = $props();

  let dialog: HTMLDialogElement | undefined = $state();

  $effect(() => {
    dialog?.showModal();
  });

  function close(action: 'confirm' | 'cancel') {
    dialog?.close();
    if (action === 'confirm') onConfirm();
    else onCancel();
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault();
      close('cancel');
    }
  }
</script>

<dialog
  bind:this={dialog}
  class="m-auto w-[min(460px,92vw)] rounded-xl border border-violet-deep bg-void-soft p-0 text-bone backdrop:bg-black/70"
  oncancel={(event) => {
    event.preventDefault();
    close('cancel');
  }}
  {onkeydown}
>
  <div class="p-6">
    <p class="eyebrow">confirm</p>
    <h2 class="mt-2 text-lg text-bone">{title}</h2>
    <p class="mt-3 text-sm leading-relaxed text-bone-dust">{body}</p>
    <div class="mt-6 flex justify-end gap-3">
      <button class="btn btn-quiet" type="button" onclick={() => close('cancel')}>cancel</button>
      <button
        class={danger ? 'btn btn-danger' : 'btn btn-acid'}
        type="button"
        onclick={() => close('confirm')}
      >
        {confirmLabel}
      </button>
    </div>
  </div>
</dialog>
