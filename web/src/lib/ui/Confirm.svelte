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
  let cancelBtn: HTMLButtonElement | undefined = $state();

  $effect(() => {
    dialog?.showModal();
    queueMicrotask(() => cancelBtn?.focus());
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
  class="obs-confirm"
  aria-label={title}
  oncancel={(event) => {
    event.preventDefault();
    close('cancel');
  }}
  {onkeydown}
>
  <div class="obs-confirm-body">
    <p class="obs-eyebrow"><span class="tick"></span>confirm</p>
    <h2 class="obs-confirm-title">{title}</h2>
    <p class="obs-confirm-copy">{body}</p>
    <div class="obs-confirm-actions">
      <button
        class="obs-btn obs-btn-ghost"
        type="button"
        bind:this={cancelBtn}
        onclick={() => close('cancel')}
      >cancel</button>
      <button
        class={danger ? 'obs-btn obs-btn-danger' : 'obs-btn obs-btn-primary'}
        type="button"
        onclick={() => close('confirm')}
      >
        {confirmLabel}
      </button>
    </div>
  </div>
</dialog>
