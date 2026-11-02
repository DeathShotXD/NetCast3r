<script lang="ts">
  import { store } from '../state.svelte';
  import Icon from './Icon.svelte';
</script>

<div class="obs-toasts" role="region" aria-label="notifications">
  <div role="status" aria-live="polite" class="flex flex-col gap-2">
    {#each store.toasts as toast (toast.id)}
      <div class="obs-toast {toast.kind}" class:leaving={toast.leaving}>
        <span class="obs-toast-dot" aria-hidden="true"></span>
        <span class="obs-toast-text">{toast.text}</span>
        <button
          class="obs-toast-dismiss"
          type="button"
          aria-label="dismiss notification"
          onclick={() => store.dismissToast(toast.id)}
        >
          <Icon name="x" size={12} />
        </button>
      </div>
    {/each}
  </div>
</div>
