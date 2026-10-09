<script lang="ts">
  import { store } from '../state.svelte';

  const color = (kind: string) =>
    kind === 'error'
      ? 'var(--nc-violet)'
      : kind === 'warn'
        ? 'var(--nc-gold)'
        : 'var(--nc-acid)';
</script>

<div class="pointer-events-none fixed bottom-5 right-5 z-50 flex w-[min(360px,90vw)] flex-col gap-2">
  <div role="status" aria-live="polite" class="flex flex-col gap-2">
    {#each store.toasts as toast (toast.id)}
      <div
        class="toast panel fade-rise flex items-start gap-3 px-4 py-3 text-sm"
        class:leaving={toast.leaving}
        style="border-color:{color(toast.kind)};color:{color(toast.kind)}"
      >
        <span class="mt-[6px] h-2 w-2 shrink-0 rounded-full" style="background:{color(toast.kind)}"></span>
        <span class="text-bone">{toast.text}</span>
      </div>
    {/each}
  </div>
</div>
