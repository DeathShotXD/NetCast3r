<script lang="ts">
  import type { Shape } from '../format';

  let {
    label,
    color,
    shape = 'dot',
    title = ''
  }: { label: string; color: string; shape?: Shape; title?: string } = $props();
</script>

<span class="chip" style="color:{color}" title={title}>
  {#if shape === 'tri'}
    <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
      <path d="M4 0l4.5 8h-9z" />
    </svg>
  {:else if shape === 'sq'}
    <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
      <rect x="0.75" y="0.75" width="6.5" height="6.5" />
    </svg>
  {:else if shape === 'dia'}
    <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
      <rect x="1.6" y="1.6" width="4.8" height="4.8" transform="rotate(45 4 4)" />
    </svg>
  {:else if shape === 'ring'}
    <svg viewBox="0 0 8 8" class="h-[7px] w-[7px]" aria-hidden="true">
      <circle cx="4" cy="4" r="3" fill="none" stroke="currentColor" stroke-width="1.6" />
    </svg>
  {:else}
    <svg viewBox="0 0 8 8" class="h-[7px] w-[7px] fill-current" aria-hidden="true">
      <circle cx="4" cy="4" r="3.4" />
    </svg>
  {/if}
  {label}
</span>
