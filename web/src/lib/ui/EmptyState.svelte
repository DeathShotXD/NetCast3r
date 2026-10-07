<script lang="ts">
  import type { Snippet } from 'svelte';
  import NetMotif from './NetMotif.svelte';

  let {
    eyebrow,
    title,
    body,
    action = '',
    onAction = () => {},
    hint = '',
    children
  }: {
    eyebrow: string;
    title: string;
    body: string;
    action?: string;
    onAction?: () => void;
    hint?: string;
    children?: Snippet;
  } = $props();
</script>

<div class="empty px-6 py-14 text-center">
  <NetMotif
    class="pointer-events-none absolute inset-x-0 top-0 h-[190px] w-full opacity-40"
    animated={false}
  />
  <div class="relative z-[1] mx-auto flex max-w-[460px] flex-col items-center gap-3">
    <p class="eyebrow">{eyebrow}</p>
    <p class="rule-in mt-1 text-lg text-bone">{title}</p>
    <p class="mt-3 text-sm leading-relaxed text-bone-dust">{body}</p>
    {#if action}
      <button class="btn btn-acid mt-3" type="button" onclick={onAction}>{action}</button>
    {/if}
    {#if hint}
      <p class="mono mt-1 text-xs text-ash">{hint}</p>
    {/if}
    {#if children}
      {@render children()}
    {/if}
  </div>
</div>
