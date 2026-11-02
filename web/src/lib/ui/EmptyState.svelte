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

<div class="obs-empty">
  <NetMotif
    class="pointer-events-none absolute inset-x-0 top-0 h-[190px] w-full opacity-35"
    animated={false}
  />
  <div class="obs-empty-inner">
    <p class="obs-eyebrow"><span class="tick"></span>{eyebrow}</p>
    <p class="obs-empty-title">{title}</p>
    <p class="obs-empty-body">{body}</p>
    {#if action}
      <button class="obs-btn obs-btn-primary" type="button" onclick={onAction} style="margin-top:6px">
        {action}
      </button>
    {/if}
    {#if hint}
      <p class="obs-empty-hint">{hint}</p>
    {/if}
    {#if children}
      {@render children()}
    {/if}
  </div>
</div>
