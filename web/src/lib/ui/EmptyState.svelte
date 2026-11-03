<script lang="ts">
  import type { Snippet } from 'svelte';
  import NetMotif from './NetMotif.svelte';

  let {
    eyebrow,
    title,
    body,
    action = '',
    onAction = () => {},
    secondaryAction = '',
    onSecondaryAction = () => {},
    tone = 'default' as 'default' | 'error',
    hint = '',
    children
  }: {
    eyebrow: string;
    title: string;
    body: string;
    action?: string;
    onAction?: () => void;
    secondaryAction?: string;
    onSecondaryAction?: () => void;
    tone?: 'default' | 'error';
    hint?: string;
    children?: Snippet;
  } = $props();
</script>

<div class="obs-empty" class:obs-empty-error={tone === 'error'} role={tone === 'error' ? 'alert' : undefined}>
  <NetMotif
    class="pointer-events-none absolute inset-x-0 top-0 h-[190px] w-full opacity-35"
    animated={false}
  />
  <div class="obs-empty-inner">
    <p class="obs-eyebrow"><span class="tick"></span>{eyebrow}</p>
    <p class="obs-empty-title">{title}</p>
    <p class="obs-empty-body">{body}</p>
    {#if action || secondaryAction}
      <div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:6px">
        {#if action}
          <button class="obs-btn obs-btn-primary" type="button" onclick={onAction}>{action}</button>
        {/if}
        {#if secondaryAction}
          <button class="obs-btn obs-btn-ghost" type="button" onclick={onSecondaryAction}>{secondaryAction}</button>
        {/if}
      </div>
    {/if}
    {#if hint}
      <p class="obs-empty-hint">{hint}</p>
    {/if}
    {#if children}
      {@render children()}
    {/if}
  </div>
</div>
