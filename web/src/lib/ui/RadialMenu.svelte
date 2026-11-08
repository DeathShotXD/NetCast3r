<script lang="ts">
  import Icon from './Icon.svelte';
  import type { RadialItem } from '../types';

  let {
    x,
    y,
    items,
    onpick,
    onclose
  }: {
    x: number;
    y: number;
    items: RadialItem[];
    onpick: (item: RadialItem) => void;
    onclose: () => void;
  } = $props();

  // Radius of the ring, and half the widest item, so the disc never leaves
  // the viewport when the menu opens near an edge.
  const R = 116;
  const HALF = 48;

  function clamp(value: number, lo: number, hi: number): number {
    return Math.max(lo, Math.min(hi, value));
  }

  let cx = $derived(clamp(x, R + HALF, window.innerWidth - (R + HALF)));
  let cy = $derived(clamp(y, R + HALF, window.innerHeight - (R + HALF)));
  let step = $derived(360 / Math.max(items.length, 1));

  function angle(i: number): number {
    return -90 + i * step;
  }
</script>

<div class="obs-radial" role="menu" aria-label="context actions">
  <button
    class="obs-radial-scrim"
    type="button"
    aria-label="dismiss menu"
    onclick={onclose}
    oncontextmenu={(event) => {
      event.preventDefault();
      onclose();
    }}
  ></button>

  <div class="obs-radial-ring" style="left:{cx}px; top:{cy}px;">
    <span class="obs-radial-halo" aria-hidden="true"></span>
    <span class="obs-radial-core" aria-hidden="true"></span>
    {#each items as item, i (item.label + i)}
      <button
        class="obs-radial-item"
        type="button"
        role="menuitem"
        style="--a:{angle(i)}deg; animation-delay:{i * 14}ms;"
        title={item.label}
        onclick={() => onpick(item)}
      >
        <span class="obs-radial-disc"><Icon name={item.icon} size={18} /></span>
        <span class="obs-radial-label">{item.label}</span>
      </button>
    {/each}
  </div>
</div>
