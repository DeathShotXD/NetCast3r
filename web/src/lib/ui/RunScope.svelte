<script lang="ts">
  let { buckets, running }: { buckets: number[]; running: boolean } = $props();

  const W = 640;
  const H = 64;
  const BASE = H - 5;
  const GRID = [6, 18, 30, 42, 54, 66, 78];

  const slot = $derived(W / Math.max(1, buckets.length));
  const bars = $derived(
    buckets.map((value, i) => {
      const h = value <= 0 ? 0 : 3 + Math.min(1, Math.sqrt(value / 16)) * (H - 18);
      return {
        i,
        h,
        x: i * slot + 1,
        w: Math.max(2, slot - 2),
        hot: running && i >= buckets.length - 2
      };
    })
  );
</script>

<!-- One bar per 250 ms of run time: the pulse of the whole run, oldest
     left, newest at the marker. Height is a sqrt scale so a twelve-event
     burst does not flatten everything quieter. -->
<svg
  viewBox="0 0 {W} {H}"
  preserveAspectRatio="none"
  class="h-16 w-full"
  aria-hidden="true"
  data-scope="1"
>
  {#each GRID as gx (gx)}
    <line
      x1={gx * slot + slot / 2}
      y1="4"
      x2={gx * slot + slot / 2}
      y2={BASE}
      stroke="var(--nc-indigo_deep)"
      stroke-width="1"
      opacity=".45"
    />
  {/each}
  <line x1="0" y1={BASE + 0.5} x2={W} y2={BASE + 0.5} stroke="var(--nc-violet_deep)" stroke-width="1" opacity=".6" />
  {#each bars as bar (bar.i)}
    {#if bar.h > 0}
      <rect
        x={bar.x}
        y={BASE - bar.h}
        width={bar.w}
        height={bar.h}
        rx="1"
        fill={bar.hot ? 'var(--nc-acid_hot)' : 'var(--nc-acid)'}
        opacity={0.16 + 0.84 * (bar.i / Math.max(1, buckets.length - 1))}
      />
    {/if}
  {/each}
  {#if running}
    <circle cx={W - 3} cy="12" r="4.5" fill="var(--nc-acid)" opacity=".16" class="pulse-live" />
    <circle cx={W - 3} cy="12" r="2" fill="var(--nc-acid_hot)" />
  {/if}
</svg>
