<script lang="ts">
  let {
    values = [],
    width = 120,
    height = 28,
    color = 'var(--nc-acid)',
    fill = true,
    class: klass = ''
  }: {
    values?: number[];
    width?: number;
    height?: number;
    color?: string;
    fill?: boolean;
    class?: string;
  } = $props();

  const top = $derived(Math.max(1, ...values));
  const floor = $derived(Math.min(0, ...values));
  const span = $derived(top - floor || 1);

  const points = $derived(
    values.map((value, index) => {
      const x = values.length <= 1 ? width / 2 : (index / (values.length - 1)) * width;
      const y = height - 2 - ((value - floor) / span) * (height - 4);
      return [x, y] as const;
    })
  );

  const line = $derived(
    points.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ')
  );
  const area = $derived(points.length > 1 ? `${line} L${width} ${height} L0 ${height} Z` : '');
  const last = $derived(points.length ? points[points.length - 1] : null);
</script>

<svg
  class={klass}
  viewBox="0 0 {width} {height}"
  preserveAspectRatio="none"
  fill="none"
  aria-hidden="true"
>
  {#if fill && area}
    <path d={area} fill={color} opacity="0.1" />
  {/if}
  {#if line}
    <path
      d={line}
      stroke={color}
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      vector-effect="non-scaling-stroke"
    />
  {/if}
  {#if last}
    <circle cx={last[0]} cy={last[1]} r="1.8" fill={color} />
  {/if}
</svg>
