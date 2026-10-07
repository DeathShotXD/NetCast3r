<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">

  let { class: klass = '' }: { class?: string } = $props();

  const id = `nc${++seq}`;
</script>

<!-- The banner monogram, scaled down: violet slash field, grid, acid hexagon with the N. -->
<svg viewBox="0 0 120 120" fill="none" class={klass} role="img" aria-label="NetCast3r">
  <defs>
    <pattern id="{id}-grid" width="12" height="12" patternUnits="userSpaceOnUse">
      <path d="M12 0H0v12" fill="none" stroke="var(--nc-violet)" stroke-width="1" opacity="0.24" />
    </pattern>
    <linearGradient id="{id}-shine" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0" />
      <stop offset="0.5" stop-color="var(--nc-acid)" stop-opacity="0.2" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </linearGradient>
    <filter id="{id}-glow" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="2.4" result="b" />
      <feMerge>
        <feMergeNode in="b" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>
    <clipPath id="{id}-clip">
      <rect x="1" y="1" width="118" height="118" rx="16" />
    </clipPath>
  </defs>

  <rect
    x="1"
    y="1"
    width="118"
    height="118"
    rx="16"
    fill="var(--nc-void_soft)"
    stroke="var(--nc-violet_deep)"
    stroke-width="1.6"
  />

  <g clip-path="url(#{id}-clip)">
    <rect width="120" height="120" fill="url(#{id}-grid)" />
    <rect x="-46" y="0" width="34" height="120" fill="url(#{id}-shine)" />
    <g stroke="var(--nc-violet)" stroke-width="5" stroke-linecap="round" opacity="0.5">
      <path d="M8 98l18-18" />
      <path d="M17 109l20-20" />
      <path d="M94 30l17-17" />
      <path d="M79 21l13-13" />
    </g>
    <g stroke="var(--nc-acid)" stroke-width="2.2" stroke-linecap="round" opacity="0.7">
      <path d="M13 44l13-13" />
      <path d="M96 94l15-15" />
    </g>
  </g>

  <polygon
    points="60,21 95,41 95,79 60,99 25,79 25,41"
    fill="var(--nc-violet_abyss)"
    stroke="var(--nc-acid)"
    stroke-width="1.8"
  />
  <polygon
    points="60,31 86,46 86,74 60,89 34,74 34,46"
    fill="none"
    stroke="var(--nc-violet)"
    stroke-width="1.1"
    opacity="0.9"
  />
  <g filter="url(#{id}-glow)">
    <text
      x="64"
      y="77"
      font-size="42"
      font-weight="900"
      text-anchor="middle"
      fill="var(--nc-violet)"
      font-family="system-ui, -apple-system, sans-serif">N</text
    >
    <text
      x="58"
      y="74"
      font-size="42"
      font-weight="900"
      text-anchor="middle"
      fill="var(--nc-acid)"
      font-family="system-ui, -apple-system, sans-serif">N</text
    >
  </g>
</svg>
