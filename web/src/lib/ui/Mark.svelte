<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">

  let {
    class: klass = '',
    live = false
  }: { class?: string; live?: boolean } = $props();

  const id = `nc${++seq}`;

  // The mascot, round like the logo: a disc of grid and shards, ringed by the
  // net, with jagged flame tendrils radiating out of the circle. Live scans
  // make the flames breathe faster.
  const R_DISC = 40;
  const R_RING = 46;

  const shards = Array.from({ length: 9 }, (_, i) => {
    const angle = (i / 9) * 360 + 12;
    const acid = i % 2 === 0;
    const len = 12 + ((i * 7) % 3) * 4.2;
    const w = 5.4 + (i % 2) * 2;
    const lean = i % 2 === 0 ? 1 : -1;
    const baseY = 60 - R_RING;
    const tipX = 60 + lean * 2.2;
    const path =
      `M${(60 - w).toFixed(1)} ${baseY}` +
      ` L${(60 - w * 0.25 * lean).toFixed(1)} ${(baseY - len * 0.55).toFixed(1)}` +
      ` L${tipX} ${(baseY - len).toFixed(1)}` +
      ` L${(60 + w * 0.4 * lean).toFixed(1)} ${(baseY - len * 0.48).toFixed(1)}` +
      ` L${(60 + w).toFixed(1)} ${baseY} Z`;
    return { angle, acid, path, delay: (i * 173) % 1700 };
  });

  const nodes = Array.from({ length: 4 }, (_, i) => {
    const a = ((i / 4) * 360 + 45) * (Math.PI / 180);
    return {
      x: (60 + Math.cos(a) * 52).toFixed(1),
      y: (60 + Math.sin(a) * 52).toFixed(1),
      delay: (i * 400) % 2400
    };
  });
</script>

<svg
  viewBox="-12 -12 144 144"
  fill="none"
  class="{klass} {live ? 'mark-live' : ''}"
  role="img"
  aria-label="NetCast3r"
>
  <defs>
    <pattern id="{id}-grid" width="10" height="10" patternUnits="userSpaceOnUse">
      <path d="M10 0H0v10" fill="none" stroke="var(--nc-violet)" stroke-width="1" opacity="0.24" />
    </pattern>
    <radialGradient id="{id}-core" cx="0.5" cy="0.42" r="0.6">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0.16" />
      <stop offset="0.55" stop-color="var(--nc-violet)" stop-opacity="0.1" />
      <stop offset="1" stop-color="var(--nc-violet_abyss)" stop-opacity="0.65" />
    </radialGradient>
    <linearGradient id="{id}-shine" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0" />
      <stop offset="0.5" stop-color="var(--nc-acid)" stop-opacity="0.22" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </linearGradient>
    <filter id="{id}-glow" x="-60%" y="-60%" width="220%" height="220%">
      <feGaussianBlur stdDeviation="2.2" result="b" />
      <feMerge>
        <feMergeNode in="b" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>
    <clipPath id="{id}-disc">
      <circle cx="60" cy="60" r={R_DISC} />
    </clipPath>
  </defs>

  <!-- flame tendrils radiating off the ring (rotate on a wrapper <g>: a CSS
       transform on the path itself would override the rotate attribute) -->
  <g>
    {#each shards as shard (shard.angle)}
      <g transform="rotate({shard.angle} 60 60)">
        <path
          d={shard.path}
          fill={shard.acid ? 'var(--nc-acid)' : 'var(--nc-violet)'}
          opacity={shard.acid ? 0.92 : 0.75}
          class="flame-shard"
          style="animation-delay:{shard.delay}ms"
        />
      </g>
    {/each}
  </g>

  <!-- the net ring -->
  <circle cx="60" cy="60" r={R_RING} fill="none" stroke="var(--nc-violet_deep)" stroke-width="1.7" />
  <circle
    cx="60"
    cy="60"
    r="52"
    fill="none"
    stroke="var(--nc-acid)"
    stroke-width="1"
    stroke-dasharray="3 7"
    opacity="0.55"
    class="mark-spin"
  />
  <g>
    {#each nodes as node (node.x + node.y)}
      <circle cx={node.x} cy={node.y} r="5.2" fill="var(--nc-acid)" opacity="0.16" />
      <circle
        cx={node.x}
        cy={node.y}
        r="2.1"
        fill="var(--nc-acid)"
        class="knot-pulse"
        style="animation-delay:{node.delay}ms"
      />
    {/each}
  </g>

  <!-- disc: grid, slashes, hex, N -->
  <circle cx="60" cy="60" r={R_DISC} fill="var(--nc-void_soft)" stroke="var(--nc-violet_deep)" stroke-width="1.4" />
  <g clip-path="url(#{id}-disc)">
    <rect x="20" y="20" width="80" height="80" fill="url(#{id}-grid)" />
    <circle cx="60" cy="60" r={R_DISC} fill="url(#{id}-core)" />
    <rect x="-10" y="20" width="26" height="80" fill="url(#{id}-shine)" />
    <g stroke="var(--nc-violet)" stroke-width="4" stroke-linecap="round" opacity="0.5">
      <path d="M30 90l10-10" />
      <path d="M84 36l9-9" />
    </g>
    <g stroke="var(--nc-acid)" stroke-width="2" stroke-linecap="round" opacity="0.65">
      <path d="M33 46l8-8" />
      <path d="M84 84l9-9" />
    </g>
  </g>

  <polygon
    points="60,34 84,47 84,73 60,86 36,73 36,47"
    fill="var(--nc-violet_abyss)"
    stroke="var(--nc-acid)"
    stroke-width="1.6"
  />
  <polygon
    points="60,41 78,51 78,69 60,79 42,69 42,51"
    fill="none"
    stroke="var(--nc-violet)"
    stroke-width="1"
    opacity="0.9"
  />
  <g filter="url(#{id}-glow)">
    <text
      x="63"
      y="71"
      font-size="30"
      font-weight="900"
      text-anchor="middle"
      fill="var(--nc-violet)"
      font-family="system-ui, -apple-system, sans-serif">N</text
    >
    <text
      x="58.5"
      y="68.5"
      font-size="30"
      font-weight="900"
      text-anchor="middle"
      fill="var(--nc-acid)"
      font-family="system-ui, -apple-system, sans-serif">N</text
    >
  </g>
</svg>
