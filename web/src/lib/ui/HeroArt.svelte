<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">
  let { class: klass = '' }: { class?: string } = $props();

  const id = `ha${++seq}`;
  const W = 1180;
  const H = 300;
  const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  // ---- the cast: ribs fanning from the hand, chords lacing them, knots --
  const O = { x: 1150, y: 30 };
  const RX = 740;
  const RY = 250;
  const RIBS = 13;
  const DEPTHS = [0.24, 0.42, 0.6, 0.78, 0.96];

  const ribSpec = (i: number) => {
    const t = i / (RIBS - 1);
    const angle = ((110 + t * 66) * Math.PI) / 180;
    return { angle };
  };

  const along = (i: number, d: number) => {
    const { angle } = ribSpec(i);
    return { x: O.x + Math.cos(angle) * RX * d, y: O.y + Math.sin(angle) * RY * d };
  };

  const ribs = Array.from({ length: RIBS }, (_, i) => {
    const end = along(i, 1);
    return {
      i,
      path: `M${O.x} ${O.y} Q${((O.x + end.x) / 2 + 8).toFixed(1)} ${((O.y + end.y) / 2 - 6).toFixed(1)} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`
    };
  });

  const chords = DEPTHS.map((d) => {
    const pts = Array.from({ length: RIBS }, (_, i) => along(i, d));
    let path = `M${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
    for (let k = 1; k < pts.length; k++) {
      const a = pts[k - 1];
      const b = pts[k];
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2;
      path += ` Q${(mx + (O.x - mx) * 0.05).toFixed(1)} ${(my + (O.y - my) * 0.05).toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
    }
    return { d, path };
  });

  const nodes = DEPTHS.flatMap((d, di) =>
    Array.from({ length: RIBS }, (_, i) => ({ i, di, ...along(i, d) })).filter(
      (_, n) => n % 2 === di % 2
    )
  );

  const weights = Array.from({ length: RIBS }, (_, i) => along(i, 1));

  // ---- topo contours: quiet texture under the copy, bottom left ----------
  const TOPO = { cx: 150, cy: 246, rings: 7 };
  const topo = Array.from({ length: TOPO.rings }, (_, i) => {
    const base = 16 + i * 13;
    const pts = Array.from({ length: 26 }, (_, k) => {
      const a = (k / 26) * Math.PI * 2;
      const r = base + Math.sin(a * 3 + i * 0.9) * 6 + Math.cos(a * 5 - i * 1.3) * 3.5;
      return `${(TOPO.cx + Math.cos(a) * r).toFixed(1)} ${(TOPO.cy + Math.sin(a) * r).toFixed(1)}`;
    });
    return { i, path: `M${pts.join(' L')} Z` };
  });

  const SPARK = { x: 1146, y: 196 };

  // ---- the catch: one secret snagged in the mesh -------------------------
  const CARD_W = 156;
  const CARD_H = 40;
  const CATCH = { x: 790, y: 152 };

  const CATALOG: { icon: string; label: string; value: string; accent: string }[] = [
    { icon: 'key', label: 'AWS_SECRET_ACCESS_KEY', value: 'wJalrXUt****4f2e', accent: 'var(--nc-acid)' },
    { icon: 'db', label: 'DATABASE_URL', value: 'postgres://u:p@***', accent: 'var(--nc-acid)' },
    { icon: 'cloud', label: 'API_KEY', value: 'sk_live_****4f2e', accent: 'var(--nc-acid)' },
    { icon: 'card', label: 'CLIENT_SECRET', value: '****', accent: 'var(--nc-violet)' },
    { icon: 'brackets', label: 'GITHUB_TOKEN', value: 'ghp_4XK2********', accent: 'var(--nc-acid)' },
    { icon: 'shield', label: 'JWT_SIGNING_KEY', value: 'eyJhbGciOi*****', accent: 'var(--nc-violet)' }
  ];

  // tethers: card edges snagged on live knots in the mesh
  const TETHERS = [
    { ax: CATCH.x + 8, ay: CATCH.y, node: along(6, 0.6) },
    { ax: CATCH.x + CARD_W - 6, ay: CATCH.y, node: along(8, 0.42) }
  ];

  let idx = $state(4);
  let rotator = 0;

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  $effect(() => {
    if (reduced) return;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      rotator += 1;
      const next = (4 + rotator) % CATALOG.length;
      idx = next;
    }, 6800);
    return () => window.clearInterval(timer);
  });
</script>

<!-- Minimal operations scene: the cast net sweeps the whole banner and a
     single caught credential hangs in the mesh, tethered to live knots. -->
<svg
  viewBox="0 0 {W} {H}"
  class={klass}
  fill="none"
  aria-hidden="true"
  preserveAspectRatio="xMidYMid slice"
>
  <defs>
    <linearGradient id="{id}-fade" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="white" stop-opacity="0" />
      <stop offset="0.16" stop-color="white" stop-opacity="0.2" />
      <stop offset="0.38" stop-color="white" stop-opacity="0.46" />
      <stop offset="0.52" stop-color="white" stop-opacity="0.85" />
      <stop offset="0.6" stop-color="white" stop-opacity="1" />
      <stop offset="1" stop-color="white" stop-opacity="1" />
    </linearGradient>
    <mask id="{id}-mask">
      <rect width={W} height={H} fill="url(#{id}-fade)" />
    </mask>

    <linearGradient id="{id}-shine" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="white" stop-opacity="0" />
      <stop offset="0.5" stop-color="white" stop-opacity="0.85" />
      <stop offset="1" stop-color="white" stop-opacity="0" />
    </linearGradient>

    <linearGradient id="{id}-beam" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0" />
      <stop offset="0.5" stop-color="var(--nc-acid)" stop-opacity="0.13" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </linearGradient>

    <radialGradient id="{id}-glow" gradientUnits="userSpaceOnUse" cx="868" cy="172" r="96">
      <stop offset="0" stop-color="var(--nc-violet)" stop-opacity="0.2" />
      <stop offset="1" stop-color="var(--nc-violet)" stop-opacity="0" />
    </radialGradient>

    <pattern id="{id}-hatch" width="9" height="9" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
      <line x1="0" y1="0" x2="0" y2="9" stroke="var(--nc-indigo)" stroke-width="1.4" />
    </pattern>

    <clipPath id="{id}-clip" clipPathUnits="userSpaceOnUse">
      <rect width={CARD_W} height={CARD_H} rx="2" />
    </clipPath>
  </defs>

  <g mask="url(#{id}-mask)">
    <!-- hatch field, top left -->
    <path d="M0 0 H260 L214 100 H0 Z" fill="url(#{id}-hatch)" opacity="0.5" />

    <!-- topo contours, bottom left -->
    <g stroke="var(--nc-violet)" stroke-width="1">
      {#each topo as ring (ring.i)}
        <path d={ring.path} opacity={(0.07 + ring.i * 0.013).toFixed(3)} />
      {/each}
    </g>

    <!-- aura behind the catch -->
    <circle cx="868" cy="172" r="96" fill="url(#{id}-glow)" />

    <!-- the line, out of the caster's hand -->
    <path d="M1150 30 L1180 6" stroke="var(--nc-violet)" stroke-width="1.4" opacity="0.7" stroke-linecap="round" />
    <circle cx="1150" cy="30" r="3.4" fill="var(--nc-violet_abyss)" stroke="var(--nc-acid)" stroke-width="1.2" />

    <!-- chords -->
    <g stroke="var(--nc-violet)" stroke-width="1" opacity="0.55">
      {#each chords as chord (chord.d)}
        <path d={chord.path} class="hero-draw" />
      {/each}
    </g>

    <!-- ribs -->
    <g stroke="var(--nc-acid)" stroke-width="1.1" opacity="0.7">
      {#each ribs as rib (rib.i)}
        <path d={rib.path} class="hero-draw" />
      {/each}
    </g>

    <!-- weighted hem -->
    <g fill="var(--nc-acid)" opacity="0.75">
      {#each weights as w, i (i)}
        <rect
          x="-2.6"
          y="-2.6"
          width="5.2"
          height="5.2"
          transform="translate({w.x.toFixed(1)} {w.y.toFixed(1)}) rotate(45)"
        />
      {/each}
    </g>

    <!-- knots -->
    <g>
      {#each nodes as node (node.i * 10 + node.di)}
        {@const r = node.di === DEPTHS.length - 1 ? 2.6 : 1.8}
        {@const color = node.di === DEPTHS.length - 1 ? 'var(--nc-acid)' : 'var(--nc-violet)'}
        <circle cx={node.x.toFixed(1)} cy={node.y.toFixed(1)} r={r + 3.4} fill={color} opacity="0.16" />
        <circle
          cx={node.x.toFixed(1)}
          cy={node.y.toFixed(1)}
          r={r}
          fill={color}
          class="knot-pulse"
          style="animation-delay:{(node.i * 170 + node.di * 320) % 2400}ms"
        />
      {/each}
    </g>

    <!-- lone spark -->
    <path
      d="M{SPARK.x} {SPARK.y - 6} V{SPARK.y + 6} M{SPARK.x - 6} {SPARK.y} H{SPARK.x + 6}"
      stroke="var(--nc-bone)"
      stroke-width="1.3"
      stroke-linecap="round"
      class="twinkle"
      style="animation-delay:2.9s"
    />

    <!-- beam sweep -->
    <rect x="-170" y="0" width="150" height={H} fill="url(#{id}-beam)" class="hero-sweep" />
  </g>

  <!-- tethers: the catch snagged on live knots -->
  {#each TETHERS as teth, i (i)}
    <path
      d="M{teth.ax} {teth.ay} Q{(teth.ax + teth.node.x) / 2} {(teth.ay + teth.node.y) / 2 - 8} {teth.node.x.toFixed(1)} {teth.node.y.toFixed(1)}"
      stroke="var(--nc-violet)"
      stroke-width="1"
      stroke-dasharray="3 4"
      opacity="0.8"
      class="ants"
    />
    <circle cx={teth.node.x.toFixed(1)} cy={teth.node.y.toFixed(1)} r="5.4" fill="var(--nc-acid)" opacity="0.16" />
    <circle
      cx={teth.node.x.toFixed(1)}
      cy={teth.node.y.toFixed(1)}
      r="2.4"
      fill="var(--nc-acid)"
      class="knot-pulse"
      style="animation-delay:{i * 600}ms"
    />
  {/each}

  <!-- the catch: one credential card, rotating through the catalogue -->
  {#key idx}
    {@const item = CATALOG[idx]}
    <g class="secret-badge">
      <g transform="translate({CATCH.x},{CATCH.y})">
        <g clip-path="url(#{id}-clip)">
          <rect width={CARD_W} height={CARD_H} rx="2" fill="var(--nc-void)" stroke="var(--nc-violet_deep)" />
          <rect x="0" y="0" width={CARD_W} height={2} fill="url(#{id}-shine)" class="badge-shine" />

          <!-- icon well -->
          <rect x="7" y="11" width="18" height="18" rx="2" fill="var(--nc-violet_abyss)" stroke="var(--nc-violet_deep)" />
          <g
            transform="translate(9.5,13.5)"
            stroke={item.accent}
            stroke-width="1.15"
            stroke-linecap="round"
            stroke-linejoin="round"
            fill="none"
          >
            {#if item.icon === 'key'}
              <circle cx="4" cy="4" r="2.5" />
              <path d="M5.8 5.8 L11.5 11.5 M9.6 9.6 l1.4 -1.4 M11 11 l1.3 1.3" />
            {:else if item.icon === 'db'}
              <ellipse cx="7" cy="3.4" rx="4.4" ry="1.9" />
              <path d="M2.6 3.4 v7.2 c0 1.05 1.97 1.9 4.4 1.9 s4.4 -0.85 4.4 -1.9 V3.4" />
              <path d="M2.6 7 c0 1.05 1.97 1.9 4.4 1.9 s4.4 -0.85 4.4 -1.9" />
            {:else if item.icon === 'cloud'}
              <path d="M4.2 10.6 a2.5 2.5 0 0 1 0.2 -4.95 a3.3 3.3 0 0 1 6.3 0.85 a2.3 2.3 0 0 1 -0.5 4.1 z" />
            {:else if item.icon === 'card'}
              <rect x="1.5" y="3" width="11" height="8" rx="1.5" />
              <path d="M1.5 5.8 h11" />
              <path d="M3.5 8.4 h3" />
            {:else if item.icon === 'brackets'}
              <path d="M5 2.5 L2.4 7 L5 11.5 M9 2.5 L11.6 7 L9 11.5" />
            {:else}
              <path d="M7 1.6 L11.8 3.4 v3.9 c0 2.9 -2.3 4.4 -4.8 5.2 c-2.5 -0.8 -4.8 -2.3 -4.8 -5.2 V3.4 z" />
            {/if}
          </g>

          <!-- label + masked value -->
          <text x="32" y="18.5" font-size="7" letter-spacing="0.05em" fill="var(--nc-bone_dust)" font-family={MONO}
            >{item.label}</text
          >
          <text x="32" y="32.5" font-size="9.5" fill="var(--nc-acid)" font-family={MONO}>{item.value}</text>

          <!-- status LED -->
          <circle cx="140" cy="13" r="3.4" fill="var(--nc-acid)" opacity="0.16" />
          <circle cx="140" cy="13" r="1.8" fill="var(--nc-acid)" class="led-blink" />
        </g>

        <!-- HUD corner ticks -->
        <path d="M0.5 7 v-6 h6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
        <path d="M{CARD_W - 6.5} {CARD_H - 0.5} h6 v-6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
      </g>
    </g>
  {/key}
</svg>
