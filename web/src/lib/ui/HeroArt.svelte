<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">
  let { class: klass = '' }: { class?: string } = $props();

  const id = `ha${++seq}`;
  const W = 1180;
  const H = 360;
  const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  const SANS = 'system-ui, -apple-system, sans-serif';

  // deterministic scatter so the city never shifts between renders
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647), seed / 2147483647);

  // ---- the city ---------------------------------------------------------
  const GROUND = 316;
  type Bld = { x: number; w: number; h: number };
  const makeRow = (minW: number, maxW: number, minH: number, maxH: number, gap: number): Bld[] => {
    const out: Bld[] = [];
    let x = -14;
    while (x < W + 10) {
      const w = minW + rnd() * (maxW - minW);
      const h = minH + rnd() * (maxH - minH);
      out.push({ x: +x.toFixed(1), w: +w.toFixed(1), h: +h.toFixed(1) });
      x += w + rnd() * gap;
    }
    return out;
  };
  const far = makeRow(30, 74, 56, 150, 16);
  const near = makeRow(24, 62, 34, 112, 18);

  type Win = { x: number; y: number; c: string; d: number };
  const wins: Win[] = [];
  const winColors = ['var(--nc-acid)', 'var(--nc-violet)', 'var(--nc-gold)'];
  for (const b of near) {
    const cols = Math.floor((b.w - 8) / 9);
    const rows = Math.floor((b.h - 10) / 11);
    for (let c = 0; c < cols; c++) {
      for (let r = 0; r < rows; r++) {
        if (rnd() > 0.55 && wins.length < 88) {
          wins.push({
            x: +(b.x + 5 + c * 9).toFixed(1),
            y: +(GROUND - b.h + 7 + r * 11).toFixed(1),
            c: winColors[Math.floor(rnd() * 3)],
            d: Math.floor(rnd() * 4200)
          });
        }
      }
    }
  }

  const spires = [3, 9, 16]
    .map((i) => far[i]).filter(Boolean)
    .map((b) => ({ x: b.x + b.w / 2, y: GROUND - b.h }))
    .filter((s) => s.x > 20 && s.x < W - 20);

  // ---- the caster: a spider at the hub of the net ------------------------
  // eight legs radiate from the origin, each anchored by a glowing silk tip
  const LEGS = [
    'M846 139 Q824 128 810 108 Q804 99 796 94',
    'M845 144 Q818 143 800 140 Q792 139 784 137',
    'M847 150 Q824 158 810 174 Q803 183 798 194',
    'M851 153 Q842 172 836 190 Q833 200 832 212',
    'M862 139 Q884 126 898 108 Q905 99 912 94',
    'M863 144 Q892 142 910 138 Q920 136 928 133',
    'M861 150 Q886 159 900 176 Q907 186 912 198',
    'M857 154 Q866 174 870 192 Q872 202 872 214'
  ];
  const LEG_TIPS = [
    { x: 796, y: 94 },
    { x: 784, y: 137 },
    { x: 798, y: 194 },
    { x: 832, y: 212 },
    { x: 912, y: 94 },
    { x: 928, y: 133 },
    { x: 912, y: 198 },
    { x: 872, y: 214 }
  ];

  // ---- the moon ---------------------------------------------------------
  const MOON = { cx: 686, cy: 150, r: 106 };
  const maria = [
    { cx: 648, cy: 118, rx: 26, ry: 15, o: 0.26, rot: -18 },
    { cx: 722, cy: 176, rx: 22, ry: 13, o: 0.24, rot: 24 },
    { cx: 674, cy: 208, rx: 30, ry: 12, o: 0.22, rot: -6 },
    { cx: 736, cy: 120, rx: 13, ry: 9, o: 0.25, rot: 0 }
  ];

  const stars = Array.from({ length: 12 }, () => ({
    x: +(560 + rnd() * 600).toFixed(1),
    y: +(10 + rnd() * 72).toFixed(1),
    r: +(0.9 + rnd() * 0.8).toFixed(1),
    c: rnd() > 0.5 ? 'var(--nc-bone)' : 'var(--nc-acid)',
    d: Math.floor(rnd() * 3200)
  }));

  // ---- the cast: net ribs from the outstretched palm --------------------
  const O = { x: 854, y: 144 };
  const ANG = [-52, -40, -28, -16, -4, 8, 20, 32, 44, 56, 68, 80, 92];
  const LEN = [470, 500, 520, 500, 470, 430, 300, 260, 240, 200, 180, 170, 168];
  const RAD = ANG.map((a) => (a * Math.PI) / 180);

  const along = (i: number, d: number) => ({
    x: O.x + Math.cos(RAD[i]) * LEN[i] * d,
    y: O.y + Math.sin(RAD[i]) * LEN[i] * d
  });

  const ribs = ANG.map((_, i) => {
    const e = along(i, 1);
    return { i, path: `M${O.x} ${O.y} L${e.x.toFixed(1)} ${e.y.toFixed(1)}` };
  });

  const DEPTHS = [0.24, 0.4, 0.56, 0.72, 0.88];
  const chords = DEPTHS.map((d) => {
    const pts = ANG.map((_, i) => along(i, d));
    let path = `M${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
    for (let k = 1; k < pts.length; k++) {
      const a = pts[k - 1];
      const b = pts[k];
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2;
      path += ` Q${(mx + (O.x - mx) * 0.06).toFixed(1)} ${(my + (O.y - my) * 0.06).toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
    }
    return { d, path };
  });

  const nodes = DEPTHS.flatMap((d, di) =>
    ANG.map((_, i) => ({ i, di, ...along(i, d) })).filter(
      (n) => n.x > 4 && n.x < 1176 && n.y > 4 && n.y < 354 && n.i % 2 === di % 2
    )
  );

  const hemTips = [6, 7, 8, 9, 10, 11, 12]
    .map((i) => ({ i, ...along(i, 1) }))
    .filter((t) => t.x < 1174 && t.y < 352);

  // ---- the caught: four credential cards floating in the banner ---------
  const CARD_W = 176;
  const CARD_H = 38;

  type Item = { icon: string; label: string; value: string; accent: string };
  type Slot = { x: number; y: number; rot: number; fl: string; item?: Item; rotator?: boolean };

  // each key sits in its own zone of the banner: top right, mid right,
  // across the moon, and over the city below it
  const SLOTS: Slot[] = [
    {
      x: 884,
      y: 30,
      rot: -2,
      fl: 'f-a',
      item: { icon: 'key', label: 'AWS_SECRET_ACCESS_KEY', value: 'wJalrXUtnFEMI********', accent: 'var(--nc-acid)' }
    },
    {
      x: 966,
      y: 124,
      rot: 2,
      fl: 'f-b',
      item: { icon: 'db', label: 'DATABASE_URL', value: 'postgres://user:pass@***', accent: 'var(--nc-acid)' }
    },
    {
      x: 596,
      y: 172,
      rot: -1.5,
      fl: 'f-c',
      item: { icon: 'cloud', label: 'API_KEY', value: 'sk_live_********', accent: 'var(--nc-acid)' }
    },
    { x: 636, y: 254, rot: 2.5, fl: 'f-d', rotator: true }
  ];

  const ROT: Item[] = [
    { icon: 'card', label: 'CLIENT_SECRET', value: '************', accent: 'var(--nc-violet)' },
    { icon: 'brackets', label: 'GITHUB_TOKEN', value: 'ghp_4XK2**********', accent: 'var(--nc-acid)' },
    { icon: 'shield', label: 'JWT_SIGNING_KEY', value: 'eyJhbGciOi*****', accent: 'var(--nc-violet)' }
  ];

  const TETHERS = [
    { ax: 890, ay: 72, i: 3, d: 0.348 },
    { ax: 966, ay: 142, i: 5, d: 0.5 }
  ];

  // ---- the report panel and the validation ladder ------------------------
  const REPORT = { x: 830, y: 216, w: 200, h: 100 };
  const CHECKS = ['PoC', 'Evidence', 'Steps to Reproduce', 'Submission Ready'];

  const CHIPS = [
    { label: 'CONFIRMED', color: 'var(--nc-acid)' },
    { label: 'CORROBORATED', color: 'var(--nc-gold)' },
    { label: 'INFERRED', color: 'var(--nc-violet)' },
    { label: 'UNRESOLVED', color: 'var(--nc-ash)' }
  ];

  // ---- the six-stage rail ------------------------------------------------
  const RAIL = [
    { key: 'crawl', label: 'CRAWL', detail: 'Target & Endpoints' },
    { key: 'readjs', label: 'READ JS', detail: 'Map Logic & Weak Spots' },
    { key: 'hunt', label: 'HUNT', detail: 'Secrets & Credentials' },
    { key: 'validate', label: 'VALIDATE', detail: 'Check Access & Impact' },
    { key: 'escalate', label: 'ESCALATE', detail: 'Find Highest Provable' },
    { key: 'report', label: 'REPORT', detail: 'Ready for Submission' }
  ];
  const cellLeft = (i: number) => 190 + i * 140;

  let rIdx = $state(0);
  let rotator = 0;

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  $effect(() => {
    if (reduced) return;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      rotator += 1;
      rIdx = rotator % ROT.length;
    }, 6800);
    return () => window.clearInterval(timer);
  });
</script>

<!-- The caster: a spider throws the net over the city. Recreated from
     assets/NetCast3r-Banner.png -- moon and skyline behind, the six-stage
     rail and validation ladder along the edges, credentials caught in the
     mesh and scattered across the banner. Dynamic copy overlays the left
     column. -->
<svg
  viewBox="0 0 {W} {H}"
  class={klass}
  fill="none"
  aria-hidden="true"
  preserveAspectRatio="xMidYMid slice"
>
  <defs>
    <linearGradient id="{id}-fade" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="white" stop-opacity="0.06" />
      <stop offset="0.34" stop-color="white" stop-opacity="0.12" />
      <stop offset="0.47" stop-color="white" stop-opacity="0.3" />
      <stop offset="0.53" stop-color="white" stop-opacity="0.82" />
      <stop offset="0.575" stop-color="white" stop-opacity="1" />
      <stop offset="1" stop-color="white" stop-opacity="1" />
    </linearGradient>
    <mask id="{id}-mask">
      <rect width={W} height={H} fill="url(#{id}-fade)" />
    </mask>

    <linearGradient id="{id}-sky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="var(--nc-violet_abyss)" stop-opacity="0.95" />
      <stop offset="0.5" stop-color="var(--nc-indigo_deep)" stop-opacity="0.75" />
      <stop offset="1" stop-color="var(--nc-void_soft)" stop-opacity="1" />
    </linearGradient>

    <radialGradient id="{id}-atmos" gradientUnits="userSpaceOnUse" cx={MOON.cx} cy={MOON.cy} r="240">
      <stop offset="0" stop-color="var(--nc-violet)" stop-opacity="0.16" />
      <stop offset="0.6" stop-color="var(--nc-violet)" stop-opacity="0.05" />
      <stop offset="1" stop-color="var(--nc-violet)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-halo" gradientUnits="userSpaceOnUse" cx={MOON.cx} cy={MOON.cy} r="150">
      <stop offset="0.71" stop-color="var(--nc-gold)" stop-opacity="0.11" />
      <stop offset="1" stop-color="var(--nc-gold)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-moon" gradientUnits="userSpaceOnUse" cx={MOON.cx} cy={MOON.cy} r={MOON.r}>
      <stop offset="0" stop-color="var(--nc-bone)" stop-opacity="0.97" />
      <stop offset="0.55" stop-color="var(--nc-gold)" stop-opacity="0.92" />
      <stop offset="0.93" stop-color="var(--nc-gold)" stop-opacity="0.68" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0.38" />
    </radialGradient>

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

    <radialGradient id="{id}-hub" gradientUnits="userSpaceOnUse" cx={O.x} cy={O.y} r="34">
      <stop offset="0" stop-color="var(--nc-void)" stop-opacity="0.78" />
      <stop offset="0.62" stop-color="var(--nc-void)" stop-opacity="0.6" />
      <stop offset="1" stop-color="var(--nc-void)" stop-opacity="0" />
    </radialGradient>

    <clipPath id="{id}-clip" clipPathUnits="userSpaceOnUse">
      <rect width={CARD_W} height={CARD_H} rx="2" />
    </clipPath>
  </defs>

  <g mask="url(#{id}-mask)">
    <!-- sky + atmosphere -->
    <rect width={W} height={H} fill="url(#{id}-sky)" />
    <circle cx={MOON.cx} cy={MOON.cy} r="240" fill="url(#{id}-atmos)" />

    <!-- the moon -->
    <g class="moon-breath">
      <circle cx={MOON.cx} cy={MOON.cy} r="150" fill="url(#{id}-halo)" />
      <circle cx={MOON.cx} cy={MOON.cy} r={MOON.r} fill="url(#{id}-moon)" />
      {#each maria as m, i (i)}
        <ellipse
          cx={m.cx}
          cy={m.cy}
          rx={m.rx}
          ry={m.ry}
          fill="var(--nc-void)"
          opacity={m.o}
          transform="rotate({m.rot} {m.cx} {m.cy})"
        />
      {/each}
      <circle
        cx={MOON.cx}
        cy={MOON.cy}
        r={MOON.r}
        stroke="var(--nc-gold)"
        stroke-width="1.4"
        opacity="0.4"
      />
    </g>

    <!-- far skyline -->
    <g fill="var(--nc-violet_abyss)" opacity="0.85">
      {#each far as b, i (i)}
        <rect x={b.x} y={GROUND - b.h} width={b.w} height={b.h} />
      {/each}
    </g>
    {#each spires as s, i (i)}
      <path d="M{s.x} {s.y} V{s.y - 26}" stroke="var(--nc-violet_abyss)" stroke-width="2" />
      <circle cx={s.x} cy={s.y - 28} r="2" fill="var(--nc-acid)" class="twinkle" style="animation-delay:{i * 900 + 400}ms" />
    {/each}

    <!-- near skyline with lit windows -->
    <g fill="var(--nc-indigo_deep)" opacity="0.92">
      {#each near as b, i (i)}
        <rect x={b.x} y={GROUND - b.h} width={b.w} height={b.h} />
      {/each}
    </g>
    <g>
      {#each wins as w, i (i)}
        <rect x={w.x} y={w.y} width="3.4" height="4.6" fill={w.c} opacity="0.55" class="win-blink" style="animation-delay:{w.d}ms" />
      {/each}
    </g>

    <!-- ground -->
    <rect x="0" y={GROUND} width={W} height={H - GROUND} fill="var(--nc-void)" opacity="0.92" />

    <!-- the net, cast from the palm -->
    <g stroke="var(--nc-violet)" stroke-width="1" opacity="0.62">
      {#each chords as chord (chord.d)}
        <path d={chord.path} class="hero-draw" />
      {/each}
    </g>
    <g stroke="var(--nc-acid)" stroke-width="1.1" opacity="0.8">
      {#each ribs as rib (rib.i)}
        <path d={rib.path} class="hero-draw" />
      {/each}
    </g>

    <!-- knots -->
    <g>
      {#each nodes as node (node.i * 10 + node.di)}
        {@const r = node.di === DEPTHS.length - 1 ? 2.5 : 1.7}
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

    <!-- weighted hem -->
    <g fill="var(--nc-acid)" opacity="0.8">
      {#each hemTips as w, i (i)}
        <rect
          x="-2.6"
          y="-2.6"
          width="5.2"
          height="5.2"
          transform="translate({w.x.toFixed(1)} {w.y.toFixed(1)}) rotate(45)"
        />
      {/each}
    </g>

    <!-- the caster: a spider at the hub, legs braced across the mesh -->
    <g>
      <!-- the web clears where the spider sits -->
      <circle cx={O.x} cy={O.y} r="34" fill="url(#{id}-hub)" />
      {#each LEGS as leg, i (i)}
        <path d={leg} stroke="var(--nc-violet)" stroke-width="2.4" stroke-linecap="round" fill="none" opacity="0.95" />
        <path
          d={leg}
          stroke="var(--nc-acid)"
          stroke-width="1.1"
          stroke-linecap="round"
          fill="none"
          opacity="0.6"
          class="knot-pulse"
          style="animation-delay:{i * 420}ms"
        />
      {/each}
      {#each LEG_TIPS as tip, i (i)}
        <circle cx={tip.x} cy={tip.y} r="3.2" fill="var(--nc-acid)" opacity="0.16" />
        <circle cx={tip.x} cy={tip.y} r="1.6" fill="var(--nc-acid)" class="twinkle" style="animation-delay:{i * 340}ms" />
      {/each}

      <!-- body: breathes inside the standing legs -->
      <g class="caster-bob">
        <circle cx={O.x} cy={O.y} r="17" fill="var(--nc-acid)" opacity="0.13" class="knot-pulse" />
        <!-- pedipalps -->
        <path d="M847 141 Q841 137 837 134" stroke="var(--nc-violet)" stroke-width="1.7" stroke-linecap="round" fill="none" />
        <path d="M847 148 Q841 152 837 155" stroke="var(--nc-violet)" stroke-width="1.7" stroke-linecap="round" fill="none" />
        <!-- abdomen -->
        <ellipse cx="878" cy="154" rx="17.5" ry="14" transform="rotate(24 878 154)" fill="var(--nc-void_soft)" stroke="var(--nc-violet)" stroke-width="1.3" />
        <path d="M869 148 Q878 152 887 148.5" stroke="var(--nc-acid)" stroke-width="1.2" fill="none" opacity="0.8" />
        <path d="M870 155 Q878 158.5 886 155" stroke="var(--nc-acid)" stroke-width="1" fill="none" opacity="0.55" />
        <!-- cephalothorax -->
        <ellipse cx={O.x} cy={O.y} rx="14" ry="11.5" fill="var(--nc-void)" stroke="var(--nc-violet)" stroke-width="1.3" />
        <path d="M845 139 Q854 135.5 863 139" stroke="var(--nc-acid)" stroke-width="1.2" fill="none" opacity="0.7" />
        <!-- eyes, facing the moon -->
        <g class="eye-glow">
          <circle cx="845.5" cy="141.5" r="1.3" fill="var(--nc-acid)" />
          <circle cx="845.5" cy="145.5" r="1.3" fill="var(--nc-acid)" />
          <circle cx="849" cy="139.5" r="1.15" fill="var(--nc-acid)" />
          <circle cx="849" cy="143.5" r="1.15" fill="var(--nc-acid)" />
        </g>
      </g>
    </g>

    <!-- tethers: cards snagged on live knots -->
    {#each TETHERS as teth, i (i)}
      {@const node = along(teth.i, teth.d)}
      <path
        d="M{teth.ax} {teth.ay} Q{(teth.ax + node.x) / 2} {(teth.ay + node.y) / 2 - 8} {node.x.toFixed(1)} {node.y.toFixed(1)}"
        stroke="var(--nc-violet)"
        stroke-width="1"
        stroke-dasharray="3 4"
        opacity="0.8"
        class="ants"
      />
      <circle cx={node.x.toFixed(1)} cy={node.y.toFixed(1)} r="5.4" fill="var(--nc-acid)" opacity="0.16" />
      <circle
        cx={node.x.toFixed(1)}
        cy={node.y.toFixed(1)}
        r="2.4"
        fill="var(--nc-acid)"
        class="knot-pulse"
        style="animation-delay:{i * 600}ms"
      />
    {/each}

    <!-- stars over the city -->
    {#each stars as star, i (i)}
      <circle cx={star.x} cy={star.y} r={star.r} fill={star.c} class="twinkle" style="animation-delay:{star.d}ms" />
    {/each}

    <!-- beam sweep -->
    <rect x="-170" y="0" width="150" height={H} fill="url(#{id}-beam)" class="hero-sweep" />
  </g>

  <!-- the caught: four credential cards. The frame lives and drifts for
       good; only the credential inside the rotator slot swaps, so the
       motion never resets when the key rotates. -->
  {#snippet cardBody(item: Item)}
    <g clip-path="url(#{id}-clip)">
      <rect width={CARD_W} height={CARD_H} rx="2" fill="var(--nc-void)" stroke="var(--nc-violet_deep)" />
      <rect x="0" y="0" width={CARD_W} height="2" fill="url(#{id}-shine)" class="badge-shine" />

      <rect x="7" y="11" width="16" height="16" rx="2" fill="var(--nc-violet_abyss)" stroke="var(--nc-violet_deep)" />
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

      <text x="30" y="17" font-size="6.8" letter-spacing="0.05em" fill="var(--nc-bone_dust)" font-family={MONO}
        >{item.label}</text
      >
      <text x="30" y="31" font-size="9.5" fill="var(--nc-acid)" font-family={MONO}>{item.value}</text>

      <circle cx="160" cy="12" r="3.4" fill="var(--nc-acid)" opacity="0.16" />
      <circle cx="160" cy="12" r="1.8" fill="var(--nc-acid)" class="led-blink" />
    </g>
  {/snippet}

  {#snippet card(item: Item, x: number, y: number, rot: number, fl: string, rotating: boolean)}
    <g class="secret-badge">
      <g class="badge-float {fl}">
        <g transform="translate({x},{y}) rotate({rot})">
          {#if rotating}
            {#key rIdx}
              <g class="rot-in">{@render cardBody(ROT[rIdx])}</g>
            {/key}
          {:else}
            {@render cardBody(item)}
          {/if}

          <path d="M0.5 7 v-6 h6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
          <path d="M{CARD_W - 6.5} {CARD_H - 0.5} h6 v-6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
        </g>
      </g>
    </g>
  {/snippet}

  {#each SLOTS as slot, i (i)}
    {@render card(slot.item ?? ROT[rIdx], slot.x, slot.y, slot.rot, slot.fl, slot.rotator ?? false)}
  {/each}

  <!-- report panel -->
  <g>
    <rect
      x={REPORT.x}
      y={REPORT.y}
      width={REPORT.w}
      height={REPORT.h}
      rx="6"
      fill="var(--nc-void)"
      stroke="var(--nc-acid)"
      stroke-width="1.3"
    />
    <path d="M{REPORT.x + 8} {REPORT.y + 18} V{REPORT.y + 8} h10" stroke="var(--nc-acid)" stroke-width="1.2" fill="none" />
    <text x={REPORT.x + 10} y={REPORT.y + 18} font-size="10.5" font-weight="700" letter-spacing="0.12em" fill="var(--nc-bone)" font-family={MONO}
      >REPORT</text
    >
    <g transform="translate({REPORT.x + 174},{REPORT.y + 6}) scale(0.5)" stroke="var(--nc-acid)" stroke-width="2.4" fill="none" stroke-linecap="round">
      <path d="M6 4.5 A1.5 1.5 0 0 1 7.5 3 H14 L18.5 7.5 V19.5 A1.5 1.5 0 0 1 17 21 H7.5 A1.5 1.5 0 0 1 6 19.5 Z" />
      <path d="M14 3 V7.5 H18.5" />
      <path d="M8.7 10.6 H15.8 M8.7 13.2 H14.2 M8.7 15.8 H11.6" />
      <circle cx="15.4" cy="16.8" r="3.5" />
      <path d="M13.9 16.8 l1.05 1.05 l1.95 -2.15" />
    </g>
    <path d="M{REPORT.x + 10} {REPORT.y + 24} H{REPORT.x + REPORT.w - 10}" stroke="var(--nc-indigo_deep)" stroke-width="1" />
    {#each CHECKS as label, i (i)}
      {@const cy = REPORT.y + 38 + i * 15}
      <path
        d="M{REPORT.x + 12} {cy - 4} l3.5 4 7 -8.5"
        stroke="var(--nc-acid)"
        stroke-width="1.6"
        stroke-linecap="round"
        stroke-linejoin="round"
        class="hero-ck"
        style="animation-delay:{0.6 + i * 0.15}s"
      />
      <text
        x={REPORT.x + 30}
        y={cy + 0.5}
        font-size="8.5"
        fill={i === 3 ? 'var(--nc-acid)' : 'var(--nc-bone)'}
        font-weight={i === 3 ? '700' : '400'}
        font-family={MONO}>{label}</text
      >
    {/each}
  </g>

  <!-- validation ladder -->
  {#each CHIPS as chip, i (i)}
    <rect
      x="1046"
      y={218 + i * 26}
      width="114"
      height="20"
      rx="4"
      fill="var(--nc-void)"
      stroke={chip.color}
      stroke-width="1.2"
      opacity="0.96"
    />
    <text
      x="1056"
      y={232 + i * 26}
      font-size="7.5"
      font-weight="700"
      letter-spacing="0.1em"
      fill="var(--nc-bone)"
      font-family={MONO}>{chip.label}</text
    >
  {/each}

  <!-- six-stage rail -->
  <rect x="170" y="318" width="858" height="40" rx="8" fill="var(--nc-void)" opacity="0.55" stroke="var(--nc-indigo_deep)" />
  {#each RAIL as cell, i (cell.key)}
    {@const left = cellLeft(i)}
    <svg x={left} y="327" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--nc-acid)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
      {#if cell.key === 'crawl'}
        <circle cx="12" cy="9.4" r="2.1" />
        <path d="M12 11.3 C9.7 11.3 8.5 13.6 8.5 16.2 C8.5 18.9 10 21 12 21 C14 21 15.5 18.9 15.5 16.2 C15.5 13.6 14.3 11.3 12 11.3 Z" />
        <path d="M10.1 10.4 L6.4 8.2 L5 5.4" />
        <path d="M9.2 12.6 L5.2 12.4 L3.2 10.4" />
        <path d="M9.4 15.4 L5.6 16.6 L4.4 19.6" />
        <path d="M13.9 10.4 L17.6 8.2 L19 5.4" />
        <path d="M14.8 12.6 L18.8 12.4 L20.8 10.4" />
        <path d="M14.6 15.4 L18.4 16.6 L19.6 19.6" />
        <path d="M11 7.5 L10.5 5.6" />
        <path d="M13 7.5 L13.5 5.6" />
      {:else if cell.key === 'readjs'}
        <path d="M6 4.5 A1.5 1.5 0 0 1 7.5 3 H14 L18.5 7.5 V19.5 A1.5 1.5 0 0 1 17 21 H7.5 A1.5 1.5 0 0 1 6 19.5 Z" />
        <path d="M14 3 V7.5 H18.5" />
        <path d="M10.2 9.6 C9.1 9.9 8.9 10.4 8.9 11.2 V12.3 C8.9 12.9 8.6 13.3 8 13.5 C8.6 13.7 8.9 14.1 8.9 14.7 V15.8 C8.9 16.6 9.1 17.1 10.2 17.4" />
        <path d="M15.2 9.6 C16.3 9.9 16.5 10.4 16.5 11.2 V12.3 C16.5 12.9 16.8 13.3 17.4 13.5 C16.8 13.7 16.5 14.1 16.5 14.7 V15.8 C16.5 16.6 16.3 17.1 15.2 17.4" />
        <path d="M11.7 16.6 L13.7 10" />
        <circle cx="13.7" cy="18" r="0.85" fill="var(--nc-acid)" stroke="none" />
      {:else if cell.key === 'hunt'}
        <circle cx="10.4" cy="10.4" r="6" />
        <path d="M14.7 14.7 L20.2 20.2" />
        <path d="M10.4 7.2 V8.9 M10.4 11.9 V13.6 M7.2 10.4 H8.9 M11.9 10.4 H13.6" />
        <circle cx="10.4" cy="10.4" r="1" fill="var(--nc-acid)" stroke="none" />
        <path d="M20.4 3.2 V5.8 M19.1 4.5 H21.7" />
      {:else if cell.key === 'validate'}
        <path d="M12 2.6 L19.3 5.2 V10.8 C19.3 15.3 16.4 18.4 12 20.1 C7.6 18.4 4.7 15.3 4.7 10.8 V5.2 Z" />
        <path d="M7.4 11.6 H9.6 L11 8.6 L12.8 14.2 L14.2 10.6 L15.1 11.2 H16.6" />
      {:else if cell.key === 'escalate'}
        <path d="M3.6 20.6 H8.3 V16.2 H13 V11.8 H17.4 V7.2" />
        <path d="M17.4 7.2 V3.4" />
        <path d="M17.4 3.6 L21.6 4.9 L17.4 6.2 Z" />
        <path d="M4.4 7.4 L6.8 5 L4.4 2.6" />
        <path d="M4.4 13.8 L6.8 11.4 L4.4 9" />
      {:else}
        <path d="M6 4.5 A1.5 1.5 0 0 1 7.5 3 H14 L18.5 7.5 V19.5 A1.5 1.5 0 0 1 17 21 H7.5 A1.5 1.5 0 0 1 6 19.5 Z" />
        <path d="M14 3 V7.5 H18.5" />
        <path d="M8.7 10.6 H15.8 M8.7 13.2 H14.2" />
        <path d="M8.7 15.8 H11.6" />
        <circle cx="15.4" cy="16.8" r="3.5" />
        <path d="M13.9 16.8 l1.05 1.05 l1.95 -2.15" />
      {/if}
    </svg>
    <text x={left + 22} y="338" font-size="10.5" font-weight="700" letter-spacing="0.1em" fill="var(--nc-bone)" font-family={MONO}
      >{cell.label}</text
    >
    <text x={left + 22} y="351" font-size="7" fill="var(--nc-bone_dust)" font-family={MONO}>{cell.detail}</text>
    {#if i < RAIL.length - 1}
      <path
        d="M{left + 124} 331 l5.5 6 -5.5 6"
        stroke="var(--nc-acid)"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        class="rail-chev"
        style="animation-delay:{i * 160}ms"
      />
    {/if}
  {/each}

  <!-- logo lockup -->
  <g transform="translate(24,320)">
    <path d="M13 3 L23 8.5 V19.5 L13 25 L3 19.5 V8.5 Z" fill="var(--nc-violet_abyss)" stroke="var(--nc-acid)" stroke-width="1.5" />
    <text x="13" y="20" font-size="13" font-weight="900" text-anchor="middle" fill="var(--nc-acid)" font-family={SANS}>N</text>
    <text x="36" y="16" font-size="11.5" font-weight="700" fill="var(--nc-bone)" font-family={SANS}>NetCast3r</text>
    <text x="36" y="28" font-size="7.5" letter-spacing="0.1em" fill="var(--nc-bone_dust)" font-family={MONO}
      >&gt; BUG BOUNTY AUTOMATION</text
    >
  </g>

  <!-- source block -->
  <g font-size="7.5" letter-spacing="0.08em" fill="var(--nc-acid)" opacity="0.85" font-family={MONO} text-anchor="end">
    <text x="1160" y="332">OPEN SOURCE</text>
    <text x="1160" y="344">AUTONOMOUS</text>
    <text x="1160" y="356">FOR SECURITY RESEARCH</text>
  </g>

  <!-- micro header -->
  <text x="32" y="17" font-size="9.5" letter-spacing="0.1em" font-family={MONO}>
    <tspan fill="var(--nc-acid)">&gt;_</tspan>
    <tspan fill="var(--nc-bone_dust)"> AUTOMATED WEB RECON / JS ANALYSIS / SECRET HUNTING / VALIDATION / REPORTING</tspan>
  </text>

  <!-- graffiti -->
  <g transform="rotate(-7 660 48)" font-family={SANS} font-style="italic" font-weight="800" font-size="15" fill="var(--nc-violet)" text-anchor="end">
    <text x="706" y="30">MORE</text>
    <text x="706" y="48">THAN JUST</text>
    <text x="706" y="66">A CRAWLER</text>
  </g>
  <g transform="rotate(-8 1120 52)" font-family={SANS} font-style="italic" font-weight="800" font-size="15" fill="var(--nc-acid)" text-anchor="end">
    <text x="1164" y="34">FIND</text>
    <text x="1164" y="52">VALIDATE</text>
    <text x="1164" y="70">ESCALATE</text>
  </g>
</svg>
