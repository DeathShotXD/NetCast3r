<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">
  let { class: klass = '' }: { class?: string } = $props();

  const id = `ha${++seq}`;
  const W = 640;
  const H = 300;
  const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  // ---- the cast: ribs fanning from the hand, chords lacing them, knots --
  const O = { x: 612, y: 14 };
  const RIBS = 13;
  const DEPTHS = [0.24, 0.42, 0.6, 0.78, 0.96];

  const ribSpec = (i: number) => {
    const t = i / (RIBS - 1);
    const angle = ((110 + t * 68) * Math.PI) / 180;
    const len = 300 + Math.sin(i * 2.1) * 26;
    return { angle, len };
  };

  const along = (i: number, d: number) => {
    const { angle, len } = ribSpec(i);
    const r = len * d;
    return { x: O.x + Math.cos(angle) * r, y: O.y + Math.sin(angle) * r };
  };

  const ribs = Array.from({ length: RIBS }, (_, i) => {
    const end = along(i, 1);
    return {
      i,
      path: `M${O.x} ${O.y} Q${((O.x + end.x) / 2 + 6).toFixed(1)} ${((O.y + end.y) / 2 - 4).toFixed(1)} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`
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

  // ---- topo contours: elevation rings crowding the faded left edge ------
  const TOPO = { cx: 118, cy: 72, rings: 7 };
  const topo = Array.from({ length: TOPO.rings }, (_, i) => {
    const base = 20 + i * 21;
    const pts = Array.from({ length: 26 }, (_, k) => {
      const a = (k / 26) * Math.PI * 2;
      const r = base + Math.sin(a * 3 + i * 0.9) * 6 + Math.cos(a * 5 - i * 1.3) * 3.5;
      return `${(TOPO.cx + Math.cos(a) * r).toFixed(1)} ${(TOPO.cy + Math.sin(a) * r).toFixed(1)}`;
    });
    return { i, path: `M${pts.join(' L')} Z` };
  });

  // ---- edge ruler, barcode, reticles, sparks ----------------------------
  const ruler = Array.from({ length: 30 }, (_, i) => ({
    x: 170 + i * 16,
    major: i % 4 === 0
  }));

  const BAR_W = [1, 2, 1, 3, 2, 1, 4, 1, 2, 1, 3, 1, 2, 4, 1, 2, 3, 1, 2, 1, 3, 2, 1, 4];
  const bars = BAR_W.reduce<{ x: number; w: number }[]>((acc, w) => {
    const last = acc[acc.length - 1];
    acc.push({ x: last ? last.x + last.w + 1 : 272, w });
    return acc;
  }, []);

  const RETICLES = [
    { x: 286, y: 26, color: 'var(--nc-acid)' },
    { x: 612, y: 84, color: 'var(--nc-violet)' }
  ];

  const SPARKS = [
    { x: 410, y: 152, delay: 0.4, color: 'var(--nc-acid)' },
    { x: 622, y: 204, delay: 1.7, color: 'var(--nc-bone)' },
    { x: 350, y: 88, delay: 2.9, color: 'var(--nc-violet)' }
  ];

  // ---- caught secrets: HUD cards floating over the mesh -----------------
  const CARD_W = 172;
  const CARD_H = 44;

  const CATALOG: { icon: string; label: string; value: string; accent: string }[] = [
    { icon: 'key', label: 'AWS_SECRET_ACCESS_KEY', value: 'wJalrXUt****4f2e', accent: 'var(--nc-acid)' },
    { icon: 'db', label: 'DATABASE_URL', value: 'postgres://u:p@***', accent: 'var(--nc-acid)' },
    { icon: 'cloud', label: 'API_KEY', value: 'sk_live_****4f2e', accent: 'var(--nc-acid)' },
    { icon: 'card', label: 'CLIENT_SECRET', value: '****', accent: 'var(--nc-violet)' },
    { icon: 'brackets', label: 'GITHUB_TOKEN', value: 'ghp_4XK2********', accent: 'var(--nc-acid)' },
    { icon: 'shield', label: 'JWT_SIGNING_KEY', value: 'eyJhbGciOi*****', accent: 'var(--nc-violet)' }
  ];

  const SLOTS = [
    { x: 330, y: 16, node: along(2, 0.24), float: 'f-a' },
    { x: 368, y: 96, node: along(2, 0.42), float: 'f-b' },
    { x: 396, y: 176, node: along(6, 0.78), float: 'f-c' }
  ];

  let shown = $state([0, 4, 3]);
  let rotator = 0;

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  $effect(() => {
    if (reduced) return;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      const slot = rotator % SLOTS.length;
      const next = (3 + rotator) % CATALOG.length;
      rotator += 1;
      const taken = shown.filter((_, i) => i !== slot);
      if (taken.includes(next)) return;
      shown = shown.map((v, i) => (i === slot ? next : v));
    }, 6800);
    return () => window.clearInterval(timer);
  });

  // ---- terminal readout -------------------------------------------------
  const TERM = [
    { y: 184, text: '> crawl: 128 pages', color: 'var(--nc-bone_dust)' },
    { y: 199.5, text: '[*] readjs: 17 scripts', color: 'var(--nc-violet)' },
    { y: 215, text: '[+] key: AWS_SECRET_A...', color: 'var(--nc-acid)' },
    { y: 230.5, text: '[*] validate: 200 ok', color: 'var(--nc-violet)' },
    { y: 246, text: '[+] grade: confirmed', color: 'var(--nc-acid)' },
    { y: 261.5, text: '> report ready', color: 'var(--nc-bone_dust)' }
  ];
</script>

<!-- DEFCON-style operations collage: contours, radar, weighted net, stamp,
     seal, terminal, barcode, and rotating credential catches. -->
<svg
  viewBox="0 0 {W} {H}"
  class={klass}
  fill="none"
  aria-hidden="true"
  preserveAspectRatio="xMaxYMid meet"
>
  <defs>
    <linearGradient id="{id}-fade" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="white" stop-opacity="0" />
      <stop offset="0.16" stop-color="white" stop-opacity="0.45" />
      <stop offset="0.34" stop-color="white" stop-opacity="1" />
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

    <radialGradient id="{id}-radar" gradientUnits="userSpaceOnUse" cx="540" cy="228" r="75">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0.34" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </radialGradient>

    <pattern id="{id}-hatch" width="9" height="9" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
      <line x1="0" y1="0" x2="0" y2="9" stroke="var(--nc-indigo)" stroke-width="1.4" />
    </pattern>

    <pattern id="{id}-dots" width="9" height="9" patternUnits="userSpaceOnUse">
      <circle cx="4.5" cy="4.5" r="1.4" fill="var(--nc-violet)" opacity="0.5" />
    </pattern>
    <radialGradient id="{id}-dotfade" cx="80%" cy="90%" r="75%">
      <stop offset="0" stop-color="white" />
      <stop offset="1" stop-color="black" />
    </radialGradient>
    <mask id="{id}-dotmask">
      <rect x="470" y="190" width="170" height="110" fill="url(#{id}-dotfade)" />
    </mask>

    {#each SLOTS as slot, i (i)}
      <clipPath id="{id}-clip{i}" clipPathUnits="userSpaceOnUse">
        <rect width={CARD_W} height={CARD_H} rx="2" />
      </clipPath>
    {/each}

    <path id="{id}-ring" d="M230 74 m -23 0 a 23 23 0 1 1 46 0 a 23 23 0 1 1 -46 0" fill="none" />
  </defs>

  <g mask="url(#{id}-mask)">
    <!-- hatch field, top left -->
    <path d="M0 0 H250 L210 96 H0 Z" fill="url(#{id}-hatch)" opacity="0.5" />

    <!-- topo contours -->
    <g stroke="var(--nc-violet)" stroke-width="1">
      {#each topo as ring (ring.i)}
        <path d={ring.path} opacity={(0.07 + ring.i * 0.013).toFixed(3)} />
      {/each}
    </g>

    <!-- edge ruler -->
    <g stroke="var(--nc-slate)" stroke-width="1">
      {#each ruler as tick (tick.x)}
        <path
          d="M{tick.x} 12 V{tick.major ? 2 : 7}"
          opacity={tick.major ? 0.8 : 0.35}
        />
      {/each}
    </g>

    <!-- glitch bars -->
    <rect x="556" y="58" width="70" height="4" fill="var(--nc-acid)" opacity="0.55" />
    <rect x="574" y="66" width="40" height="2" fill="var(--nc-violet)" opacity="0.7" />
    <rect x="548" y="72" width="14" height="2" fill="var(--nc-bone)" opacity="0.4" />

    <!-- the line, out of the caster's hand -->
    <path d="M612 14 L640 -8" stroke="var(--nc-violet)" stroke-width="1.4" opacity="0.7" stroke-linecap="round" />
    <circle cx="612" cy="14" r="3.4" fill="var(--nc-violet_abyss)" stroke="var(--nc-acid)" stroke-width="1.2" />

    <!-- chords -->
    <g stroke="var(--nc-violet)" stroke-width="1" opacity="0.55">
      {#each chords as chord (chord.d)}
        <path d={chord.path} class="draw-in" />
      {/each}
    </g>

    <!-- ribs -->
    <g stroke="var(--nc-acid)" stroke-width="1.1" opacity="0.7">
      {#each ribs as rib (rib.i)}
        <path d={rib.path} class="draw-in" />
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

    <!-- radar dish -->
    <g>
      <circle cx="540" cy="228" r="70" stroke="var(--nc-acid)" stroke-width="1" opacity="0.09" />
      <circle cx="540" cy="228" r="52" stroke="var(--nc-acid)" stroke-width="1" opacity="0.12" />
      <circle cx="540" cy="228" r="34" stroke="var(--nc-acid)" stroke-width="1" opacity="0.15" />
      <circle cx="540" cy="228" r="16" stroke="var(--nc-acid)" stroke-width="1" opacity="0.2" />
      <path d="M540 158 V298 M470 228 H610" stroke="var(--nc-acid)" stroke-width="1" opacity="0.12" />
      <path d="M540 228 L540 158 A70 70 0 0 1 600.6 193 Z" fill="url(#{id}-radar)" class="radar-sweep" />
      <circle cx="540" cy="228" r="2.4" fill="var(--nc-acid)" opacity="0.6" />
      <circle cx="568" cy="206" r="2" fill="var(--nc-acid)" class="twinkle" style="animation-delay:0.6s" />
      <circle cx="514" cy="252" r="1.6" fill="var(--nc-violet)" class="twinkle" style="animation-delay:1.8s" />
    </g>

    <!-- halftone patch, bottom right -->
    <rect x="470" y="190" width="170" height="110" fill="url(#{id}-dots)" mask="url(#{id}-dotmask)" />

    <!-- HUD reticles -->
    {#each RETICLES as ret (ret.x + ':' + ret.y)}
      <g stroke={ret.color} stroke-width="1.2" opacity="0.55">
        <path
          d="M{ret.x} {ret.y - 7} V{ret.y - 2} M{ret.x} {ret.y + 2} V{ret.y + 7}
             M{ret.x - 7} {ret.y} H{ret.x - 2} M{ret.x + 2} {ret.y} H{ret.x + 7}"
        />
        <circle cx={ret.x} cy={ret.y} r="5.5" opacity="0.35" fill="none" />
      </g>
    {/each}

    <!-- sparks -->
    {#each SPARKS as s (s.x + ':' + s.y)}
      <path
        d="M{s.x} {s.y - 6} V{s.y + 6} M{s.x - 6} {s.y} H{s.x + 6}"
        stroke={s.color}
        stroke-width="1.3"
        stroke-linecap="round"
        class="twinkle"
        style="animation-delay:{s.delay}s"
      />
    {/each}

    <!-- beam sweep -->
    <rect x="-150" y="0" width="130" height={H} fill="url(#{id}-beam)" class="hero-sweep" />

    <!-- authorization stamp -->
    <g transform="rotate(-8 478 264)" opacity="0.85">
      <rect x="413" y="249" width="130" height="30" rx="3" fill="none" stroke="var(--nc-violet)" stroke-width="1.6" stroke-dasharray="6 3" />
      <rect x="417" y="253" width="122" height="22" rx="2" fill="none" stroke="var(--nc-violet)" stroke-width="0.8" opacity="0.6" />
      <text
        x="478"
        y="268.5"
        text-anchor="middle"
        font-size="9.5"
        font-weight="600"
        letter-spacing="0.16em"
        fill="var(--nc-violet)"
        font-family={MONO}>AUTHORIZED USE</text
      >
    </g>
  </g>

  <!-- tethers: card edge to a live knot -->
  {#each SLOTS as slot, i (i)}
    <path
      d="M{slot.x + CARD_W} {slot.y + 10} Q{(slot.x + CARD_W + slot.node.x) / 2} {slot.y + 4} {slot.node.x.toFixed(1)} {slot.node.y.toFixed(1)}"
      stroke="var(--nc-violet)"
      stroke-width="1"
      stroke-dasharray="3 4"
      opacity="0.8"
      class="ants"
    />
    <circle cx={slot.node.x.toFixed(1)} cy={slot.node.y.toFixed(1)} r="5.4" fill="var(--nc-acid)" opacity="0.16" />
    <circle
      cx={slot.node.x.toFixed(1)}
      cy={slot.node.y.toFixed(1)}
      r="2.4"
      fill="var(--nc-acid)"
      class="knot-pulse"
      style="animation-delay:{i * 600}ms"
    />
  {/each}

  <!-- terminal readout -->
  <g>
    <rect x="176" y="150" width="220" height="136" rx="4" fill="var(--nc-void)" fill-opacity="0.92" stroke="var(--nc-indigo)" />
    <rect x="176" y="150" width="220" height="18" rx="4" fill="var(--nc-indigo_deep)" opacity="0.9" />
    <path d="M176 168 H396" stroke="var(--nc-indigo)" stroke-width="1" />
    <text x="184" y="162.5" font-size="8.5" letter-spacing="0.06em" fill="var(--nc-bone_dust)" opacity="0.85" font-family={MONO}>
      netcast3r -- cast
    </text>
    <g stroke="var(--nc-slate)" fill="none" stroke-width="1">
      <rect x="366" y="155.5" width="6" height="6" rx="1" />
      <rect x="375" y="155.5" width="6" height="6" rx="1" />
      <rect x="384" y="155.5" width="6" height="6" rx="1" />
    </g>
    {#each TERM as line (line.y)}
      <text x="186" y={line.y} font-size="9" fill={line.color} font-family={MONO}>{line.text}</text>
    {/each}
    <rect x="258" y="255" width="7" height="9.5" fill="var(--nc-acid)" class="term-cursor" />
  </g>

  <!-- operations seal -->
  <g transform="rotate(-7 230 74)">
    <circle cx="230" cy="74" r="36" fill="var(--nc-void)" fill-opacity="0.55" stroke="var(--nc-violet)" stroke-width="1.3" opacity="0.9" />
    <circle cx="230" cy="74" r="30" fill="none" stroke="var(--nc-acid)" stroke-width="0.9" stroke-dasharray="3.5 3.5" opacity="0.65" />
    <text font-size="6.6" letter-spacing="0.1em" fill="var(--nc-bone-dust)" font-family={MONO}>
      <textPath href="#{id}-ring" startOffset="2%">NETCAST3R // CREDENTIAL RECON</textPath>
    </text>
    <text x="230" y="73.5" text-anchor="middle" font-size="11" font-weight="700" letter-spacing="0.08em" fill="var(--nc-acid)" font-family={MONO}>
      NC3R
    </text>
    <text x="230" y="83.5" text-anchor="middle" font-size="4.8" letter-spacing="0.2em" fill="var(--nc-bone-dust)" opacity="0.8" font-family={MONO}>
      EST 2026
    </text>
    <g class="seal-orbit">
      <circle cx="230" cy="38" r="2" fill="var(--nc-acid)" />
    </g>
  </g>

  <!-- barcode block -->
  <g fill="var(--nc-bone)">
    {#each bars as bar, i (i)}
      <rect x={bar.x} y="110" width={bar.w} height="24" opacity={0.5 + (i % 3) * 0.18} />
    {/each}
  </g>
  <text x="272" y="143" font-size="7" letter-spacing="0.14em" fill="var(--nc-bone-dust)" opacity="0.7" font-family={MONO}>
    NC-7749 // AUTH
  </text>

  <!-- caught secrets, floating over the mesh -->
  {#each shown as itemIdx, slotIdx (slotIdx + ':' + itemIdx)}
    {@const item = CATALOG[itemIdx]}
    {@const slot = SLOTS[slotIdx]}
    <g class="badge-float {slot.float}">
      <g class="secret-badge">
        <g transform="translate({slot.x},{slot.y})">
          <g clip-path="url(#{id}-clip{slotIdx})">
            <rect width={CARD_W} height={CARD_H} rx="2" fill="var(--nc-void)" stroke="var(--nc-violet_deep)" />
            <rect x="0" y="0" width={CARD_W} height="2" fill="url(#{id}-shine)" class="badge-shine" />

            <!-- icon well -->
            <rect x="7" y="13" width="18" height="18" rx="2" fill="var(--nc-violet_abyss)" stroke="var(--nc-violet_deep)" />
            <g
              transform="translate(9.5,15.5)"
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
            <text
              x="34"
              y="21"
              font-size="8.2"
              letter-spacing="0.08em"
              fill="var(--nc-bone_dust)"
              font-family={MONO}>{item.label}</text
            >
            <text x="34" y="36" font-size="10" fill="var(--nc-acid)" font-family={MONO}>{item.value}</text
            >

            <!-- status LED -->
            <circle cx="158" cy="16" r="3.4" fill="var(--nc-acid)" opacity="0.16" />
            <circle
              cx="158"
              cy="16"
              r="1.8"
              fill="var(--nc-acid)"
              class="led-blink"
              style="animation-delay:{slotIdx * 0.55}s"
            />
          </g>

          <!-- HUD corner ticks -->
          <path d="M0.5 7 v-6 h6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
          <path d="M{CARD_W - 6.5} {CARD_H - 0.5} h6 v-6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
        </g>
      </g>
    </g>
  {/each}
</svg>
