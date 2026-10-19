<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">
  let {
    class: klass = '',
    live = false
  }: { class?: string; live?: boolean } = $props();

  const id = `ha${++seq}`;
  const W = 1180;
  const H = 360;
  const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  const SANS = 'system-ui, -apple-system, sans-serif';

  const f1 = (n: number) => +n.toFixed(1);
  const rad = (deg: number) => (deg * Math.PI) / 180;

  // ---- the scope ---------------------------------------------------------
  // everything in the scene hangs off one instrument face: a hub, a rim,
  // twelve rays, five rings. the sweep and every blip share one clock, so
  // a knot lights up exactly when the sweep crosses its bearing.
  const C = { x: 862, y: 160 };
  const RIM = 134;
  const SWEEP_S = 9;
  const HUB = 34;

  const at = (deg: number, r: number) => ({
    x: f1(C.x + Math.cos(rad(deg)) * r),
    y: f1(C.y + Math.sin(rad(deg)) * r)
  });

  const RAYS = Array.from({ length: 12 }, (_, i) => -90 + i * 30);
  const RING_R = [0.18, 0.34, 0.5, 0.66, 0.82].map((f) => f1(RIM * f));

  // silk: radii run hub to rim, each ring sags toward the hub between
  // neighbouring radii -- the curve that makes a starburst read as a web
  const radii = RAYS.map((deg) => {
    const a = at(deg, HUB);
    const b = at(deg, RIM);
    return `M${a.x} ${a.y} L${b.x} ${b.y}`;
  });

  const ringPath = (r: number) => {
    const pts = RAYS.map((deg) => at(deg, r));
    let d = `M${pts[0].x} ${pts[0].y}`;
    for (let k = 1; k <= pts.length; k++) {
      const a = pts[k - 1];
      const b = pts[k % pts.length];
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2;
      d += ` Q${f1(mx + (C.x - mx) * 0.14)} ${f1(my + (C.y - my) * 0.14)} ${b.x} ${b.y}`;
    }
    return d;
  };
  const rings = RING_R.map(ringPath);
  const rim = ringPath(RIM);

  // bearing ticks every six degrees; majors land on the radii
  const ticks = Array.from({ length: 60 }, (_, i) => {
    const major = i % 5 === 0;
    const a = at(i * 6 - 90, RIM - (major ? 11 : 6));
    const b = at(i * 6 - 90, RIM - 2);
    return { x: a.x, y: a.y, x2: b.x, y2: b.y, major };
  });

  // anchors: scaffold silk pinning the web past the rim, out to the frame
  const anchors = (
    [
      { rim: -152, to: [596, 38] },
      { rim: -28, to: [1046, 44] },
      { rim: 148, to: [640, 318] },
      { rim: 60, to: [1006, 314] },
      { rim: -105, to: [827, 0] },
      { rim: -75, to: [897, 0] }
    ] as { rim: number; to: [number, number] }[]
  ).map((a) => {
    const p = at(a.rim, RIM);
    return `M${p.x} ${p.y} L${a.to[0]} ${a.to[1]}`;
  });

  // the sweep: a wedge trailing the leading edge, spun about the hub
  const wedge = (() => {
    const lead = at(-90, RIM);
    const tail = at(-124, RIM);
    return `M0 0 L${f1(tail.x - C.x)} ${f1(tail.y - C.y)} A${RIM} ${RIM} 0 0 1 ${f1(lead.x - C.x)} ${f1(lead.y - C.y)} Z`;
  })();
  const tailLine = at(-124, RIM);

  // blips: knots in the silk; each flares as the sweep reaches its bearing.
  // the knot on the rim burns brightest.
  const blips = (
    [
      { deg: -30, r: RIM, hot: true },
      { deg: 30, r: f1(RIM * 0.82) },
      { deg: 120, r: f1(RIM * 0.66) },
      { deg: 180, r: f1(RIM * 0.5) },
      { deg: 210, r: f1(RIM * 0.82) },
      { deg: 300, r: f1(RIM * 0.5) },
      { deg: 0, r: f1(RIM * 0.82) }
    ] as { deg: number; r: number; hot?: boolean }[]
  ).map((b) => {
    const p = at(b.deg, b.r);
    const t = (((b.deg + 90) % 360) / 360) * SWEEP_S;
    return { x: p.x, y: p.y, hot: !!b.hot, delay: f1(t - SWEEP_S) };
  });

  // ---- the caster: line-art spider at the hub ----------------------------
  // drawn like an engraving instead of a body: silk-thin legs jointed at
  // the elbow, void held in the abdomen, a dragline paid toward the rail
  const legs = (
    [
      { s: [-6, -6], k: [-26, -26], t: [-44, -30] },
      { s: [-9, -2], k: [-34, -12], t: [-52, -12] },
      { s: [-9, 4], k: [-32, 18], t: [-48, 26] },
      { s: [-6, 9], k: [-20, 30], t: [-30, 44] },
      { s: [6, -6], k: [26, -26], t: [44, -30] },
      { s: [9, -2], k: [34, -12], t: [52, -12] },
      { s: [9, 4], k: [32, 18], t: [48, 26] },
      { s: [6, 9], k: [20, 30], t: [30, 44] }
    ] as { s: [number, number]; k: [number, number]; t: [number, number] }[]
  ).map((l) => ({
    d: `M${l.s[0]} ${l.s[1]} Q${l.k[0]} ${l.k[1]} ${l.t[0]} ${l.t[1]}`,
    k: l.k,
    t: l.t
  }));

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

  const CHIPS = [
    { label: 'CONFIRMED', color: 'var(--nc-acid)' },
    { label: 'CORROBORATED', color: 'var(--nc-gold)' },
    { label: 'INFERRED', color: 'var(--nc-violet)' },
    { label: 'UNRESOLVED', color: 'var(--nc-ash)' }
  ];

  let svgEl = $state<SVGSVGElement | null>(null);

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---- the scene listens back --------------------------------------------
  // pointer sweeps bend the depth layers on their own parallax factors and
  // the caster's eyes track the cursor; everything eases on a damped lerp
  // and sleeps while the banner is scrolled away or the tab is hidden.
  $effect(() => {
    if (reduced) return;
    const root = document.documentElement;
    const svg = svgEl;
    if (!svg) return;
    let tx = 0;
    let ty = 0;
    let px = 0;
    let py = 0;
    let raf = 0;
    let visible = true;
    const io = new IntersectionObserver(
      (entries) => {
        visible = entries[0]?.isIntersecting ?? true;
      },
      { rootMargin: '60px' }
    );
    io.observe(svg);
    const onMove = (event: PointerEvent) => {
      tx = (event.clientX / window.innerWidth) * 2 - 1;
      ty = (event.clientY / window.innerHeight) * 2 - 1;
    };
    const step = () => {
      px += (tx - px) * 0.05;
      py += (ty - py) * 0.05;
      if (visible && !document.hidden) {
        root.style.setProperty('--hx', px.toFixed(4));
        root.style.setProperty('--hy', py.toFixed(4));
      }
      raf = requestAnimationFrame(step);
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    raf = requestAnimationFrame(step);
    return () => {
      io.disconnect();
      window.removeEventListener('pointermove', onMove);
      cancelAnimationFrame(raf);
    };
  });
</script>

<!-- The caster: a spider at the hub of a radar scope, its web strung across
     the instrument face. The sweep orbits once every nine seconds and every
     knot in the silk flares as the beam crosses its bearing; one credential
     hangs off the rim knot. Dynamic copy overlays the left column. -->
<svg
  viewBox="0 0 {W} {H}"
  class="caster-scene {klass}"
  class:is-live={live}
  fill="none"
  aria-hidden="true"
  bind:this={svgEl}
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
      <stop offset="0" stop-color="var(--nc-violet_abyss)" stop-opacity="0.72" />
      <stop offset="0.55" stop-color="var(--nc-indigo_deep)" stop-opacity="0.5" />
      <stop offset="1" stop-color="var(--nc-void)" stop-opacity="0.88" />
    </linearGradient>

    <radialGradient id="{id}-atmos" gradientUnits="userSpaceOnUse" cx={C.x} cy={C.y} r="250">
      <stop offset="0" stop-color="var(--nc-violet)" stop-opacity="0.14" />
      <stop offset="0.55" stop-color="var(--nc-violet)" stop-opacity="0.05" />
      <stop offset="1" stop-color="var(--nc-violet)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-sweep" gradientUnits="userSpaceOnUse" cx="0" cy="0" r={RIM}>
      <stop offset="0.12" stop-color="var(--nc-acid)" stop-opacity="0.2" />
      <stop offset="0.6" stop-color="var(--nc-acid)" stop-opacity="0.06" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-hub" gradientUnits="userSpaceOnUse" cx={C.x} cy={C.y} r="46">
      <stop offset="0" stop-color="var(--nc-void)" stop-opacity="0.85" />
      <stop offset="0.62" stop-color="var(--nc-void)" stop-opacity="0.6" />
      <stop offset="1" stop-color="var(--nc-void)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-eye-halo" gradientUnits="userSpaceOnUse" cx="874" cy="149" r="13">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0.22" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </radialGradient>
  </defs>

  <g mask="url(#{id}-mask)">
    <!-- the dark the scope hangs in -->
    <rect width={W} height={H} fill="url(#{id}-sky)" />
    <circle class="px-sky" cx={C.x} cy={C.y} r="250" fill="url(#{id}-atmos)" />

    <!-- anchors: the web tied back past the rim -->
    <g class="px-near" stroke="var(--nc-violet_deep)" stroke-width="1" opacity="0.32">
      {#each anchors as d, i (i)}
        <path d={d} class="hero-draw" style="animation-delay:{60 + i * 90}ms" />
      {/each}
    </g>

    <!-- the instrument face: bezel, bearings, crosshair -->
    <g class="px-far">
      <circle cx={C.x} cy={C.y} r={RIM} stroke="var(--nc-violet_deep)" stroke-width="1.4" opacity="0.9" />
      <circle cx={C.x} cy={C.y} r={RIM - 5} stroke="var(--nc-indigo_deep)" stroke-width="1" opacity="0.9" />
      {#each ticks as t, i (i)}
        <line
          x1={t.x}
          y1={t.y}
          x2={t.x2}
          y2={t.y2}
          stroke={t.major ? 'var(--nc-acid)' : 'var(--nc-ash)'}
          stroke-width={t.major ? 1.1 : 0.7}
          opacity={t.major ? 0.45 : 0.22}
        />
      {/each}
      <line x1={C.x} y1={C.y - RIM + 8} x2={C.x} y2={C.y + RIM - 8} stroke="var(--nc-acid)" stroke-width="0.8" opacity="0.12" />
      <line x1={C.x - RIM + 8} y1={C.y} x2={C.x + RIM - 8} y2={C.y} stroke="var(--nc-acid)" stroke-width="0.8" opacity="0.12" />
    </g>

    <!-- the web strung across the face -->
    <g class="px-near">
      <g stroke="var(--nc-violet)" stroke-width="0.9" opacity="0.46">
        {#each radii as d, i (i)}
          <path d={d} class="hero-draw" style="animation-delay:{240 + i * 45}ms" />
        {/each}
      </g>
      <g stroke="var(--nc-violet)" stroke-width="0.9" opacity="0.54">
        {#each rings as d, i (i)}
          <path d={d} class="hero-draw" style="animation-delay:{140 + i * 80}ms" />
        {/each}
      </g>
      <path d={rim} stroke="var(--nc-acid)" stroke-width="1.1" opacity="0.5" class="hero-draw" style="animation-delay:900ms" />

      <!-- sweep: the beam that ties every knot to one clock -->
      <g transform="translate({C.x},{C.y})">
        <g class="scope-sweep">
          <path d={wedge} fill="url(#{id}-sweep)" />
          <line x1="0" y1="0" x2={f1(tailLine.x - C.x)} y2={f1(tailLine.y - C.y)} stroke="var(--nc-violet)" stroke-width="0.8" opacity="0.55" />
          <line x1="0" y1="0" x2="0" y2={-RIM} stroke="var(--nc-acid)" stroke-width="1.35" opacity="0.62" />
        </g>
      </g>

      <!-- knots: static standing dots, then the flares the sweep triggers -->
      {#each blips as bp, i (i)}
        <circle cx={bp.x} cy={bp.y} r={bp.hot ? 2.4 : 1.2} fill="var(--nc-violet)" opacity={bp.hot ? 0.9 : 0.55} />
        <g class="scope-blip" style="animation-delay:{bp.delay}s">
          <circle cx={bp.x} cy={bp.y} r={bp.hot ? 7.5 : 5.5} stroke="var(--nc-acid)" stroke-width="1" />
          <circle cx={bp.x} cy={bp.y} r={bp.hot ? 2.4 : 1.6} fill="var(--nc-acid)" />
        </g>
      {/each}
    </g>

    <!-- the caster: line-art spider at the hub, dragline paid to the rail -->
    <g class="px-net">
      <circle class="hub-shadow" cx={C.x} cy={C.y} r="46" fill="url(#{id}-hub)" />
      <path d="M846 175 Q836 222 818 252" stroke="var(--nc-bone_dust)" stroke-width="0.8" opacity="0.28" />
      <circle cx="818" cy="252" r="1.4" fill="var(--nc-bone_dust)" opacity="0.4" />

      <g transform="translate({C.x},{C.y})">
        {#each legs as leg, i (i)}
          <path d={leg.d} stroke="var(--nc-violet)" stroke-width="1.3" stroke-linecap="round" opacity="0.9" />
          <circle cx={leg.k[0]} cy={leg.k[1]} r="1.8" fill="var(--nc-void)" stroke="var(--nc-violet)" stroke-width="0.8" />
          <circle cx={leg.k[0]} cy={leg.k[1]} r="0.7" fill="var(--nc-acid)" opacity="0.8" />
          <circle cx={leg.t[0]} cy={leg.t[1]} r="2.2" fill="var(--nc-acid)" opacity="0.12" class="twinkle" style="animation-delay:{i * 520}ms" />
          <circle cx={leg.t[0]} cy={leg.t[1]} r="0.95" fill="var(--nc-acid)" opacity="0.85" />
        {/each}

        <g class="caster-bob">
          <!-- abdomen, turned up-right; the hourglass sits on the dorsum -->
          <ellipse cx="-10" cy="9" rx="12" ry="9.5" fill="var(--nc-void)" stroke="var(--nc-violet)" stroke-width="1.3" transform="rotate(-35 -10 9)" />
          <g transform="rotate(-35 -8 8)">
            <path d="M-12 3 L-4 5.6 L-8.2 8.4 Z" fill="var(--nc-acid)" opacity="0.9" />
            <path d="M-12 12.4 L-4 9.8 L-8.2 8.4 Z" fill="var(--nc-acid)" opacity="0.9" />
          </g>

          <!-- cephalothorax, chelicerae, pedipalps facing the catch -->
          <ellipse cx="7" cy="-6" rx="8.5" ry="7" fill="var(--nc-void)" stroke="var(--nc-violet)" stroke-width="1.3" />
          <path d="M14 -12 Q19 -17 23 -16" stroke="var(--nc-violet_abyss)" stroke-width="2.2" stroke-linecap="round" />
          <path d="M14 -7 Q20 -5 23 -7" stroke="var(--nc-violet_abyss)" stroke-width="2.2" stroke-linecap="round" />
          <circle cx="23" cy="-16" r="0.8" fill="var(--nc-acid)" opacity="0.9" />
          <circle cx="23" cy="-7" r="0.8" fill="var(--nc-acid)" opacity="0.9" />

          <!-- eyes: they follow your cursor across the page -->
          <g class="eye-glow eye-track">
            <circle cx="12" cy="-11" r="13" fill="url(#{id}-eye-halo)" />
            <circle cx="13" cy="-12.5" r="1.4" fill="var(--nc-acid)" />
            <circle cx="15.4" cy="-9.8" r="1.4" fill="var(--nc-acid)" />
            <circle cx="10.4" cy="-15" r="0.9" fill="var(--nc-acid)" />
            <circle cx="13" cy="-10.6" r="0.9" fill="var(--nc-acid)" />
            <circle cx="12.5" cy="-13" r="0.5" fill="var(--nc-bone)" />
            <circle cx="14.9" cy="-10.3" r="0.5" fill="var(--nc-bone)" />
          </g>
        </g>
      </g>
    </g>

    <!-- readout under the face -->
    <text x={C.x} y="312" text-anchor="middle" font-size="7" letter-spacing="0.16em" fill="var(--nc-acid)" opacity="0.45" font-family={MONO}
      >R{RIM} / SWEEP {SWEEP_S}.0S / 7 KNOTS LIVE</text
    >
  </g>

  <!-- validation ladder -->
  {#each CHIPS as chip, i (i)}
    <rect
      x="1062"
      y={20 + i * 26}
      width="108"
      height="20"
      rx="4"
      fill="var(--nc-void)"
      stroke={chip.color}
      stroke-width="1.2"
      opacity="0.96"
    />
    <text
      x="1072"
      y={34 + i * 26}
      font-size="7.5"
      font-weight="700"
      letter-spacing="0.1em"
      fill="var(--nc-bone)"
      font-family={MONO}>{chip.label}</text
    >
  {/each}

  <!-- six-stage rail -->
  <rect x="170" y="318" width="820" height="40" rx="8" fill="var(--nc-void)" opacity="0.55" stroke="var(--nc-indigo_deep)" />
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
    <text x="1172" y="332">OPEN SOURCE</text>
    <text x="1172" y="344">AUTONOMOUS</text>
    <text x="1172" y="356">FOR SECURITY RESEARCH</text>
  </g>

  <!-- micro header -->
  <text x="32" y="17" font-size="9.5" letter-spacing="0.1em" font-family={MONO}>
    <tspan fill="var(--nc-acid)">&gt;_</tspan>
    <tspan fill="var(--nc-bone_dust)"> AUTOMATED WEB RECON / JS ANALYSIS / SECRET HUNTING / VALIDATION / REPORTING</tspan>
  </text>
</svg>
