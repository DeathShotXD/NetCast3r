<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">
  let {
    class: klass = '',
    live = false
  }: { class?: string; live?: boolean } = $props();

  const id = `ha${++seq}`;
  const W = 1200;
  const H = 520;
  const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  const f1 = (n: number) => +n.toFixed(1);
  const rad = (deg: number) => (deg * Math.PI) / 180;

  // ---- the atlas ---------------------------------------------------------
  // A geodesic sphere, not a spider: a wireframe world with a lit limb, a
  // floor shadow, and signal arcs leaving the surface. The globe is the
  // instrument; every other mark is telemetry around it.
  const C = { x: 838, y: 294 };
  const R = 156;
  const PITCH = rad(-16);
  const YAW = rad(-118);
  const sinX = Math.sin(PITCH);
  const cosX = Math.cos(PITCH);
  const sinY = Math.sin(YAW);
  const cosY = Math.cos(YAW);

  type P = { x: number; y: number; z: number };

  function project(latDeg: number, lonDeg: number): P {
    const lat = rad(latDeg);
    const lon = rad(lonDeg);
    const x = Math.cos(lat) * Math.cos(lon);
    const y = Math.sin(lat);
    const z = Math.cos(lat) * Math.sin(lon);
    const x1 = x * cosY + z * sinY;
    const z1 = -x * sinY + z * cosY;
    const y1 = y * cosX - z1 * sinX;
    const z2 = y * sinX + z1 * cosX;
    return { x: f1(C.x + x1 * R), y: f1(C.y - y1 * R), z: z2 };
  }

  function segmentPath(points: P[], front: boolean): string {
    let d = '';
    let penned = false;
    for (const point of points) {
      if ((point.z >= 0) !== front) {
        penned = false;
        continue;
      }
      d += `${penned ? 'L' : 'M'}${point.x} ${point.y}`;
      penned = true;
    }
    return d;
  }

  const LATITUDES = [-75, -60, -45, -30, -15, 0, 15, 30, 45, 60, 75];
  const LONGITUDES = Array.from({ length: 12 }, (_, i) => -180 + i * 30);
  const LON_SWEEP = Array.from({ length: 73 }, (_, i) => -180 + i * 5);
  const LAT_SWEEP = Array.from({ length: 37 }, (_, i) => -90 + i * 5);

  const parallels = LATITUDES.map((lat) => {
    const points = LON_SWEEP.map((lon) => project(lat, lon));
    return { back: segmentPath(points, false), front: segmentPath(points, true) };
  });

  const meridians = LONGITUDES.map((lon) => {
    const points = LAT_SWEEP.map((lat) => project(lat, lon));
    return { back: segmentPath(points, false), front: segmentPath(points, true) };
  });

  // Chords across each latitude band turn the grid into a geodesic lattice.
  const chords: string[] = [];
  for (let row = 0; row < LATITUDES.length - 1; row++) {
    for (let col = 0; col < LONGITUDES.length; col += 2) {
      const a = project(LATITUDES[row], LONGITUDES[col]);
      const b = project(LATITUDES[row + 1], LONGITUDES[(col + 1) % LONGITUDES.length]);
      if (a.z > 0 && b.z > 0) chords.push(`M${a.x} ${a.y}L${b.x} ${b.y}`);
    }
  }

  const NODES = [
    { lat: 40.7, lon: -74, label: 'AUTH', tone: 'acid' },
    { lat: 51.5, lon: -0.1, label: 'JWT', tone: 'violet' },
    { lat: -23.5, lon: -46.6, label: 'S3', tone: 'acid' },
    { lat: -33.9, lon: 18.4, label: 'API', tone: 'violet' },
    { lat: 25.2, lon: 55.3, label: 'SSRF', tone: 'acid' },
    { lat: 19.4, lon: -99.1, label: 'TOKEN', tone: 'violet' },
    { lat: 52.5, lon: 13.4, label: '', tone: 'acid' },
    { lat: -1.3, lon: 36.8, label: '', tone: 'violet' }
  ].map((node, i) => {
    const p = project(node.lat, node.lon);
    const right = p.x >= C.x;
    return {
      ...node,
      ...p,
      delay: f1(i * 0.72),
      anchor: right ? 'start' : 'end',
      labelX: p.x + (right ? 12 : -12),
      labelY: p.y - 9
    };
  }).filter((node) => node.z > 0.08);

  function arcFor(
    from: [number, number],
    to: [number, number],
    lift: number
  ) {
    const a = project(from[0], from[1]);
    const b = project(to[0], to[1]);
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2 - lift;
    return {
      d: `M${a.x} ${a.y}Q${f1(mx)} ${f1(my)} ${b.x} ${b.y}`,
      labelX: f1(0.25 * a.x + 0.5 * mx + 0.25 * b.x),
      labelY: f1(0.25 * a.y + 0.5 * my + 0.25 * b.y - 6)
    };
  }

  const ARCS = [
    { ...arcFor([40.7, -74], [51.5, -0.1], 92), label: 'AUTH', dur: 8.5, begin: '-1.2s' },
    { ...arcFor([-23.5, -46.6], [-33.9, 18.4], 104), label: 'S3', dur: 10.5, begin: '-4.4s' },
    { ...arcFor([51.5, -0.1], [25.2, 55.3], 108), label: 'JWT', dur: 9.4, begin: '-2.8s' },
    { ...arcFor([19.4, -99.1], [40.7, -74], 58), label: 'SSRF', dur: 7.2, begin: '-5.1s' }
  ];

  const TICKS = Array.from({ length: 72 }, (_, i) => {
    const angle = i * 5;
    const major = i % 6 === 0;
    const inner = R + 26;
    const outer = inner + (major ? 10 : 4);
    const a = { x: C.x + Math.cos(rad(angle)) * inner, y: C.y + Math.sin(rad(angle)) * inner };
    const b = { x: C.x + Math.cos(rad(angle)) * outer, y: C.y + Math.sin(rad(angle)) * outer };
    return { ...a, x2: b.x, y2: b.y, major, angle };
  });

  const PARTICLES = Array.from({ length: 26 }, (_, i) => {
    const angle = (i * 137.5 + 18) % 360;
    const radius = 212 + ((i * 53) % 150);
    return {
      x: f1(C.x + Math.cos(rad(angle)) * radius),
      y: f1(C.y + Math.sin(rad(angle)) * radius * 0.58),
      r: i % 6 === 0 ? 1.5 : 0.8,
      delay: f1((i * 0.43) % 5.6)
    };
  });

  const orbit = (rx: number, ry: number, rotate: number) => {
    const path = `M${C.x - rx} ${C.y}A${rx} ${ry} 0 1 1 ${C.x + rx} ${C.y}A${rx} ${ry} 0 1 1 ${C.x - rx} ${C.y}`;
    return { path, transform: `rotate(${rotate} ${C.x} ${C.y})` };
  };
  const outerOrbit = orbit(252, 82, -17);
  const innerOrbit = orbit(214, 68, 31);

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let svgEl = $state<SVGSVGElement | null>(null);

  // Pointer parallax: the atlas is a window, not a sticker. Layers drift on
  // damped factors and park themselves when the hero leaves the viewport.
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
      { rootMargin: '80px' }
    );
    io.observe(svg);
    const onMove = (event: PointerEvent) => {
      tx = (event.clientX / window.innerWidth) * 2 - 1;
      ty = (event.clientY / window.innerHeight) * 2 - 1;
    };
    const step = () => {
      px += (tx - px) * 0.045;
      py += (ty - py) * 0.045;
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

<!-- Geodesic signal atlas: a lit wireframe globe with a lat/lon lattice,
     signal arcs leaving the surface, an orbital HUD and a slow scan band.
     The left third stays deliberately quiet: Home prints the mission copy
     there. Everything animates on CSS clocks so the scene parks offscreen. -->
<svg
  viewBox="0 0 {W} {H}"
  class="atlas-scene {klass}"
  class:is-live={live}
  fill="none"
  aria-hidden="true"
  bind:this={svgEl}
  preserveAspectRatio="xMaxYMid slice"
>
  <defs>
    <radialGradient id="{id}-halo" gradientUnits="userSpaceOnUse" cx={C.x} cy={C.y} r="380">
      <stop offset="0" stop-color="var(--nc-violet)" stop-opacity="0.24" />
      <stop offset="0.42" stop-color="var(--nc-violet)" stop-opacity="0.1" />
      <stop offset="0.72" stop-color="var(--nc-indigo)" stop-opacity="0.045" />
      <stop offset="1" stop-color="var(--nc-void)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-disc" cx="0.36" cy="0.3" r="0.82">
      <stop offset="0" stop-color="#1a1236" stop-opacity="0.94" />
      <stop offset="0.5" stop-color="#0a0718" stop-opacity="0.92" />
      <stop offset="1" stop-color="#010104" stop-opacity="0.96" />
    </radialGradient>

    <radialGradient id="{id}-shade" cx="0.68" cy="0.26" r="0.74">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0.08" />
      <stop offset="0.44" stop-color="var(--nc-violet)" stop-opacity="0.03" />
      <stop offset="0.78" stop-color="#010104" stop-opacity="0.42" />
      <stop offset="1" stop-color="#010104" stop-opacity="0.72" />
    </radialGradient>

    <linearGradient id="{id}-limb" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="var(--nc-violet)" stop-opacity="0" />
      <stop offset="0.62" stop-color="var(--nc-violet)" stop-opacity="0.5" />
      <stop offset="0.9" stop-color="var(--nc-acid)" stop-opacity="0.82" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0.2" />
    </linearGradient>

    <linearGradient id="{id}-arc" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0.92" />
      <stop offset="0.58" stop-color="var(--nc-violet)" stop-opacity="0.72" />
      <stop offset="1" stop-color="var(--nc-violet)" stop-opacity="0.12" />
    </linearGradient>

    <linearGradient id="{id}-scan" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0" />
      <stop offset="0.48" stop-color="var(--nc-acid)" stop-opacity="0.2" />
      <stop offset="0.56" stop-color="var(--nc-acid)" stop-opacity="0.34" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </linearGradient>

    <radialGradient id="{id}-node" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="var(--nc-acid)" stop-opacity="0.4" />
      <stop offset="0.38" stop-color="var(--nc-acid)" stop-opacity="0.14" />
      <stop offset="1" stop-color="var(--nc-acid)" stop-opacity="0" />
    </radialGradient>

    <radialGradient id="{id}-floor" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#000000" stop-opacity="0.72" />
      <stop offset="0.55" stop-color="#000000" stop-opacity="0.3" />
      <stop offset="1" stop-color="#000000" stop-opacity="0" />
    </radialGradient>

    <filter id="{id}-glow" x="-220%" y="-220%" width="540%" height="540%">
      <feGaussianBlur stdDeviation="2.8" result="soft" />
      <feMerge>
        <feMergeNode in="soft" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>

    <clipPath id="{id}-clip">
      <circle cx={C.x} cy={C.y} r={R} />
    </clipPath>
  </defs>

  <!-- atmosphere and floor shadow -->
  <g class="atlas-world">
  <g class="atlas-far">
    <circle cx={C.x} cy={C.y} r="380" fill="url(#{id}-halo)" class="atlas-breathe" />
    <ellipse cx={C.x} cy={C.y + R + 44} rx="204" ry="24" fill="url(#{id}-floor)" />
    <path
      d="M{C.x - 280} {C.y + R + 44}H{C.x + 280}"
      stroke="var(--nc-violet_deep)"
      stroke-width="0.8"
      opacity="0.35"
    />
  </g>

  <!-- the orbital shell -->
  <g class="atlas-mid">
    <g transform={outerOrbit.transform}>
      <ellipse cx={C.x} cy={C.y} rx="252" ry="82" stroke="var(--nc-violet_deep)" stroke-width="0.9" opacity="0.55" />
      <ellipse
        cx={C.x}
        cy={C.y}
        rx="252"
        ry="82"
        stroke="var(--nc-acid)"
        stroke-width="1"
        stroke-dasharray="1 11"
        opacity="0.34"
        class="atlas-dash"
      />
      {#if !reduced}
        <circle r="2.1" fill="var(--nc-acid)" filter="url(#{id}-glow)">
          <animateMotion dur="19s" repeatCount="indefinite" path={outerOrbit.path} begin="-3s" />
        </circle>
      {/if}
    </g>
    <g transform={innerOrbit.transform}>
      <ellipse cx={C.x} cy={C.y} rx="214" ry="68" stroke="var(--nc-indigo_deep)" stroke-width="0.8" opacity="0.7" />
      <ellipse
        cx={C.x}
        cy={C.y}
        rx="214"
        ry="68"
        stroke="var(--nc-violet)"
        stroke-width="0.9"
        stroke-dasharray="18 13"
        opacity="0.24"
        class="atlas-dash-reverse"
      />
      {#if !reduced}
        <circle r="1.6" fill="var(--nc-violet)" filter="url(#{id}-glow)">
          <animateMotion dur="15s" repeatCount="indefinite" path={innerOrbit.path} begin="-8s" />
        </circle>
      {/if}
    </g>

    {#each TICKS as tick, i (i)}
      <line
        x1={tick.x}
        y1={tick.y}
        x2={tick.x2}
        y2={tick.y2}
        stroke={tick.major ? 'var(--nc-acid)' : 'var(--nc-slate)'}
        stroke-width={tick.major ? 1 : 0.55}
        opacity={tick.major ? 0.32 : 0.14}
      />
    {/each}
    <circle
      cx={C.x}
      cy={C.y}
      r={R + 44}
      stroke="var(--nc-acid)"
      stroke-width="0.8"
      stroke-dasharray="90 520"
      opacity="0.18"
      class="atlas-dash"
    />
  </g>

  <!-- the globe -->
  <g class="atlas-near">
    <!-- back hemisphere -->
    <g stroke="var(--nc-violet)" stroke-width="0.7" opacity="0.13">
      {#each parallels as line, i (i)}
        {#if line.back}<path d={line.back} />{/if}
      {/each}
      {#each meridians as line, i (i)}
        {#if line.back}<path d={line.back} />{/if}
      {/each}
    </g>

    <circle cx={C.x} cy={C.y} r={R} fill="url(#{id}-disc)" />
    <circle cx={C.x} cy={C.y} r={R} fill="url(#{id}-shade)" />

    <!-- front hemisphere: violet lattice, acid chords -->
    <g stroke="var(--nc-violet)" stroke-width="0.85" opacity="0.42">
      {#each parallels as line, i (i)}
        {#if line.front}<path d={line.front} pathLength="1000" style="animation-delay:{i * 55}ms" class="atlas-draw" />{/if}
      {/each}
      {#each meridians as line, i (i)}
        {#if line.front}<path d={line.front} pathLength="1000" style="animation-delay:{i * 70}ms" class="atlas-draw" />{/if}
      {/each}
    </g>
    <g stroke="var(--nc-acid)" stroke-width="0.55" opacity="0.16">
      {#each chords as d, i (i)}
        <path d={d} />
      {/each}
    </g>

    <!-- the scan band rolls under the lattice -->
    <g clip-path="url(#{id}-clip)">
      <g class="atlas-scan">
        <rect x={C.x - R} y={C.y - R} width={R * 2} height="24" fill="url(#{id}-scan)" />
        <line x1={C.x - R + 8} y1={C.y - R} x2={C.x + R - 8} y2={C.y - R} stroke="var(--nc-acid)" stroke-width="0.8" opacity="0.5" />
      </g>
    </g>

    <!-- rim light on the lit limb -->
    <circle cx={C.x} cy={C.y} r={R} stroke="url(#{id}-limb)" stroke-width="1.6" opacity="0.9" />
    <circle cx={C.x} cy={C.y} r={R - 4} stroke="var(--nc-violet_deep)" stroke-width="0.7" opacity="0.55" />
    <path
      d="M{C.x + 94} {C.y - 139}A168 168 0 0 1 {C.x + 143} {C.y - 88}"
      stroke="var(--nc-acid)"
      stroke-width="2"
      stroke-linecap="round"
      opacity="0.65"
      filter="url(#{id}-glow)"
    />

    <!-- signal arcs and their packets -->
    {#each ARCS as arc, i (i)}
      <g>
        <path d={arc.d} stroke="var(--nc-violet)" stroke-width="4.5" opacity="0.07" />
        <path d={arc.d} stroke="var(--nc-indigo_deep)" stroke-width="1.1" opacity="0.5" />
        <path d={arc.d} stroke="url(#{id}-arc)" stroke-width="1.25" stroke-dasharray="3 7" class="atlas-arc" style="animation-delay:{i * 0.45}s" />
        {#if !reduced}
          <circle r="2" fill="var(--nc-acid)" filter="url(#{id}-glow)">
            <animateMotion dur="{arc.dur}s" repeatCount="indefinite" path={arc.d} begin={arc.begin} />
          </circle>
        {/if}
        <g opacity="0.8">
          <circle cx={arc.labelX} cy={arc.labelY} r="1.35" fill="var(--nc-acid)" />
          <text
            x={arc.labelX + 7}
            y={arc.labelY + 2.6}
            font-size="6.4"
            letter-spacing="0.16em"
            fill="var(--nc-bone_dust)"
            font-family={MONO}>{arc.label}</text
          >
        </g>
      </g>
    {/each}

    <!-- signal nodes -->
    {#each NODES as node, i (i)}
      <g style="animation-delay:{node.delay}s" class="atlas-node">
        <circle cx={node.x} cy={node.y} r="15" fill="url(#{id}-node)" />
        <circle
          cx={node.x}
          cy={node.y}
          r="5"
          stroke={node.tone === 'acid' ? 'var(--nc-acid)' : 'var(--nc-violet)'}
          stroke-width="0.8"
          class="atlas-ping"
          style="animation-delay:{node.delay}s"
        />
        <circle
          cx={node.x}
          cy={node.y}
          r={node.label ? 2.5 : 1.7}
          fill={node.tone === 'acid' ? 'var(--nc-acid)' : 'var(--nc-violet)'}
          filter="url(#{id}-glow)"
        />
        {#if node.label}
          <line
            x1={node.x + (node.anchor === 'start' ? 4 : -4)}
            y1={node.y - 3}
            x2={node.labelX - (node.anchor === 'start' ? 3 : -3)}
            y2={node.labelY + 1}
            stroke={node.tone === 'acid' ? 'var(--nc-acid)' : 'var(--nc-violet)'}
            stroke-width="0.5"
            opacity="0.4"
          />
          <text
            x={node.labelX}
            y={node.labelY}
            text-anchor={node.anchor}
            font-size="6.2"
            letter-spacing="0.15em"
            fill={node.tone === 'acid' ? 'var(--nc-acid)' : 'var(--nc-violet)'}
            opacity="0.78"
            font-family={MONO}>{node.label}</text
          >
        {/if}
      </g>
    {/each}
  </g>

  <!-- particles -->
  <g class="atlas-far">
    {#each PARTICLES as particle, i (i)}
      <circle
        cx={particle.x}
        cy={particle.y}
        r={particle.r}
        fill={i % 3 === 0 ? 'var(--nc-violet)' : 'var(--nc-acid)'}
        opacity="0.3"
        class="atlas-twinkle"
        style="animation-delay:{particle.delay}s"
      />
    {/each}
  </g>
  </g>
</svg>
