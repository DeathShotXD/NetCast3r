<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">

  let {
    class: klass = '',
    animated = true,
    chips = false
  }: { class?: string; animated?: boolean; chips?: boolean } = $props();

  const id = `nc${++seq}`;

  // The cast: one throw, ribs fanning from the caster's hand, chords tying
  // the mesh together, knots glowing where they cross.
  const O = { x: 402, y: 30 };
  const RIBS = 8;
  const DEPTHS = [0.3, 0.52, 0.74, 0.97];

  const ribSpec = (i: number) => {
    const t = i / (RIBS - 1);
    const angle = ((106 + t * 92) * Math.PI) / 180;
    const len = 430 + Math.sin(i * 1.7) * 24;
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
      path: `M${O.x} ${O.y} Q${(O.x + end.x) / 2 + 8} ${(O.y + end.y) / 2 - 6} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`
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
      const cx = mx + (O.x - mx) * 0.05;
      const cy = my + (O.y - my) * 0.05;
      path += ` Q${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
    }
    return { d, path };
  });

  const nodes = DEPTHS.flatMap((d, di) =>
    Array.from({ length: RIBS }, (_, i) => ({ i, di, ...along(i, d) })).filter(
      (_, n) => n % 2 === di % 2
    )
  );

  // Caught secrets, the way the banner draws them: little HUD cards with a
  // glyph well, a label, a masked value, and a tether down into the mesh.
  const CARD_W = 172;
  const CARD_H = 40;

  const CATALOG: { icon: string; label: string; value: string; accent: string }[] = [
    { icon: 'key', label: 'AWS_SECRET_ACCESS_KEY', value: 'wJalrXUtnFEMI********', accent: 'var(--nc-acid)' },
    { icon: 'db', label: 'DATABASE_URL', value: 'postgres://user:pass@***', accent: 'var(--nc-acid)' },
    { icon: 'cloud', label: 'API_KEY', value: 'sk_live_********4f2e', accent: 'var(--nc-acid)' },
    { icon: 'card', label: 'CLIENT_SECRET', value: '************', accent: 'var(--nc-violet)' },
    { icon: 'brackets', label: 'GITHUB_TOKEN', value: 'ghp_4XK2**********', accent: 'var(--nc-acid)' },
    { icon: 'shield', label: 'JWT_SIGNING_KEY', value: 'eyJhbGciOi*******', accent: 'var(--nc-violet)' }
  ];

  const SLOTS = [
    { x: 16, y: 14, node: along(2, 0.52), float: 'f-a' },
    { x: 58, y: 66, node: along(4, 0.74), float: 'f-b' },
    { x: 30, y: 118, node: along(1, 0.97), float: 'f-c' }
  ];

  let shown = $state([0, 4, 3]); // aws key, github token, client secret
  let rotator = 0;

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  $effect(() => {
    if (reduced || !chips) return;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      const slot = rotator % SLOTS.length;
      const next = (3 + rotator) % CATALOG.length;
      rotator += 1;
      // never swap in what another slot already shows
      const taken = shown.filter((_, i) => i !== slot);
      if (taken.includes(next)) return;
      shown = shown.map((v, i) => (i === slot ? next : v));
    }, 6800);
    return () => window.clearInterval(timer);
  });
</script>

<svg
  viewBox="0 0 420 200"
  fill="none"
  aria-hidden="true"
  class={klass}
  preserveAspectRatio="xMidYMid slice"
>
  <defs>
    <linearGradient id="{id}-fade" x1="0" y1="0" x2="1" y2="0.5">
      <stop offset="0" stop-color="white" stop-opacity="0.35" />
      <stop offset="0.45" stop-color="white" stop-opacity="1" />
      <stop offset="1" stop-color="white" stop-opacity="0.55" />
    </linearGradient>
    <mask id="{id}-mask">
      <rect width="420" height="200" fill="url(#{id}-fade)" />
    </mask>
    <linearGradient id="{id}-sweep" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="white" stop-opacity="0" />
      <stop offset="0.5" stop-color="white" stop-opacity="0.85" />
      <stop offset="1" stop-color="white" stop-opacity="0" />
    </linearGradient>
    {#each SLOTS as slot, i (i)}
      <clipPath id="{id}-clip{i}" clipPathUnits="userSpaceOnUse">
        <rect x="0" y="0" width={CARD_W} height={CARD_H} rx="2" />
      </clipPath>
    {/each}
  </defs>

  <g mask="url(#{id}-mask)">
    <!-- the line, out of the caster's hand -->
    <path
      d="M402 30 L470 -14"
      stroke="var(--nc-violet)"
      stroke-width="1.4"
      opacity="0.7"
      stroke-linecap="round"
    />
    <circle cx="402" cy="30" r="3.4" fill="var(--nc-violet_abyss)" stroke="var(--nc-acid)" stroke-width="1.2" />

    <!-- chords -->
    <g stroke="var(--nc-violet)" stroke-width="1" opacity="0.55">
      {#each chords as chord (chord.d)}
        <path d={chord.path} class:draw-in={animated} />
      {/each}
    </g>

    <!-- ribs -->
    <g stroke="var(--nc-acid)" stroke-width="1.1" opacity="0.7">
      {#each ribs as rib (rib.i)}
        <path d={rib.path} class:draw-in={animated} />
      {/each}
    </g>

    <!-- knots: static halo + pulsing core, no filters (blur re-raster kills fps) -->
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

    <!-- tethers: card edge to a live knot -->
    {#if chips}
      {#each SLOTS as slot, i (i)}
        <path
          d="M{slot.x + CARD_W} {slot.y + 9} Q{(slot.x + CARD_W + slot.node.x) / 2} {slot.y + 4} {slot.node.x.toFixed(1)} {slot.node.y.toFixed(1)}"
          stroke="var(--nc-violet)"
          stroke-width="1"
          stroke-dasharray="3 4"
          opacity="0.75"
        />
        <circle
          cx={slot.node.x.toFixed(1)}
          cy={slot.node.y.toFixed(1)}
          r="5.4"
          fill="var(--nc-acid)"
          opacity="0.16"
        />
        <circle
          cx={slot.node.x.toFixed(1)}
          cy={slot.node.y.toFixed(1)}
          r="2.4"
          fill="var(--nc-acid)"
          class="knot-pulse"
          style="animation-delay:{i * 600}ms"
        />
      {/each}
    {/if}
  </g>

  <!-- caught secrets, floating over the mesh -->
  {#if chips}
    {#each shown as itemIdx, slotIdx (slotIdx + ':' + itemIdx)}
      {@const item = CATALOG[itemIdx]}
      {@const slot = SLOTS[slotIdx]}
      <g class="badge-float {slot.float}">
        <g class="secret-badge">
          <g transform="translate({slot.x},{slot.y})">
            <g clip-path="url(#{id}-clip{slotIdx})">
              <rect width={CARD_W} height={CARD_H} rx="2" fill="var(--nc-void)" stroke="var(--nc-violet_deep)" />
              <rect x="0" y="0" width={CARD_W} height="2" fill="url(#{id}-sweep)" class="badge-shine" />

              <!-- icon well -->
              <rect x="8" y="11" width="18" height="18" rx="2" fill="var(--nc-violet_abyss)" stroke="var(--nc-violet_deep)" />
              <g
                transform="translate(10.5,13.5)"
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
                y="18"
                font-size="9"
                letter-spacing="0.12em"
                fill="var(--nc-bone_dust)"
                font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">{item.label}</text
              >
              <text
                x="34"
                y="32"
                font-size="11"
                fill="var(--nc-acid)"
                font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">{item.value}</text
              >
            </g>

            <!-- HUD corner ticks -->
            <path d="M0.5 7 v-6 h6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
            <path d="M{CARD_W - 6.5} {CARD_H - 0.5} h6 v-6" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0.75" />
          </g>
        </g>
      </g>
    {/each}
  {/if}
</svg>
