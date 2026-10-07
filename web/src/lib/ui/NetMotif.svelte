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
    <filter id="{id}-glow" x="-60%" y="-60%" width="220%" height="220%">
      <feGaussianBlur stdDeviation="2" result="b" />
      <feMerge>
        <feMergeNode in="b" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>
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

    <!-- knots -->
    <g filter="url(#{id}-glow)">
      {#each nodes as node (node.i * 10 + node.di)}
        <circle
          cx={node.x.toFixed(1)}
          cy={node.y.toFixed(1)}
          r={node.di === DEPTHS.length - 1 ? 2.6 : 1.8}
          fill={node.di === DEPTHS.length - 1 ? 'var(--nc-acid)' : 'var(--nc-violet)'}
          class="glow-pulse"
          style="animation-delay:{(node.i * 170 + node.di * 320) % 2400}ms"
        />
      {/each}
    </g>
  </g>

  <!-- caught secrets, floating over the mesh -->
  {#if chips}
    <g class="float-slow">
      <rect x="18" y="18" width="172" height="30" rx="7" fill="var(--nc-void)" stroke="var(--nc-violet_deep)" />
      <circle cx="34" cy="33" r="3.2" fill="var(--nc-acid)" />
      <text
        x="46"
        y="37"
        font-size="11"
        fill="var(--nc-bone_dust)"
        font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">AWS_SECRET_ACCESS_KEY</text
      >
    </g>
    <g class="float-slower">
      <rect x="44" y="64" width="132" height="30" rx="7" fill="var(--nc-void)" stroke="var(--nc-violet_deep)" />
      <circle cx="60" cy="79" r="3.2" fill="var(--nc-violet)" />
      <text
        x="72"
        y="83"
        font-size="11"
        fill="var(--nc-acid)"
        font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">ghp_4XK2************</text
      >
    </g>
  {/if}
</svg>
