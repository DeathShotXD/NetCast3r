<script lang="ts" module>
  let seq = 0;
</script>

<script lang="ts">
  let {
    class: klass = '',
    active = false
  }: { class?: string; active?: boolean } = $props();

  const id = `ns${++seq}`;

  // The net, seen as an instrument: ribs fan from the hand at the corner,
  // chords tie the mesh, knots glow where they cross, and a scan pulse
  // runs down every rib while a sonar ring sweeps out of the hand.
  const O = { x: 184, y: 8 };
  const RIBS = 9;
  const DEPTHS = [0.3, 0.5, 0.7, 0.9, 1.02];

  const ribSpec = (i: number) => {
    const t = i / (RIBS - 1);
    const angle = ((104 + t * 74) * Math.PI) / 180;
    const len = 176 + Math.sin(i * 1.9) * 12;
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
      path: `M${O.x} ${O.y} Q${((O.x + end.x) / 2 + 6).toFixed(1)} ${((O.y + end.y) / 2 + 4).toFixed(1)} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`
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
      path += ` Q${(mx + (O.x - mx) * 0.06).toFixed(1)} ${(my + (O.y - my) * 0.06).toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
    }
    return { d, path };
  });

  const nodes = DEPTHS.flatMap((d, di) =>
    Array.from({ length: RIBS }, (_, i) => ({ i, di, ...along(i, d) })).filter(
      (n, k) => k % 2 === di % 2 && n.x > 4 && n.x < 192 && n.y > 4 && n.y < 108
    )
  );

  const reduced =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
</script>

<svg viewBox="0 0 196 112" fill="none" aria-hidden="true" class={klass} preserveAspectRatio="xMidYMid meet">
  <defs>
    <linearGradient id="{id}-fade" x1="0" y1="0" x2="1" y2="0.9">
      <stop offset="0" stop-color="white" stop-opacity="0.2" />
      <stop offset="0.3" stop-color="white" stop-opacity="1" />
      <stop offset="0.85" stop-color="white" stop-opacity="1" />
      <stop offset="1" stop-color="white" stop-opacity="0.4" />
    </linearGradient>
    <mask id="{id}-mask">
      <rect width="196" height="112" fill="url(#{id}-fade)" />
    </mask>
  </defs>

  <g mask="url(#{id}-mask)">
    <!-- the line, out of the caster's hand -->
    <path d="M184 8 L196 -6" stroke="var(--nc-violet)" stroke-width="1.3" opacity="0.7" stroke-linecap="round" />
    <circle cx="184" cy="8" r="3.2" fill="var(--nc-violet_abyss)" stroke="var(--nc-acid)" stroke-width="1.2" />

    <!-- chords -->
    <g stroke="var(--nc-violet)" stroke-width="1" opacity="0.5">
      {#each chords as chord (chord.d)}
        <path d={chord.path} />
      {/each}
    </g>

    <!-- ribs -->
    <g stroke="var(--nc-acid)" stroke-width="1.1" opacity="0.7">
      {#each ribs as rib (rib.i)}
        <path d={rib.path} />
      {/each}
    </g>

    <!-- scan pulses: light running down every rib into the mesh -->
    {#if !reduced}
      <g class="scope-run" class:hot={active} fill="none" stroke="var(--nc-acid)" stroke-width="2.2" stroke-linecap="round" opacity="0.9">
        {#each ribs as rib (rib.i)}
          <path d={rib.path} style="animation-delay:{(rib.i * 0.22).toFixed(2)}s" />
        {/each}
      </g>
      <!-- sonar ring, cast from the hand -->
      <circle cx={O.x} cy={O.y} r="10" fill="none" stroke="var(--nc-acid)" stroke-width="1.2" opacity="0">
        <animate attributeName="r" values="10;210" dur="3.6s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.5;0.14;0" dur="3.6s" repeatCount="indefinite" />
      </circle>
    {/if}

    <!-- knots: halo + pulsing core -->
    <g>
      {#each nodes as node (node.i * 10 + node.di)}
        {@const r = node.di === DEPTHS.length - 1 ? 2.2 : 1.5}
        {@const color = node.di === DEPTHS.length - 1 ? 'var(--nc-acid)' : 'var(--nc-violet)'}
        {@const pulse = (node.i + node.di) % 2 === 0}
        <circle cx={node.x.toFixed(1)} cy={node.y.toFixed(1)} r={r + 3} fill={color} opacity="0.16" />
        <circle
          cx={node.x.toFixed(1)}
          cy={node.y.toFixed(1)}
          r={r}
          fill={color}
          class={pulse ? 'knot-pulse' : ''}
          style={pulse ? 'animation-delay:{(node.i * 170 + node.di * 320) % 2400}ms' : ''}
        />
      {/each}
    </g>
  </g>
</svg>
