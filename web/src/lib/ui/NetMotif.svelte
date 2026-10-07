<script lang="ts">
  let {
    class: klass = '',
    animated = true
  }: { class?: string; animated?: boolean } = $props();
</script>

<!-- The signature net: one hand-drawn cast across the hero, drawn once. -->
<svg
  viewBox="0 0 420 200"
  fill="none"
  aria-hidden="true"
  class={klass}
  class:draw-in={animated}
  preserveAspectRatio="xMidYMid slice"
>
  <g stroke="var(--nc-acid)" stroke-width="1" opacity="0.55">
    <path d="M6 168 C 90 96, 210 74, 404 40" />
    <path d="M6 168 C 118 152, 254 136, 404 96" />
    <path d="M6 168 C 140 190, 272 184, 404 156" />
  </g>
  <g stroke="var(--nc-violet)" stroke-width="1" opacity="0.5">
    <path d="M52 178 C 74 120, 96 74, 120 24" />
    <path d="M132 186 C 152 126, 176 80, 206 34" />
    <path d="M216 190 C 234 130, 258 88, 292 44" />
    <path d="M300 184 C 320 128, 344 92, 376 52" />
  </g>
  <g fill="var(--nc-acid)">
    <circle cx="120" cy="24" r="2.4" />
    <circle cx="292" cy="44" r="2.4" />
    <circle cx="404" cy="40" r="2.4" />
  </g>
  <g fill="var(--nc-violet)">
    <circle cx="206" cy="34" r="2" />
    <circle cx="376" cy="52" r="2" />
    <circle cx="6" cy="168" r="2.6" />
  </g>
</svg>
