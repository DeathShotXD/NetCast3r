<script lang="ts">
  let {
    name,
    size = 16,
    class: klass = ''
  }: { name: string; size?: number; class?: string } = $props();
</script>

<svg
  class="obs-icon {klass}"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.65"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <use href="#i-{name}"></use>
</svg>
