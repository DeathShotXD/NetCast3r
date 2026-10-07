<script lang="ts">
  let {
    stage,
    class: klass = ''
  }: { stage: string; class?: string } = $props();
</script>

<!-- One bespoke HUD icon per pipeline stage. currentColor drives the
     active/done/pending tints from the parent. -->
<svg
  viewBox="0 0 24 24"
  class={klass}
  fill="none"
  stroke="currentColor"
  stroke-width="1.6"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  {#if stage === 'crawl'}
    <!-- crawler: wireframe spider, angular legs, twin palps -->
    <circle cx="12" cy="9.4" r="2.1" />
    <path
      d="M12 11.3 C9.7 11.3 8.5 13.6 8.5 16.2 C8.5 18.9 10 21 12 21 C14 21 15.5 18.9 15.5 16.2 C15.5 13.6 14.3 11.3 12 11.3 Z"
    />
    <path d="M10.1 10.4 L6.4 8.2 L5 5.4" />
    <path d="M9.2 12.6 L5.2 12.4 L3.2 10.4" />
    <path d="M9.4 15.4 L5.6 16.6 L4.4 19.6" />
    <path d="M13.9 10.4 L17.6 8.2 L19 5.4" />
    <path d="M14.8 12.6 L18.8 12.4 L20.8 10.4" />
    <path d="M14.6 15.4 L18.4 16.6 L19.6 19.6" />
    <path d="M11 7.5 L10.5 5.6" />
    <path d="M13 7.5 L13.5 5.6" />
  {:else if stage === 'readjs'}
    <!-- source page with JS braces, slash, and dot -->
    <path
      d="M6 4.5 A1.5 1.5 0 0 1 7.5 3 H14 L18.5 7.5 V19.5 A1.5 1.5 0 0 1 17 21 H7.5 A1.5 1.5 0 0 1 6 19.5 Z"
    />
    <path d="M14 3 V7.5 H18.5" />
    <path
      d="M10.2 9.6 C9.1 9.9 8.9 10.4 8.9 11.2 V12.3 C8.9 12.9 8.6 13.3 8 13.5 C8.6 13.7 8.9 14.1 8.9 14.7 V15.8 C8.9 16.6 9.1 17.1 10.2 17.4"
    />
    <path
      d="M15.2 9.6 C16.3 9.9 16.5 10.4 16.5 11.2 V12.3 C16.5 12.9 16.8 13.3 17.4 13.5 C16.8 13.7 16.5 14.1 16.5 14.7 V15.8 C16.5 16.6 16.3 17.1 15.2 17.4"
    />
    <path d="M11.7 16.6 L13.7 10" />
    <circle cx="13.7" cy="18" r="0.85" fill="currentColor" stroke="none" />
  {:else if stage === 'hunt'}
    <!-- lens with crosshair and HUD tick -->
    <circle cx="10.4" cy="10.4" r="6" />
    <path d="M14.7 14.7 L20.2 20.2" />
    <path d="M10.4 7.2 V8.9 M10.4 11.9 V13.6 M7.2 10.4 H8.9 M11.9 10.4 H13.6" />
    <circle cx="10.4" cy="10.4" r="1" fill="currentColor" stroke="none" />
    <path d="M20.4 3.2 V5.8 M19.1 4.5 H21.7" />
  {:else if stage === 'validate'}
    <!-- shield carrying a live check signal -->
    <path
      d="M12 2.6 L19.3 5.2 V10.8 C19.3 15.3 16.4 18.4 12 20.1 C7.6 18.4 4.7 15.3 4.7 10.8 V5.2 Z"
    />
    <path d="M7.4 11.6 H9.6 L11 8.6 L12.8 14.2 L14.2 10.6 L15.1 11.2 H16.6" />
  {:else if stage === 'escalate'}
    <!-- steps up to a planted flag, chevrons rising beside it -->
    <path d="M3.6 20.6 H8.3 V16.2 H13 V11.8 H17.4 V7.2" />
    <path d="M17.4 7.2 V3.4" />
    <path d="M17.4 3.6 L21.6 4.9 L17.4 6.2 Z" />
    <path d="M4.4 7.4 L6.8 5 L4.4 2.6" />
    <path d="M4.4 13.8 L6.8 11.4 L4.4 9" />
  {:else}
    <!-- submission-ready document with an approval seal -->
    <path
      d="M6 4.5 A1.5 1.5 0 0 1 7.5 3 H14 L18.5 7.5 V19.5 A1.5 1.5 0 0 1 17 21 H7.5 A1.5 1.5 0 0 1 6 19.5 Z"
    />
    <path d="M14 3 V7.5 H18.5" />
    <path d="M8.7 10.6 H15.8 M8.7 13.2 H14.2" />
    <path d="M8.7 15.8 H11.6" />
    <circle cx="15.4" cy="16.8" r="3.5" />
    <path d="M13.9 16.8 l1.05 1.05 l1.95 -2.15" />
  {/if}
</svg>
