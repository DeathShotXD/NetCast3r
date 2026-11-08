<script lang="ts">
  import type { Shape } from '../format';

  let {
    label,
    color,
    shape = 'dot',
    title = '',
    pulse = false
  }: { label: string; color: string; shape?: Shape; title?: string; pulse?: boolean } = $props();
</script>

<span
  class="chip"
  class:chip-pulse={pulse}
  style="color:{color};--chip-c:{color}"
  title={title || label}
  data-shape={shape}
>
  <span class="chip-glyph" aria-hidden="true">
    {#if shape === 'tri'}
      <svg viewBox="0 0 8 8" class="fill-current">
        <path d="M4 0l4.5 8h-9z" />
      </svg>
    {:else if shape === 'sq'}
      <svg viewBox="0 0 8 8" class="fill-current">
        <rect x="0.75" y="0.75" width="6.5" height="6.5" />
      </svg>
    {:else if shape === 'dia'}
      <svg viewBox="0 0 8 8" class="fill-current">
        <rect x="1.6" y="1.6" width="4.8" height="4.8" transform="rotate(45 4 4)" />
      </svg>
    {:else if shape === 'ring'}
      <svg viewBox="0 0 8 8">
        <circle cx="4" cy="4" r="3" fill="none" stroke="currentColor" stroke-width="1.6" />
      </svg>
    {:else}
      <svg viewBox="0 0 8 8" class="fill-current">
        <circle cx="4" cy="4" r="3.4" />
      </svg>
    {/if}
  </span>
  <span class="chip-label">{label}</span>
</span>

<style>
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px 2px 6px;
    border: 1px solid color-mix(in srgb, var(--chip-c) 30%, transparent);
    border-radius: 6px;
    background: linear-gradient(
      180deg,
      color-mix(in srgb, var(--chip-c) 15%, transparent),
      color-mix(in srgb, var(--chip-c) 5%, transparent)
    );
    box-shadow:
      inset 0 0 0 1px color-mix(in srgb, var(--chip-c) 6%, transparent),
      0 6px 16px -14px var(--chip-c);
    font-family: var(--mono);
    font-size: 8.5px;
    font-weight: 500;
    letter-spacing: 0.12em;
    line-height: 1.55;
    text-transform: uppercase;
    white-space: nowrap;
  }

  .chip-glyph {
    display: inline-flex;
    flex: none;
    opacity: 0.9;
  }

  .chip-glyph svg {
    width: 7px;
    height: 7px;
  }

  .chip-label {
    min-width: 0;
  }

  .chip-pulse .chip-glyph {
    animation: chip-pulse 1.6s ease-in-out infinite;
  }

  @keyframes chip-pulse {
    0%,
    100% {
      opacity: 0.45;
    }
    50% {
      opacity: 1;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .chip-pulse .chip-glyph {
      animation: none;
    }
  }
</style>