<script lang="ts">
  // Compact wait-state for model replies, engages, and sync - Obsidian Signal.
  type Tone = 'acid' | 'quiet' | 'violet';
  type Variant = 'inline' | 'block' | 'bar' | 'skeleton';

  let {
    label = 'Working',
    detail = '',
    tone = 'acid' as Tone,
    variant = 'inline' as Variant,
    compact = false
  }: {
    label?: string;
    detail?: string;
    tone?: Tone;
    variant?: Variant;
    compact?: boolean;
  } = $props();
</script>

{#if variant === 'skeleton'}
  <div class="obs-buffer-skel" role="status" aria-label={label} aria-busy="true">
    <span class="obs-buffer-skel-label">{label}</span>
    <i style="width:72%"></i><i style="width:94%"></i><i style="width:58%"></i>
    {#if detail}<span class="obs-buffer-detail">{detail}</span>{/if}
  </div>
{:else if variant === 'bar'}
  <div class="obs-buffer-track" data-tone={tone} role="progressbar" aria-label={label} aria-busy="true">
    <i></i>
  </div>
{:else}
  <div
    class="obs-buffer"
    class:block={variant === 'block'}
    class:compact
    data-tone={tone}
    role="status"
    aria-live="polite"
    aria-busy="true"
  >
    <span class="obs-buffer-dots" aria-hidden="true">
      <i></i><i></i><i></i>
    </span>
    <span class="obs-buffer-copy">
      <span class="obs-buffer-label">
        {label}<span class="obs-buffer-caret" aria-hidden="true"></span>
      </span>
      {#if detail}
        <span class="obs-buffer-detail">{detail}</span>
      {/if}
    </span>
  </div>
{/if}

<style>
  .obs-buffer {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
    color: var(--obs-muted);
  }

  .obs-buffer.block {
    position: relative;
    overflow: hidden;
    width: 100%;
    border: 1px solid rgba(245, 233, 220, 0.08);
    border-radius: 12px;
    padding: 12px 14px;
    background:
      linear-gradient(135deg, rgba(200, 248, 26, 0.045), transparent 55%),
      rgba(0, 0, 0, 0.22);
    box-shadow: inset 0 1px 0 rgba(245, 233, 220, 0.04);
    animation: obs-buffer-in 280ms var(--ease, ease) both;
  }

  .obs-buffer.block::after {
    content: '';
    pointer-events: none;
    position: absolute;
    inset: 0;
    background: linear-gradient(
      105deg,
      transparent 40%,
      rgba(245, 233, 220, 0.035) 50%,
      transparent 60%
    );
    background-size: 220% 100%;
    animation: obs-buffer-shimmer 2.4s var(--ease, ease) infinite;
  }

  .obs-buffer.compact {
    gap: 8px;
  }

  .obs-buffer[data-tone='violet'].block {
    background:
      linear-gradient(135deg, rgba(159, 35, 221, 0.09), transparent 55%),
      rgba(0, 0, 0, 0.22);
  }

  .obs-buffer-dots {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    flex: none;
  }

  .obs-buffer-dots i {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--obs-acid);
    opacity: 0.28;
    animation: obs-buffer-dot 1.1s var(--ease, ease) infinite;
  }

  .obs-buffer[data-tone='quiet'] .obs-buffer-dots i {
    background: var(--obs-text-2);
  }

  .obs-buffer[data-tone='violet'] .obs-buffer-dots i {
    background: var(--obs-violet-3);
  }

  .obs-buffer-dots i:nth-child(2) {
    animation-delay: 0.14s;
  }

  .obs-buffer-dots i:nth-child(3) {
    animation-delay: 0.28s;
  }

  .obs-buffer-copy {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .obs-buffer-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--obs-text-2);
  }

  .obs-buffer[data-tone='acid'] .obs-buffer-label {
    color: var(--obs-acid);
  }

  .obs-buffer[data-tone='violet'] .obs-buffer-label {
    color: var(--obs-violet-3);
  }

  .obs-buffer-caret {
    display: inline-block;
    width: 1.5px;
    height: 0.85em;
    border-radius: 1px;
    background: currentColor;
    opacity: 0.55;
    animation: obs-buffer-caret 1s steps(1) infinite;
  }

  .obs-buffer-detail {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 11.5px;
    line-height: 1.35;
    color: var(--obs-faint);
  }

  .obs-buffer-track {
    position: relative;
    overflow: hidden;
    width: 100%;
    height: 2px;
    border-radius: 99px;
    background: rgba(245, 233, 220, 0.06);
  }

  .obs-buffer-track i {
    position: absolute;
    inset: 0 auto 0 0;
    width: 38%;
    border-radius: inherit;
    background: linear-gradient(90deg, transparent, var(--obs-acid), transparent);
    animation: obs-buffer-sweep 1.35s var(--ease, ease) infinite;
  }

  .obs-buffer-track[data-tone='violet'] i {
    background: linear-gradient(90deg, transparent, var(--obs-violet-3), transparent);
  }

  .obs-buffer-track[data-tone='quiet'] i {
    background: linear-gradient(90deg, transparent, var(--obs-text-2), transparent);
  }

  @keyframes obs-buffer-dot {
    0%,
    80%,
    100% {
      opacity: 0.22;
      transform: translateY(0);
    }
    40% {
      opacity: 1;
      transform: translateY(-2px);
    }
  }

  @keyframes obs-buffer-sweep {
    0% {
      transform: translateX(-120%);
    }
    100% {
      transform: translateX(320%);
    }
  }

  @keyframes obs-buffer-caret {
    0%,
    49% {
      opacity: 0.7;
    }
    50%,
    100% {
      opacity: 0;
    }
  }

  @keyframes obs-buffer-shimmer {
    0% {
      background-position: 120% 0;
    }
    100% {
      background-position: -120% 0;
    }
  }

  @keyframes obs-buffer-in {
    from {
      opacity: 0;
      transform: translateY(4px);
    }
    to {
      opacity: 1;
      transform: none;
    }
  }

  .obs-buffer-skel{display:flex;flex-direction:column;gap:8px;width:100%;padding:4px 0}
  .obs-buffer-skel-label{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--obs-acid)}
  .obs-buffer-skel i{display:block;height:9px;border-radius:99px;background:linear-gradient(100deg,rgba(245,233,220,.06) 40%,rgba(245,233,220,.13) 50%,rgba(245,233,220,.06) 60%);background-size:220% 100%;animation:obs-buffer-shimmer 1.6s ease infinite}
  @media (prefers-reduced-motion: reduce) { .obs-buffer-skel i{animation:none} }
  @media (prefers-reduced-motion: reduce) {
    .obs-buffer-dots i,
    .obs-buffer-track i,
    .obs-buffer-caret,
    .obs-buffer.block,
    .obs-buffer.block::after {
      animation: none;
    }

    .obs-buffer-dots i {
      opacity: 0.7;
    }

    .obs-buffer-caret {
      opacity: 0.45;
    }

    .obs-buffer-track i {
      width: 100%;
      transform: none;
      opacity: 0.35;
    }
  }
</style>
