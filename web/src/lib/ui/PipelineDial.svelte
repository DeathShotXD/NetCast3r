<script lang="ts">
  // A precision completion dial: a thin track, a graduated tick ring, and one
  // luminous progress arc. The number is the only large element, so the dial
  // reads as instrumentation rather than a badge.
  let {
    value = 0,
    state = 'standby',
    label = 'pipeline'
  }: {
    value?: number;
    state?: 'live' | 'complete' | 'standby' | 'failed';
    label?: string;
  } = $props();

  const uid = $props.id();
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const pct = $derived(Math.max(0, Math.min(100, Math.round(value))));
  const dash = $derived((circumference * pct) / 100);
  const kicker = $derived(
    state === 'live' ? 'live' : state === 'complete' ? 'complete' : state === 'failed' ? 'fault' : 'standby'
  );
</script>

<div class="nc-dial" class:is-live={state === 'live'} class:is-failed={state === 'failed'}>
  <svg
    class="nc-dial-svg"
    viewBox="0 0 120 120"
    role="img"
    aria-label={`${label}: ${pct} percent, ${kicker}`}
  >
    <defs>
      <linearGradient id={`${uid}-stroke`} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="var(--obs-acid-2)" />
        <stop offset="46%" stop-color="var(--obs-acid)" />
        <stop offset="100%" stop-color="var(--obs-acid-2)" />
      </linearGradient>
      <filter id={`${uid}-glow`} x="-40%" y="-40%" width="180%" height="180%">
        <feGaussianBlur stdDeviation="2.2" result="blur" />
        <feMerge>
          <feMergeNode in="blur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>

    <circle class="nc-dial-ticks" cx="60" cy="60" r="57" />
    <circle class="nc-dial-track" cx="60" cy="60" r="52" />
    <circle class="nc-dial-inner" cx="60" cy="60" r="44" />
    <circle
      class="nc-dial-progress"
      cx="60"
      cy="60"
      r={radius}
      stroke={`url(#${uid}-stroke)`}
      stroke-dasharray={`${dash} ${circumference}`}
      filter={pct > 0 ? `url(#${uid}-glow)` : undefined}
    />
    {#if state === 'live' && pct > 0}
      <circle class="nc-dial-pulse" cx="60" cy="60" r="52" />
    {/if}
  </svg>

  <div class="nc-dial-copy">
    <span class="nc-dial-kicker">{kicker}</span>
    <strong>{pct}<small>%</small></strong>
    <span class="nc-dial-label">{label}</span>
  </div>
</div>

<style>
  .nc-dial {
    position: relative;
    display: grid;
    width: 112px;
    height: 112px;
    place-items: center;
  }

  .nc-dial-svg {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    overflow: visible;
    transform: rotate(-90deg);
  }

  .nc-dial-ticks {
    fill: none;
    stroke: color-mix(in srgb, var(--obs-line-strong) 72%, transparent);
    stroke-width: 0.75;
    stroke-dasharray: 0.5 5.47;
  }

  .nc-dial-track {
    fill: none;
    stroke: color-mix(in srgb, var(--obs-line-strong) 58%, transparent);
    stroke-width: 1;
  }

  .nc-dial-inner {
    fill: none;
    stroke: color-mix(in srgb, var(--obs-line) 80%, transparent);
    stroke-width: 0.75;
    stroke-dasharray: 1 4;
  }

  .nc-dial-progress {
    fill: none;
    stroke-width: 3;
    stroke-linecap: round;
    transition: stroke-dasharray 700ms cubic-bezier(0.22, 0.61, 0.36, 1);
  }

  .nc-dial-pulse {
    fill: none;
    stroke: var(--obs-acid);
    stroke-width: 1;
    opacity: 0.28;
    animation: nc-dial-breathe 2.8s ease-in-out infinite;
  }

  .nc-dial-copy {
    position: relative;
    z-index: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
  }

  .nc-dial-kicker {
    font-family: var(--mono);
    font-size: 6.5px;
    font-weight: 600;
    letter-spacing: 0.2em;
    line-height: 1;
    text-transform: uppercase;
    color: var(--obs-acid);
  }

  .nc-dial.is-live .nc-dial-kicker {
    animation: nc-dial-pulse 2.8s ease-in-out infinite;
  }

  .nc-dial.is-failed .nc-dial-kicker {
    color: var(--obs-red);
  }

  .nc-dial.is-failed .nc-dial-progress {
    stroke: var(--obs-red);
  }

  .nc-dial-copy strong {
    margin-top: 7px;
    font-family: var(--sans);
    font-size: 30px;
    font-weight: 500;
    font-variant-numeric: tabular-nums;
    letter-spacing: -0.065em;
    line-height: 0.9;
    color: var(--obs-text);
  }

  .nc-dial-copy strong small {
    margin-left: 1px;
    font-family: var(--mono);
    font-size: 9px;
    font-weight: 400;
    letter-spacing: 0;
    color: var(--obs-faint);
  }

  .nc-dial-label {
    margin-top: 7px;
    font-family: var(--mono);
    font-size: 6px;
    letter-spacing: 0.18em;
    line-height: 1;
    text-transform: uppercase;
    color: var(--obs-faint);
  }

  @keyframes nc-dial-breathe {
    0%,
    100% {
      opacity: 0.14;
      transform: scale(0.99);
    }
    50% {
      opacity: 0.34;
      transform: scale(1.01);
    }
  }

  @keyframes nc-dial-pulse {
    0%,
    100% {
      opacity: 0.62;
    }
    50% {
      opacity: 1;
    }
  }
</style>
