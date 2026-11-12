<script lang="ts">
  import { SEVERITIES, STATES } from '../../tokens';
  import { sevColor, sevShape, stateColor } from '../format';
  import Chip from '../ui/Chip.svelte';
  import PipelineLadder from '../ui/PipelineLadder.svelte';

  const ladder: { key: string; text: string }[] = [
    { key: 'confirmed', text: 'A real API call proved this credential works right now. Treat it as live access.' },
    { key: 'corroborated', text: 'The credential is structurally valid and matches more than one independent signal, but no live call was made.' },
    { key: 'inferred', text: 'The pattern, entropy, and context say this is very likely a real secret. Verify before acting.' },
    { key: 'unresolved', text: 'Caught, but not enough signal yet to place it on the ladder. It stays in review.' },
    { key: 'rejected', text: 'You decided it is not a problem: a placeholder, a public value, or a false positive.' }
  ];

  const severityText: Record<string, string> = {
    critical: 'Live, privileged access that is ready to use.',
    high: 'A real secret with clear access, needs an extra step or a narrow condition.',
    medium: 'Sensitive material that raises risk but is not directly usable.',
    low: 'Low-value or low-confidence material worth logging.',
    info: 'Context, not a credential. Kept for the report.'
  };

  const triage: { key: string; text: string }[] = [
    { key: 'new', text: 'Needs review. Nobody has decided yet.' },
    { key: 'confirmed', text: 'You agree it is real and worth acting on.' },
    { key: 'escalated', text: 'Ready for a report: real, proven, and high enough impact.' },
    { key: 'rejected', text: 'Not a problem. Hidden from escalations, kept in history.' }
  ];
</script>

<div class="obs-page obs-page-narrow is-reading flex flex-col gap-5">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Field guide</div>
      <h1>What every word on screen means</h1>
      <p class="obs-page-sub">
        NetCast3r is an authorized-testing tool. It maps a target you are allowed to test, reasons
        over the JavaScript it loads, matches credentials against 310 patterns, and validates what
        it catches against 135 read-only provider checks. It does not scan the internet at large,
        does not store your keys anywhere but your machine, and does not upload results.
      </p>
    </div>
  </header>

  <section class="obs-card p-5">
    <div class="obs-card-title">Six stages, in order</div>
    <div class="obs-card-sub">the pipeline</div>
    <div class="mt-5"><PipelineLadder showAgent /></div>
  </section>

  <section class="obs-card p-5">
    <div class="obs-card-title">How sure are we?</div>
    <div class="obs-card-sub">validation ladder</div>
    <ul class="mt-4 flex flex-col gap-3">
      {#each ladder as rung (rung.key)}
        <li class="flex gap-4 border-b border-indigo-deep/60 pb-3 last:border-0 last:pb-0">
          <Chip label={rung.key} color={stateColor(rung.key)} shape={rung.key === 'confirmed' ? 'tri' : 'dot'} />
          <p class="text-sm leading-relaxed text-bone-dust">{rung.text}</p>
        </li>
      {/each}
    </ul>
    <p class="mt-4 text-xs leading-relaxed text-ash">
      Validation never invents access. Checks are read-only by default; a write-tier proof only
      runs when you switch it on for a specific scan.
    </p>
  </section>

  <section class="grid gap-5 lg:grid-cols-2">
    <div class="obs-card p-5">
      <div class="obs-card-title">Colour, shape, and text</div>
      <div class="obs-card-sub">severity</div>
      <ul class="mt-4 flex flex-col gap-3">
        {#each Object.keys(SEVERITIES).filter((key) => key !== 'none') as key (key)}
          <li class="flex items-start gap-3">
            <Chip label={key} color={sevColor(key)} shape={sevShape(key)} />
            <p class="text-sm leading-relaxed text-bone-dust">{severityText[key] ?? ''}</p>
          </li>
        {/each}
      </ul>
    </div>

    <div class="obs-card p-5">
      <div class="obs-card-title">Your decision, carried forward</div>
      <div class="obs-card-sub">triage states</div>
      <ul class="mt-4 flex flex-col gap-3">
        {#each triage as row (row.key)}
          <li class="flex items-start gap-3">
            <Chip label={row.key} color={stateColor(row.key === 'new' ? 'unresolved' : row.key)} shape="dot" />
            <p class="text-sm leading-relaxed text-bone-dust">{row.text}</p>
          </li>
        {/each}
      </ul>
      <p class="mt-4 text-xs leading-relaxed text-ash">
        Every finding carries a fingerprint. Re-scanning the same target keeps your decisions: a
        rejected false positive stays rejected, a confirmed one stays confirmed.
      </p>
    </div>
  </section>

  <section class="obs-card p-5">
    <div class="obs-card-title">State colours</div>
    <div class="obs-card-sub">one word, one colour, one shape</div>
    <div class="mt-3 flex flex-wrap gap-2">
      {#each Object.keys(STATES) as key (key)}
        <Chip label={key} color={stateColor(key)} shape="dot" />
      {/each}
    </div>
  </section>

  <section class="obs-card p-5">
    <div class="obs-card-title">The net cursor</div>
    <div class="obs-card-sub">shell behaviour</div>
    <p class="mt-3 max-w-[70ch] text-sm leading-relaxed text-bone-dust">
      A light reticle follows the pointer on a short elastic leash. As it comes near a control it
      spins a web out to that control's edges, tightens, leans in, and knots itself on. Press
      anywhere to throw a short burst. It is the banner's gesture, live, and it only reaches for
      what is really there: a control hidden behind a palette or a dialog, faded out, or sitting in
      another pane is left alone, and keyboard focus gets a cast of its own. Toggle it with
      <strong>Net</strong> in the top bar; the choice is remembered. It never runs for touch input
      or under a reduced-motion preference, and text fields always keep a normal caret cursor.
    </p>
  </section>

  <section class="obs-card p-5">
    <div class="obs-card-title">From the terminal</div>
    <div class="obs-card-sub">the same engine without the dashboard</div>
    <pre
      class="mono mt-3 overflow-x-auto rounded-[6px] border border-indigo-deep bg-void px-4 py-3 text-xs leading-relaxed text-bone-dust">netcast3r ui                 # this dashboard, then open the printed link
netcast3r run TARGET         # the same pipeline, straight to the console
netcast3r run --tier write   # impact proof (writes) - only on targets you own
netcast3r dashboard          # the single-file HTML report for a finished run</pre>
    <p class="mt-3 text-xs leading-relaxed text-ash">
      Exit codes: 0 clean, 1 findings found, 2 usage or startup error.
    </p>
  </section>
</div>
