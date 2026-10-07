<script lang="ts">
  import { AGENT_STAGE, SEVERITIES, STAGES, STATES } from '../../tokens';
  import { sevColor, sevShape, stateColor } from '../format';
  import Chip from '../ui/Chip.svelte';
  import StageGlyph from '../ui/StageGlyph.svelte';
  import StageRail from '../ui/StageRail.svelte';

  const stages = STAGES as unknown as { key: string; label: string; detail: string; agent: string }[];

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

<div class="stagger mx-auto flex max-w-[980px] flex-col gap-6">
  <section>
    <p class="eyebrow">help</p>
    <h1 class="mt-1 text-xl text-bone">What every word on screen means</h1>
    <p class="mt-2 max-w-[70ch] text-sm leading-relaxed text-bone-dust">
      NetCast3r is an authorized-testing tool. It crawls a target you are allowed to test, reads
      the JavaScript it loads, matches credentials against 310 patterns, and validates what it
      catches against 135 read-only provider checks. It does not scan the internet at large, does
      not store your keys anywhere but your machine, and does not upload results.
    </p>
  </section>

  <section class="panel p-5">
    <p class="eyebrow">the pipeline</p>
    <h2 class="mt-1 text-lg text-bone">Six stages, in order</h2>
    <div class="mt-4"><StageRail dense /></div>
    <ul class="mt-4 grid gap-3 border-t border-indigo-deep pt-4 sm:grid-cols-2">
      {#each stages as stage, i (stage.key)}
        <li class="flex gap-3">
          <span class="num w-6 shrink-0 text-xs text-slate">{String(i + 1).padStart(2, '0')}</span>
          <span>
            <span class="flex items-center gap-1.5">
              <StageGlyph stage={stage.key} class="h-4 w-4 shrink-0 text-violet" />
              <span class="mono text-sm text-bone">{stage.label}</span>
            </span>
            <span class="block text-xs leading-relaxed text-bone-dust">{stage.detail}</span>
            <span class="mono block text-[11px] text-slate">
              agent: {stage.agent} -&gt; {(AGENT_STAGE as Record<string, string>)[stage.agent]}
            </span>
          </span>
        </li>
      {/each}
    </ul>
  </section>

  <section class="panel p-5">
    <p class="eyebrow">validation ladder</p>
    <h2 class="mt-1 text-lg text-bone">How sure are we?</h2>
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
    <div class="panel p-5">
      <p class="eyebrow">severity</p>
      <h2 class="mt-1 text-lg text-bone">Colour, shape, and text</h2>
      <ul class="mt-4 flex flex-col gap-3">
        {#each Object.keys(SEVERITIES).filter((key) => key !== 'none') as key (key)}
          <li class="flex items-start gap-3">
            <Chip label={key} color={sevColor(key)} shape={sevShape(key)} />
            <p class="text-sm leading-relaxed text-bone-dust">{severityText[key] ?? ''}</p>
          </li>
        {/each}
      </ul>
    </div>

    <div class="panel p-5">
      <p class="eyebrow">triage states</p>
      <h2 class="mt-1 text-lg text-bone">Your decision, carried forward</h2>
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

  <section class="panel p-5">
    <p class="eyebrow">state colours</p>
    <div class="mt-3 flex flex-wrap gap-2">
      {#each Object.keys(STATES) as key (key)}
        <Chip label={key} color={stateColor(key)} shape="dot" />
      {/each}
    </div>
  </section>

  <section class="panel p-5">
    <p class="eyebrow">from the terminal</p>
    <pre
      class="mono mt-3 overflow-x-auto rounded-lg border border-indigo-deep bg-void px-4 py-3 text-xs leading-relaxed text-bone-dust">netcast3r ui                 # this dashboard, then open the printed link
netcast3r run TARGET         # the same pipeline, straight to the console
netcast3r run --tier write   # impact proof (writes) - only on targets you own
netcast3r dashboard          # the single-file HTML report for a finished run</pre>
    <p class="mt-3 text-xs leading-relaxed text-ash">
      Exit codes: 0 clean, 1 findings found, 2 usage or startup error.
    </p>
  </section>
</div>
