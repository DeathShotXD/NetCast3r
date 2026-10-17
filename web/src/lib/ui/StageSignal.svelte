<script lang="ts">
  import { countup } from '../actions';
  import StageGlyph from './StageGlyph.svelte';

  let {
    stages,
    counts,
    current,
    running
  }: {
    stages: { key: string; label: string }[];
    counts: Record<string, number>;
    current: string;
    running: boolean;
  } = $props();

  const at = $derived(stages.findIndex((stage) => stage.key === current));
</script>

<!-- Six stage nodes strung on a wire that charges as the run advances; the
     node under the live stage pulses, the wire into it flows. -->
<div class="flex items-center overflow-x-auto py-1" data-stages="1">
  {#each stages as stage, i (stage.key)}
    {@const count = counts[stage.key] ?? 0}
    {@const done = count > 0 && (at < 0 || i < at)}
    <div class="stage-node" class:active={running && i === at} class:done={done}>
      <span class="glyph"><StageGlyph stage={stage.key} class="h-4 w-4" /></span>
      <span class="eyebrow label">{stage.label}</span>
      <span class="num count"><span use:countup={count}>0</span></span>
    </div>
    {#if i < stages.length - 1}
      <span
        class="stage-wire"
        class:charged={at >= 0 && i < at}
        class:flow={running && i === at - 1}
        aria-hidden="true"
      ></span>
    {/if}
  {/each}
</div>
