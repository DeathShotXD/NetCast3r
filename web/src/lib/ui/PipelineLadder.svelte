<script lang="ts">
  import { AGENT_STAGE, STAGES } from '../../tokens';
  import StageGlyph from './StageGlyph.svelte';

  let { showAgent = false }: { showAgent?: boolean } = $props();

  const stages = STAGES as unknown as {
    key: string;
    label: string;
    detail: string;
    agent: string;
  }[];
</script>

<ol class="flex flex-col" aria-label="pipeline stages in order">
  {#each stages as stage, i (stage.key)}
    <li class="fade-rise group relative flex gap-4 pb-5 last:pb-0" style="animation-delay:{i * 70}ms">
      {#if i < stages.length - 1}
        <span class="ladder-line" aria-hidden="true"></span>
      {/if}
      <span
        class="z-[1] grid h-8 w-8 shrink-0 place-items-center rounded-lg border bg-void-soft text-violet transition-[border-color,color,box-shadow] duration-150 group-hover:border-acid group-hover:text-acid group-hover:shadow-[0_0_14px_-4px_rgba(200,248,26,0.55)]"
        aria-hidden="true"
      >
        <StageGlyph stage={stage.key} class="h-4 w-4" />
      </span>
      <span class="min-w-0 flex-1">
        <span class="flex items-baseline gap-2">
          <span class="num text-[11px] text-slate">{String(i + 1).padStart(2, '0')}</span>
          <span class="eyebrow transition-colors group-hover:text-acid">{stage.label}</span>
        </span>
        <span class="mt-1 block text-xs leading-relaxed text-bone-dust">{stage.detail}</span>
        {#if showAgent}
          <span class="mono mt-1 block text-[11px] text-slate">
            agent: {stage.agent} -&gt; {(AGENT_STAGE as Record<string, string>)[stage.agent]}
          </span>
        {/if}
      </span>
    </li>
  {/each}
</ol>
