<script lang="ts">
  import { STAGES } from '../../tokens';

  let {
    current = '',
    finished = [],
    dense = false
  }: { current?: string; finished?: string[]; dense?: boolean } = $props();

  const stages = STAGES as unknown as { key: string; label: string; detail: string; glyph: string }[];
  const index = (key: string) => stages.findIndex((stage) => stage.key === key);
  const currentAt = $derived(index(current));

  const progress = $derived(
    Math.min(100, ((finished.length + (current ? 1 : 0)) / stages.length) * 100)
  );
</script>

<div>
  <div class="mb-2 h-[3px] overflow-hidden rounded-full bg-indigo/60" aria-hidden="true">
    <div
      class="h-full rounded-full transition-[width] duration-700"
      style="width:{progress}%; background:linear-gradient(90deg, var(--nc-violet_deep), var(--nc-acid)); box-shadow:0 0 8px rgba(200,248,26,0.45);"
    ></div>
  </div>

  <ol class="stagger grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6" aria-label="pipeline stages">
    {#each stages as stage, i}
      {@const done = finished.includes(stage.key) || (currentAt >= 0 && i < currentAt)}
      {@const active = stage.key === current}
      <li
        class="panel relative flex flex-col gap-1.5 px-3 py-2.5 transition-[border-color,background,box-shadow] duration-150"
        class:border-acid={active}
        class:bg-acid-abyss={active}
        class:border-violet-deep={done && !active}
        class:glow-pulse={active}
      >
        <div class="flex items-center gap-2">
          <span
            class="mono grid h-5 w-5 place-items-center rounded border text-[10px]"
            class:border-acid={active}
            class:text-acid={active}
            class:border-violet-deep={done && !active}
            class:text-bone-dust={!active && !done}
            class:border-indigo={!active && !done}
          >
            {#if done && !active}<span aria-hidden="true">&#10003;</span>{:else}{stage.glyph}{/if}
          </span>
          <span class="eyebrow" class:text-acid={active}>{stage.label}</span>
          {#if active}
            <span class="pulse-live ml-auto h-1.5 w-1.5 rounded-full bg-acid" aria-hidden="true"></span>
          {/if}
        </div>
        {#if !dense}
          <p class="text-xs leading-snug text-bone-dust">{stage.detail}</p>
        {/if}
        <span class="sr-only">{active ? 'in progress' : done ? 'complete' : 'pending'}</span>
      </li>
    {/each}
  </ol>
</div>
