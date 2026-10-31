<script lang="ts">
  import { onMount } from 'svelte';
  import { store } from '../state.svelte';
  import { Netcaster } from '../netcaster';

  let canvas: HTMLCanvasElement | undefined = $state();
  let engine = $state<Netcaster | null>(null);

  onMount(() => {
    if (!canvas) return;
    engine = new Netcaster(canvas);
    return () => {
      engine?.destroy();
      engine = null;
    };
  });

  $effect(() => {
    const wanted = store.netCursor;
    if (!engine) return;
    if (wanted) engine.start();
    else engine.stop();
  });
</script>

<canvas bind:this={canvas} class="nc-canvas nc-skip" aria-hidden="true"></canvas>
