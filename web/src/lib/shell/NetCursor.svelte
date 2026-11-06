<script lang="ts">
  import { onMount } from 'svelte';
  import { store } from '../state.svelte';
  import { Netcaster } from '../netcaster';

  let canvas: HTMLCanvasElement | undefined = $state();
  let engine = $state<Netcaster | null>(null);

  function formOpenTarget(node: EventTarget | null): boolean {
    if (!(node instanceof Element)) return false;
    return Boolean(node.closest('select, input[type="date"], input[type="time"], input[type="datetime-local"], input[type="month"], input[type="week"], input[type="color"]'));
  }

  function setFormOpen(open: boolean) {
    // Class only - CSS restores the native cursor while the net is paused.
    document.documentElement.classList.toggle('nc-form-open', open);
  }

  function onFocusIn(event: FocusEvent) {
    if (formOpenTarget(event.target)) setFormOpen(true);
  }

  function onFocusOut(event: FocusEvent) {
    if (!formOpenTarget(event.target)) return;
    // Defer so a select-to-select tab does not flash the net between fields.
    queueMicrotask(() => {
      setFormOpen(formOpenTarget(document.activeElement));
    });
  }

  function onPointerDown(event: PointerEvent) {
    // A press on a native picker parks the net before the OS menu paints.
    if (formOpenTarget(event.target)) setFormOpen(true);
  }

  onMount(() => {
    if (!canvas) return;
    engine = new Netcaster(canvas);
    document.addEventListener('focusin', onFocusIn, true);
    document.addEventListener('focusout', onFocusOut, true);
    document.addEventListener('pointerdown', onPointerDown, true);
    return () => {
      document.removeEventListener('focusin', onFocusIn, true);
      document.removeEventListener('focusout', onFocusOut, true);
      document.removeEventListener('pointerdown', onPointerDown, true);
      setFormOpen(false);
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
