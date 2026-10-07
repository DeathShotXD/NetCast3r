<script lang="ts">
  import { onMount } from 'svelte';
  import { store } from './lib/state.svelte';
  import CommandBar from './lib/shell/CommandBar.svelte';
  import Rail from './lib/shell/Rail.svelte';
  import Findings from './lib/screens/Findings.svelte';
  import Help from './lib/screens/Help.svelte';
  import Home from './lib/screens/Home.svelte';
  import Keys from './lib/screens/Keys.svelte';
  import LiveScan from './lib/screens/LiveScan.svelte';
  import NewScan from './lib/screens/NewScan.svelte';
  import Runs from './lib/screens/Runs.svelte';
  import Backdrop from './lib/ui/Backdrop.svelte';
  import ToastHost from './lib/ui/ToastHost.svelte';
  import Unlock from './lib/ui/Unlock.svelte';

  let railOpen = $state(false);

  onMount(() => {
    void store.boot();
  });
</script>

{#if !store.ready}
  <Backdrop />
  <div class="grid h-full place-items-center">
    <p class="mono text-sm text-ash">loading dashboard...</p>
  </div>
{:else if store.locked}
  <Backdrop />
  <Unlock />
{:else}
  <Backdrop />
  <div class="flex min-h-screen lg:pl-[248px]">
    <Rail open={railOpen} onNavigate={() => (railOpen = false)} />

    <div class="flex min-w-0 flex-1 flex-col">
      <CommandBar onMenu={() => (railOpen = true)} />

      <main class="flex-1 px-4 py-6 sm:px-6 lg:px-8">
        {#key store.screen === 'live' ? `live:${store.activeRunId}` : store.screen}
        <div class="screen-in">
          {#if store.screen === 'new'}
            <NewScan />
          {:else if store.screen === 'live'}
            <LiveScan />
          {:else if store.screen === 'findings'}
            <Findings />
          {:else if store.screen === 'runs'}
            <Runs />
          {:else if store.screen === 'keys'}
            <Keys />
          {:else if store.screen === 'help'}
            <Help />
          {:else}
            <Home />
          {/if}
        </div>
        {/key}
      </main>
    </div>
  </div>

  <ToastHost />
{/if}
