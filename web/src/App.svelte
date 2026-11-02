<script lang="ts">
  import { onMount } from 'svelte';
  import { store } from './lib/state.svelte';
  import CommandBar from './lib/shell/CommandBar.svelte';
  import NetCursor from './lib/shell/NetCursor.svelte';
  import Connect from './lib/screens/Connect.svelte';
  import Rail from './lib/shell/Rail.svelte';
  import AgentStudio from './lib/screens/AgentStudio.svelte';
  import Findings from './lib/screens/Findings.svelte';
  import Help from './lib/screens/Help.svelte';
  import Home from './lib/screens/Home.svelte';
  import Keys from './lib/screens/Keys.svelte';
  import LiveScan from './lib/screens/LiveScan.svelte';
  import Missions from './lib/screens/Missions.svelte';
  import NewScan from './lib/screens/NewScan.svelte';
  import Reports from './lib/screens/Reports.svelte';
  import ReverseLab from './lib/screens/ReverseLab.svelte';
  import Runs from './lib/screens/Runs.svelte';
  import Backdrop from './lib/ui/Backdrop.svelte';
  import Palette from './lib/ui/Palette.svelte';
  import ToastHost from './lib/ui/ToastHost.svelte';
  import Unlock from './lib/ui/Unlock.svelte';
  import Symbols from './lib/ui/Symbols.svelte';
  import BrainDock from './lib/shell/BrainDock.svelte';

  let railOpen = $state(false);

  onMount(() => {
    void store.boot().then(() => store.startHeartbeat());

    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing =
        !!target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable);
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        store.palette = !store.palette;
        return;
      }
      if (event.key === 'Escape') {
        if (store.palette) {
          store.palette = false;
          return;
        }
        if (store.brainDock) {
          store.brainDock = false;
          return;
        }
        if (railOpen) {
          railOpen = false;
          return;
        }
      }
      if (store.palette) return;
      if (event.key === '/' && !typing) {
        event.preventDefault();
        document.querySelector<HTMLInputElement>('header [data-search]')?.focus();
        return;
      }
      if ((event.key === 'b' || event.key === 'B') && !typing && !event.metaKey && !event.ctrlKey && !event.altKey) {
        event.preventDefault();
        store.brainDock = !store.brainDock;
      }
    };

    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      store.stopHeartbeat();
    };
  });
</script>

{#if !store.ready}
  <Backdrop />
  <div class="obs-boot" role="status" aria-live="polite">
    <div class="obs-boot-card">
      <div class="obs-boot-mark" aria-hidden="true">
        <svg viewBox="0 0 28 28" fill="none">
          <path
            d="M14 2.5 24.5 8.6v10.8L14 25.5 3.5 19.4V8.6z"
            stroke="#C8F81A"
            stroke-width="1.3"
          />
          <circle cx="14" cy="14" r="2.1" fill="#C8F81A" />
        </svg>
      </div>
      <div class="obs-boot-title">NetCast3r</div>
      <div class="obs-boot-sub">warming the control plane</div>
      <div class="obs-boot-bar" aria-hidden="true"><i></i></div>
    </div>
  </div>
{:else if store.locked}
  <Backdrop />
  <Unlock />
{:else}
  <a class="obs-skip" href="#main">Skip to content</a>
  <Backdrop />
  <Symbols />
  <NetCursor />
  <div class="obs-app">
    <Rail open={railOpen} onNavigate={() => (railOpen = false)} />

    <div class="obs-main">
      <CommandBar onMenu={() => (railOpen = true)} />

      <main id="main" class="obs-content" tabindex="-1">
        {#key store.screen === 'live' ? `live:${store.activeRunId}` : store.screen}
        <div class="screen-in">
          {#if store.screen === 'new'}
            <NewScan />
          {:else if store.screen === 'missions'}
            <Missions />
          {:else if store.screen === 'live'}
            <LiveScan />
          {:else if store.screen === 'findings'}
            <Findings />
          {:else if store.screen === 'runs'}
            <Runs />
          {:else if store.screen === 'agent'}
            <AgentStudio />
          {:else if store.screen === 'connect'}
            <Connect />
          {:else if store.screen === 'reports'}
            <Reports />
          {:else if store.screen === 'reveng'}
            <ReverseLab />
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
  <Palette />
  <BrainDock />
{/if}
