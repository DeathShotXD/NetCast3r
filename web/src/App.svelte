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
  import BrandMark from './lib/ui/BrandMark.svelte';
  import Palette from './lib/ui/Palette.svelte';
  import Shortcuts from './lib/ui/Shortcuts.svelte';
  import RadialMenu from './lib/ui/RadialMenu.svelte';
  import ToastHost from './lib/ui/ToastHost.svelte';
  import Unlock from './lib/ui/Unlock.svelte';
  import Symbols from './lib/ui/Symbols.svelte';
  import BrainDock from './lib/shell/BrainDock.svelte';
  import type { RadialItem } from './lib/types';

  let railOpen = $state(false);
  let radial = $state<{ x: number; y: number; items: RadialItem[] } | null>(null);

  async function copyText(text: string, note: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      store.toast('ok', note);
    } catch {
      store.toast('warn', 'the browser blocked clipboard access');
    }
  }

  function radialItems(target: EventTarget | null): RadialItem[] {
    const el = target instanceof HTMLElement ? target : null;
    const items: RadialItem[] = [];
    const selection = window.getSelection()?.toString().trim() ?? '';

    const link = el?.closest('a[href]') as HTMLAnchorElement | null;
    if (link?.href) {
      const href = link.href;
      items.push({ icon: 'external', label: 'open link', action: () => window.open(href, '_blank', 'noopener') });
      items.push({ icon: 'link', label: 'copy link', action: () => void copyText(href, 'link copied') });
      const text = (link.textContent ?? '').trim();
      if (text) items.push({ icon: 'copy', label: 'copy text', action: () => void copyText(text, 'text copied') });
    }

    const img = el?.closest('img') as HTMLImageElement | null;
    if (img?.src) {
      const src = img.src;
      items.push({ icon: 'image', label: 'open image', action: () => window.open(src, '_blank', 'noopener') });
      items.push({ icon: 'copy', label: 'copy image url', action: () => void copyText(src, 'image url copied') });
      items.push({
        icon: 'download',
        label: 'download',
        action: () => {
          const a = document.createElement('a');
          a.href = src;
          a.download = '';
          document.body.appendChild(a);
          a.click();
          a.remove();
        }
      });
    }

    const code = el?.closest('pre, code') as HTMLElement | null;
    if (code) {
      items.push({ icon: 'code', label: 'copy code', action: () => void copyText(code.innerText, 'code copied') });
    }

    const tagged = el?.closest(
      '[data-run-id],[data-finding-id],[data-mission-id],[data-id]'
    ) as HTMLElement | null;
    const id =
      tagged?.dataset.runId || tagged?.dataset.findingId || tagged?.dataset.missionId || tagged?.dataset.id;
    if (id) {
      items.push({ icon: 'pin', label: 'copy id', action: () => void copyText(id, 'id copied') });
    }

    if (selection) {
      items.push({ icon: 'copy', label: 'copy selection', action: () => void copyText(selection, 'selection copied') });
    }

    items.push({
      icon: 'bot',
      label: 'ask helix',
      action: () => {
        store.brainDock = true;
      }
    });
    items.push({ icon: 'link', label: 'copy page url', action: () => void copyText(window.location.href, 'page url copied') });
    items.push({ icon: 'arrow-up', label: 'to top', action: () => window.scrollTo({ top: 0, behavior: 'smooth' }) });

    return items.slice(0, 8);
  }

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
        if (radial) {
          radial = null;
          return;
        }
        if (store.shortcuts) {
          store.shortcuts = false;
          return;
        }
        if (store.palette) {
          store.palette = false;
          return;
        }
        const insideOverlay =
          !!target && (target.closest('.nc-brain-panel') !== null || target.closest('dialog') !== null);
        if (store.brainDock && !insideOverlay) {
          store.brainDock = false;
          return;
        }
        if (railOpen) {
          railOpen = false;
          return;
        }
      }
      if (store.palette) return;
      if (event.key === '?' && !typing) {
        event.preventDefault();
        store.shortcuts = true;
        return;
      }
      if ((event.key === 'f' || event.key === 'F') && !typing && !event.metaKey && !event.ctrlKey && !event.altKey) {
        event.preventDefault();
        store.setFocusMode(!store.focusMode);
        return;
      }
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

    const onContext = (event: MouseEvent) => {
      if (!(event.ctrlKey || event.metaKey)) return;
      if (event.target instanceof HTMLElement && event.target.closest('.obs-radial')) return;
      event.preventDefault();
      radial = { x: event.clientX, y: event.clientY, items: radialItems(event.target) };
    };
    window.addEventListener('contextmenu', onContext);

    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('contextmenu', onContext);
      store.stopHeartbeat();
    };
  });
</script>

{#if !store.ready}
  <Backdrop />
  <div class="obs-boot" role="status" aria-live="polite">
    <div class="obs-boot-card">
      <div class="obs-boot-mark" aria-hidden="true">
        <BrandMark size={30} shadow />
      </div>
      <div class="obs-boot-title">NetCast<span class="obs-brand-3r">3R</span></div>
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
  <div class="obs-app" class:is-focus={store.focusMode}>
    <Rail open={railOpen} onNavigate={() => (railOpen = false)} />

    <div class="obs-main">
      <CommandBar onMenu={() => (railOpen = true)} />

      {#if store.syncState === 'error'}
        <div class="obs-conn-banner" role="alert">
          <span class="obs-conn-dot" aria-hidden="true"></span>
          <span class="obs-conn-text">
            control plane unreachable - showing the last data
            {store.lastSync ? ` from ${new Date(store.lastSync).toLocaleTimeString()}` : ''}
          </span>
          <button class="obs-btn obs-btn-sm" type="button" onclick={() => void store.retry()}>
            retry
          </button>
        </div>
      {/if}

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
  <Shortcuts />
  <BrainDock />
  {#if radial}
    <RadialMenu
      x={radial.x}
      y={radial.y}
      items={radial.items}
      onpick={(item) => {
        radial = null;
        item.action();
      }}
      onclose={() => (radial = null)}
    />
  {/if}
{/if}
