<script lang="ts">
  import { store } from '../state.svelte';
  import { ago } from '../format';
  import type { Screen } from '../types';

  type Item = { label: string; hint: string; glyph: string; run: () => void };

  const NAV: { id: Screen; label: string; glyph: string; hint: string }[] = [
    { id: 'home', label: 'Home', glyph: '#', hint: 'overview, what to do next' },
    { id: 'missions', label: 'Missions', glyph: '@', hint: 'scoped objectives and their runs' },
    { id: 'new', label: 'New scan', glyph: '>', hint: 'point the tool at a target' },
    { id: 'live', label: 'Live runs', glyph: '[*]', hint: 'watch a scan, inspect everything it found' },
    { id: 'findings', label: 'Findings', glyph: '*', hint: 'triage what came back' },
    { id: 'runs', label: 'Runs', glyph: '//', hint: 'history, rerun, delete' },
    { id: 'reports', label: 'Reports', glyph: '=', hint: 'submissions, outcomes, payouts' },
    { id: 'agent', label: 'Agent Studio', glyph: '::', hint: 'MCP tools, policy, audit' },
    { id: 'keys', label: 'Providers', glyph: '^', hint: 'keys, models, health' },
    { id: 'help', label: 'Help', glyph: '?', hint: 'what every state means' }
  ];

  let q = $state('');
  let cursor = $state(0);
  let input = $state<HTMLInputElement | null>(null);

  const navItems = $derived<Item[]>(
    NAV.map((s) => ({ label: s.label, hint: s.hint, glyph: s.glyph, run: () => store.go(s.id) }))
  );

  const actionItems = $derived.by<Item[]>(() => {
    const list: Item[] = [];
    const running =
      store.runs.find((run) => run.status === 'running' || run.status === 'queued') ??
      store.liveRun ??
      null;
    const last = store.totals?.last_run ?? store.runs[0] ?? null;
    if (running) {
      list.push({
        label: `Watch ${running.target}`,
        hint: 'open the live run',
        glyph: '[*]',
        run: () => store.watch(running.id)
      });
    } else if (last) {
      list.push({
        label: `Open ${last.target}`,
        hint: `last cast ${ago(last.created_at)}`,
        glyph: '[*]',
        run: () => store.watch(last.id)
      });
    }
    if (last?.counts?.report) {
      list.push({
        label: 'Open the latest report',
        hint: 'submission markdown',
        glyph: 'R',
        run: () => store.watch(last.id, 'report')
      });
    }
    const open =
      (store.totals?.triage?.new ?? 0) + (store.totals?.triage?.in_progress ?? 0);
    if (open > 0) {
      list.push({
        label: 'Review the human queue',
        hint: `${open} waiting`,
        glyph: '*',
        run: () => store.go('findings')
      });
    } else if ((store.totals?.findings ?? 0) > 0) {
      list.push({
        label: 'Search findings',
        hint: `${store.totals?.findings} in the index`,
        glyph: '*',
        run: () => store.go('findings')
      });
    }
    list.push({
      label: 'Refresh the control plane',
      hint: 'summary + run ledger',
      glyph: '~',
      run: () => {
        void store.refreshPulse();
        store.toast('ok', 'control plane refreshed');
      }
    });
    list.push({
      label: 'Copy this view',
      hint: 'share the current screen',
      glyph: '#',
      run: () => {
        void navigator.clipboard?.writeText(window.location.href);
        store.toast('ok', 'view link copied');
      }
    });
    return list;
  });

  const items = $derived.by<Item[]>(() => {
    const all = [...navItems, ...actionItems];
    const needle = q.trim().toLowerCase();
    if (!needle) return all;
    return all.filter(
      (item) =>
        item.label.toLowerCase().includes(needle) || item.hint.toLowerCase().includes(needle)
    );
  });

  const sel = $derived(Math.min(cursor, Math.max(0, items.length - 1)));

  $effect(() => {
    if (store.palette) {
      q = '';
      cursor = 0;
      void input?.focus();
    }
  });

  function onkey(event: KeyboardEvent) {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      cursor = Math.min(sel + 1, items.length - 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      cursor = Math.max(sel - 1, 0);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      items[sel]?.run();
      store.palette = false;
    } else if (event.key === 'Escape') {
      store.palette = false;
    }
  }

  function pick(item: Item) {
    item.run();
    store.palette = false;
  }
</script>

{#if store.palette}
  <div class="palette-veil" role="presentation" onclick={() => (store.palette = false)}>
    <div
      class="mx-auto mt-[14vh] w-[min(560px,92vw)]"
      role="dialog"
      aria-label="command palette"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <div class="palette-panel panel overflow-hidden">
        <div class="flex items-center gap-3 border-b border-indigo-deep px-4">
          <span class="mono text-sm text-acid" aria-hidden="true">&gt;</span>
          <input
            class="w-full min-w-0 bg-transparent py-3 text-sm text-bone outline-none placeholder:text-slate"
            placeholder="jump to a screen, or search..."
            aria-label="command palette search"
            bind:value={q}
            bind:this={input}
            onkeydown={onkey}
          />
          <span class="kbd shrink-0">esc</span>
        </div>

        <ul class="max-h-[46vh] overflow-auto p-2">
          {#each items as item, i (item.label)}
            <li>
              <button
                class="palette-item"
                class:on={i === sel}
                type="button"
                onmouseenter={() => (cursor = i)}
                onclick={() => pick(item)}
              >
                <span class="palette-glyph" aria-hidden="true">{item.glyph}</span>
                <span class="min-w-0 flex-1 truncate">{item.label}</span>
                <span class="hidden shrink-0 text-xs text-ash sm:inline">{item.hint}</span>
              </button>
            </li>
          {:else}
            <li class="px-3 py-5 text-center text-xs text-ash">no command matches</li>
          {/each}
        </ul>

        <div class="flex items-center gap-2 border-t border-indigo-deep px-4 py-2">
          <span class="mono text-[10px] tracking-[0.14em] text-ash">move</span>
          <span class="kbd">up</span>
          <span class="kbd">down</span>
          <span class="mono ml-2 text-[10px] tracking-[0.14em] text-ash">run</span>
          <span class="kbd">enter</span>
          <span class="mono ml-auto text-[10px] tracking-[0.24em] text-slate">netcast3r palette</span>
        </div>
      </div>
    </div>
  </div>
{/if}
