<script lang="ts">
  import { store } from '../state.svelte';
  import { ago } from '../format';
  import type { Screen } from '../types';

  type Item = { label: string; hint: string; glyph: string; group: string; run: () => void };

  const NAV: { id: Screen; label: string; glyph: string; hint: string }[] = [
    { id: 'home', label: 'Command Center', glyph: '#', hint: 'overview, what needs you' },
    { id: 'missions', label: 'Missions', glyph: '@', hint: 'scoped objectives and their runs' },
    { id: 'new', label: 'Engage target', glyph: '>', hint: 'one seed -> full agentic hunt' },
    { id: 'live', label: 'Live runs', glyph: '[*]', hint: 'watch a cast mid-hunt' },
    { id: 'findings', label: 'Findings', glyph: '*', hint: 'triage what came back' },
    { id: 'runs', label: 'Cast history', glyph: '//', hint: 'every cast, rerun, delete' },
    { id: 'reveng', label: 'Reverse Lab', glyph: '</>', hint: 'source, APK, contracts, drivers' },
    { id: 'reports', label: 'Reports', glyph: '=', hint: 'submissions, outcomes, payouts' },
    { id: 'agent', label: 'Agent Studio', glyph: '::', hint: 'MCP tools, policy, audit' },
    { id: 'connect', label: 'Connect', glyph: '~', hint: 'OpenCode, Hermes, Agent Zero' },
    { id: 'keys', label: 'Providers', glyph: '^', hint: 'keys, models, health' },
    { id: 'help', label: 'Field guide', glyph: '?', hint: 'what every state means' }
  ];

  let q = $state('');
  let cursor = $state(0);
  let input = $state<HTMLInputElement | null>(null);

  const navItems = $derived<Item[]>(
    NAV.map((s) => ({
      label: s.label,
      hint: s.hint,
      glyph: s.glyph,
      group: 'Navigate',
      run: () => store.go(s.id)
    }))
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
        group: 'Actions',
        run: () => store.watch(running.id)
      });
    } else if (last) {
      list.push({
        label: `Open ${last.target}`,
        hint: `last cast ${ago(last.created_at)}`,
        glyph: '[*]',
        group: 'Actions',
        run: () => store.watch(last.id)
      });
    }
    if (last?.counts?.report) {
      list.push({
        label: 'Open the latest report',
        hint: 'submission markdown',
        glyph: 'R',
        group: 'Actions',
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
        group: 'Actions',
        run: () => store.go('findings')
      });
    } else if ((store.totals?.findings ?? 0) > 0) {
      list.push({
        label: 'Search findings',
        hint: `${store.totals?.findings} in the index`,
        glyph: '*',
        group: 'Actions',
        run: () => store.go('findings')
      });
    }
    list.push({
      label: store.brainDock ? 'Close main brain' : 'Open main brain',
      hint: 'instruct mid-hunt - shortcut B',
      glyph: 'B',
      group: 'Actions',
      run: () => {
        store.brainDock = !store.brainDock;
      }
    });
    list.push({
      label: 'Refresh the control plane',
      hint: 'summary + run ledger',
      glyph: '~',
      group: 'Actions',
      run: () => {
        void store.refreshPulse();
        store.toast('ok', 'control plane refreshed');
      }
    });
    list.push({
      label: 'Copy this view',
      hint: 'share the current screen',
      glyph: '#',
      group: 'Actions',
      run: () => {
        void navigator.clipboard?.writeText(window.location.href);
        store.toast('ok', 'view link copied');
      }
    });
    return list;
  });

  const items = $derived.by<Item[]>(() => {
    const all = [...actionItems, ...navItems];
    const needle = q.trim().toLowerCase();
    if (!needle) return all;
    return all.filter(
      (item) =>
        item.label.toLowerCase().includes(needle) ||
        item.hint.toLowerCase().includes(needle) ||
        item.group.toLowerCase().includes(needle)
    );
  });

  const sections = $derived.by(() => {
    const order = ['Actions', 'Navigate'];
    const grouped = new Map<string, { item: Item; index: number }[]>();
    items.forEach((item, index) => {
      const rows = grouped.get(item.group) ?? [];
      rows.push({ item, index });
      grouped.set(item.group, rows);
    });
    return order
      .filter((name) => grouped.has(name))
      .map((name) => ({ name, rows: grouped.get(name)! }));
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
  <div class="palette-veil fixed inset-0" role="presentation" onclick={() => (store.palette = false)}>
    <div
      class="mx-auto mt-[12vh] w-[min(580px,92vw)]"
      role="dialog"
      aria-label="command palette"
      aria-modal="true"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <div class="palette-panel panel overflow-hidden">
        <div class="flex items-center gap-3 border-b border-indigo-deep px-4">
          <span class="mono text-sm text-acid" aria-hidden="true">&gt;</span>
          <input
            class="w-full min-w-0 bg-transparent py-3.5 text-sm text-bone outline-none placeholder:text-slate"
            placeholder="Jump, instruct, search..."
            aria-label="command palette search"
            bind:value={q}
            bind:this={input}
            onkeydown={onkey}
          />
          <span class="kbd shrink-0">esc</span>
        </div>

        <ul class="max-h-[52vh] overflow-auto p-2">
          {#each sections as section (section.name)}
            <li class="palette-section" aria-hidden="true">{section.name}</li>
            {#each section.rows as row (row.item.label)}
              <li>
                <button
                  class="palette-item"
                  class:on={row.index === sel}
                  type="button"
                  onmouseenter={() => (cursor = row.index)}
                  onclick={() => pick(row.item)}
                >
                  <span class="palette-glyph" aria-hidden="true">{row.item.glyph}</span>
                  <span class="min-w-0 flex-1 truncate" title={row.item.label}>{row.item.label}</span>
                  <span class="hidden shrink-0 text-xs text-ash sm:inline">{row.item.hint}</span>
                </button>
              </li>
            {/each}
          {:else}
            <li class="px-3 py-5 text-center text-xs text-ash">no command matches</li>
          {/each}
        </ul>

        <div class="flex items-center gap-2 border-t border-indigo-deep px-4 py-2">
          <span class="mono text-[10px] tracking-[0.14em] text-ash">move</span>
          <span class="kbd">^</span>
          <span class="kbd">v</span>
          <span class="mono ml-2 text-[10px] tracking-[0.14em] text-ash">run</span>
          <span class="kbd">Enter</span>
          <span class="mono ml-2 text-[10px] tracking-[0.14em] text-ash">brain</span>
          <span class="kbd">B</span>
          <span class="mono ml-auto text-[10px] tracking-[0.24em] text-slate">netcast3r</span>
        </div>
      </div>
    </div>
  </div>
{/if}
