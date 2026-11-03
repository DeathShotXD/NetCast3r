<script lang="ts">
  // Helix - floating, draggable, resizable hunt steward. Layout persists.
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import type { BrainLiveEntry, BrainLoopStatus, BrainTurn } from '../types';
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';

  const BUFFER_PHASES = [
    'Reading the plane',
    'Reading mesh chats',
    'Reasoning',
    'Selecting actions',
    'Steering the hunt'
  ] as const;

  type FeedChannel = 'all' | 'journal' | 'mesh' | 'run' | 'log';

  const COMPANION = 'Helix';
  const LAYOUT_KEY = 'netcast3r.helix.layout.v1';
  const MIN_W = 380;
  const MIN_H = 320;
  const DEFAULT = {
    x: null as number | null,
    y: null as number | null,
    w: 520,
    h: 560,
    fullscreen: false
  };

  let feed = $state<BrainTurn[]>([]);
  let timeline = $state<BrainLiveEntry[]>([]);
  let loop = $state<BrainLoopStatus | null>(null);
  let ticker = $state<{ kind: string; note: string }[]>([]);
  let channel = $state<FeedChannel>('all');
  let input = $state('');
  let busy = $state(false);
  let acting = $state('');
  let target = $state<'brain' | 'both' | 'director'>('both');
  let timer: number | undefined;
  let phaseTimer: number | undefined;
  let feedEl = $state<HTMLUListElement>();
  let inputEl = $state<HTMLInputElement>();
  let panelEl = $state<HTMLElement>();
  let source: EventSource | null = null;

  let layout = $state({ ...DEFAULT });
  let dragging = $state(false);
  let resizing = $state(false);
  let dragOrigin = { px: 0, py: 0, x: 0, y: 0 };
  let resizeOrigin = { px: 0, py: 0, w: 0, h: 0 };
  let seenHail = $state('');
  /** Only auto-scroll when the operator is already near the bottom. */
  let stickToBottom = $state(true);
  let pendingText = $state('');
  let bufferPhase = $state<(typeof BUFFER_PHASES)[number]>(BUFFER_PHASES[0]);

  const open = $derived(store.brainDock);
  const latest = $derived(feed.length ? feed[feed.length - 1] : null);
  const visible = $derived.by(() => {
    if (channel === 'all') return timeline;
    return timeline.filter((row) => row.channel === channel);
  });
  const channelCounts = $derived.by(() => {
    const counts = { all: timeline.length, journal: 0, mesh: 0, run: 0, log: 0 };
    for (const row of timeline) {
      if (row.channel in counts) {
        counts[row.channel as keyof typeof counts] += 1;
      }
    }
    return counts;
  });
  const meshRoles = [
    { id: 'osint', label: 'OSINT' },
    { id: 'scout', label: 'Scout' },
    { id: 'auth', label: 'Auth' },
    { id: 'exegete', label: 'Exegete' },
    { id: 'attacker', label: 'Attack' },
    { id: 'validator', label: 'Validate' },
    { id: 'pivot', label: 'Pivot' }
  ] as const;

  const stateLabel = $derived(
    loop ? (loop.paused ? 'Paused' : loop.running ? 'Autonomous' : 'Idle') : 'Standby'
  );
  const stateTone = $derived(
    loop ? (loop.paused ? 'paused' : loop.running ? 'live' : 'idle') : 'idle'
  );
  const activeRoles = $derived.by(() => {
    const blob = [
      ...ticker.map((row) => `${row.kind} ${row.note}`),
      ...timeline.slice(-24).map((row) => `${row.agent} ${row.focus} ${row.text}`)
    ]
      .join(' ')
      .toLowerCase();
    const hits = new Set<string>();
    for (const role of meshRoles) {
      if (blob.includes(role.id) || blob.includes(role.label.toLowerCase())) hits.add(role.id);
    }
    if (blob.includes('train') || blob.includes('lab')) hits.add('exegete');
    if (blob.includes('swarm') || blob.includes('hunt')) hits.add('attacker');
    if (blob.includes('brain') || blob.includes('think') || blob.includes('helix')) hits.add('scout');
    if (blob.includes('auth') || blob.includes('oauth') || blob.includes('session')) hits.add('auth');
    if (blob.includes('osint') || blob.includes('recon')) hits.add('osint');
    return hits;
  });

  const panelStyle = $derived.by(() => {
    if (layout.fullscreen) {
      return 'left:10px;top:10px;right:10px;bottom:10px;width:auto;height:auto;';
    }
    const vw = typeof window !== 'undefined' ? window.innerWidth : 1280;
    const vh = typeof window !== 'undefined' ? window.innerHeight : 800;
    const w = Math.min(Math.max(layout.w, MIN_W), vw - 16);
    const h = Math.min(Math.max(layout.h, MIN_H), vh - 16);
    let x = layout.x;
    let y = layout.y;
    if (x == null || y == null) {
      x = Math.max(16, Math.round(vw - w - 28));
      y = Math.max(72, Math.round(vh - h - 88));
    }
    x = Math.min(Math.max(8, x), vw - Math.min(w, 120));
    y = Math.min(Math.max(8, y), vh - 64);
    return `left:${x}px;top:${y}px;width:${w}px;height:${h}px;`;
  });

  function loadLayout() {
    try {
      const raw = window.localStorage.getItem(LAYOUT_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw) as Partial<typeof DEFAULT>;
      layout = {
        x: typeof parsed.x === 'number' ? parsed.x : null,
        y: typeof parsed.y === 'number' ? parsed.y : null,
        w: typeof parsed.w === 'number' ? parsed.w : DEFAULT.w,
        h: typeof parsed.h === 'number' ? parsed.h : DEFAULT.h,
        fullscreen: Boolean(parsed.fullscreen)
      };
    } catch {
      /* keep defaults */
    }
  }

  function persistLayout() {
    try {
      window.localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
    } catch {
      /* ignore */
    }
  }

  function clampLayout(next: typeof layout) {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const w = Math.min(Math.max(next.w, MIN_W), vw - 16);
    const h = Math.min(Math.max(next.h, MIN_H), vh - 16);
    let x = next.x ?? Math.max(16, Math.round(vw - w - 28));
    let y = next.y ?? Math.max(72, Math.round(vh - h - 88));
    x = Math.min(Math.max(8, x), vw - Math.min(w, 120));
    y = Math.min(Math.max(8, y), vh - 64);
    return { ...next, x, y, w, h };
  }

  function toggleFullscreen() {
    layout = { ...layout, fullscreen: !layout.fullscreen };
    persistLayout();
  }

  function onDragStart(event: PointerEvent) {
    if (layout.fullscreen) return;
    if (event.button !== 0) return;
    const targetEl = event.target as HTMLElement | null;
    if (targetEl?.closest('button, select, input, a')) return;
    event.preventDefault();
    const rect = panelEl?.getBoundingClientRect();
    const x = layout.x ?? rect?.left ?? 0;
    const y = layout.y ?? rect?.top ?? 0;
    dragging = true;
    dragOrigin = { px: event.clientX, py: event.clientY, x, y };
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  }

  function onDragMove(event: PointerEvent) {
    if (!dragging) return;
    layout = clampLayout({
      ...layout,
      x: dragOrigin.x + (event.clientX - dragOrigin.px),
      y: dragOrigin.y + (event.clientY - dragOrigin.py)
    });
  }

  function onDragEnd() {
    if (!dragging) return;
    dragging = false;
    persistLayout();
  }

  function onResizeStart(event: PointerEvent) {
    if (layout.fullscreen) return;
    if (event.button !== 0) return;
    event.preventDefault();
    event.stopPropagation();
    resizing = true;
    resizeOrigin = {
      px: event.clientX,
      py: event.clientY,
      w: layout.w,
      h: layout.h
    };
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  }

  function onResizeMove(event: PointerEvent) {
    if (!resizing) return;
    layout = clampLayout({
      ...layout,
      w: resizeOrigin.w + (event.clientX - resizeOrigin.px),
      h: resizeOrigin.h + (event.clientY - resizeOrigin.py)
    });
  }

  function onResizeEnd() {
    if (!resizing) return;
    resizing = false;
    persistLayout();
  }

  function resetLayout() {
    layout = { ...DEFAULT };
    persistLayout();
  }

  function onFeedScroll() {
    if (!feedEl) return;
    const gap = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight;
    stickToBottom = gap < 56;
  }

  $effect(() => {
    if (open && feedEl && visible.length && stickToBottom) {
      feedEl.scrollTop = feedEl.scrollHeight;
    }
  });

  $effect(() => {
    if (open) {
      armPoll(1500);
      queueMicrotask(() => inputEl?.focus());
    } else {
      armPoll(4000);
    }
  });

  function roleLabel(entry: BrainLiveEntry): string {
    if (entry.channel === 'mesh') {
      const model = entry.model ? ` - ${entry.model}` : '';
      return `${entry.agent || 'mesh'}${model}`;
    }
    if (entry.channel === 'run') {
      return `${entry.agent || 'run'} - ${entry.role || 'thought'}`;
    }
    if (entry.channel === 'log') {
      return `Plane - ${entry.agent || 'log'}`;
    }
    if (entry.role === 'operator') {
      return entry.source && entry.source !== 'ui' ? `You - ${entry.source}` : 'You';
    }
    if (entry.role === 'helix') return `${COMPANION} - hail`;
    if (entry.role === 'auto') {
      return entry.model ? `${COMPANION} - ${entry.model}` : `${COMPANION} - thinking`;
    }
    if (entry.model) return `${COMPANION} - ${entry.model}`;
    return COMPANION;
  }

  async function load() {
    try {
      const missionId = (loop?.mission_id || '').trim();
      const result = await api.brainLive(100, missionId);
      feed = [...(result.items || [])].reverse();
      timeline = result.timeline || [];
      if (result.loop && Object.keys(result.loop).length) {
        loop = result.loop;
      }
      ticker = (result.logs || [])
        .slice(0, 14)
        .map((row) => ({
          kind: String(row.kind || 'event'),
          note: String(row.message || '').slice(0, 180)
        }))
        .filter((row) => row.note);
      const hail = [...feed].reverse().find((turn) => turn.role === 'helix');
      if (hail && String(hail.id) !== seenHail && hail.text) {
        seenHail = String(hail.id);
        if (!open) {
          store.toast('ok', `${COMPANION}: ${hail.text.slice(0, 120)}`);
        }
      }
    } catch {
      /* fall back to journal-only so the dock still works */
      try {
        const result = await api.brainJournal(60);
        feed = [...result.items].reverse();
        loop = result.loop;
        timeline = feed.map((turn) => ({
          id: `journal:${turn.id}`,
          channel: 'journal',
          role: turn.role,
          agent: turn.role,
          text: turn.text,
          focus: turn.focus,
          provider: turn.provider,
          model: turn.model,
          source: turn.source,
          actions: turn.actions,
          mission_id: turn.mission_id,
          ts: turn.ts
        }));
      } catch {
        /* optional */
      }
      try {
        const log = await api.directorLog(32);
        ticker = (log.items || [])
          .slice(0, 14)
          .map((row) => ({
            kind: String(row.kind || 'event'),
            note: String(row.message || '').slice(0, 180)
          }))
          .filter((row) => row.note);
      } catch {
        /* advisory */
      }
    }
  }

  function armPoll(ms: number) {
    if (timer) window.clearInterval(timer);
    timer = window.setInterval(() => void load(), ms);
  }

  function armBufferPhases() {
    let i = 0;
    bufferPhase = BUFFER_PHASES[0];
    if (phaseTimer) window.clearInterval(phaseTimer);
    phaseTimer = window.setInterval(() => {
      i = (i + 1) % BUFFER_PHASES.length;
      bufferPhase = BUFFER_PHASES[i];
    }, 1600);
  }

  function clearBufferPhases() {
    if (phaseTimer) window.clearInterval(phaseTimer);
    phaseTimer = undefined;
    bufferPhase = BUFFER_PHASES[0];
  }

  async function send() {
    const message = input.trim();
    if (!message || busy) return;
    busy = true;
    pendingText = message;
    input = '';
    stickToBottom = true;
    armBufferPhases();
    try {
      const missionId = (loop?.mission_id || '').trim();
      const body: Record<string, unknown> = { target, act: true };
      if (missionId) body.mission_id = missionId;
      else if (target !== 'brain') {
        store.toast('error', 'pick an active mission before directing the hunt');
        busy = false;
        pendingText = '';
        clearBufferPhases();
        input = message;
        return;
      }
      await api.instruct(message, body);
      await load();
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'instruction failed');
    } finally {
      busy = false;
      pendingText = '';
      clearBufferPhases();
    }
  }

  async function control(action: string) {
    acting = action;
    try {
      loop = await api.brainLoop(action);
      if (action === 'tick') await load();
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : `${COMPANION} ${action} failed`);
    } finally {
      acting = '';
    }
  }

  function listen() {
    try {
      source?.close();
      source = new EventSource(api.eventsUrl());
      source.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          const type = String(data?.type || '');
          if (
            type === 'brain.turn' ||
            type === 'instruct' ||
            type.startsWith('director') ||
            type === 'tool' ||
            type === 'finding' ||
            type === 'finding.created' ||
            type === 'candidate' ||
            type === 'reasoning' ||
            type === 'model' ||
            type === 'log' ||
            type === 'error' ||
            type === 'agent' ||
            type.includes('swarm') ||
            type.includes('mission')
          ) {
            void load();
          }
        } catch {
          /* ignore */
        }
      };
    } catch {
      /* polling fallback */
    }
  }

  function toggleOpen() {
    store.brainDock = !store.brainDock;
  }

  function onKey(event: KeyboardEvent) {
    if (event.key === 'Escape' && layout.fullscreen) {
      layout = { ...layout, fullscreen: false };
      persistLayout();
    }
  }

  onMount(() => {
    loadLayout();
    void load();
    listen();
    armPoll(8000);
    window.addEventListener('keydown', onKey);
  });

  onDestroy(() => {
    if (timer) window.clearInterval(timer);
    clearBufferPhases();
    source?.close();
    window.removeEventListener('keydown', onKey);
  });
</script>

{#if open}
  <section
    class="nc-brain-panel"
    class:dragging
    class:resizing
    class:fullscreen={layout.fullscreen}
    class:live={stateTone === 'live'}
    class:awaiting={busy}
    bind:this={panelEl}
    style={panelStyle}
    aria-label="{COMPANION} hunt steward"
    aria-busy={busy}
  >
    <div class="nc-brain-sheen" aria-hidden="true"></div>
    {#if busy}
      <div class="nc-brain-await-bar" aria-hidden="true">
        <Buffering variant="bar" label="{COMPANION} responding" />
      </div>
    {/if}

    <header
      class="nc-brain-head"
      onpointerdown={onDragStart}
      onpointermove={onDragMove}
      onpointerup={onDragEnd}
      onpointercancel={onDragEnd}
    >
      <div class="nc-brain-titleblock">
        <span class="nc-brain-grip" aria-hidden="true"></span>
        <div class="nc-brain-identity">
          <span class="nc-brain-wordmark">{COMPANION}</span>
          <span class="nc-brain-role-tag">Hunt steward</span>
          <span class="nc-brain-badge" data-tone={stateTone}>
            <span class="nc-brain-dot" class:paused={loop?.paused} class:off={!loop?.running}></span>
            {stateLabel}
          </span>
        </div>
        <div class="nc-brain-meta">
          {#if loop}
            <span>{loop.turns} turns</span>
            <span class="nc-brain-sep" aria-hidden="true">-</span>
          {/if}
          <span title={loop?.last_model || ''}>{loop?.last_model || 'prime route'}</span>
        </div>
      </div>
      <div class="nc-brain-controls">
        <button
          class="nc-brain-icon"
          type="button"
          title={layout.fullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}
          aria-label={layout.fullscreen ? 'exit fullscreen' : 'enter fullscreen'}
          onclick={toggleFullscreen}
        >
          {#if layout.fullscreen}
            <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
              <path d="M5 3H3v2M11 3h2v2M5 13H3v-2M11 13h2v-2" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
            </svg>
          {:else}
            <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
              <path d="M3 6V3h3M10 3h3v3M3 10v3h3M13 10v3h-3" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
            </svg>
          {/if}
        </button>
        <button
          class="nc-brain-icon"
          type="button"
          title="Reset position and size"
          aria-label="reset layout"
          onclick={resetLayout}
        >
          <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
            <path
              d="M3 8a5 5 0 0 1 8.5-3.5M13 3v3.2H9.8M13 8a5 5 0 0 1-8.5 3.5M3 13v-3.2h3.2"
              fill="none"
              stroke="currentColor"
              stroke-width="1.3"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </button>
        <button
          class="nc-brain-action"
          type="button"
          disabled={acting !== ''}
          onclick={() => void control(loop?.paused ? 'engage' : 'pause')}
        >
          {loop?.paused ? 'Resume' : 'Pause'}
        </button>
        <button
          class="nc-brain-action primary"
          type="button"
          disabled={acting !== ''}
          onclick={() => void control('tick')}
        >
          {acting === 'tick' ? 'Thinking...' : 'Think'}
        </button>
        <button
          class="nc-brain-icon"
          type="button"
          aria-label="close {COMPANION}"
          onclick={() => (store.brainDock = false)}
        >
          <Icon name="x" size={12} />
        </button>
      </div>
    </header>

    <nav class="nc-brain-mesh" aria-label="agent mesh lanes">
      {#each meshRoles as role}
        <span class="nc-brain-lane" class:on={activeRoles.has(role.id)}>{role.label}</span>
      {/each}
    </nav>

    {#if ticker.length}
      <section class="nc-brain-ops" aria-label="live plane logs">
        <div class="nc-brain-ops-label">Plane logs</div>
        <ul class="nc-brain-ticker">
          {#each ticker.slice(0, 8) as row, i (i + row.kind + row.note.slice(0, 24))}
            <li>
              <span class="nc-brain-tick-kind">{row.kind}</span>
              <span class="nc-brain-tick-note">{row.note}</span>
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <section class="nc-brain-cognition">
      <div class="nc-brain-feed-head">
        <div class="nc-brain-ops-label">Live feed</div>
        <div class="nc-brain-channels" role="tablist" aria-label="Helix feed channels">
          {#each [
            ['all', 'All'],
            ['journal', 'Helix'],
            ['mesh', 'Mesh'],
            ['run', 'Models'],
            ['log', 'Logs']
          ] as [id, label] (id)}
            <button
              class="nc-brain-channel"
              class:active={channel === id}
              type="button"
              role="tab"
              aria-selected={channel === id}
              onclick={() => {
                channel = id as FeedChannel;
                stickToBottom = true;
              }}
            >
              {label}
              <b>{channelCounts[id as FeedChannel] ?? 0}</b>
            </button>
          {/each}
        </div>
      </div>
      <ul class="nc-brain-feed" bind:this={feedEl} onscroll={onFeedScroll}>
        {#each visible as entry (entry.id)}
          <li
            class:operator={entry.role === 'operator'}
            class:auto={entry.role === 'auto' || entry.channel === 'mesh'}
            class:helix={entry.role === 'helix'}
            class:mesh={entry.channel === 'mesh'}
            class:run={entry.channel === 'run'}
            class:logrow={entry.channel === 'log'}
          >
            <header class="nc-brain-turn-head">
              <span class="nc-brain-role">{roleLabel(entry)}</span>
              {#if entry.focus}
                <span class="nc-brain-focus">{entry.focus}</span>
              {:else if entry.provider || entry.model}
                <span class="nc-brain-focus">{[entry.provider, entry.model].filter(Boolean).join(' / ')}</span>
              {/if}
            </header>
            <p class="nc-brain-text">{entry.text}</p>
            {#if entry.actions && entry.actions.length}
              <div class="nc-brain-actions">
                {#each entry.actions as action}
                  <span class:refused={!action.applied}>{action.kind}</span>
                {/each}
              </div>
            {/if}
          </li>
        {/each}
        {#if pendingText}
          <li class="operator pending">
            <header class="nc-brain-turn-head">
              <span class="nc-brain-role">You</span>
              <span class="nc-brain-focus">sending</span>
            </header>
            <p class="nc-brain-text">{pendingText}</p>
          </li>
          <li class="buffering" aria-live="polite">
            <Buffering
              variant="block"
              tone="acid"
              label={bufferPhase}
              detail="{COMPANION} is reading logs and mesh chats, then composing a steer..."
            />
          </li>
        {:else if visible.length === 0}
          <li class="nc-brain-empty">
            {COMPANION} will stream journal turns, mesh model chats, run thoughts, and plane logs here continuously.
          </li>
        {/if}
      </ul>
    </section>

    <footer class="nc-brain-composer" class:locked={busy}>
      <select class="nc-brain-target" bind:value={target} aria-label="instruction target" disabled={busy}>
        <option value="both">{COMPANION} + hunt</option>
        <option value="brain">{COMPANION} only</option>
        <option value="director">Hunt queue</option>
      </select>
      <input
        class="nc-brain-input"
        bind:this={inputEl}
        bind:value={input}
        placeholder={busy ? `${COMPANION} is responding...` : 'Steer mid-hunt - pivot auth, skip CDN, deepen IDOR...'}
        aria-label="instruct {COMPANION} or hunt mid-engagement"
        disabled={busy}
        onkeydown={(event) => {
          if (event.key === 'Enter') void send();
        }}
      />
      <button
        class="nc-brain-send"
        class:is-busy={busy}
        type="button"
        disabled={busy || !input.trim()}
        onclick={() => void send()}
      >
        {#if busy}
          <span class="nc-brain-send-spin" aria-hidden="true"></span>
          Wait
        {:else}
          Instruct
        {/if}
      </button>
    </footer>

    <div
      class="nc-brain-resize"
      role="separator"
      aria-orientation="horizontal"
      aria-label="resize brain console"
      onpointerdown={onResizeStart}
      onpointermove={onResizeMove}
      onpointerup={onResizeEnd}
      onpointercancel={onResizeEnd}
    ></div>
  </section>
{/if}

<button
  class="nc-brain-pill"
  class:awaiting={busy && !open}
  type="button"
  aria-expanded={open}
  onclick={() => toggleOpen()}
>
  <span
    class="nc-brain-dot"
    class:paused={loop?.paused}
    class:off={!loop?.running}
    class:busy={busy && !open}
  ></span>
  <span class="nc-brain-pill-label">{COMPANION}</span>
  <span class="nc-brain-pill-meta">
    {busy && !open
      ? 'replying...'
      : loop
        ? loop.paused
          ? 'paused'
          : `${loop.turns} turns`
        : 'standby'}
  </span>
  {#if latest && !open}
    <span class="nc-brain-pill-focus">
      {latest.role === 'helix' ? latest.focus || 'hail' : latest.focus || 'reasoning'}
    </span>
  {/if}
  <kbd class="nc-brain-kbd">B</kbd>
</button>

<style>
  .nc-brain-panel {
    position: fixed;
    z-index: 46;
    display: flex;
    flex-direction: column;
    min-width: 380px;
    min-height: 320px;
    overflow: hidden;
    border: 1px solid rgba(245, 233, 220, 0.1);
    border-radius: 18px;
    background:
      linear-gradient(180deg, rgba(20, 17, 31, 0.97), rgba(6, 5, 10, 0.98));
    box-shadow:
      0 0 0 1px rgba(159, 35, 221, 0.12),
      0 28px 80px rgba(0, 0, 0, 0.55),
      0 1px 0 rgba(245, 233, 220, 0.04) inset;
    color: var(--obs-text);
    touch-action: none;
  }

  .nc-brain-panel.live {
    border-color: rgba(200, 248, 26, 0.18);
    box-shadow:
      0 0 0 1px rgba(200, 248, 26, 0.08),
      0 28px 80px rgba(0, 0, 0, 0.55),
      0 0 40px -18px rgba(200, 248, 26, 0.28);
  }

  .nc-brain-panel.awaiting {
    border-color: rgba(200, 248, 26, 0.28);
    box-shadow:
      0 0 0 1px rgba(200, 248, 26, 0.1),
      0 28px 80px rgba(0, 0, 0, 0.55),
      0 0 48px -16px rgba(200, 248, 26, 0.32);
    animation: nc-brain-await-glow 2.4s var(--ease, ease) infinite;
  }

  .nc-brain-await-bar {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    z-index: 3;
  }

  @keyframes nc-brain-await-glow {
    0%,
    100% {
      box-shadow:
        0 0 0 1px rgba(200, 248, 26, 0.08),
        0 28px 80px rgba(0, 0, 0, 0.55),
        0 0 36px -18px rgba(200, 248, 26, 0.22);
    }
    50% {
      box-shadow:
        0 0 0 1px rgba(200, 248, 26, 0.16),
        0 28px 80px rgba(0, 0, 0, 0.55),
        0 0 56px -14px rgba(200, 248, 26, 0.4);
    }
  }

  .nc-brain-panel.fullscreen {
    z-index: 60;
    border-radius: 14px;
  }

  .nc-brain-panel.fullscreen .nc-brain-grip {
    opacity: 0.25;
  }

  .nc-brain-panel.fullscreen .nc-brain-resize {
    display: none;
  }

  .nc-brain-panel.dragging,
  .nc-brain-panel.resizing {
    user-select: none;
    border-color: rgba(200, 248, 26, 0.32);
  }

  .nc-brain-sheen {
    pointer-events: none;
    position: absolute;
    inset: 0 0 auto;
    height: 88px;
    background: radial-gradient(120% 100% at 12% 0%, rgba(159, 35, 221, 0.14), transparent 58%);
  }

  .nc-brain-head {
    position: relative;
    z-index: 1;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 14px 12px;
    cursor: grab;
    border-bottom: 1px solid rgba(245, 233, 220, 0.06);
  }

  .nc-brain-panel.dragging .nc-brain-head {
    cursor: grabbing;
  }

  .nc-brain-titleblock {
    display: grid;
    grid-template-columns: 10px 1fr;
    gap: 2px 10px;
    min-width: 0;
  }

  .nc-brain-grip {
    grid-row: 1 / span 2;
    align-self: center;
    width: 8px;
    height: 22px;
    border-radius: 99px;
    background:
      linear-gradient(180deg, transparent 0 2px, rgba(245, 233, 220, 0.22) 2px 3px, transparent 3px 6px)
        0 0 / 100% 6px repeat-y;
    opacity: 0.7;
  }

  .nc-brain-identity {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .nc-brain-wordmark {
    font-size: 13px;
    font-weight: 560;
    letter-spacing: 0.01em;
    color: var(--obs-text);
  }

  .nc-brain-role-tag {
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--obs-violet-3);
  }

  .nc-brain-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border-radius: 999px;
    padding: 2px 8px 2px 6px;
    background: rgba(245, 233, 220, 0.04);
    border: 1px solid rgba(245, 233, 220, 0.08);
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--obs-muted);
  }

  .nc-brain-badge[data-tone='live'] {
    border-color: rgba(200, 248, 26, 0.28);
    background: rgba(200, 248, 26, 0.07);
    color: var(--obs-acid);
  }

  .nc-brain-badge[data-tone='paused'] {
    border-color: rgba(240, 194, 107, 0.28);
    background: rgba(240, 194, 107, 0.08);
    color: var(--obs-orange);
  }

  .nc-brain-meta {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    font-family: var(--mono);
    font-size: 10px;
    color: var(--obs-faint);
  }

  .nc-brain-meta span:last-child {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .nc-brain-sep {
    opacity: 0.5;
  }

  .nc-brain-controls {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: none;
  }

  .nc-brain-action,
  .nc-brain-send {
    border: 1px solid rgba(245, 233, 220, 0.1);
    border-radius: 8px;
    padding: 6px 10px;
    background: rgba(245, 233, 220, 0.03);
    font-size: 11px;
    font-weight: 500;
    color: var(--obs-text-2);
    cursor: pointer;
    transition: border-color 140ms ease, background 140ms ease, color 140ms ease;
  }

  .nc-brain-action:hover,
  .nc-brain-send:hover {
    border-color: rgba(200, 248, 26, 0.28);
    color: var(--obs-acid);
  }

  .nc-brain-action.primary {
    border-color: rgba(200, 248, 26, 0.3);
    background: rgba(200, 248, 26, 0.1);
    color: var(--obs-acid);
  }

  .nc-brain-action:disabled,
  .nc-brain-send:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .nc-brain-icon {
    display: grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border: 1px solid transparent;
    border-radius: 8px;
    background: transparent;
    color: var(--obs-faint);
    cursor: pointer;
  }

  .nc-brain-icon:hover {
    border-color: rgba(245, 233, 220, 0.1);
    background: rgba(245, 233, 220, 0.04);
    color: var(--obs-text);
  }

  .nc-brain-dot {
    width: 6px;
    height: 6px;
    flex: none;
    border-radius: 50%;
    background: var(--obs-acid);
    box-shadow: 0 0 8px 1px rgba(200, 248, 26, 0.55);
    animation: nc-brain-breathe 2.4s ease-in-out infinite;
  }

  .nc-brain-dot.paused,
  .nc-brain-dot.off {
    background: var(--obs-faint);
    box-shadow: none;
    animation: none;
  }

  .nc-brain-mesh {
    position: relative;
    z-index: 1;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    padding: 10px 14px 12px;
    border-bottom: 1px solid rgba(245, 233, 220, 0.06);
  }

  .nc-brain-lane {
    border-radius: 999px;
    padding: 4px 9px;
    background: rgba(245, 233, 220, 0.025);
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--obs-faint);
    transition: color 160ms ease, background 160ms ease, box-shadow 160ms ease;
  }

  .nc-brain-lane.on {
    background: rgba(200, 248, 26, 0.1);
    color: var(--obs-acid);
    box-shadow: inset 0 0 0 1px rgba(200, 248, 26, 0.22);
  }

  .nc-brain-ops,
  .nc-brain-cognition {
    position: relative;
    z-index: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .nc-brain-ops {
    flex: none;
    max-height: 118px;
    border-bottom: 1px solid rgba(245, 233, 220, 0.06);
    background: linear-gradient(180deg, rgba(200, 248, 26, 0.03), transparent);
  }

  .nc-brain-cognition {
    flex: 1;
  }

  .nc-brain-ops-label {
    padding: 10px 14px 0;
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--obs-faint);
  }

  .nc-brain-ticker {
    display: flex;
    flex-direction: column;
    gap: 5px;
    overflow: auto;
    margin: 0;
    padding: 8px 14px 10px;
    list-style: none;
  }

  .nc-brain-ticker li {
    display: grid;
    grid-template-columns: minmax(70px, 92px) 1fr;
    gap: 10px;
    align-items: baseline;
  }

  .nc-brain-tick-kind {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.04em;
    color: var(--obs-acid);
  }

  .nc-brain-tick-note {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 11px;
    color: var(--obs-muted);
  }

  .nc-brain-feed {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    margin: 0;
    padding: 8px 14px 12px;
    list-style: none;
  }

  .nc-brain-feed li {
    border-radius: 12px;
    border: 1px solid rgba(245, 233, 220, 0.06);
    background: rgba(0, 0, 0, 0.22);
    padding: 10px 12px;
  }

  .nc-brain-feed li.operator {
    border-color: rgba(200, 248, 26, 0.18);
    background: rgba(200, 248, 26, 0.045);
  }

  .nc-brain-feed li.auto {
    border-color: rgba(159, 35, 221, 0.2);
    background:
      linear-gradient(135deg, rgba(159, 35, 221, 0.1), transparent 55%),
      rgba(0, 0, 0, 0.2);
  }

  .nc-brain-feed li.helix {
    border-color: rgba(200, 248, 26, 0.28);
    background:
      linear-gradient(135deg, rgba(200, 248, 26, 0.1), transparent 60%),
      rgba(0, 0, 0, 0.24);
  }

  .nc-brain-feed li.helix .nc-brain-role {
    color: var(--obs-acid);
  }

  .nc-brain-feed-head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 8px;
  }

  .nc-brain-channels {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .nc-brain-channel {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 22px;
    border: 1px solid rgba(245, 233, 220, 0.1);
    border-radius: 999px;
    padding: 0 8px;
    background: rgba(0, 0, 0, 0.22);
    color: var(--obs-faint);
    font-family: var(--mono);
    font-size: 8.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    cursor: pointer;
  }

  .nc-brain-channel b {
    font-weight: 560;
    color: var(--obs-text-2);
  }

  .nc-brain-channel.active {
    border-color: rgba(200, 248, 26, 0.28);
    background: rgba(200, 248, 26, 0.08);
    color: var(--obs-acid);
  }

  .nc-brain-channel.active b {
    color: var(--obs-acid);
  }

  .nc-brain-feed li.pending {
    opacity: 0.88;
    animation: nc-brain-enter 220ms var(--ease, ease) both;
  }

  .nc-brain-feed li.buffering {
    border: none;
    background: transparent;
    padding: 0;
    animation: nc-brain-enter 280ms var(--ease, ease) both;
  }

  .nc-brain-feed li.mesh {
    border-color: rgba(159, 35, 221, 0.22);
    background:
      linear-gradient(135deg, rgba(159, 35, 221, 0.1), transparent 55%),
      rgba(0, 0, 0, 0.2);
  }

  .nc-brain-feed li.run {
    border-color: rgba(245, 233, 220, 0.1);
    background: rgba(0, 0, 0, 0.18);
  }

  .nc-brain-feed li.logrow {
    border-style: dashed;
    border-color: rgba(245, 233, 220, 0.1);
    background: transparent;
    opacity: 0.92;
  }

  .nc-brain-feed li.logrow .nc-brain-text {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--obs-muted);
  }

  .nc-brain-turn-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 5px;
  }

  .nc-brain-role {
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--obs-faint);
  }

  .nc-brain-focus {
    overflow: hidden;
    max-width: 58%;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 10px;
    color: var(--obs-violet-3);
  }

  .nc-brain-text {
    margin: 0;
    font-size: 12.5px;
    line-height: 1.5;
    color: var(--obs-text-2);
    white-space: pre-wrap;
  }

  .nc-brain-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
    margin-top: 8px;
  }

  .nc-brain-actions span {
    border-radius: 999px;
    padding: 2px 7px;
    background: rgba(200, 248, 26, 0.08);
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.04em;
    color: var(--obs-acid);
  }

  .nc-brain-actions span.refused {
    background: rgba(217, 112, 168, 0.1);
    color: var(--obs-red);
  }

  .nc-brain-empty {
    border-style: dashed !important;
    color: var(--obs-muted);
    font-size: 12px;
    line-height: 1.55;
  }

  .nc-brain-composer {
    position: relative;
    z-index: 1;
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 8px;
    flex: none;
    border-top: 1px solid rgba(245, 233, 220, 0.07);
    padding: 12px 14px 16px;
    background: linear-gradient(180deg, transparent, rgba(0, 0, 0, 0.28));
    transition: opacity 160ms ease;
  }

  .nc-brain-composer.locked {
    opacity: 0.78;
  }

  .nc-brain-composer.locked .nc-brain-input,
  .nc-brain-composer.locked .nc-brain-target {
    cursor: wait;
  }

  .nc-brain-target,
  .nc-brain-input {
    border: 1px solid rgba(245, 233, 220, 0.1);
    border-radius: 10px;
    background: rgba(0, 0, 0, 0.35);
    color: var(--obs-text);
    outline: none;
  }

  .nc-brain-target {
    max-width: 128px;
    padding: 8px 10px;
    font-size: 11px;
  }

  .nc-brain-input {
    min-width: 0;
    padding: 8px 12px;
    font-size: 12.5px;
  }

  .nc-brain-input:focus,
  .nc-brain-target:focus {
    border-color: rgba(200, 248, 26, 0.35);
    box-shadow: 0 0 0 3px rgba(200, 248, 26, 0.08);
  }

  .nc-brain-send {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    min-width: 78px;
    padding-inline: 14px;
    border-color: rgba(200, 248, 26, 0.32);
    background: rgba(200, 248, 26, 0.12);
    color: var(--obs-acid);
  }

  .nc-brain-send.is-busy {
    cursor: wait;
  }

  .nc-brain-send-spin {
    width: 11px;
    height: 11px;
    border: 1.5px solid rgba(200, 248, 26, 0.25);
    border-top-color: var(--obs-acid);
    border-radius: 50%;
    animation: nc-brain-spin 0.7s linear infinite;
  }

  .nc-brain-resize {
    position: absolute;
    right: 4px;
    bottom: 4px;
    width: 14px;
    height: 14px;
    cursor: nwse-resize;
    border-radius: 2px;
    opacity: 0.55;
    background:
      linear-gradient(135deg, transparent 42%, rgba(245, 233, 220, 0.45) 43% 48%, transparent 49%),
      linear-gradient(135deg, transparent 62%, rgba(245, 233, 220, 0.45) 63% 68%, transparent 69%);
  }

  .nc-brain-pill {
    position: fixed;
    left: 50%;
    bottom: 18px;
    z-index: 45;
    display: inline-flex;
    align-items: center;
    gap: 9px;
    max-width: min(520px, calc(100vw - 28px));
    transform: translateX(-50%);
    border: 1px solid rgba(245, 233, 220, 0.12);
    border-radius: 999px;
    padding: 8px 14px;
    background: rgba(10, 9, 18, 0.92);
    box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(16px);
    cursor: pointer;
    transition: border-color 150ms ease, transform 150ms ease;
  }

  .nc-brain-pill:hover {
    border-color: rgba(200, 248, 26, 0.28);
    transform: translateX(-50%) translateY(-1px);
  }

  .nc-brain-pill.awaiting {
    border-color: rgba(200, 248, 26, 0.34);
    box-shadow:
      0 14px 40px rgba(0, 0, 0, 0.45),
      0 0 24px -10px rgba(200, 248, 26, 0.35);
  }

  .nc-brain-dot.busy {
    background: var(--obs-acid);
    animation: nc-brain-breathe 1s ease-in-out infinite;
  }

  .nc-brain-pill-label {
    font-size: 12px;
    font-weight: 560;
    color: var(--obs-text);
  }

  .nc-brain-pill-meta {
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.06em;
    color: var(--obs-acid);
  }

  .nc-brain-pill-focus {
    overflow: hidden;
    max-width: 180px;
    text-overflow: ellipsis;
    white-space: nowrap;
    border-left: 1px solid rgba(245, 233, 220, 0.1);
    padding-left: 9px;
    font-size: 11px;
    color: var(--obs-faint);
  }

  .nc-brain-kbd {
    border: 1px solid rgba(245, 233, 220, 0.12);
    border-radius: 5px;
    padding: 1px 5px;
    font-family: var(--mono);
    font-size: 9px;
    color: var(--obs-faint);
  }

  @keyframes nc-brain-breathe {
    0%,
    100% {
      opacity: 0.55;
    }
    50% {
      opacity: 1;
    }
  }

  @keyframes nc-brain-spin {
    to {
      transform: rotate(360deg);
    }
  }

  @keyframes nc-brain-enter {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @media (max-width: 720px) {
    .nc-brain-panel {
      left: 8px !important;
      right: 8px;
      width: auto !important;
      max-width: calc(100vw - 16px);
    }

    .nc-brain-composer {
      grid-template-columns: 1fr;
    }

    .nc-brain-target {
      max-width: none;
    }

    .nc-brain-pill {
      left: 10px;
      right: 10px;
      bottom: 10px;
      transform: none;
      max-width: none;
      justify-content: center;
    }

    .nc-brain-pill:hover {
      transform: translateY(-1px);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .nc-brain-dot,
    .nc-brain-send-spin,
    .nc-brain-feed li.pending,
    .nc-brain-feed li.buffering,
    .nc-brain-panel.awaiting,
    .nc-brain-pill.awaiting,
    .nc-brain-dot.busy {
      animation: none;
    }
  }
</style>
