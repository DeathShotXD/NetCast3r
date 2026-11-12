<script lang="ts">
  // Helix - floating, draggable, resizable hunt steward. Layout persists.
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import type { BrainLiveEntry, BrainLoopStatus, BrainSession, BrainTurn } from '../types';
  import Buffering from '../ui/Buffering.svelte';
  import Confirm from '../ui/Confirm.svelte';
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
  let sessions = $state<BrainSession[]>([]);
  let sessionId = $state('');
  let session = $state<BrainSession | null>(null);
  let sessionMenu = $state(false);
  let renaming = $state(false);
  let renameText = $state('');
  let sessionBusy = $state('');
  let pendingDelete = $state(false);
  let menuEl = $state<HTMLDivElement | undefined>(undefined);
  let sessionBtnEl = $state<HTMLButtonElement | undefined>(undefined);
  let sessionsAt = 0;
  let timer: number | undefined;
  let loadTimer: number | undefined;
  let phaseTimer: number | undefined;
  let feedEl = $state<HTMLUListElement>();
  let inputEl = $state<HTMLTextAreaElement>();
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
  let unread = $state(0);
  let lastSeenLen = 0;
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
  const SLASH_COMMANDS = [
    { cmd: '/new', hint: 'start a fresh chat session', arg: false },
    { cmd: '/fork', hint: 'branch this chat, keeping its history', arg: false },
    { cmd: '/brain', hint: 'ask Helix only, no hunt action', arg: true },
    { cmd: '/queue', hint: 'queue a director instruction', arg: true },
    { cmd: '/stop', hint: 'stop the active cast', arg: false },
    { cmd: '/help', hint: 'list composer commands', arg: false }
  ] as const;
  let slashIndex = $state(0);
  const showSlash = $derived(input.startsWith('/') && !input.includes(' '));
  const slashMatches = $derived(
    showSlash
      ? SLASH_COMMANDS.filter((item) => item.cmd.startsWith(input.toLowerCase()))
      : []
  );

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

  function scrollFeedToBottom() {
    requestAnimationFrame(() => {
      if (feedEl) feedEl.scrollTop = feedEl.scrollHeight;
    });
  }

  function jumpToLatest() {
    stickToBottom = true;
    unread = 0;
    lastSeenLen = visible.length;
    scrollFeedToBottom();
  }

  function onFeedScroll() {
    if (!feedEl) return;
    const gap = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight;
    stickToBottom = gap < 72;
    if (stickToBottom) {
      unread = 0;
      lastSeenLen = visible.length;
    }
  }

  // Stable scroll: only follow when pinned; otherwise count unread so
  // polling / SSE updates never yank the operator away from history.
  $effect(() => {
    const len = visible.length;
    if (!open || !feedEl || !len) return;
    if (stickToBottom) {
      lastSeenLen = len;
      unread = 0;
      scrollFeedToBottom();
    } else if (len > lastSeenLen) {
      unread = len - lastSeenLen;
    }
  });

  $effect(() => {
    if (store.brainPrefill) {
      const draft = store.brainPrefill;
      store.brainPrefill = '';
      input = draft;
      store.brainDock = true;
      stickToBottom = true;
      queueMicrotask(() => inputEl?.focus());
    }
  });

  $effect(() => {
    if (!sessionMenu) return;
    const closeMenu = (event: PointerEvent) => {
      const node = event.target as Node | null;
      if (node && (menuEl?.contains(node) || sessionBtnEl?.contains(node))) return;
      sessionMenu = false;
    };
    document.addEventListener('pointerdown', closeMenu, true);
    return () => document.removeEventListener('pointerdown', closeMenu, true);
  });

  $effect(() => {
    if (open) {
      armPoll(8000);
      queueMicrotask(() => inputEl?.focus());
    } else {
      armPoll(20000);
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

  async function ensureSession(missionId: string) {
    if (sessionId) return;
    try {
      const page = await api.brainSessions(missionId);
      sessions = page.items || [];
      sessionsAt = Date.now();
      let chosen = sessions[0];
      if (!chosen) {
        chosen = await api.brainSessionCreate({
          mission_id: missionId,
          title: 'New chat',
          agent: 'helix',
          permission: 'full'
        });
        sessions = [chosen, ...sessions];
      }
      sessionId = chosen.id;
      session = chosen;
    } catch {
      /* an older server has no session store; the journal still works */
    }
  }

  async function newChat() {
    try {
      const missionId = (loop?.mission_id || '').trim();
      const created = await api.brainSessionCreate({
        mission_id: missionId,
        title: 'New chat',
        agent: 'helix',
        permission: 'full'
      });
      sessions = [created, ...sessions.filter((item) => item.id !== created.id)];
      sessionsAt = Date.now();
      sessionId = created.id;
      session = created;
      feed = [];
      await load();
      queueMicrotask(() => inputEl?.focus());
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'could not start a new chat');
    }
  }

  async function switchSession() {
    session = sessions.find((item) => item.id === sessionId) ?? null;
    renaming = false;
    sessionMenu = false;
    await load();
  }

  /** Branch the current chat, keeping its history, so the operator can try a
   *  different direction without disturbing the original thread. */
  async function forkChat() {
    if (!sessionId) {
      store.toast('warn', 'start a chat first');
      return;
    }
    if (sessionBusy) return;
    sessionBusy = 'fork';
    try {
      const forked = await api.brainSessionFork(sessionId, '');
      sessions = [forked, ...sessions.filter((item) => item.id !== forked.id)];
      sessionsAt = Date.now();
      sessionId = forked.id;
      session = forked;
      await load();
      store.toast('ok', 'branched into a new chat');
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'could not branch the chat');
    } finally {
      sessionBusy = '';
    }
  }

  /** Coalesce SSE bursts into one refresh; eight events in a second used to
   *  mean eight brain reads. */
  function scheduleLoad() {
    if (loadTimer) window.clearTimeout(loadTimer);
    loadTimer = window.setTimeout(() => void load(), 900);
  }

  function startRename() {
    if (!session) return;
    renaming = true;
    renameText = session.title || 'New chat';
    sessionMenu = false;
  }

  async function saveRename() {
    if (!session || sessionBusy) return;
    const title = renameText.trim();
    if (!title) return;
    sessionBusy = 'rename';
    try {
      const updated = await api.brainSessionPatch(session.id, { title });
      sessions = sessions.map((item) => (item.id === updated.id ? updated : item));
      session = updated;
      renaming = false;
      store.toast('ok', 'chat renamed');
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'could not rename the chat');
    } finally {
      sessionBusy = '';
    }
  }

  async function forkSession() {
    if (!session || sessionBusy) return;
    sessionBusy = 'fork';
    try {
      const created = await api.brainSessionFork(session.id, `${session.title || 'Chat'} (fork)`);
      sessions = [created, ...sessions.filter((item) => item.id !== created.id)];
      sessionId = created.id;
      session = created;
      sessionMenu = false;
      await load();
      store.toast('ok', 'chat forked');
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'could not fork the chat');
    } finally {
      sessionBusy = '';
    }
  }

  async function deleteSession() {
    if (!session || sessionBusy) return;
    sessionBusy = 'delete';
    try {
      await api.brainSessionDelete(session.id);
      sessions = sessions.filter((item) => item.id !== session?.id);
      sessionId = sessions[0]?.id ?? '';
      session = sessions[0] ?? null;
      pendingDelete = false;
      await load();
      store.toast('ok', 'chat deleted');
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'could not delete the chat');
    } finally {
      sessionBusy = '';
    }
  }

  function pickSlash(item: (typeof SLASH_COMMANDS)[number]) {
    slashIndex = 0;
    input = item.arg ? `${item.cmd} ` : item.cmd;
    queueMicrotask(() => inputEl?.focus());
    if (!item.arg) void send();
  }

  async function load() {
    try {
      const missionId = (loop?.mission_id || '').trim();
      if (session && missionId && session.mission_id && session.mission_id !== missionId) {
        sessionId = '';
        session = null;
      }
      await ensureSession(missionId);
      const result = await api.brainLive(100, missionId, sessionId);
      feed = [...(result.items || [])].reverse();
      timeline = result.timeline || [];
      if (result.loop && Object.keys(result.loop).length) {
        loop = result.loop;
      }
      if (sessionId && Date.now() - sessionsAt > 15000) {
        const page = await api.brainSessions(missionId);
        sessions = page.items || sessions;
        sessionsAt = Date.now();
        session = sessions.find((item) => item.id === sessionId) ?? session;
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
        const missionId = (loop?.mission_id || '').trim();
        const result = await api.brainJournal(60, missionId, sessionId);
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
          chat_provider: turn.chat_provider,
          chat_model: turn.chat_model,
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
    let message = input.trim();
    if (!message || busy) return;
    const missionId = (loop?.mission_id || '').trim();
    // One chat surface. The old target dropdown is gone; explicit slash
    // commands replace it, and the default is the useful one: Helix plus the
    // hunt when a mission is active, Helix alone otherwise.
    let target: 'brain' | 'both' | 'director' = missionId ? 'both' : 'brain';
    if (message.startsWith('/')) {
      const [command, ...rest] = message.split(/\s+/);
      const argument = rest.join(' ').trim();
      const name = command.toLowerCase();
      if (name === '/help') {
        store.toast('ok', 'commands: /new  /fork  /brain <text>  /queue <text>  /stop  /help');
        return;
      }
      if (name === '/new') {
        await newChat();
        return;
      }
      if (name === '/fork') {
        await forkChat();
        return;
      }
      if (name === '/stop') {
        const runId = (store.activeRunId || store.liveRunId || '').trim();
        if (!runId) {
          store.toast('warn', 'no active run to stop');
          return;
        }
        try {
          await api.stopRun(runId);
          store.toast('ok', `stop requested for ${runId}`);
        } catch (exc) {
          store.toast('error', exc instanceof Error ? exc.message : 'stop failed');
        }
        return;
      }
      if (name === '/brain' || name === '/queue') {
        target = name === '/brain' ? 'brain' : 'director';
        message = argument;
        if (!message) {
          store.toast('warn', `${command} needs a message`);
          return;
        }
      } else {
        store.toast('warn', `unknown command ${command}; try /help`);
        return;
      }
    }
    if (target !== 'brain' && !missionId) {
      store.toast('error', 'pick an active mission before directing the hunt');
      return;
    }
    busy = true;
    pendingText = message;
    input = '';
    stickToBottom = true;
    armBufferPhases();
    try {
      const body: Record<string, unknown> = { target, act: true };
      if (missionId) body.mission_id = missionId;
      if (sessionId) body.session_id = sessionId;
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

  function onComposerKey(event: KeyboardEvent) {
    if (slashMatches.length) {
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        slashIndex = (slashIndex + 1) % slashMatches.length;
        return;
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault();
        slashIndex = (slashIndex - 1 + slashMatches.length) % slashMatches.length;
        return;
      }
      if (event.key === 'Enter') {
        event.preventDefault();
        pickSlash(slashMatches[Math.min(slashIndex, slashMatches.length - 1)]);
        return;
      }
      if (event.key === 'Escape') {
        event.preventDefault();
        input = '';
        return;
      }
    }
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      void send();
    }
  }

  function growComposer() {
    if (!inputEl) return;
    inputEl.style.height = 'auto';
    inputEl.style.height = `${Math.min(inputEl.scrollHeight, 132)}px`;
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
            scheduleLoad();
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
    if (event.key !== 'Escape') return;
    if (sessionMenu || renaming) {
      sessionMenu = false;
      renaming = false;
      return;
    }
    if (layout.fullscreen) {
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
    if (loadTimer) window.clearTimeout(loadTimer);
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
    aria-label="{COMPANION} operator harness"
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
      role="toolbar"
      tabindex="-1"
      aria-label="Brain dock controls and drag handle"
      onpointerdown={onDragStart}
      onpointermove={onDragMove}
      onpointerup={onDragEnd}
      onpointercancel={onDragEnd}
    >
      <div class="nc-brain-titleblock">
        <span class="nc-brain-grip" aria-hidden="true"></span>
        <div class="nc-brain-identity">
          <span class="nc-brain-wordmark">{COMPANION}</span>
          <span class="nc-brain-role-tag">Operator harness</span>
          <span class="nc-brain-badge" data-tone={stateTone}>
            <span class="nc-brain-dot" class:paused={loop?.paused} class:off={!loop?.running}></span>
            {stateLabel}
          </span>
        </div>
        <div class="nc-brain-meta">
          {#if session}
            <span class="nc-brain-session-title" title={session.title}>{session.title}</span>
            <span class="nc-brain-sep" aria-hidden="true">-</span>
            <span class="nc-brain-session-mode" title="agent and permission mode">{session.agent} / {session.permission}</span>
            <span class="nc-brain-sep" aria-hidden="true">-</span>
          {/if}
          {#if loop}
            <span>{loop.turns} turns</span>
            <span class="nc-brain-sep" aria-hidden="true">-</span>
          {/if}
          <span title={loop?.last_model || ''}>{loop?.last_model || 'prime route'}</span>
        </div>
      </div>
      <div class="nc-brain-controls">
        {#if sessions.length}
          <select
            class="nc-brain-session-pick"
            bind:value={sessionId}
            onchange={() => void switchSession()}
            aria-label="chat session"
            disabled={busy || sessionBusy !== ''}
          >
            {#each sessions as item (item.id)}
              <option value={item.id}>{item.title || 'New chat'}</option>
            {/each}
          </select>
          <div class="nc-brain-session-wrap">
            <button
              class="nc-brain-icon"
              type="button"
              title="Chat actions"
              aria-label="chat actions"
              aria-expanded={sessionMenu}
              aria-haspopup="menu"
              bind:this={sessionBtnEl}
              disabled={!session || busy}
              onclick={() => (sessionMenu = !sessionMenu)}
            >
              <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
                <circle cx="3" cy="8" r="1.1" fill="currentColor"/>
                <circle cx="8" cy="8" r="1.1" fill="currentColor"/>
                <circle cx="13" cy="8" r="1.1" fill="currentColor"/>
              </svg>
            </button>
            {#if sessionMenu}
              <div class="nc-brain-menu" role="menu" aria-label="chat actions" bind:this={menuEl}>
                <button type="button" role="menuitem" onclick={startRename} disabled={!session}>rename</button>
                <button
                  type="button"
                  role="menuitem"
                  onclick={() => void forkSession()}
                  disabled={!session || sessionBusy !== ''}
                >fork</button>
                <button
                  class="danger"
                  type="button"
                  role="menuitem"
                  onclick={() => {
                    sessionMenu = false;
                    pendingDelete = true;
                  }}
                  disabled={!session || sessionBusy !== ''}
                >delete</button>
              </div>
            {/if}
          </div>
        {/if}
        <button
          class="nc-brain-action"
          type="button"
          title="Start a new chat"
          disabled={busy}
          onclick={() => void newChat()}
        >
          New
        </button>
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

    {#if renaming && session}
      <form
        class="nc-brain-rename"
        onsubmit={(event) => {
          event.preventDefault();
          void saveRename();
        }}
      >
        <input
          bind:value={renameText}
          maxlength="80"
          placeholder="chat title"
          aria-label="chat title"
          onkeydown={(event) => {
            if (event.key === 'Escape') {
              event.preventDefault();
              renaming = false;
            }
          }}
        />
        <button type="submit" disabled={sessionBusy === 'rename' || !renameText.trim()}>
          {sessionBusy === 'rename' ? 'saving' : 'save'}
        </button>
        <button type="button" onclick={() => (renaming = false)}>cancel</button>
      </form>
    {/if}

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
            ['all', 'All', 'Every channel'],
            ['journal', 'Helix', 'Helix journal turns'],
            ['mesh', 'Mesh', 'Agent mesh chats'],
            ['run', 'Models', 'Model run thoughts'],
            ['log', 'Logs', 'Control-plane logs']
          ] as [id, label, hint] (id)}
            <button
              class="nc-brain-channel"
              class:active={channel === id}
              data-channel={id}
              type="button"
              role="tab"
              title={hint}
              aria-selected={channel === id}
              onclick={() => {
                channel = id as FeedChannel;
                stickToBottom = true;
                unread = 0;
                lastSeenLen = 0;
              }}
            >
              <i aria-hidden="true"></i>{label}
              <b>{channelCounts[id as FeedChannel] ?? 0}</b>
            </button>
          {/each}
        </div>
      </div>
      {#if !stickToBottom && visible.length > 0}
        <button
          class="nc-brain-jump"
          type="button"
          onclick={() => {
            stickToBottom = true;
            if (feedEl) feedEl.scrollTop = feedEl.scrollHeight;
          }}
        >
          Jump to latest
        </button>
      {/if}
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
              <span class="nc-brain-chan-tag">{entry.channel}</span>
              {#if entry.focus}
                <span class="nc-brain-focus">{entry.focus}</span>
              {/if}
              {#if entry.provider || entry.chat_model}
                <span class="nc-brain-focus nc-brain-models" title="planner / chat lane">
                  {[entry.provider, entry.model].filter(Boolean).join(' / ')}{#if entry.chat_model} + {entry.chat_model}{/if}
                </span>
              {/if}
            </header>
            <p class="nc-brain-text">{entry.text}</p>
            {#if entry.actions && entry.actions.length}
              <div class="nc-brain-actions">
                {#each entry.actions as action}
                  {#if action.result}
                    <details class="nc-brain-action-card">
                      <summary class:refused={!action.applied}>
                        {action.kind}{#if action.detail} - {String(action.detail).slice(0, 90)}{/if}
                      </summary>
                      <pre>{JSON.stringify(action.result, null, 2).slice(0, 1800)}</pre>
                    </details>
                  {:else}
                    <span class:refused={!action.applied}>
                      {action.kind}{#if action.detail} - {String(action.detail).slice(0, 90)}{/if}
                    </span>
                  {/if}
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
            {#if channel === 'all'}
              No feed yet. Helix journal turns, mesh chats, model thoughts, and plane logs stream here continuously.
            {:else if channel === 'journal'}
              No Helix turns yet. Send an instruction below or press Think.
            {:else if channel === 'mesh'}
              No mesh chats yet. Specialist agents speak here once a hunt is running.
            {:else if channel === 'run'}
              No model thoughts yet. Run reasoning appears here during a cast.
            {:else}
              No plane logs yet. Control-plane events appear here.
            {/if}
          </li>
        {/if}
      </ul>
      {#if !stickToBottom && visible.length}
        <button class="nc-brain-jump" type="button" onclick={jumpToLatest} aria-live="polite">
          Jump to latest{#if unread} - {unread} new{/if}
        </button>
      {/if}
    </section>

    <footer class="nc-brain-composer" class:locked={busy}>
      {#if slashMatches.length}
        <div class="nc-brain-slash" role="listbox" aria-label="composer commands">
          {#each slashMatches as item, i (item.cmd)}
            <button
              class="nc-brain-slash-item"
              class:active={i === slashIndex}
              type="button"
              role="option"
              aria-selected={i === slashIndex}
              onmousedown={(event) => {
                event.preventDefault();
                pickSlash(item);
              }}
            >
              <b>{item.cmd}</b>
              <span>{item.hint}</span>
            </button>
          {/each}
        </div>
      {/if}
      <textarea
        class="nc-brain-input"
        bind:this={inputEl}
        bind:value={input}
        rows="1"
        placeholder={busy ? `${COMPANION} is responding...` : `Tell ${COMPANION} anything - /help for commands`}
        aria-label="message {COMPANION}"
        disabled={busy}
        onkeydown={onComposerKey}
        oninput={growComposer}
      ></textarea>
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
          Send
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

  {#if pendingDelete && session}
    <Confirm
      title="Delete this chat?"
      body={`"${session.title || 'New chat'}" and its turns will be removed. This cannot be undone.`}
      confirmLabel="delete chat"
      danger
      onConfirm={() => void deleteSession()}
      onCancel={() => (pendingDelete = false)}
    />
  {/if}
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
    <span
      class="nc-brain-pill-focus"
      title={latest.role === 'helix' ? latest.focus || 'hail' : latest.focus || 'reasoning'}
    >
      {latest.role === 'helix' ? latest.focus || 'hail' : latest.focus || 'reasoning'}
    </span>
  {/if}
  <kbd class="nc-brain-kbd">B</kbd>
</button>

<style>
  .nc-brain-panel {
    position: fixed;
    /* Above .nc-canvas (1000) so Helix chat stays readable under the net. */
    z-index: 1050;
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
    z-index: 1140;
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

  .nc-brain-session-pick {
    max-width: 150px;
    padding: 4px 6px;
    border: 1px solid rgba(245, 233, 220, 0.12);
    border-radius: 7px;
    background: rgba(0, 0, 0, 0.35);
    color: var(--obs-text-2);
    font: inherit;
    font-size: 10px;
    outline: none;
  }

  .nc-brain-session-pick:focus-visible {
    border-color: rgba(200, 248, 26, 0.35);
    box-shadow: var(--obs-focus);
  }

  .nc-brain-session-wrap {
    position: relative;
    display: inline-flex;
  }

  .nc-brain-menu {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    z-index: 6;
    display: flex;
    flex-direction: column;
    min-width: 156px;
    padding: 4px;
    border: 1px solid rgba(245, 233, 220, 0.12);
    border-radius: 10px;
    background: rgba(11, 9, 18, 0.98);
    box-shadow: 0 18px 44px rgba(0, 0, 0, 0.55);
  }

  .nc-brain-menu button {
    padding: 7px 10px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: var(--obs-text-2);
    font: inherit;
    font-size: 11px;
    text-align: left;
    cursor: pointer;
  }

  .nc-brain-menu button:hover {
    background: rgba(245, 233, 220, 0.06);
    color: var(--obs-text);
  }

  .nc-brain-menu button:focus-visible,
  .nc-brain-rename button:focus-visible,
  .nc-brain-action:focus-visible,
  .nc-brain-send:focus-visible,
  .nc-brain-icon:focus-visible,
  .nc-brain-slash-item:focus-visible {
    outline: none;
    box-shadow: var(--obs-focus);
  }

  .nc-brain-menu button:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .nc-brain-menu button.danger {
    color: var(--obs-red);
  }

  .nc-brain-rename {
    position: relative;
    z-index: 2;
    display: flex;
    gap: 6px;
    padding: 9px 14px;
    border-bottom: 1px solid rgba(245, 233, 220, 0.06);
    background: rgba(0, 0, 0, 0.22);
  }

  .nc-brain-rename input {
    flex: 1;
    min-width: 0;
    padding: 6px 9px;
    border: 1px solid rgba(245, 233, 220, 0.12);
    border-radius: 8px;
    background: rgba(0, 0, 0, 0.4);
    color: var(--obs-text);
    font: inherit;
    font-size: 12px;
    outline: none;
  }

  .nc-brain-rename input:focus-visible {
    border-color: rgba(200, 248, 26, 0.35);
    box-shadow: var(--obs-focus);
  }

  .nc-brain-rename button {
    padding: 6px 10px;
    border: 1px solid rgba(245, 233, 220, 0.1);
    border-radius: 8px;
    background: rgba(245, 233, 220, 0.03);
    color: var(--obs-text-2);
    font: inherit;
    font-size: 11px;
    cursor: pointer;
  }

  .nc-brain-rename button[type='submit'] {
    border-color: rgba(200, 248, 26, 0.3);
    color: var(--obs-acid);
  }

  .nc-brain-rename button:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .nc-brain-session-title {
    overflow: hidden;
    max-width: 190px;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--obs-text-2);
  }

  .nc-brain-session-mode {
    flex: 0 0 auto;
    color: var(--obs-faint);
    font-size: 9px;
    letter-spacing: 0.04em;
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
    position: relative;
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

  .nc-brain-jump {
    position: absolute;
    right: 16px;
    bottom: 72px;
    z-index: 3;
    border: 1px solid rgba(200, 248, 26, 0.35);
    border-radius: 999px;
    padding: 6px 12px;
    background: rgba(12, 14, 12, 0.92);
    color: var(--obs-acid);
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    backdrop-filter: blur(8px);
  }

  .nc-brain-jump:hover {
    border-color: rgba(200, 248, 26, 0.6);
    background: rgba(200, 248, 26, 0.08);
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

  .nc-brain-models {
    flex: 0 0 auto;
    margin-left: auto;
    max-width: 46%;
    color: var(--obs-faint);
    font-size: 9px;
    letter-spacing: 0.04em;
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

  .nc-brain-action-card {
    max-width: 100%;
    border: 1px solid rgba(245, 233, 220, 0.09);
    border-radius: 8px;
    padding: 4px 8px;
    background: rgba(0, 0, 0, 0.24);
  }

  .nc-brain-action-card summary {
    cursor: pointer;
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.04em;
    color: var(--obs-acid);
  }

  .nc-brain-action-card summary.refused {
    color: var(--obs-red);
  }

  .nc-brain-action-card pre {
    margin: 6px 0 0;
    max-height: 220px;
    overflow: auto;
    white-space: pre-wrap;
    font-size: 10px;
    line-height: 1.45;
    color: var(--obs-text-2);
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
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 8px;
    flex: none;
    border-top: 1px solid rgba(245, 233, 220, 0.07);
    padding: 12px 14px 16px;
    background: linear-gradient(180deg, transparent, rgba(0, 0, 0, 0.28));
    transition: opacity 160ms ease;
  }

  .nc-brain-slash {
    position: absolute;
    left: 14px;
    right: 14px;
    bottom: calc(100% + 6px);
    z-index: 5;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 5px;
    border: 1px solid rgba(245, 233, 220, 0.12);
    border-radius: 11px;
    background: rgba(11, 9, 18, 0.98);
    box-shadow: 0 18px 44px rgba(0, 0, 0, 0.55);
  }

  .nc-brain-slash-item {
    display: flex;
    align-items: baseline;
    gap: 9px;
    padding: 7px 9px;
    border: 0;
    border-radius: 7px;
    background: transparent;
    color: var(--obs-text-2);
    font: inherit;
    font-size: 11px;
    text-align: left;
    cursor: pointer;
  }

  .nc-brain-slash-item b {
    flex: 0 0 auto;
    font-family: var(--mono);
    font-size: 10.5px;
    font-weight: 560;
    color: var(--obs-acid);
  }

  .nc-brain-slash-item span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--obs-faint);
    font-size: 10.5px;
  }

  .nc-brain-slash-item:hover,
  .nc-brain-slash-item.active {
    background: rgba(200, 248, 26, 0.07);
  }

  .nc-brain-composer.locked {
    opacity: 0.78;
  }

  .nc-brain-composer.locked .nc-brain-input {
    cursor: wait;
  }

  .nc-brain-input {
    min-width: 0;
    max-height: 132px;
    padding: 9px 12px;
    border: 1px solid rgba(245, 233, 220, 0.1);
    border-radius: 10px;
    background: rgba(0, 0, 0, 0.35);
    color: var(--obs-text);
    outline: none;
    resize: none;
    overflow-y: auto;
    font: inherit;
    font-size: 12.5px;
    line-height: 1.45;
  }

  .nc-brain-input:focus-visible {
    outline: none;
    border-color: rgba(200, 248, 26, 0.35);
    box-shadow: var(--obs-focus);
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
    z-index: 1050;
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
      grid-template-columns: minmax(0, 1fr) auto;
    }

    .nc-brain-pill {
      left: 10px;
      right: 10px;
      bottom: 10px;
      transform: none;
      max-width: none;
      justify-content: center;
      gap: 7px;
      padding: 7px 12px;
    }

    .nc-brain-pill:hover {
      transform: translateY(-1px);
    }
  }

  @media (max-width: 560px) {
    .nc-brain-pill-focus {
      display: none;
    }

    .nc-brain-pill-meta {
      font-size: 8.5px;
    }

    .nc-brain-session-pick {
      max-width: 104px;
    }

    .nc-brain-session-title {
      max-width: 120px;
    }

    /* On a phone the plane ticker eats the feed; the same lines remain in
       the Logs channel. Keep the conversation readable instead. */
    .nc-brain-ops {
      display: none;
    }

    .nc-brain-mesh {
      gap: 5px;
      padding: 8px 12px 10px;
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
