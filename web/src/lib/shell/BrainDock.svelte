<script lang="ts">
  // A persistent operator console for the main brain. The brain thinks on its
  // own loop; this dock keeps that loop visible from any screen and lets the
  // operator talk to it without leaving the hunt.
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import type { BrainLoopStatus, BrainTurn } from '../types';

  let open = $state(false);
  let feed = $state<BrainTurn[]>([]);
  let loop = $state<BrainLoopStatus | null>(null);
  let input = $state('');
  let busy = $state(false);
  let acting = $state('');
  let timer: number | undefined;
  let feedEl = $state<HTMLUListElement>();

  const latest = $derived(feed.length ? feed[feed.length - 1] : null);

  $effect(() => {
    if (open && feedEl && feed.length) {
      feedEl.scrollTop = feedEl.scrollHeight;
    }
  });

  async function load() {
    try {
      const result = await api.brainJournal(24);
      feed = [...result.items].reverse();
      loop = result.loop;
    } catch {
      /* the dock is optional; the rest of the app keeps working */
    }
  }

  async function send() {
    const message = input.trim();
    if (!message || busy) return;
    busy = true;
    input = '';
    try {
      await api.brainChat(message, { history: [] });
      await load();
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : 'the brain did not answer');
    } finally {
      busy = false;
    }
  }

  async function control(action: string) {
    acting = action;
    try {
      loop = await api.brainLoop(action);
      if (action === 'tick') await load();
    } catch (exc) {
      store.toast('error', exc instanceof Error ? exc.message : `brain ${action} failed`);
    } finally {
      acting = '';
    }
  }

  onMount(() => {
    void load();
    timer = window.setInterval(() => void load(), 8000);
  });

  onDestroy(() => {
    if (timer) window.clearInterval(timer);
  });
</script>

<div class="nc-brain-dock">
  {#if open}
    <section class="nc-brain-panel" aria-label="main brain console">
      <header class="nc-brain-head">
        <span class="nc-brain-dot" class:paused={loop?.paused} class:off={!loop?.running}></span>
        <span class="nc-brain-state">
          {loop ? (loop.paused ? 'paused' : loop.running ? 'autonomous' : 'idle') : 'standby'}
        </span>
        <span class="nc-brain-count">{loop ? `${loop.turns} turns` : ''}</span>
        <span class="nc-brain-model">{loop?.last_model || 'prime route'}</span>
        <button
          class="nc-brain-mini"
          type="button"
          disabled={acting !== ''}
          onclick={() => void control(loop?.paused ? 'engage' : 'pause')}
        >
          {loop?.paused ? 'resume' : 'pause'}
        </button>
        <button
          class="nc-brain-mini"
          type="button"
          disabled={acting !== ''}
          onclick={() => void control('tick')}
        >
          {acting === 'tick' ? 'thinking' : 'think now'}
        </button>
        <button class="nc-brain-close" type="button" aria-label="close brain console" onclick={() => (open = false)}>
          x
        </button>
      </header>

      <ul class="nc-brain-feed" bind:this={feedEl}>
        {#each feed.slice(-14) as turn (turn.id)}
          <li class:operator={turn.role === 'operator'} class:auto={turn.role === 'auto'}>
            <span class="nc-brain-role">
              {turn.role === 'operator'
                ? (turn.source && turn.source !== 'ui' ? `you - ${turn.source}` : 'you')
                : turn.role === 'auto' ? 'thinking' : 'brain'}
            </span>
            <span class="nc-brain-text">{turn.text}</span>
            {#if turn.focus}
              <span class="nc-brain-focus">next: {turn.focus}</span>
            {/if}
            {#if turn.actions && turn.actions.length}
              <span class="nc-brain-actions">
                {turn.actions.map((a) => `${a.kind}${a.applied ? '' : ' (refused)'}`).join(', ')}
              </span>
            {/if}
          </li>
        {/each}
        {#if feed.length === 0}
          <li class="nc-brain-empty">The brain begins reasoning as soon as a mission is active. Ask it anything or point it at a lead.</li>
        {/if}
      </ul>

      <div class="nc-brain-input-row">
        <input
          class="nc-brain-input"
          bind:value={input}
          placeholder={"steer the brain: 'focus the consent API'"}
          aria-label="message the main brain"
          onkeydown={(event) => { if (event.key === 'Enter') void send(); }}
        />
        <button class="nc-brain-send" type="button" disabled={busy || !input.trim()} onclick={() => void send()}>
          {busy ? '...' : 'send'}
        </button>
      </div>
    </section>
  {/if}

  <button class="nc-brain-pill" type="button" aria-expanded={open} onclick={() => (open = !open)}>
    <span class="nc-brain-dot" class:paused={loop?.paused} class:off={!loop?.running}></span>
    <span class="nc-brain-pill-label">main brain</span>
    <span class="nc-brain-pill-meta">
      {loop ? (loop.paused ? 'paused' : `${loop.turns} turns`) : 'standby'}
    </span>
    {#if latest && !open}
      <span class="nc-brain-pill-focus">{latest.focus || 'reasoning'}</span>
    {/if}
  </button>
</div>

<style>
  .nc-brain-dock {
    position: fixed;
    left: 50%;
    bottom: 18px;
    transform: translateX(-50%);
    z-index: 45;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    max-width: min(440px, calc(100vw - 36px));
  }

  .nc-brain-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 100%;
    border: 1px solid var(--obs-line-strong);
    border-radius: 999px;
    padding: 7px 13px;
    background: color-mix(in srgb, var(--obs-panel-2) 92%, transparent);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.42);
    backdrop-filter: blur(10px);
    cursor: pointer;
    transition: border-color 150ms ease, transform 150ms ease;
  }

  .nc-brain-pill:hover {
    border-color: var(--obs-line-acid);
    transform: translateY(-1px);
  }

  .nc-brain-pill-label {
    font-family: var(--mono);
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--obs-text);
  }

  .nc-brain-pill-meta {
    font-family: var(--mono);
    font-size: 8px;
    letter-spacing: 0.06em;
    color: var(--obs-acid);
  }

  .nc-brain-pill-focus {
    overflow: hidden;
    max-width: 190px;
    text-overflow: ellipsis;
    white-space: nowrap;
    border-left: 1px solid var(--obs-line);
    padding-left: 8px;
    font-size: 10px;
    color: var(--obs-faint);
  }

  .nc-brain-dot {
    width: 6px;
    height: 6px;
    flex: none;
    border-radius: 50%;
    background: var(--obs-acid);
    box-shadow: 0 0 8px 1px var(--obs-acid);
    animation: nc-brain-breathe 2.4s ease-in-out infinite;
  }

  .nc-brain-dot.paused,
  .nc-brain-dot.off {
    background: var(--obs-faint);
    box-shadow: none;
    animation: none;
  }

  .nc-brain-panel {
    display: flex;
    flex-direction: column;
    width: min(440px, calc(100vw - 36px));
    max-height: min(560px, calc(100vh - 120px));
    overflow: hidden;
    border: 1px solid var(--obs-line-strong);
    border-radius: 14px;
    background: color-mix(in srgb, var(--obs-panel) 96%, transparent);
    box-shadow: var(--obs-shadow);
    backdrop-filter: blur(14px);
  }

  .nc-brain-head {
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid var(--obs-line);
    padding: 9px 11px;
  }

  .nc-brain-state {
    font-family: var(--mono);
    font-size: 8px;
    font-weight: 600;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--obs-acid);
  }

  .nc-brain-count {
    font-family: var(--mono);
    font-size: 8px;
    color: var(--obs-faint);
  }

  .nc-brain-model {
    overflow: hidden;
    flex: 1;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--mono);
    font-size: 8px;
    color: var(--obs-faint);
  }

  .nc-brain-mini,
  .nc-brain-send {
    border: 1px solid var(--obs-line-strong);
    border-radius: 6px;
    padding: 4px 8px;
    background: transparent;
    font-family: var(--mono);
    font-size: 8px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--obs-muted);
    cursor: pointer;
  }

  .nc-brain-mini:hover,
  .nc-brain-send:hover {
    border-color: var(--obs-line-acid);
    color: var(--obs-acid);
  }

  .nc-brain-mini:disabled,
  .nc-brain-send:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .nc-brain-send {
    border-color: var(--obs-line-acid);
    color: var(--obs-acid);
  }

  .nc-brain-close {
    border: none;
    background: transparent;
    padding: 2px 4px;
    font-family: var(--mono);
    font-size: 10px;
    color: var(--obs-faint);
    cursor: pointer;
  }

  .nc-brain-close:hover {
    color: var(--obs-text);
  }

  .nc-brain-feed {
    display: flex;
    flex-direction: column;
    gap: 6px;
    overflow-y: auto;
    padding: 10px 11px;
  }

  .nc-brain-feed li {
    display: grid;
    gap: 3px;
    border-left: 2px solid var(--obs-line-strong);
    padding: 4px 8px;
  }

  .nc-brain-feed li.operator {
    border-left-color: var(--obs-acid);
  }

  .nc-brain-feed li.auto {
    border-left-color: var(--obs-violet);
    background: linear-gradient(90deg, var(--obs-violet-soft), transparent 62%);
  }

  .nc-brain-role {
    font-family: var(--mono);
    font-size: 8px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--obs-faint);
  }

  .nc-brain-text {
    font-size: 11.5px;
    line-height: 1.45;
    color: var(--obs-text-2);
    white-space: pre-wrap;
  }

  .nc-brain-focus {
    font-size: 10.5px;
    color: var(--obs-violet-3);
  }

  .nc-brain-actions {
    font-family: var(--mono);
    font-size: 8px;
    letter-spacing: 0.06em;
    color: var(--obs-acid);
  }

  .nc-brain-empty {
    color: var(--obs-muted);
    font-size: 11px;
    line-height: 1.5;
  }

  .nc-brain-input-row {
    display: flex;
    gap: 6px;
    border-top: 1px solid var(--obs-line);
    padding: 9px 11px;
  }

  .nc-brain-input {
    flex: 1;
    min-width: 0;
    border: 1px solid var(--obs-line);
    border-radius: 6px;
    padding: 6px 9px;
    background: var(--obs-bg-2);
    font-size: 11.5px;
    color: var(--obs-text);
    outline: none;
  }

  .nc-brain-input:focus {
    border-color: var(--obs-line-acid);
  }

  @keyframes nc-brain-breathe {
    0%,
    100% {
      opacity: 0.5;
    }
    50% {
      opacity: 1;
    }
  }

  @media (max-width: 720px) {
    .nc-brain-dock {
      left: 10px;
      right: 10px;
      bottom: 10px;
      transform: none;
      max-width: none;
    }

    .nc-brain-panel {
      width: 100%;
    }
  }
</style>
