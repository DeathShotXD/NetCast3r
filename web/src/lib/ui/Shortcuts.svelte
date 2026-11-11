<script lang="ts">
  import { store } from '../state.svelte';
  import { focusTrap } from '../actions';
  import Icon from './Icon.svelte';

  const rows: { keys: string[]; label: string; hint: string }[] = [
    { keys: ['Ctrl', 'K'], label: 'Command palette', hint: 'jump, search, or ask Helix' },
    { keys: ['/'], label: 'Search findings', hint: 'focus the top search field' },
    { keys: ['B'], label: 'Toggle Helix', hint: 'open the hunt steward' },
    { keys: ['F'], label: 'Focus mode', hint: 'hide the sidebar for a live cast' },
    { keys: ['?'], label: 'Shortcut sheet', hint: 'this list' },
    { keys: ['Esc'], label: 'Close', hint: 'dismiss an overlay or dialog' },
    { keys: ['Ctrl', 'click'], label: 'Radial menu', hint: 'context actions on any element' }
  ];
</script>

{#if store.shortcuts}
  <div
    class="obs-modal-veil"
    role="presentation"
    onclick={() => (store.shortcuts = false)}
  >
    <div
      class="obs-modal obs-shortcuts"
      role="dialog"
      aria-modal="true"
      aria-label="keyboard shortcuts"
      tabindex="-1"
      use:focusTrap
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          store.shortcuts = false;
        }
      }}
    >
      <header class="obs-modal-head">
        <div>
          <div class="obs-eyebrow"><span class="tick"></span> Reference</div>
          <h2>Keyboard shortcuts</h2>
        </div>
        <button
          class="obs-icon-btn"
          type="button"
          aria-label="close"
          onclick={() => (store.shortcuts = false)}
        >
          <Icon name="x" size={14} />
        </button>
      </header>

      <div class="obs-modal-body">
        <ul class="obs-shortcuts-list">
          {#each rows as row (row.label)}
            <li class="obs-shortcuts-row">
              <span class="obs-shortcuts-keys">
                {#each row.keys as key (key)}
                  <span class="obs-kbd">{key}</span>
                {/each}
              </span>
              <span class="obs-shortcuts-label">{row.label}</span>
              <span class="obs-shortcuts-hint">{row.hint}</span>
            </li>
          {/each}
        </ul>
      </div>

      <footer class="obs-modal-foot">
        <span class="obs-modal-note">
          Shortcuts are ignored while you are typing in a field.
        </span>
      </footer>
    </div>
  </div>
{/if}
