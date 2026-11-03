<script lang="ts">
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { spotlight } from '../actions';
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';

  const mesh = [
    {
      id: 'osint',
      title: 'OSINT map',
      detail: 'Certs, DNS, subdomains, Wayback, live hosts via web2root + cast.'
    },
    {
      id: 'scout',
      title: 'Scout mesh',
      detail: 'Fingerprint stacks, crawl routes, inventory APIs and JS surfaces.'
    },
    {
      id: 'auth',
      title: 'Auth agents',
      detail: 'Temp-mail signup, session capture, authenticated probing.'
    },
    {
      id: 'exegete',
      title: 'JS / source reverse',
      detail: 'Bundle and artifact reverse for secrets, endpoints, hidden params.'
    },
    {
      id: 'attack',
      title: 'Attack + validate',
      detail: 'Falsify leads; independent validators refuse reachability-as-vuln.'
    },
    {
      id: 'pivot',
      title: 'Escalate + pivot',
      detail: 'Chain supported impact; lateral only inside the mission scope.'
    }
  ];

  let target = $state('');
  let busy = $state(false);
  let error = $state('');
  let phase = $state('');

  const trimmed = $derived(target.trim());
  const ready = $derived(trimmed.length > 2 && !busy);

  async function engage() {
    if (!ready) return;
    busy = true;
    error = '';
    phase = 'seeding mission + engaging brain…';
    try {
      const result = await api.campaignStart(trimmed);
      const mission = result.mission;
      store.toast('ok', `hunt engaged on ${trimmed}`);
      store.brainDock = true;
      phase = 'bootstrapping OSINT cast + swarm + hunt…';
      try {
        await store.refreshTotals();
      } catch {
        /* non-fatal */
      }
      // Prefer live spectate when a cast already exists; else mission board.
      const runs = store.runs.filter((run) => run.status === 'running' || run.status === 'queued');
      if (runs[0]) {
        store.watch(runs[0].id);
      } else {
        store.go('missions');
        // Soft poll: cast may appear a moment after bootstrap thread starts.
        window.setTimeout(() => {
          void store.refreshTotals().then(() => {
            const live =
              store.runs.find((run) => run.status === 'running' || run.status === 'queued') ??
              null;
            if (live) store.watch(live.id);
          });
        }, 1800);
      }
      if (mission?.id) {
        store.toast(
          'ok',
          `mission ${mission.id.slice(0, 12)} · brain + director autonomous — spectate or instruct`
        );
      }
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not engage the hunt';
      phase = '';
    } finally {
      busy = false;
    }
  }
</script>

<div class="obs-page">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Engage</div>
      <h1>One seed. Full hunt.</h1>
      <p class="obs-page-sub">
        Drop a domain, URL, or public endpoint. Helix maps the surface, spins the agent mesh
        (OSINT, auth via temp mail, JS reverse, validate, escalate), and will hail you mid-hunt — instruct anytime.
      </p>
    </div>
  </header>

  <div class="obs-op-grid">
    <section class="obs-card obs-engage-card" use:spotlight>
      <div class="obs-card-body">
        <form
          class="obs-engage-form"
          onsubmit={(event) => {
            event.preventDefault();
            void engage();
          }}
        >
          <div>
            <label class="obs-eyebrow" for="seed">target seed</label>
            <input
              id="seed"
              class="obs-field obs-engage-input"
              style="margin-top:8px"
              placeholder="app.example.com  ·  https://api.example.com  ·  staging.example.io"
              bind:value={target}
              autocomplete="off"
              spellcheck="false"
            />
            <p class="obs-engage-hint">
              Authorized targets only. One string is enough — no separate “mission” vs “operation”.
            </p>
          </div>

          {#if error}
            <p class="obs-alert" role="alert">{error}</p>
          {/if}
          {#if phase && busy}
            <div class="obs-engage-phase" role="status">
              <Buffering variant="block" tone="acid" label="Engaging" detail={phase} />
            </div>
          {/if}

          <div class="obs-engage-actions">
            <button
              class="obs-btn obs-btn-primary obs-engage-cta"
              class:is-busy={busy}
              type="submit"
              disabled={!ready}
              aria-busy={busy}
            >
              {#if !busy}
                <Icon name="crosshair" size={14} />
              {/if}
              {busy ? 'engaging…' : 'engage hunt'}
            </button>
            <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('home')}>
              cancel
            </button>
          </div>
        </form>
      </div>
    </section>

    <section class="obs-card obs-mesh-card">
      <div class="obs-card-head">
        <div>
          <div class="obs-card-title">What Helix starts</div>
          <div class="obs-card-sub">Parallel agent mesh — Helix hails you when it matters</div>
        </div>
      </div>
      <div class="obs-card-body">
        <ol class="obs-mesh-list" aria-label="agent mesh">
          {#each mesh as role, i (role.id)}
            <li class="obs-mesh-item" style="animation-delay:{i * 60}ms">
              <span class="obs-mesh-idx" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
              <span>
                <strong>{role.title}</strong>
                <span>{role.detail}</span>
              </span>
            </li>
          {/each}
        </ol>
        <p class="obs-mesh-foot">
          Open Helix (B) anytime — fullscreen from the panel. Successful proofs and attempts stream into Live and the conversation feed.
        </p>
      </div>
    </section>
  </div>
</div>

<style>
  .obs-engage-form {
    display: flex;
    flex-direction: column;
    gap: 18px;
  }

  .obs-engage-input {
    font-size: 15px;
    letter-spacing: 0.01em;
  }

  .obs-engage-hint {
    margin: 10px 0 0;
    font-size: 11px;
    line-height: 1.5;
    color: var(--obs-faint);
  }

  .obs-engage-phase {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--obs-acid);
  }

  .obs-engage-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }

  .obs-engage-cta {
    min-width: 148px;
  }

  .obs-mesh-list {
    display: grid;
    gap: 10px;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .obs-mesh-item {
    display: grid;
    grid-template-columns: 28px 1fr;
    gap: 10px;
    align-items: start;
    animation: fade-rise 420ms ease both;
  }

  .obs-mesh-item strong {
    display: block;
    font-size: 12px;
    color: var(--obs-text);
  }

  .obs-mesh-item span span {
    display: block;
    margin-top: 2px;
    font-size: 11px;
    line-height: 1.45;
    color: var(--obs-faint);
  }

  .obs-mesh-idx {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.08em;
    color: var(--obs-acid);
    padding-top: 2px;
  }

  .obs-mesh-foot {
    margin: 16px 0 0;
    padding-top: 14px;
    border-top: 1px solid var(--obs-line);
    font-size: 11px;
    line-height: 1.55;
    color: var(--obs-faint);
  }

  @keyframes fade-rise {
    from {
      opacity: 0;
      transform: translateY(6px);
    }
    to {
      opacity: 1;
      transform: none;
    }
  }
</style>
