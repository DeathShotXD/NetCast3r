<script lang="ts">
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { spotlight } from '../actions';
  import { onMount } from 'svelte';
  import Buffering from '../ui/Buffering.svelte';
  import Icon from '../ui/Icon.svelte';

  const mesh = [
    {
      id: 'osint',
      icon: 'globe',
      stage: 'recon',
      title: 'OSINT map',
      detail: 'Certs, DNS, subdomains, Wayback, live hosts via web2root + cast.'
    },
    {
      id: 'scout',
      icon: 'target',
      stage: 'scout',
      title: 'Scout mesh',
      detail: 'Fingerprint stacks, map routes, inventory APIs and JS surfaces.'
    },
    {
      id: 'auth',
      icon: 'lock',
      stage: 'auth',
      title: 'Auth agents',
      detail: 'Temp-mail signup, session capture, authenticated probing.'
    },
    {
      id: 'exegete',
      icon: 'code',
      stage: 'reverse',
      title: 'JS / source reverse',
      detail: 'Bundle and artifact reverse for secrets, endpoints, hidden params.'
    },
    {
      id: 'attack',
      icon: 'crosshair',
      stage: 'attack',
      title: 'Attack + validate',
      detail: 'Falsify leads; independent validators refuse reachability-as-vuln.'
    },
    {
      id: 'pivot',
      icon: 'flow',
      stage: 'escalate',
      title: 'Escalate + pivot',
      detail: 'Chain supported impact; lateral only inside the mission scope.'
    }
  ];

  let target = $state('');
  let busy = $state(false);
  let error = $state('');
  let phase = $state('');
  let seedEl = $state<HTMLTextAreaElement>();
  const examples = ['app.example.com', 'https://api.example.com', 'staging.example.io'];
  const MAX_SEEDS = 25;
  onMount(() => seedEl?.focus());

  /** Accept one domain or a pasted list: newlines, commas, or whitespace. */
  function parseSeeds(raw: string): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const piece of raw.split(/[\s,;]+/)) {
      const seed = piece.trim().replace(/^[-*>\d.)\s]+/, '').replace(/\/+$/, '');
      if (!seed) continue;
      const key = seed.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(seed);
      if (out.length >= MAX_SEEDS) break;
    }
    return out;
  }

  const seeds = $derived(parseSeeds(target));
  const invalid = $derived(
    seeds.filter((seed) => !/^(https?:\/\/)?[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}(:\d+)?(\/|$)/i.test(seed))
  );
  const ready = $derived(seeds.length > 0 && invalid.length === 0 && !busy);

  async function engage() {
    if (busy) return;
    const list = seeds;
    if (list.length === 0) {
      error = 'enter at least one domain or URL';
      return;
    }
    if (invalid.length) {
      error = `not a usable host: ${invalid.slice(0, 3).join(', ')}`;
      return;
    }
    busy = true;
    error = '';
    const created: string[] = [];
    const failed: string[] = [];
    phase = list.length > 1
      ? `seeding ${list.length} missions and engaging the brain...`
      : 'seeding mission + engaging brain...';
    try {
      for (let i = 0; i < list.length; i += 1) {
        if (list.length > 1) phase = `engaging ${i + 1}/${list.length}: ${list[i]}`;
        try {
          await api.campaignStart(list[i]);
          created.push(list[i]);
        } catch (exc) {
          failed.push(`${list[i]}: ${exc instanceof Error ? exc.message : 'failed'}`);
        }
      }
      if (created.length === 0) {
        error = failed[0] || 'could not engage the hunt';
        phase = '';
        return;
      }
      store.brainDock = true;
      phase = 'bootstrapping OSINT cast + swarm + hunt...';
      store.toast(
        'ok',
        created.length === 1
          ? `hunt engaged on ${created[0]}`
          : `engaged ${created.length} targets`
      );
      if (failed.length) {
        store.toast('warn', `${failed.length} seed(s) refused: ${failed[0].slice(0, 90)}`);
      }
      await store.refreshRuns();
      void store.refreshTotals();
      // Prefer live spectate when a cast already exists; else the mission board.
      const live =
        store.runs.find((run) => run.status === 'running' || run.status === 'queued') ?? null;
      if (live) {
        store.watch(live.id);
      } else {
        store.go('missions');
        // Casts appear a moment after the bootstrap thread starts. Poll a few
        // times with a widening backoff instead of a single fixed hop.
        const delays = [1200, 2500, 4000, 6000];
        const chase = (index: number) => {
          if (index >= delays.length) return;
          window.setTimeout(() => {
            void store.refreshRuns().then(() => {
              const now =
                store.runs.find((run) => run.status === 'running' || run.status === 'queued') ?? null;
              if (now) store.watch(now.id);
              else chase(index + 1);
            });
          }, delays[index]);
        };
        chase(0);
      }
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
        (OSINT, auth via temp mail, JS reverse, validate, escalate), and will hail you mid-hunt - instruct anytime.
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
            <textarea
              id="seed"
              class="obs-field obs-engage-input"
              style="margin-top:8px"
              rows="2"
              placeholder="app.example.com - or paste a list, one per line"
              bind:this={seedEl}
              bind:value={target}
              autocomplete="off"
              spellcheck="false"
              aria-describedby="seed-hint seed-ready"
              onkeydown={(e) => {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                  e.preventDefault();
                  void engage();
                }
              }}
            ></textarea>
            <div class="obs-seed-examples" aria-label="example seeds">
              {#each examples as ex (ex)}<button type="button" onclick={() => { target = ex; seedEl?.focus(); }}>{ex}</button>{/each}
            </div>
            <p class="obs-engage-hint" id="seed-hint">
              Authorized targets only. One seed starts the full autonomous hunt - no separate mission
              setup. Paste several (one per line, or comma/space separated) to engage a portfolio at
              once, up to {MAX_SEEDS}.
            </p>
            <p class="obs-seed-ready" class:ready={ready} id="seed-ready" role="status">
              <i aria-hidden="true"></i>{busy
                ? phase || 'Engaging...'
                : invalid.length
                  ? `Not a usable host: ${invalid.slice(0, 3).join(', ')}`
                  : seeds.length > 1
                    ? `${seeds.length} targets armed - Engage hunt seeds them all`
                    : seeds.length === 1
                      ? 'Ready - click Engage hunt to start Helix, mesh and director'
                      : 'Paste a domain or URL to arm the hunt'}
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
              {busy ? 'engaging...' : 'engage hunt'}
            </button>
            <button class="obs-btn obs-btn-ghost" type="button" onclick={() => store.go('home')}>Back</button>
            <span style="font-family:var(--mono);font-size:10px;color:var(--obs-faint)">Helix opens on engage - press B anytime to steer</span>
          </div>
        </form>
      </div>
    </section>

    <section class="obs-card obs-mesh-card">
      <div class="obs-card-head">
        <div>
          <div class="obs-card-title">What Helix starts</div>
          <div class="obs-card-sub">Parallel agent mesh - Helix hails you when it matters</div>
        </div>
      </div>
      <div class="obs-card-body">
        <ol class="obs-mesh-list" aria-label="agent mesh">
          {#each mesh as role, i (role.id)}
            <li class="obs-mesh-item" style="--i:{i}">
              <span class="obs-mesh-ico" aria-hidden="true"><Icon name={role.icon} size={15} /></span>
              <div class="obs-mesh-copy">
                <div class="obs-mesh-head">
                  <span class="obs-mesh-idx" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
                  <strong>{role.title}</strong>
                </div>
                <span class="obs-mesh-detail">{role.detail}</span>
              </div>
              <span class="obs-mesh-stage">{role.stage}</span>
            </li>
          {/each}
        </ol>
        <p class="obs-mesh-foot">
          Open Helix (B) anytime - fullscreen from the panel. Successful proofs and attempts stream into Live and the conversation feed.
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
    min-height: 62px;
    font-size: 15px;
    letter-spacing: 0.01em;
    line-height: 1.45;
    resize: vertical;
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
    grid-template-columns: repeat(auto-fit, minmax(238px, 1fr));
    gap: 10px;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .obs-mesh-item {
    position: relative;
    display: grid;
    grid-template-columns: 30px minmax(0, 1fr) auto;
    gap: 11px;
    align-items: start;
    padding: 11px 12px;
    overflow: hidden;
    border: 1px solid var(--obs-line);
    border-radius: 6px;
    background: var(--obs-panel-2);
    animation: fade-rise 460ms var(--ease) both;
    animation-delay: calc(var(--i) * 55ms);
    transition:
      border-color 160ms var(--ease),
      transform 160ms var(--ease),
      box-shadow 160ms var(--ease);
  }

  .obs-mesh-item::before {
    content: '';
    position: absolute;
    inset: 0 auto 0 0;
    width: 2px;
    background: var(--obs-acid);
    opacity: 0.45;
  }

  .obs-mesh-item:hover {
    border-color: var(--obs-line-acid);
    transform: translateY(-1px);
    box-shadow: 0 0 16px rgba(200, 248, 26, 0.14);
  }

  .obs-mesh-ico {
    display: grid;
    width: 30px;
    height: 30px;
    place-items: center;
    border: 1px solid var(--obs-line);
    border-radius: 6px;
    background: var(--obs-panel);
    color: var(--obs-acid);
  }

  .obs-mesh-copy {
    min-width: 0;
  }

  .obs-mesh-head {
    display: flex;
    align-items: baseline;
    gap: 7px;
  }

  .obs-mesh-head strong {
    font-size: 12px;
    color: var(--obs-text);
  }

  .obs-mesh-detail {
    display: block;
    margin-top: 3px;
    font-size: 10.5px;
    line-height: 1.5;
    color: var(--obs-faint);
  }

  .obs-mesh-stage {
    align-self: start;
    padding: 2px 7px;
    border: 1px solid var(--obs-line);
    border-radius: 2px;
    font-family: var(--mono);
    font-size: 7.5px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--obs-muted);
  }

  .obs-mesh-idx {
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 0.08em;
    color: var(--obs-acid);
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
