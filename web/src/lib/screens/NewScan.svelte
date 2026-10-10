<script lang="ts">
  import { api } from '../api';
  import { store } from '../state.svelte';
  import { spotlight } from '../actions';
  import PipelineLadder from '../ui/PipelineLadder.svelte';
  import Confirm from '../ui/Confirm.svelte';

  const presets = [
    {
      id: 'quick',
      name: 'Quick look',
      blurb: 'One page and its scripts. The fastest honest pass.',
      options: { depth: 1, tier: 'read', subdomains: false }
    },
    {
      id: 'standard',
      name: 'Standard audit',
      blurb: 'Follow links two hops deep and validate everything it catches.',
      options: { depth: 2, tier: 'read', subdomains: true }
    },
    {
      id: 'deep',
      name: 'Deep hunt',
      blurb: 'Four hops through every endpoint and bundle. Slow, thorough.',
      options: { depth: 4, tier: 'read', subdomains: true }
    }
  ];

  let target = $state('');
  let preset = $state('standard');
  let advanced = $state(false);
  let depth = $state(2);
  let timeout = $state('');
  let writeTier = $state(false);
  let rate = $state('');
  let delay = $state('');
  let retries = $state('');
  let maxPages = $state('');
  let randomAgent = $state(false);
  let wayback = $state(true);
  let subdomains = $state(true);
  let busy = $state(false);
  let error = $state('');
  let confirmOpen = $state(false);

  const trimmed = $derived(target.trim());
  const ready = $derived(trimmed.length > 3 && !busy);

  function choose(id: string) {
    preset = id;
    const found = presets.find((item) => item.id === id)!;
    depth = Number(found.options.depth);
    subdomains = Boolean(found.options.subdomains);
  }

  async function start() {
    if (!ready) return;
    if (writeTier) {
      confirmOpen = true;
      return;
    }
    await launch();
  }

  async function launch() {
    confirmOpen = false;
    busy = true;
    error = '';
    const found = presets.find((item) => item.id === preset)!;
    const options: Record<string, unknown> = { depth, tier: writeTier ? 'write' : found.options.tier };
    if (timeout.trim()) options.timeout = Number(timeout.trim());
    if (rate.trim()) options.rate = Number(rate.trim());
    if (delay.trim()) options.delay = Number(delay.trim());
    if (retries.trim()) options.retries = Number(retries.trim());
    if (maxPages.trim()) options.max_pages = Number(maxPages.trim());
    options.random_agent = randomAgent;
    options.wayback = wayback;
    options.subdomains = subdomains;
    try {
      const run = await api.startRun(trimmed, options);
      store.toast('ok', `scan started against ${trimmed}`);
      store.runs = [{ ...run }, ...store.runs];
      store.watch(run.id);
      await store.refreshTotals();
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'the scan could not be started';
    } finally {
      busy = false;
    }
  }
</script>

<div class="stagger mx-auto grid max-w-[1180px] gap-5 lg:grid-cols-[1.15fr_1fr]">
  <section class="panel p-6" use:spotlight>
    <p class="eyebrow">new scan</p>
    <h1 class="mt-1 text-xl text-bone">Where should we look?</h1>

    <form class="mt-5 flex flex-col gap-5" onsubmit={(event) => { event.preventDefault(); start(); }}>
      <div>
        <label class="eyebrow" for="target">target</label>
        <input
          id="target"
          class="field mt-2"
          placeholder="https://example.com"
          bind:value={target}
          autocomplete="off"
          spellcheck="false"
        />
        <p class="mt-2 text-xs text-ash">
          A host or a full URL. Only test targets you are authorized to test.
        </p>
      </div>

      <fieldset>
        <legend class="eyebrow">how deep</legend>
        <div class="mt-2 grid gap-2">
          {#each presets as item (item.id)}
            <button
              type="button"
              class="flex items-start gap-3 rounded-lg border px-4 py-3 text-left transition-[border-color,background] duration-150 {preset ===
              item.id
                ? 'border-acid bg-acid-abyss'
                : 'border-indigo-deep hover:border-violet-deep'}"
              aria-pressed={preset === item.id}
              onclick={() => choose(item.id)}
            >
              <span
                class="mt-1 h-3 w-3 shrink-0 rounded-full border"
                class:border-acid={preset === item.id}
                class:bg-acid={preset === item.id}
                class:border-indigo={preset !== item.id}
                aria-hidden="true"
              ></span>
              <span>
                <span class="mono block text-sm tracking-wide text-bone">{item.name}</span>
                <span class="mt-0.5 block text-xs leading-relaxed text-bone-dust">{item.blurb}</span>
              </span>
            </button>
          {/each}
        </div>
      </fieldset>

      <div class="border-t border-indigo-deep pt-4">
        <button
          class="mono text-sm text-bone-dust transition-colors hover:text-bone"
          type="button"
          onclick={() => (advanced = !advanced)}
          aria-expanded={advanced}
        >
          {advanced ? 'x' : '>'} advanced options
        </button>

        {#if advanced}
          <div class="mt-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label class="eyebrow" for="depth">crawl depth</label>
              <input id="depth" class="field mt-2" type="number" min="0" max="8" bind:value={depth} />
            </div>
            <div>
              <label class="eyebrow" for="timeout">request timeout (s)</label>
              <input
                id="timeout"
                class="field mt-2"
                type="number"
                min="1"
                max="120"
                placeholder="default 15"
                bind:value={timeout}
              />
            </div>
            <div>
              <label class="eyebrow" for="rate">requests per second</label>
              <input
                id="rate"
                class="field mt-2"
                type="number"
                min="0"
                max="50"
                step="0.5"
                placeholder="0 = unlimited"
                bind:value={rate}
              />
            </div>
            <div>
              <label class="eyebrow" for="delay">delay between requests (s)</label>
              <input
                id="delay"
                class="field mt-2"
                type="number"
                min="0"
                max="10"
                step="0.1"
                placeholder="default 0"
                bind:value={delay}
              />
            </div>
            <div>
              <label class="eyebrow" for="retries">retries per request</label>
              <input
                id="retries"
                class="field mt-2"
                type="number"
                min="0"
                max="6"
                placeholder="default 2"
                bind:value={retries}
              />
            </div>
            <div>
              <label class="eyebrow" for="maxpages">max pages</label>
              <input
                id="maxpages"
                class="field mt-2"
                type="number"
                min="25"
                max="2000"
                placeholder="default 100"
                bind:value={maxPages}
              />
            </div>
          </div>

          <div class="mt-4 grid gap-2 sm:grid-cols-2">
            <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-indigo-deep px-4 py-3">
              <input class="mt-1 accent-[var(--nc-acid)]" type="checkbox" bind:checked={subdomains} />
              <span>
                <span class="mono block text-sm text-bone">map subdomains</span>
                <span class="mt-1 block text-xs leading-relaxed text-bone-dust">
                  Enumerate the host's subdomains from certificate transparency and DNS, then crawl
                  each one for JavaScript.
                </span>
              </span>
            </label>
            <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-indigo-deep px-4 py-3">
              <input class="mt-1 accent-[var(--nc-acid)]" type="checkbox" bind:checked={randomAgent} />
              <span>
                <span class="mono block text-sm text-bone">randomize user agent</span>
                <span class="mt-1 block text-xs leading-relaxed text-bone-dust">
                  Rotate through a pool of browser identities on every request.
                </span>
              </span>
            </label>
            <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-indigo-deep px-4 py-3">
              <input class="mt-1 accent-[var(--nc-acid)]" type="checkbox" bind:checked={wayback} />
              <span>
                <span class="mono block text-sm text-bone">mine the wayback machine</span>
                <span class="mt-1 block text-xs leading-relaxed text-bone-dust">
                  Pull historic URLs and js bundles from archive snapshots.
                </span>
              </span>
            </label>
          </div>

          <label class="mt-4 flex cursor-pointer items-start gap-3 rounded-lg border border-indigo-deep px-4 py-3">
            <input class="mt-1 accent-[var(--nc-acid)]" type="checkbox" bind:checked={writeTier} />
            <span>
              <span class="mono block text-sm text-bone">allow impact proof (write tier)</span>
              <span class="mt-1 block text-xs leading-relaxed text-bone-dust">
                Sends a real write call to the provider that issued a credential, to prove what an
                attacker could do. Off by default. Leave it off unless you own the account.
              </span>
            </span>
          </label>
        {/if}
      </div>

      {#if error}
        <p class="rounded-lg border border-violet-deep bg-violet-abyss px-4 py-3 text-sm text-bone">
          {error}
        </p>
      {/if}

      <div class="flex flex-wrap items-center gap-3">
        <button class="btn btn-acid" type="submit" disabled={!ready}>
          {busy ? 'starting...' : writeTier ? 'review and start' : 'start scan'}
        </button>
        <button class="btn btn-quiet" type="button" onclick={() => store.go('home')}>cancel</button>
        <span class="mono text-xs text-ash">presets are non-destructive</span>
      </div>
    </form>
  </section>

  <section class="panel flex flex-col gap-4 p-6">
    <div>
      <p class="eyebrow">what will happen</p>
      <h2 class="mt-1 text-lg text-bone">Six stages, in order</h2>
    </div>
    <div class="mt-1">
      <PipelineLadder />
    </div>
    <p class="mt-auto border-t border-indigo-deep pt-4 text-xs leading-relaxed text-ash">
      Results are written to your own results folder as markdown, JSON, SARIF, and an HTML
      dashboard. Nothing is uploaded anywhere.
    </p>
  </section>
</div>

{#if confirmOpen}
  <Confirm
    title="Send a write request to {trimmed}?"
    body="Write tier sends a real API call that changes data in the account that owns the credential. Run it only against accounts you control. Cancel to start a read-only scan instead."
    confirmLabel="start write-tier scan"
    danger
    onConfirm={launch}
    onCancel={() => (confirmOpen = false)}
  />
{/if}
