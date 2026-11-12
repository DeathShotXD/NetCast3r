<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import type { KeyEntry, Provider } from '../types';
  import Confirm from '../ui/Confirm.svelte';
  import Buffering from '../ui/Buffering.svelte';

  const common = [
    'openai', 'anthropic', 'github', 'slack', 'stripe', 'twilio', 'sendgrid',
    'huggingface', 'replicate', 'groq', 'deepseek', 'nvidia', 'openrouter', 'ollama'
  ];

  interface Preset {
    id: string;
    label: string;
    hint: string;
    base_url: string;
    key_name: string;
    placeholder: string;
    needsKey: boolean;
    hinted: string[];
    free: string[];
  }

  const PRESETS: Preset[] = [
    {
      id: 'openrouter', label: 'openrouter', hint: 'free model pool',
      base_url: 'https://openrouter.ai/api/v1', key_name: 'openrouter',
      placeholder: 'sk-or-v1-...', needsKey: true,
      hinted: ['openrouter/free', 'nvidia/nemotron-3.5-lightning:free', 'nvidia/nemotron-3-super-120b-a12b:free'],
      free: [':free']
    },
    {
      id: 'nvidia', label: 'nvidia', hint: 'nemotron reasoning models',
      base_url: 'https://integrate.api.nvidia.com/v1', key_name: 'nvidia',
      placeholder: 'nvapi-...', needsKey: true,
      hinted: [
        'nvidia/nemotron-3-ultra-550b-a55b',
        'nvidia/nemotron-3.5-lightning-30b-a3b',
        'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning'
      ],
      free: []
    },
    {
      id: 'opencode', label: 'opencode zen', hint: 'opencode zen gateway',
      base_url: 'https://opencode.ai/zen/v1', key_name: 'opencode',
      placeholder: 'paste the zen key', needsKey: true,
      hinted: ['mimo-v2.6-flash-free'], free: ['free']
    },
    {
      id: 'groq', label: 'groq', hint: 'fast, generous free tier',
      base_url: 'https://api.groq.com/openai/v1', key_name: 'groq',
      placeholder: 'gsk_...', needsKey: true,
      hinted: ['llama-3.3-70b-versatile'], free: []
    },
    {
      id: 'deepseek', label: 'deepseek', hint: 'deepseek chat api',
      base_url: 'https://api.deepseek.com/v1', key_name: 'deepseek',
      placeholder: 'sk-...', needsKey: true, hinted: ['deepseek-chat'], free: []
    },
    {
      id: 'mistral', label: 'mistral', hint: 'la plateforme',
      base_url: 'https://api.mistral.ai/v1', key_name: 'mistral',
      placeholder: 'paste the api key', needsKey: true, hinted: ['mistral-large-latest'], free: []
    },
    {
      id: 'cerebras', label: 'cerebras', hint: 'very fast inference',
      base_url: 'https://api.cerebras.ai/v1', key_name: 'cerebras',
      placeholder: 'csk-...', needsKey: true, hinted: ['llama-3.3-70b'], free: []
    },
    {
      id: 'openai', label: 'openai', hint: 'platform.openai.com',
      base_url: 'https://api.openai.com/v1', key_name: 'openai',
      placeholder: 'sk-...', needsKey: true, hinted: ['gpt-4o-mini'], free: []
    },
    {
      id: 'anthropic', label: 'anthropic', hint: 'openai-compatible endpoint',
      base_url: 'https://api.anthropic.com/v1', key_name: 'anthropic',
      placeholder: 'sk-ant-...', needsKey: true, hinted: [], free: []
    },
    {
      id: 'gemini', label: 'gemini', hint: 'google openai-compat',
      base_url: 'https://generativelanguage.googleapis.com/v1beta/openai',
      key_name: 'gemini', placeholder: 'AIza...', needsKey: true,
      hinted: ['gemini-2.0-flash'], free: []
    },
    {
      id: 'ollama', label: 'ollama', hint: 'localhost, no key needed',
      base_url: 'http://127.0.0.1:11434/v1', key_name: 'ollama',
      placeholder: 'not needed', needsKey: false, hinted: ['llama3:8b'], free: []
    },
    {
      id: 'custom', label: 'custom', hint: 'any openai-compatible url',
      base_url: '', key_name: '', placeholder: 'optional',
      needsKey: false, hinted: [], free: []
    }
  ];

  let keys = $state<KeyEntry[]>([]);
  let providers = $state<Provider[]>([]);
  let loading = $state(true);
  let error = $state('');
  let keyName = $state('');
  let keyValue = $state('');
  let custom = $state({ name: '', kind: 'openai', base_url: '', model: '', key_name: '' });

  // wizard
  let selected = $state('');
  let stepName = $state('');
  let stepKeyName = $state('');
  let stepUrl = $state('');
  let stepKey = $state('');
  let connectBusy = $state(false);
  let connectResult = $state<
    { ok: boolean; text: string; models: string[]; savedId: string } | null
  >(null);
  let chosen = $state<string[]>([]);

  let testing = $state('');
  let results = $state<Record<string, { ok: boolean; text: string; models?: string[] }>>({});
  let deletingKey = $state('');
  let deletingProvider = $state('');
  // The pool holds dozens of providers. Keep every row to one line and reveal
  // a provider's models on demand, instead of painting a wall of chips that
  // ran this page to six thousand pixels.
  let expanded = $state<Set<string>>(new Set());

  function toggleExpanded(id: string) {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    expanded = next;
  }

  const preset = $derived(PRESETS.find((item) => item.id === selected) ?? null);
  const enabledCount = $derived(providers.filter((item) => item.enabled !== 0).length);
  const modelTotal = $derived(
    providers
      .filter((item) => item.enabled !== 0)
      .reduce((sum, item) => sum + (item.models?.length || (item.model ? 1 : 0)), 0)
  );
  const liveCount = $derived(providers.filter((item) => item.healthy === 1).length);

  function providerModels(item: Provider): string[] {
    return item.models?.length ? item.models : item.model ? [item.model] : [];
  }

  function isFree(model: string, item: Preset): boolean {
    return item.free.some((tag) => model.includes(tag));
  }

  async function load() {
    loading = true;
    try {
      keys = (await api.keys()).items;
      providers = (await api.providers()).items;
      error = '';
    } catch (exc) {
      error = exc instanceof Error ? exc.message : 'could not read providers';
    } finally {
      loading = false;
    }
  }

  function pickPreset(item: Preset) {
    selected = item.id;
    stepName = item.id;
    stepKeyName = item.key_name || item.id;
    stepUrl = item.base_url;
    stepKey = '';
    connectResult = null;
    chosen = [];
  }

  function defaultModels(item: Preset, fetched: string[]): string[] {
    const intersect = item.hinted.filter((model) => fetched.includes(model));
    if (intersect.length) return intersect;
    if (fetched.length) return fetched.slice(0, 3);
    return item.hinted.slice(0, 3);
  }

  function nextPriority(): number {
    const base = providers.length
      ? Math.min(...providers.map((item) => item.priority))
      : 10;
    return Math.max(1, base - 5);
  }

  async function connect() {
    if (!preset) return;
    const name = (preset.id === 'custom' ? stepName : preset.id).trim();
    const base = stepUrl.trim();
    if (!name || !base) return;
    connectBusy = true;
    connectResult = null;
    try {
      const key_name = stepKeyName.trim() || name;
      if (stepKey.trim()) await api.putKey(key_name, stepKey.trim());
      const existing = providers.find((item) => item.name === name);
      let saved: Provider;
      if (existing) {
        saved = await api.patchProvider(existing.id, { base_url: base, key_name });
      } else {
        saved = await api.addProvider({
          name, kind: 'openai', base_url: base, key_name,
          priority: nextPriority(), enabled: true
        });
      }
      const result = await api.testProvider(saved.id);
      const models = result.models ?? [];
      connectResult = {
        ok: result.ok,
        text: result.ok
          ? `reachable - ${result.latency_ms ?? '?'} ms - ${models.length} models`
          : `${result.reason}${result.detail ? ` - ${result.detail}` : ''}`,
        models,
        savedId: saved.id
      };
      chosen = models.length ? defaultModels(preset, models) : [];
      store.toast(result.ok ? 'ok' : 'warn',
        result.ok ? `${preset.label} is reachable` : `${preset.label} is not reachable yet`);
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the provider could not be saved');
    } finally {
      connectBusy = false;
    }
  }

  async function saveModels() {
    if (!connectResult || chosen.length === 0) return;
    connectBusy = true;
    try {
      await api.patchProvider(connectResult.savedId, { models: chosen });
      store.toast('ok', `${chosen.length} models added to the pool`);
      selected = '';
      stepName = '';
      stepKeyName = '';
      stepUrl = '';
      stepKey = '';
      connectResult = null;
      chosen = [];
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'models could not be saved');
    } finally {
      connectBusy = false;
    }
  }

  function keepProvider() {
    selected = '';
    stepName = '';
    stepKeyName = '';
    stepUrl = '';
    stepKey = '';
    connectResult = null;
    chosen = [];
  }

  function toggleChosen(model: string) {
    chosen = chosen.includes(model)
      ? chosen.filter((item) => item !== model)
      : [...chosen, model];
  }

  async function saveKey() {
    const name = keyName.trim();
    if (!name || !keyValue.trim()) return;
    try {
      const saved = await api.putKey(name, keyValue.trim());
      store.toast('ok', `key saved as ${saved.name} (${saved.masked})`);
      keyValue = '';
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the key could not be saved');
    }
  }

  async function dropKey(name: string) {
    try {
      await api.deleteKey(name);
      store.toast('ok', `removed the ${name} key`);
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the key could not be removed');
    } finally {
      deletingKey = '';
    }
  }

  async function addCustom() {
    if (!custom.name.trim() || !custom.base_url.trim()) return;
    connectBusy = true;
    try {
      await api.addProvider({
        ...custom,
        key_name: custom.key_name || custom.name,
        models: custom.model ? [custom.model] : [],
        priority: nextPriority(),
        enabled: true
      });
      store.toast('ok', 'provider added to the pool');
      custom = { name: '', kind: 'openai', base_url: '', model: '', key_name: '' };
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the provider could not be saved');
    } finally {
      connectBusy = false;
    }
  }

  async function test(id: string) {
    testing = id;
    try {
      const result = await api.testProvider(id);
      results = {
        ...results,
        [id]: {
          ok: result.ok,
          models: result.models,
          text: result.ok
            ? `reachable - ${result.latency_ms ?? '?'} ms - ${result.models?.length ?? 0} models`
            : `${result.reason}${result.detail ? ` - ${result.detail}` : ''}`
        }
      };
      store.toast(result.ok ? 'ok' : 'warn',
        result.ok ? 'provider reachable' : 'provider not reachable');
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'test failed');
    } finally {
      testing = '';
    }
  }

  async function adoptModels(id: string) {
    const models = results[id]?.models ?? [];
    if (!models.length) return;
    try {
      await api.patchProvider(id, { models });
      store.toast('ok', `${models.length} models in the pool`);
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'models could not be saved');
    }
  }

  async function toggleEnabled(item: Provider) {
    try {
      await api.patchProvider(item.id, { enabled: item.enabled === 0 ? 1 : 0 });
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the switch did not move');
    }
  }

  async function dropModel(item: Provider, model: string) {
    try {
      await api.patchProvider(item.id, {
        models: providerModels(entry(item)).filter((name) => name !== model)
      });
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the model could not be removed');
    }
  }

  function entry(item: Provider): Provider {
    return providers.find((row) => row.id === item.id) ?? item;
  }

  async function move(index: number, delta: number) {
    const next = [...providers];
    const target = index + delta;
    if (target < 0 || target >= next.length) return;
    const [row] = next.splice(index, 1);
    next.splice(target, 0, row);
    providers = next;
    try {
      for (let i = 0; i < next.length; i += 1) {
        const wanted = (i + 1) * 5;
        if (next[i].priority !== wanted) {
          const updated = await api.patchProvider(next[i].id, { priority: wanted });
          providers = providers.map((item) => (item.id === updated.id ? updated : item));
        }
      }
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the order could not be saved');
      await load();
    }
  }

  async function dropProvider(id: string) {
    try {
      await api.deleteProvider(id);
      store.toast('ok', 'provider removed');
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the provider could not be removed');
    } finally {
      deletingProvider = '';
    }
  }

  onMount(() => {
    void load();
  });
</script>

<div class="obs-page obs-page-narrow flex flex-col gap-5">
  <header class="obs-page-head">
    <div>
      <div class="obs-eyebrow"><span class="tick"></span> Providers and keys</div>
      <h1>Bring your own model</h1>
      <p class="obs-page-sub">
        A model is optional. Without one NetCast3r still maps the surface, reasons over JavaScript,
        matches 310 patterns, and validates 135 credential types against read-only provider
        endpoints - it just ranks candidates deterministically instead of asking a model. Pick a
        provider below, paste a key, and the connect step saves it, probes the endpoint, and hands
        you the model list. Every enabled provider stays in one pool: the run tries them in priority
        order and rotates on rate limits, so an NVIDIA key and an OpenRouter key work side by side.
      </p>
    </div>
  </header>

  {#if error && providers.length === 0}
    <section class="obs-card px-5 py-4 text-sm" role="alert" style="color:var(--obs-red)">
      Could not read the provider pool: {error}
      <button class="obs-btn obs-btn-sm" type="button" style="margin-left:10px" onclick={() => void load()}>
        Try again
      </button>
    </section>
  {:else if loading && providers.length === 0 && keys.length === 0}
    <section class="obs-card p-5">
      <Buffering
        variant="block"
        tone="quiet"
        label="Reading providers"
        detail="Loading the model pool, stored keys, and reachability."
      />
    </section>
  {/if}

  {#if providers.length > 0}
    <section class="obs-kpis cols-4" aria-label="pool summary">
      <article class="obs-card obs-kpi">
        <p class="obs-kpi-label">providers on duty</p>
        <p class="obs-kpi-value">{enabledCount}<small>/{providers.length}</small></p>
        <p class="obs-kpi-foot">enabled in the pool</p>
      </article>
      <article class="obs-card obs-kpi">
        <p class="obs-kpi-label">models ready</p>
        <p class="obs-kpi-value">{modelTotal}</p>
        <p class="obs-kpi-foot">routed in priority order</p>
      </article>
      <article class="obs-card obs-kpi {liveCount > 0 ? 'acid' : ''}">
        <p class="obs-kpi-label">reach now</p>
        <p class="obs-kpi-value">{liveCount}</p>
        <p class="obs-kpi-foot">{liveCount > 0 ? 'answering health probes' : 'waiting for a probe'}</p>
      </article>
      <article class="obs-card obs-kpi">
        <p class="obs-kpi-label">keys stored</p>
        <p class="obs-kpi-value">{keys.length}</p>
        <p class="obs-kpi-foot">in the local keyring</p>
      </article>
    </section>
  {/if}

  <section class="obs-card p-5">
    <div class="obs-card-title">Connect a provider</div>
    <div class="obs-card-sub">pick one, paste a key, we probe it</div>
    <p class="mt-2 max-w-[70ch] text-xs leading-relaxed text-bone-dust">
      The connect step saves the key into your OS keyring (or a 0600 file under
      <span class="mono text-acid-dim">~/.netcast3r</span>), creates the provider, calls its
      <span class="mono">/models</span> endpoint, and shows you what it can reach. Nothing is sent
      anywhere but the provider you picked.
    </p>

    <div class="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
      {#each PRESETS as item (item.id)}
        <button
          class="group flex flex-col items-start rounded-[6px] border px-3 py-2.5 text-left transition"
          class:border-acid={selected === item.id}
          class:bg-acid-abyss={selected === item.id}
          class:border-indigo-deep={selected !== item.id}
          class:hover:border-acid-deep={selected !== item.id}
          type="button"
          onclick={() => pickPreset(item)}
        >
          <span class="mono text-sm" class:text-acid={selected === item.id} class:text-bone={selected !== item.id}>
            {item.label}
          </span>
          <span class="mt-0.5 text-[11px] leading-tight text-ash">{item.hint}</span>
        </button>
      {/each}
    </div>

    {#if preset}
      <form
        class="mt-5 grid gap-3 border-t border-indigo-deep pt-4 sm:grid-cols-2"
        onsubmit={(event) => { event.preventDefault(); void connect(); }}
      >
        {#if preset.id === 'custom'}
          <label class="block">
            <span class="eyebrow">provider name</span>
            <input class="field mt-2" placeholder="my gateway" bind:value={stepName} />
          </label>
        {/if}
        <label class="block" class:sm:col-span-2={preset.id !== 'custom'}>
          <span class="eyebrow">base url</span>
          <input class="field mt-2" placeholder="https://api.example.com/v1" bind:value={stepUrl} />
        </label>
        <label class="block">
          <span class="eyebrow">key name</span>
          <input class="field mt-2" placeholder={preset.key_name || preset.id} bind:value={stepKeyName} />
        </label>
        <label class="block">
          <span class="eyebrow">{preset.needsKey ? 'api key' : 'key (optional)'}</span>
          <input
            class="field mt-2"
            type="password"
            placeholder={preset.placeholder}
            bind:value={stepKey}
            autocomplete="off"
            spellcheck="false"
          />
        </label>
        <div class="flex items-center gap-3 sm:col-span-2">
          <button class="btn btn-acid" type="submit" disabled={connectBusy || !stepUrl.trim()}>
            {connectBusy ? 'probing...' : 'connect and probe'}
          </button>
          <span class="mono text-xs text-ash">
            {preset.needsKey ? 'the key never leaves this machine' : 'no key required'}
          </span>
        </div>
      </form>

      {#if connectResult}
        <div class="mt-4 rounded-[6px] border px-4 py-3" class:border-acid={connectResult.ok} class:border-indigo-deep={!connectResult.ok}>
          <div class="flex flex-wrap items-center gap-3">
            <span class="chip" class:text-acid={connectResult.ok} class:text-violet={!connectResult.ok}>
              <span class="h-2 w-2 rounded-full" class:bg-acid={connectResult.ok} class:bg-violet={!connectResult.ok}></span>
              {connectResult.ok ? 'reachable' : 'not reachable'}
            </span>
            <span class="mono text-xs text-bone-dust">{connectResult.text}</span>
          </div>
          {#if connectResult.models.length > 0}
            <p class="eyebrow mt-3">pick the models to route</p>
            <div class="mt-2 flex flex-wrap gap-1.5">
              {#each connectResult.models as model (model)}
                <button
                  class="mono rounded-[2px] border px-2.5 py-1 text-[11px] transition"
                  class:border-acid={chosen.includes(model)}
                  class:bg-acid-abyss={chosen.includes(model)}
                  class:text-acid={chosen.includes(model)}
                  class:border-indigo-deep={!chosen.includes(model)}
                  class:text-bone-dust={!chosen.includes(model)}
                  type="button"
                  onclick={() => toggleChosen(model)}
                  title={model}
                >
                  {model.length > 42 ? `${model.slice(0, 41)}...` : model}
                  {#if isFree(model, preset)}
                    <span class="ml-1 text-acid-dim">free</span>
                  {/if}
                </button>
              {/each}
            </div>
            <div class="mt-3 flex items-center gap-3">
              <button class="btn btn-acid" type="button" disabled={connectBusy || chosen.length === 0} onclick={() => void saveModels()}>
                {connectBusy ? 'saving...' : `add ${chosen.length} to the pool`}
              </button>
              <span class="mono text-xs text-ash">routes rotate across every model you keep</span>
            </div>
          {:else if connectResult.ok}
            <div class="mt-3 flex items-center gap-3">
              <button class="btn btn-acid" type="button" disabled={connectBusy} onclick={keepProvider}>
                keep this provider
              </button>
              <span class="mono text-xs text-ash">the endpoint listed no models; add one by hand below</span>
            </div>
          {/if}
        </div>
      {/if}
    {/if}
  </section>

  <section class="obs-card p-5">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <div class="obs-card-title">Model pool</div>
        <div class="obs-card-sub">tried in order, rotated under rate limits</div>
      </div>
      <span class="mono text-xs text-ash">{enabledCount} on / {modelTotal} models</span>
    </div>

    {#if providers.length === 0}
      <p class="mt-4 text-sm text-bone-dust">
        No providers yet. Ollama on localhost works with no key; everything else just needs a key
        pasted into the connect step above.
      </p>
    {:else}
      <ul class="mt-4 flex flex-col gap-2">
        {#each providers as item, i (item.id)}
          <li
            class="rounded-[6px] border border-indigo-deep px-4 py-3 transition"
            class:opacity-60={item.enabled === 0}
          >
            <div class="flex flex-wrap items-center gap-3">
              <span
                class="h-2 w-2 shrink-0 rounded-full"
                class:bg-acid={item.healthy === 1}
                class:bg-slate={item.healthy !== 1}
                title={item.healthy === 1 ? 'reachable' : 'not tested or unreachable'}
                aria-hidden="true"
              ></span>
              <span class="mono text-sm text-bone">{item.name}</span>
              <span class="mono min-w-0 flex-1 truncate text-xs text-bone-dust">{item.base_url || '-'}</span>
              <span class="mono text-xs text-ash">{item.masked || 'no key'}</span>
              <span class="mono text-[11px] text-ash">p{item.priority}</span>
              <button
                class="btn btn-quiet shrink-0 px-2! py-0.5! text-[11px]"
                type="button"
                aria-expanded={expanded.has(item.id)}
                onclick={() => toggleExpanded(item.id)}
              >
                {providerModels(item).length} model{providerModels(item).length === 1 ? '' : 's'}
                <span aria-hidden="true">{expanded.has(item.id) ? '^' : 'v'}</span>
              </button>
              <span class="flex shrink-0 items-center gap-1">
                <button class="btn btn-quiet px-2! py-0.5! text-xs" type="button" disabled={i === 0} onclick={() => void move(i, -1)} aria-label="move up">^</button>
                <button class="btn btn-quiet px-2! py-0.5! text-xs" type="button" disabled={i === providers.length - 1} onclick={() => void move(i, 1)} aria-label="move down">v</button>
                <button
                  class="btn px-2! py-0.5! text-xs"
                  class:bg-acid-abyss={item.enabled !== 0}
                  type="button"
                  onclick={() => void toggleEnabled(item)}
                >
                  {item.enabled === 0 ? 'off' : 'on'}
                </button>
                <button class="btn btn-quiet px-2! py-0.5! text-xs" type="button" disabled={testing === item.id}
                  onclick={() => void test(item.id)}
                >
                  {testing === item.id ? 'testing...' : 'test'}
                </button>
                <button
                  class="btn btn-quiet btn-danger shrink-0 px-2! py-0.5! text-xs"
                  type="button"
                  onclick={() => (deletingProvider = item.id)}
                >
                  remove
                </button>
              </span>
            </div>
            {#if providerModels(item).length === 0}
              <div class="mt-2">
                <span class="mono text-[11px] text-violet">no models - this provider is skipped</span>
              </div>
            {:else if expanded.has(item.id)}
              <div class="mt-2 flex flex-wrap gap-1.5">
                {#each providerModels(item) as model (model)}
                  <button
                    class="mono group flex items-center gap-1 rounded-[2px] border border-indigo-deep px-2 py-0.5 text-[11px] text-bone-dust"
                    type="button"
                    title="click to drop this model"
                    onclick={() => void dropModel(item, model)}
                  >
                    {model}
                    <span class="text-slate group-hover:text-violet" aria-hidden="true">x</span>
                  </button>
                {/each}
              </div>
            {/if}
            {#if results[item.id]}
              <div class="mt-2 flex flex-wrap items-center gap-3">
                <span class="mono text-xs" class:text-acid={results[item.id].ok} class:text-violet={!results[item.id].ok}>
                  {results[item.id].text}
                </span>
                {#if results[item.id].ok && results[item.id].models?.length &&
                  JSON.stringify(results[item.id].models) !== JSON.stringify(providerModels(item))}
                  <button class="btn btn-quiet px-2! py-0.5! text-xs" type="button" onclick={() => void adoptModels(item.id)}>
                    use these {results[item.id].models?.length}
                  </button>
                {/if}
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section class="grid gap-5">
    <div class="obs-card p-5">
      <div class="obs-card-title">Stored keys</div>
      <div class="obs-card-sub">one machine, one keyring</div>
      <p class="mt-2 text-xs leading-relaxed text-bone-dust">
        Keys go into your operating system keyring when one is available, otherwise a 0600 file
        under <span class="mono text-acid-dim">~/.netcast3r</span>. Every screen shows a masked
        value, nothing is logged, and nothing is sent to us - there is no us.
      </p>

      <form class="mt-4 flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); void saveKey(); }}>
        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block">
            <span class="eyebrow">name</span>
            <input class="field mt-2" list="keynames" placeholder="openai" bind:value={keyName} autocomplete="off" />
            <datalist id="keynames">
              {#each common as name (name)}
                <option value={name}></option>
              {/each}
            </datalist>
          </label>
          <label class="block">
            <span class="eyebrow">key</span>
            <input
              class="field mt-2"
              type="password"
              placeholder="paste it here"
              bind:value={keyValue}
              autocomplete="off"
              spellcheck="false"
            />
          </label>
        </div>
        <div class="flex items-center gap-3">
          <button class="btn btn-acid" type="submit" disabled={!keyName.trim() || !keyValue.trim()}>
            save key
          </button>
          <span class="mono text-xs text-ash">never leaves this machine</span>
        </div>
      </form>

      <div class="mt-5 border-t border-indigo-deep pt-4">
        <p class="eyebrow">key store</p>
        {#if keys.length === 0}
          <p class="mt-2 text-sm text-bone-dust">No keys stored yet.</p>
        {:else}
          <ul class="mt-2 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
            {#each keys as key (key.name)}
              <li class="flex flex-wrap items-center gap-3 rounded-[6px] border border-indigo-deep px-3 py-2">
                <span class="mono text-sm text-bone">{key.name}</span>
                <span class="mono text-xs text-acid-dim">{key.masked}</span>
                <span class="mono ml-auto text-[11px] text-ash">{key.source}</span>
                <button
                  class="btn btn-quiet btn-danger shrink-0 px-2! py-0.5! text-xs"
                  type="button"
                  onclick={() => (deletingKey = key.name)}
                >
                  remove
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </div>

    <div class="obs-card p-5">
      <div class="obs-card-title">Custom endpoint</div>
      <div class="obs-card-sub">anything OpenAI-compatible</div>
      <p class="mt-2 text-xs leading-relaxed text-bone-dust">
        Gateways, proxies, and self-hosted runtimes work too. The endpoint must speak the
        <span class="mono">/chat/completions</span> and <span class="mono">/models</span> dialect.
        A single model name is enough to join the pool.
      </p>
      <form class="mt-4 grid gap-3 sm:grid-cols-2" onsubmit={(event) => { event.preventDefault(); void addCustom(); }}>
        <label class="block">
          <span class="eyebrow">name</span>
          <input class="field mt-2" placeholder="my gateway" bind:value={custom.name} />
        </label>
        <label class="block">
          <span class="eyebrow">key name</span>
          <input class="field mt-2" placeholder="same as name" bind:value={custom.key_name} />
        </label>
        <label class="block sm:col-span-2">
          <span class="eyebrow">base url</span>
          <input class="field mt-2" placeholder="https://gateway.example.com/v1" bind:value={custom.base_url} />
        </label>
        <label class="block sm:col-span-2">
          <span class="eyebrow">model</span>
          <input class="field mt-2" placeholder="optional, one model is enough" bind:value={custom.model} />
        </label>
        <div class="sm:col-span-2">
          <button class="btn btn-acid" type="submit" disabled={connectBusy || !custom.name.trim() || !custom.base_url.trim()}>
            add to pool
          </button>
        </div>
      </form>
    </div>
  </section>
</div>

{#if deletingKey}
  <Confirm
    title="Remove the {deletingKey} key?"
    body="The saved value is erased from this machine. Scans that need it will fall back to a deterministic pass until you paste it again."
    confirmLabel="remove key"
    danger
    onConfirm={() => dropKey(deletingKey)}
    onCancel={() => (deletingKey = '')}
  />
{/if}

{#if deletingProvider}
  <Confirm
    title="Remove this provider?"
    body="The provider leaves the pool. Its stored key is removed too, unless another provider still references the same key name."
    confirmLabel="remove provider"
    danger
    onConfirm={() => dropProvider(deletingProvider)}
    onCancel={() => (deletingProvider = '')}
  />
{/if}
