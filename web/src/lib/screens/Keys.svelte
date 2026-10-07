<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api';
  import { store } from '../state.svelte';
  import type { KeyEntry, Provider } from '../types';
  import Confirm from '../ui/Confirm.svelte';

  const common = [
    'openai', 'anthropic', 'github', 'slack', 'stripe', 'twilio', 'sendgrid',
    'huggingface', 'replicate', 'groq', 'deepseek', 'openrouter', 'ollama'
  ];

  let keys = $state<KeyEntry[]>([]);
  let providers = $state<Provider[]>([]);
  let keyName = $state('');
  let keyValue = $state('');
  let provider = $state({ name: '', kind: 'openai', base_url: '', model: '', key_name: '' });
  let testing = $state('');
  let results = $state<Record<string, { ok: boolean; text: string }>>({});
  let deletingKey = $state('');
  let deletingProvider = $state('');
  let busy = $state(false);

  async function load() {
    try {
      keys = (await api.keys()).items;
      providers = (await api.providers()).items;
    } catch {
      /* backend not reachable */
    }
  }

  async function saveKey() {
    const name = keyName.trim();
    if (!name || !keyValue.trim()) return;
    busy = true;
    try {
      const saved = await api.putKey(name, keyValue.trim());
      store.toast('ok', `key saved as ${saved.name} (${saved.masked})`);
      keyValue = '';
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the key could not be saved');
    } finally {
      busy = false;
    }
  }

  async function dropKey(name: string) {
    try {
      await api.deleteKey(name);
      store.toast('ok', `removed the ${name} key`);
      await load();
    } finally {
      deletingKey = '';
    }
  }

  async function addProvider() {
    if (!provider.name.trim()) return;
    busy = true;
    try {
      await api.addProvider({ ...provider, key_name: provider.key_name || provider.name });
      store.toast('ok', 'provider added');
      provider = { name: '', kind: 'openai', base_url: '', model: '', key_name: '' };
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'the provider could not be saved');
    } finally {
      busy = false;
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
          text: result.ok
            ? `ok - ${result.latency_ms ?? '?'} ms - ${result.models?.length ?? 0} models`
            : `${result.reason}${result.detail ? ` - ${result.detail}` : ''}`
        }
      };
      store.toast(result.ok ? 'ok' : 'warn', result.ok ? 'provider reachable' : 'provider not reachable');
      await load();
    } catch (exc) {
      store.fail(exc instanceof Error ? exc.message : 'test failed');
    } finally {
      testing = '';
    }
  }

  async function dropProvider(id: string) {
    try {
      await api.deleteProvider(id);
      store.toast('ok', 'provider removed');
      await load();
    } finally {
      deletingProvider = '';
    }
  }

  onMount(load);
</script>

<div class="fade-rise mx-auto flex max-w-[1180px] flex-col gap-5">
  <section>
    <p class="eyebrow">providers and keys</p>
    <h1 class="mt-1 text-xl text-bone">Bring your own model</h1>
    <p class="mt-2 max-w-[70ch] text-sm leading-relaxed text-bone-dust">
      A model is optional. Without one NetCast3r still crawls, reads JavaScript, matches 310
      patterns, and validates 135 credential types against read-only provider endpoints - it just
      ranks candidates deterministically instead of asking a model. Paste a key to turn on
      classification and ranking.
    </p>
  </section>

  <section class="grid gap-5 lg:grid-cols-2">
    <div class="panel p-5">
      <p class="eyebrow">paste a key</p>
      <h2 class="mt-1 text-lg text-bone">Stored on this machine only</h2>
      <p class="mt-2 text-xs leading-relaxed text-bone-dust">
        Keys go into your operating system keyring when one is available, otherwise a 0600 file
        under <span class="mono text-acid-dim">~/.netcast3r</span>. Every screen shows a masked
        value, nothing is logged, and nothing is sent to us - there is no us.
      </p>

      <form class="mt-4 flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); saveKey(); }}>
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
        <div class="flex items-center gap-3">
          <button class="btn btn-acid" type="submit" disabled={!keyName.trim() || !keyValue.trim() || busy}>
            {busy ? 'saving...' : 'save key'}
          </button>
          <span class="mono text-xs text-ash">never leaves this machine</span>
        </div>
      </form>

      <div class="mt-5 border-t border-indigo-deep pt-4">
        <p class="eyebrow">stored keys</p>
        {#if keys.length === 0}
          <p class="mt-2 text-sm text-bone-dust">No keys stored yet.</p>
        {:else}
          <ul class="mt-2 flex flex-col gap-1">
            {#each keys as key (key.name)}
              <li class="flex items-center gap-3 rounded-lg border border-indigo-deep px-3 py-2">
                <span class="mono text-sm text-bone">{key.name}</span>
                <span class="mono text-xs text-acid-dim">{key.masked}</span>
                <span class="mono ml-auto text-[11px] text-ash">{key.source}</span>
                <button
                  class="btn btn-quiet btn-danger px-2! py-0.5! text-xs"
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

    <div class="panel p-5">
      <p class="eyebrow">add a provider</p>
      <h2 class="mt-1 text-lg text-bone">Point it at an API</h2>
      <form class="mt-4 grid gap-3 sm:grid-cols-2" onsubmit={(event) => { event.preventDefault(); addProvider(); }}>
        <label class="block">
          <span class="eyebrow">name</span>
          <input class="field mt-2" placeholder="openai" bind:value={provider.name} />
        </label>
        <label class="block">
          <span class="eyebrow">kind</span>
          <select class="field mt-2" bind:value={provider.kind}>
            <option value="openai">openai compatible</option>
            <option value="anthropic">anthropic</option>
            <option value="ollama">ollama</option>
            <option value="custom">custom</option>
          </select>
        </label>
        <label class="block sm:col-span-2">
          <span class="eyebrow">base url</span>
          <input class="field mt-2" placeholder="https://api.openai.com/v1" bind:value={provider.base_url} />
        </label>
        <label class="block">
          <span class="eyebrow">model</span>
          <input class="field mt-2" placeholder="optional" bind:value={provider.model} />
        </label>
        <label class="block">
          <span class="eyebrow">key name</span>
          <input class="field mt-2" placeholder="same as name" bind:value={provider.key_name} />
        </label>
        <div class="sm:col-span-2">
          <button class="btn btn-acid" type="submit" disabled={!provider.name.trim() || busy}>
            add provider
          </button>
        </div>
      </form>

      <div class="mt-5 border-t border-indigo-deep pt-4">
        <p class="eyebrow">configured</p>
        {#if providers.length === 0}
          <p class="mt-2 text-sm text-bone-dust">No providers configured. Ollama on localhost works with no key.</p>
        {:else}
          <ul class="mt-2 flex flex-col gap-1">
            {#each providers as item (item.id)}
              <li class="flex flex-wrap items-center gap-3 rounded-lg border border-indigo-deep px-3 py-2">
                <span
                  class="h-2 w-2 shrink-0 rounded-full"
                  class:bg-acid={item.healthy === 1}
                  class:bg-slate={item.healthy !== 1}
                  title={item.healthy === 1 ? 'healthy' : 'not tested or unhealthy'}
                  aria-hidden="true"
                ></span>
                <span class="mono text-sm text-bone">{item.name}</span>
                <span class="mono truncate text-xs text-bone-dust">{item.base_url || '-'}</span>
                <span class="mono text-xs text-ash">{item.masked || 'no key'}</span>
                <span class="ml-auto flex gap-2">
                  <button class="btn btn-quiet px-2! py-0.5! text-xs" type="button" disabled={testing === item.id}
                    onclick={() => test(item.id)}
                  >
                    {testing === item.id ? 'testing...' : 'test'}
                  </button>
                  <button
                    class="btn btn-quiet btn-danger px-2! py-0.5! text-xs"
                    type="button"
                    onclick={() => (deletingProvider = item.id)}
                  >
                    remove
                  </button>
                </span>
                {#if results[item.id]}
                  <span
                    class="mono w-full text-xs"
                    class:text-acid={results[item.id].ok}
                    class:text-bone-dust={!results[item.id].ok}
                  >
                    {results[item.id].text}
                  </span>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </div>
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
    body="The provider configuration is deleted. The key it referenced stays in the key store until you remove it separately."
    confirmLabel="remove provider"
    danger
    onConfirm={() => dropProvider(deletingProvider)}
    onCancel={() => (deletingProvider = '')}
  />
{/if}
