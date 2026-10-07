<script lang="ts">
  let token = $state('');
  let hint = $state(false);
  let error = $state('');
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const value = token.trim();
    if (!value || busy) return;
    busy = true;
    error = '';
    try {
      const res = await fetch('/api/v1/session', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: value })
      });
      if (!res.ok) {
        error = 'That token was not accepted. Copy the whole line the server printed.';
        return;
      }
      window.location.href = '/';
    } catch {
      error = 'The dashboard server is not reachable.';
    } finally {
      busy = false;
    }
  }
</script>

<div class="grid min-h-full place-items-center px-5 py-10">
  <div class="panel-raised grid-noise relative w-full max-w-[440px] overflow-hidden p-7">
    <p class="eyebrow">session</p>
    <h1 class="mt-2 font-mono text-xl tracking-[0.14em] text-acid">NETCAST3R</h1>
    <p class="mt-3 text-sm leading-relaxed text-bone-dust">
      This dashboard is locked with a per-session token so nothing on your machine can reach it
      from another tab or another process.
    </p>

    <form class="mt-5 flex flex-col gap-3" onsubmit={submit}>
      <label class="eyebrow" for="token">session token</label>
      <input
        id="token"
        name="token"
        class="field"
        type="password"
        autocomplete="off"
        spellcheck="false"
        placeholder="paste the token from your terminal"
        bind:value={token}
      />
      <button class="btn btn-acid w-full" type="submit" disabled={!token.trim() || busy}>
        {busy ? 'checking...' : 'unlock'}
      </button>
      {#if error}
        <p class="rounded-lg border border-violet-deep bg-violet-abyss px-3 py-2 text-xs text-bone">
          {error}
        </p>
      {/if}
    </form>

    <button
      class="mt-4 text-left text-xs text-ash transition-colors hover:text-bone"
      onclick={() => (hint = !hint)}
      type="button"
    >
      {hint ? 'x close' : '> where do I find it?'}
    </button>
    {#if hint}
      <p class="mt-2 text-xs leading-relaxed text-bone-dust">
        Run <code class="mono text-acid-dim">netcast3r ui</code> in a terminal. The first line it
        prints is <code class="mono text-acid-dim">NetCast3r API on http://127.0.0.1:7857/?token=...</code>
        - open that link, or paste the token here. The token changes every time the server restarts.
      </p>
    {/if}

    <p class="mt-5 border-t border-indigo-deep pt-3 text-[11px] leading-relaxed text-ash">
      Authorized security research only. The dashboard binds to loopback and never leaves this
      machine.
    </p>
  </div>
</div>
