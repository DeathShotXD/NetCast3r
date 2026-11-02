<script lang="ts">
  import Mark from './Mark.svelte';

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

<div class="obs-unlock">
  <div class="obs-unlock-card">
    <div class="obs-unlock-head">
      <Mark class="h-11 w-11 shrink-0" />
      <div>
        <p class="obs-eyebrow"><span class="tick"></span> session</p>
        <h1 class="obs-unlock-title">NETCAST3R</h1>
      </div>
    </div>
    <p class="obs-unlock-copy">
      This dashboard is locked with a per-session token so nothing on your machine can reach it
      from another tab or another process.
    </p>

    <form class="obs-unlock-form" onsubmit={submit}>
      <label class="obs-eyebrow" for="token">session token</label>
      <input
        id="token"
        name="token"
        class="obs-field"
        type="password"
        autocomplete="off"
        spellcheck="false"
        placeholder="paste the token from your terminal"
        bind:value={token}
      />
      <button class="obs-btn obs-btn-primary" type="submit" disabled={!token.trim() || busy} style="width:100%;height:36px">
        {busy ? 'checking...' : 'unlock'}
      </button>
      {#if error}
        <p class="obs-alert" role="alert">{error}</p>
      {/if}
    </form>

    <button class="obs-unlock-hint" onclick={() => (hint = !hint)} type="button">
      {hint ? 'close hint' : 'where do I find it?'}
    </button>
    {#if hint}
      <p class="obs-unlock-copy" style="margin-top:8px">
        Run <code class="obs-mono" style="color:var(--obs-acid)">netcast3r ui</code> in a terminal. The first line it
        prints is <code class="obs-mono" style="color:var(--obs-acid)">NetCast3r API on http://127.0.0.1:7857/?token=...</code>
        — open that link, or paste the token here. The token changes every time the server restarts.
      </p>
    {/if}

    <p class="obs-unlock-legal">
      Authorized security research only. The dashboard binds to loopback and never leaves this
      machine.
    </p>
  </div>
</div>
