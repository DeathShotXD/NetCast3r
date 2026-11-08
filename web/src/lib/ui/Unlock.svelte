<script lang="ts">
  import Mark from './Mark.svelte';

  let username = $state('admin');
  let password = $state('');
  let show = $state(false);
  let hint = $state(false);
  let error = $state('');
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    const user = username.trim();
    if (!user || !password) return;
    busy = true;
    error = '';
    try {
      const res = await fetch('/api/v1/session', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password })
      });
      if (!res.ok) {
        error =
          res.status === 401
            ? 'That username and password were not accepted.'
            : `The dashboard could not start a session (HTTP ${res.status}).`;
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
        <p class="obs-eyebrow"><span class="tick"></span> sign in</p>
        <h1 class="obs-unlock-title">NETCAST3R</h1>
      </div>
    </div>
    <p class="obs-unlock-copy">
      Sign in to reach the control plane. The dashboard binds to loopback and signs in with a
      local username and password.
    </p>

    <form class="obs-unlock-form" onsubmit={submit}>
      <label class="obs-eyebrow" for="username">username</label>
      <input
        id="username"
        name="username"
        class="obs-field"
        type="text"
        autocomplete="username"
        spellcheck="false"
        placeholder="admin"
        bind:value={username}
      />
      <label class="obs-eyebrow" for="password" style="margin-top:2px">password</label>
      <div class="obs-unlock-pass">
        <input
          id="password"
          name="password"
          class="obs-field"
          type={show ? 'text' : 'password'}
          autocomplete="current-password"
          spellcheck="false"
          placeholder="123"
          bind:value={password}
        />
        <button
          class="obs-unlock-reveal"
          type="button"
          aria-label={show ? 'hide password' : 'show password'}
          onclick={() => (show = !show)}
        >
          {show ? 'hide' : 'show'}
        </button>
      </div>
      <button
        class="obs-btn obs-btn-primary"
        type="submit"
        disabled={!username.trim() || !password || busy}
        style="width:100%;height:36px"
      >
        {busy ? 'signing in...' : 'sign in'}
      </button>
      {#if error}
        <p class="obs-alert" role="alert">{error}</p>
      {/if}
    </form>

    <button class="obs-unlock-hint" onclick={() => (hint = !hint)} type="button">
      {hint ? 'close hint' : 'first time here?'}
    </button>
    {#if hint}
      <p class="obs-unlock-copy" style="margin-top:8px">
        The default login is <code class="obs-mono" style="color:var(--obs-acid)">admin</code> /
        <code class="obs-mono" style="color:var(--obs-acid)">123</code>. Sign in, then change it
        from <strong>Connect -> Dashboard access</strong>. The username and password are stored
        as a salted hash in a <code class="obs-mono">0600</code> file under
        <code class="obs-mono">~/.netcast3r</code>.
      </p>
    {/if}

    <p class="obs-unlock-legal">
      Authorized security research only. The dashboard binds to loopback and never leaves this
      machine.
    </p>
  </div>
</div>
