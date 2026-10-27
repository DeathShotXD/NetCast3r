/* NetCast3r — Command Center prototype behavior.
   No build step, no framework: this file only exists to make the design
   clickable. Production behavior lives in Svelte + the Python API. */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const root = document.documentElement;

  /* ------------------------------------------------------------------ */
  /* Toasts                                                              */
  /* ------------------------------------------------------------------ */

  const toastHost = $('#toasts');

  function toast(title, message, { icon = 'check', tone = 'default', duration = 4600 } = {}) {
    const el = document.createElement('div');
    el.className = 'toast';
    el.dataset.tone = tone;
    el.innerHTML =
      `<svg class="icon"><use href="#i-${icon}"/></svg>` +
      `<div><strong></strong><span></span></div>`;
    el.querySelector('strong').textContent = title;
    el.querySelector('span').textContent = message;
    el.addEventListener('click', () => el.remove());
    toastHost.append(el);
    window.setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(6px)';
      window.setTimeout(() => el.remove(), 220);
    }, duration);
    return el;
  }

  /* ------------------------------------------------------------------ */
  /* Theme                                                               */
  /* ------------------------------------------------------------------ */

  const storedTheme = localStorage.getItem('nc-theme');
  if (storedTheme === 'light' || storedTheme === 'dark') root.dataset.theme = storedTheme;

  function toggleTheme() {
    const next = root.dataset.theme === 'light' ? 'dark' : 'light';
    root.dataset.theme = next;
    localStorage.setItem('nc-theme', next);
    toast(
      next === 'light' ? 'Paper theme' : 'Obsidian theme',
      next === 'light' ? 'Daylight triage is easier on the eyes.' : 'Back to the void. Signal only.',
      { icon: next === 'light' ? 'sun' : 'moon', duration: 2200 }
    );
  }

  $('#theme-toggle')?.addEventListener('click', toggleTheme);

  /* ------------------------------------------------------------------ */
  /* Clock                                                               */
  /* ------------------------------------------------------------------ */

  const clockEl = $('#clock');

  function tickClock() {
    if (!clockEl) return;
    const now = new Date();
    const time = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'UTC', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }).format(now);
    const date = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'UTC', weekday: 'short', day: '2-digit', month: 'short', year: 'numeric'
    }).format(now).replace(',', '');
    clockEl.textContent = `${time} UTC`;
    if (clockEl.nextSibling) clockEl.nextSibling.nodeValue = ` ${date}`;
  }

  tickClock();
  window.setInterval(tickClock, 1000);

  /* ------------------------------------------------------------------ */
  /* Views                                                               */
  /* ------------------------------------------------------------------ */

  const viewNames = { command: 'Command Center', missions: 'Missions', findings: 'Findings', studio: 'Agent Studio' };
  const crumb = $('#crumb');

  function viewFromHash() {
    const raw = (location.hash || '').replace(/^#\/?/, '').split('/')[0];
    return viewNames[raw] ? raw : 'command';
  }

  function showView(name, { scroll = true } = {}) {
    if (!viewNames[name]) name = 'command';
    $$('.view').forEach((view) => { view.hidden = view.dataset.view !== name; });
    const active = $(`.view[data-view="${name}"]`);
    if (active && !reducedMotion) {
      active.classList.remove('screen-in');
      void active.offsetWidth;
      active.classList.add('screen-in');
    }
    $$('.nav .nav-item').forEach((item) => {
      const target = item.dataset.viewLink;
      item.classList.toggle('active', target === name);
    });
    if (crumb) crumb.textContent = viewNames[name];
    document.title = `${viewNames[name]} · NetCast3r`;
    if (scroll) window.scrollTo({ top: 0, behavior: reducedMotion ? 'auto' : 'smooth' });
  }

  function navigate(name) {
    if (!viewNames[name]) return;
    showView(name);
    if (location.hash !== `#/${name}`) history.pushState(null, '', `#/${name}`);
  }

  $$('[data-view-link]').forEach((btn) => {
    btn.addEventListener('click', (event) => {
      const nested = event.target.closest('button, a');
      if (nested && nested !== btn) return;
      event.preventDefault();
      navigate(btn.dataset.viewLink);
    });
  });

  /* Mission cards behave like links without nesting real anchors. */
  $$('.mission-card[data-view-link]').forEach((card) => {
    card.tabIndex = 0;
    card.setAttribute('role', 'link');
    card.addEventListener('keydown', (event) => {
      if (event.target !== card) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        navigate(card.dataset.viewLink);
      }
    });
  });

  window.addEventListener('popstate', () => showView(viewFromHash(), { scroll: false }));
  showView(viewFromHash(), { scroll: false });

  /* ------------------------------------------------------------------ */
  /* Command palette                                                     */
  /* ------------------------------------------------------------------ */

  const paletteOverlay = $('#palette-overlay');
  const paletteInput = $('#palette-input');
  const paletteResults = $('#palette-results');
  let paletteIndex = -1;

  function visiblePaletteItems() {
    return $$('.palette-item', paletteResults).filter((item) => !item.classList.contains('hidden'));
  }

  function refreshPaletteGroups() {
    const children = Array.from(paletteResults.children);
    children.forEach((child, index) => {
      if (!child.classList.contains('palette-group')) return;
      let hasVisible = false;
      for (let i = index + 1; i < children.length; i += 1) {
        if (children[i].classList.contains('palette-group')) break;
        if (children[i].classList.contains('palette-item') && !children[i].classList.contains('hidden')) {
          hasVisible = true;
          break;
        }
      }
      child.classList.toggle('hidden', !hasVisible);
    });
  }

  function filterPalette(query) {
    const needle = query.trim().toLowerCase();
    const items = $$('.palette-item', paletteResults);
    items.forEach((item) => {
      item.classList.toggle('hidden', needle.length > 0 && !item.textContent.toLowerCase().includes(needle));
    });
    const empty = $('#palette-empty');
    if (empty) empty.classList.toggle('hidden', items.some((item) => !item.classList.contains('hidden')));
    refreshPaletteGroups();
    paletteIndex = -1;
    items.forEach((item) => item.classList.remove('active'));
  }

  function setPaletteActive(index) {
    const items = visiblePaletteItems();
    if (!items.length) return;
    paletteIndex = (index + items.length) % items.length;
    items.forEach((item, i) => item.classList.toggle('active', i === paletteIndex));
    items[paletteIndex].scrollIntoView({ block: 'nearest' });
  }

  function openPalette() {
    if (!paletteOverlay) return;
    paletteOverlay.classList.add('open');
    if (paletteInput) {
      paletteInput.value = '';
      filterPalette('');
      window.requestAnimationFrame(() => paletteInput.focus());
    }
    paletteOverlay.dataset.open = 'true';
  }

  function closePalette() {
    if (!paletteOverlay) return;
    paletteOverlay.classList.remove('open');
    delete paletteOverlay.dataset.open;
    paletteIndex = -1;
    if (paletteInput) paletteInput.blur();
  }

  function runCommand(command) {
    closePalette();
    if (command.startsWith('finding:')) {
      focusFinding(command.slice(8));
      return;
    }
    switch (command) {
      case 'mission':
        openMission();
        break;
      case 'findings':
        navigate('findings');
        break;
      case 'missions':
        navigate('missions');
        break;
      case 'studio':
        navigate('studio');
        break;
      case 'command':
        navigate('command');
        break;
      case 'copilot':
        openCopilot();
        break;
      case 'pause': {
        const pause = $('[data-pause]');
        if (pause) pause.click();
        break;
      }
      case 'theme':
        toggleTheme();
        break;
      case 'audit':
        toast('Audit log', 'Every event in this prototype is already append-only in the real event store. The viewer lands with the control plane.');
        break;
      default:
        break;
    }
  }

  $$('[data-open-palette]').forEach((btn) => btn.addEventListener('click', openPalette));
  $$('.palette-item', paletteResults).forEach((item) => {
    item.addEventListener('click', () => runCommand(item.dataset.command));
  });

  paletteInput?.addEventListener('input', () => filterPalette(paletteInput.value));

  paletteOverlay?.addEventListener('click', (event) => {
    if (event.target === paletteOverlay) closePalette();
  });

  paletteInput?.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setPaletteActive(paletteIndex + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setPaletteActive(paletteIndex - 1);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const items = visiblePaletteItems();
      const chosen = items[paletteIndex] || items[0];
      if (chosen) runCommand(chosen.dataset.command);
      else toast('No match', 'Try “idor”, “report”, “mission”, or “theme”.', { icon: 'search', duration: 2600 });
    }
  });

  /* ------------------------------------------------------------------ */
  /* Mission composer                                                    */
  /* ------------------------------------------------------------------ */

  const missionOverlay = $('#mission-overlay');
  const targetInput = $('#m-target');
  const briefInput = $('#m-brief');
  const budgetInput = $('#m-budget');
  const budgetValue = $('#budget-value');

  function openMission() {
    if (!missionOverlay) return;
    closePalette();
    missionOverlay.classList.add('open');
    missionOverlay.dataset.open = 'true';
    if (targetInput) {
      targetInput.focus();
      targetInput.select();
    }
  }

  function closeMission() {
    if (!missionOverlay) return;
    missionOverlay.classList.remove('open');
    delete missionOverlay.dataset.open;
  }

  $$('[data-open-mission]').forEach((btn) => btn.addEventListener('click', (event) => {
    event.stopPropagation();
    openMission();
  }));
  $$('[data-close-mission]').forEach((btn) => btn.addEventListener('click', closeMission));

  missionOverlay?.addEventListener('click', (event) => {
    if (event.target === missionOverlay) closeMission();
  });

  $$('#autonomy .seg').forEach((seg) => {
    seg.addEventListener('click', () => {
      $$('#autonomy .seg').forEach((other) => other.classList.toggle('active', other === seg));
    });
  });

  function syncBudget() {
    if (budgetInput && budgetValue) budgetValue.textContent = `$${budgetInput.value}`;
  }

  budgetInput?.addEventListener('input', syncBudget);
  syncBudget();

  $('[data-launch-mission]')?.addEventListener('click', () => {
    const target = (targetInput?.value || 'the target').trim();
    const autonomy = ($('#autonomy .seg.active')?.textContent || 'Supervised').trim();
    const budget = budgetInput?.value || '60';
    closeMission();
    toast(
      'Mission queued',
      `${autonomy} mission on ${target}. Plan accepted: 7 tasks, 2 approval gates, $${budget} cap. Agents are starting.`,
      { icon: 'zap', duration: 6200 }
    );
  });

  /* ------------------------------------------------------------------ */
  /* Approvals                                                           */
  /* ------------------------------------------------------------------ */

  function refreshApprovalCount() {
    const card = $('.approval-card');
    if (!card) return;
    const pending = $$('.approval', card).filter((item) => !item.classList.contains('resolved')).length;
    const badge = $('.nav-badge', card);
    const sub = $('.card-sub', card);
    if (badge) {
      badge.textContent = String(pending);
      badge.classList.toggle('hot', pending > 0);
    }
    if (sub) sub.textContent = pending === 0 ? 'Queue clear · nice work' : `${pending} action${pending === 1 ? '' : 's'} need you`;
  }

  $$('[data-approval]').forEach((card) => {
    $('[data-approve]', card)?.addEventListener('click', (event) => {
      event.stopPropagation();
      card.classList.add('resolved');
      refreshApprovalCount();
      toast('Approved', 'The prober may run the authz test. Scope shield will enforce the 12 in-scope assets.', { icon: 'check' });
    });
    $('[data-decline]', card)?.addEventListener('click', (event) => {
      event.stopPropagation();
      card.classList.add('resolved');
      refreshApprovalCount();
      toast('Declined', 'The agent will propose an alternative or ask for guidance. Nothing was executed.', { icon: 'shield', tone: 'warning' });
    });
  });

  /* ------------------------------------------------------------------ */
  /* Pause and kill switch                                               */
  /* ------------------------------------------------------------------ */

  let paused = false;
  let killArmed = false;
  let killTimer = 0;

  const liveTag = $('.live-tag');
  const pauseButton = $('[data-pause]');

  function setLiveLabel(text) {
    if (!liveTag) return;
    Array.from(liveTag.childNodes).forEach((node) => {
      if (node.nodeType === Node.TEXT_NODE) node.nodeValue = ` ${text}`;
    });
  }

  pauseButton?.addEventListener('click', () => {
    paused = !paused;
    pauseButton.innerHTML = paused
      ? '<svg class="icon"><use href="#i-play"/></svg> Resume'
      : '<svg class="icon"><use href="#i-pause"/></svg> Pause';
    setLiveLabel(paused ? 'Mission paused' : 'Live mission');
    toast(
      paused ? 'Mission paused' : 'Mission resumed',
      paused ? 'Agents are holding state. No tool calls will run until you resume.' : 'Agents are picking up from the last checkpoint.',
      { icon: paused ? 'pause' : 'play', duration: 3200 }
    );
  });

  function resetKill() {
    killArmed = false;
    window.clearTimeout(killTimer);
    const kill = $('[data-kill]');
    if (kill) kill.innerHTML = '<svg class="icon"><use href="#i-x"/></svg> Kill switch';
  }

  $('[data-kill]')?.addEventListener('click', () => {
    const kill = $('[data-kill]');
    if (!kill) return;
    if (!killArmed) {
      killArmed = true;
      kill.innerHTML = '<svg class="icon"><use href="#i-x"/></svg> Confirm stop';
      toast('Kill switch armed', 'Press again within 4 seconds to stop every agent and close the sandbox. Evidence is preserved.', {
        icon: 'lock', tone: 'danger', duration: 4000
      });
      killTimer = window.setTimeout(resetKill, 4000);
      return;
    }
    resetKill();
    setLiveLabel('Mission stopped');
    if (liveTag) {
      const pulse = $('.pulse', liveTag);
      if (pulse) pulse.style.animation = 'none';
    }
    $$('.agent-card.active').forEach((card) => card.classList.remove('active'));
    toast('Mission stopped', 'All agents halted, sandbox closed, evidence chain sealed. Resume from the last checkpoint whenever you are ready.', {
      icon: 'shield', tone: 'danger', duration: 7000
    });
  });

  /* ------------------------------------------------------------------ */
  /* Findings data                                                       */
  /* ------------------------------------------------------------------ */

  const findings = {
    idor: {
      title: 'IDOR exposes cross-tenant user records',
      sev: 'critical', sevLabel: 'Critical',
      status: 'verified', statusClass: 'acid',
      cwe: 'CWE-639', cvss: 'CVSS 9.1',
      asset: 'api.acme.com', id: 'H-014', mission: 'Operation Nightfall',
      firstSeen: '14:35:19 UTC',
      confidence: '96%', impact: 'Cross-tenant read', bounty: '$3,500', duplicate: 'No match', duplicateClass: 'acid',
      readiness: { score: 94, repro: '3/3', impact: 'Proven', scope: 'Verified', duplicate: 'Clear', blocked: false, note: 'Ready to submit after your approval. Nothing else is blocking.' },
      summary:
        'The endpoint accepts a numeric user id and returns the full user object without checking that the object belongs to the caller\'s tenant. A user in tenant <span class="mono">acme</span> can read records from tenant <span class="mono">beta</span> by iterating the id space. The response includes email, role, and MFA state.',
      request:
        '<span class="c"># authenticated as tenant acme</span>\n' +
        '<span class="k">GET</span> /api/v1/users/8842 <span class="k">HTTP/1.1</span>\n' +
        '<span class="k">Host:</span> api.acme.com\n' +
        '<span class="k">Authorization:</span> Bearer <span class="s">acme-user-token</span>\n\n' +
        '<span class="c"># 200 OK · tenant beta object returned</span>\n' +
        '{"id":8842,"tenant":"beta","email":"...","role":"admin"}',
      evidence: [
        ['check', 'Candidate observed', 'seq 1712 · 14:35:19 · prober'],
        ['check', 'Independent replay 3/3', 'seq 1798 · 14:36:40 · assayer'],
        ['check', 'Scope and duplicate check passed', 'seq 1811 · 14:37:02 · chiron'],
        ['file', 'Report draft ready', 'quality 94 · HackerOne template']
      ]
    },
    oauth: {
      title: 'OAuth redirect_uri allows authorization code theft',
      sev: 'high', sevLabel: 'High',
      status: 'verifying', statusClass: 'orange',
      cwe: 'CWE-601', cvss: 'CVSS 8.1',
      asset: 'auth.acme.com', id: 'H-019', mission: 'Operation Nightfall',
      firstSeen: '14:41:02 UTC',
      confidence: '91%', impact: 'Authorization code theft', bounty: '$2,000', duplicate: 'Checking', duplicateClass: '',
      readiness: { score: 71, repro: 'Partial', impact: 'Proven', scope: 'Verified', duplicate: 'Checking', blocked: true, note: 'Second-identity replay is queued. Hold submission until it lands.' },
      summary:
        'The authorization endpoint accepts a <span class="mono">redirect_uri</span> whose path is not validated against the registered callback. A crafted link can send the authorization code to an attacker-controlled host, and the <span class="mono">state</span> parameter is not bound to the session.',
      request:
        '<span class="c"># victim opens a crafted link</span>\n' +
        '<span class="k">GET</span> /oauth/authorize?client_id=acme-web&redirect_uri=<span class="s">https://evil.example/cb</span>&amp;state=... <span class="k">HTTP/1.1</span>\n' +
        '<span class="k">Host:</span> auth.acme.com\n\n' +
        '<span class="c"># 302 Found · code delivered to the attacker host</span>',
      evidence: [
        ['check', 'Unregistered redirect accepted', 'seq 1822 · 14:41:08 · prober'],
        ['clock', 'Second identity replay', 'queued · awaiting approval'],
        ['eye', 'Severity held at High', 'provisional · critic pending']
      ]
    },
    s3: {
      title: 'S3 bucket allows anonymous listing',
      sev: 'high', sevLabel: 'High',
      status: 'verified', statusClass: 'acid',
      cwe: 'CWE-284', cvss: 'CVSS 7.5',
      asset: 'assets.acme.com', id: 'H-021', mission: 'Operation Nightfall',
      firstSeen: '14:22:41 UTC',
      confidence: '88%', impact: 'Object disclosure', bounty: '$1,500', duplicate: 'No match', duplicateClass: 'acid',
      readiness: { score: 91, repro: '2/2', impact: 'Proven', scope: 'Verified', duplicate: 'Clear', blocked: false, note: 'Ready. Draft and object inventory are attached to H-021.' },
      summary:
        'The bucket behind <span class="mono">assets.acme.com</span> allows anonymous <span class="mono">ListBucket</span> and <span class="mono">GetObject</span>. 1,204 objects are enumerable, including source maps and customer upload samples.',
      request:
        '<span class="k">GET</span> /?list-type=2 <span class="k">HTTP/1.1</span>\n' +
        '<span class="k">Host:</span> assets.acme.com\n\n' +
        '<span class="c"># 200 OK · ListBucketResult · 1,204 keys</span>',
      evidence: [
        ['check', 'Anonymous list returned 1,204 keys', 'seq 1688 · 14:22:41 · recon'],
        ['check', 'Object read confirmed', 'seq 1691 · 14:23:02 · prober'],
        ['file', 'Report draft ready', 'quality 91 · HackerOne template']
      ]
    },
    graphql: {
      title: 'GraphQL introspection enabled in production',
      sev: 'medium', sevLabel: 'Medium',
      status: 'triaged', statusClass: '',
      cwe: 'CWE-200', cvss: 'CVSS 5.3',
      asset: 'api.acme.com', id: 'H-024', mission: 'Operation Nightfall',
      firstSeen: '14:18:04 UTC',
      confidence: '84%', impact: 'Schema disclosure', bounty: '$750', duplicate: 'No match', duplicateClass: 'acid',
      readiness: { score: 64, repro: '1/1', impact: 'Informational', scope: 'Verified', duplicate: 'Clear', blocked: true, note: 'Impact is weak alone. Hold for a mutation or authz chain.' },
      summary:
        'The production GraphQL endpoint answers introspection queries. The full schema, including internal mutations and deprecated fields, is exposed. Impact is informational on its own; the schema is now feeding hypothesis generation.',
      request:
        '<span class="k">POST</span> /graphql <span class="k">HTTP/1.1</span>\n' +
        '<span class="k">Host:</span> api.acme.com\n' +
        '<span class="k">Content-Type:</span> application/json\n\n' +
        '{"query":"{ __schema { types { name fields { name } } } }"}',
      evidence: [
        ['check', 'Introspection returned 214 types', 'seq 1602 · 14:18:04 · prober'],
        ['database', 'Schema stored in target graph', 'seq 1605 · 14:18:22 · recon'],
        ['eye', 'Triaged as informational', 'seq 1610 · 14:19:01 · chiron']
      ]
    },
    debug: {
      title: 'Verbose stack traces on /debug endpoint',
      sev: 'medium', sevLabel: 'Medium',
      status: 'new', statusClass: '',
      cwe: 'CWE-209', cvss: 'CVSS 5.0',
      asset: 'staging.acme.com', id: 'H-027', mission: 'Operation Nightfall',
      firstSeen: '14:09:55 UTC',
      confidence: '79%', impact: 'Information disclosure', bounty: '$500', duplicate: 'Checking', duplicateClass: '',
      readiness: { score: 58, repro: '1/1', impact: 'Unproven', scope: 'Verified', duplicate: 'Checking', blocked: true, note: 'Sanitizer is queued. Do not promote until the four keys are triaged.' },
      summary:
        'The staging debug endpoint returns full stack traces and a configuration fragment. Four environment keys are visible in the response. A sanitizer is checking whether any value is sensitive before this is promoted.',
      request:
        '<span class="k">GET</span> /debug/config <span class="k">HTTP/1.1</span>\n' +
        '<span class="k">Host:</span> staging.acme.com\n\n' +
        '<span class="c"># 500 Internal Server Error · stack trace + env keys</span>',
      evidence: [
        ['check', '500 response with stack trace', 'seq 1544 · 14:09:55 · prober'],
        ['key', 'Four environment keys visible', 'seq 1546 · 14:10:12 · exegete'],
        ['clock', 'Sanitizer queued', 'next task · read-only']
      ]
    },
    headers: {
      title: 'Missing security headers on marketing site',
      sev: 'low', sevLabel: 'Low',
      status: 'new', statusClass: '',
      cwe: 'CWE-693', cvss: 'CVSS 3.1',
      asset: 'www.acme.com', id: 'H-030', mission: 'Operation Nightfall',
      firstSeen: '13:58:12 UTC',
      confidence: '72%', impact: 'Defense in depth', bounty: '$150', duplicate: 'No match', duplicateClass: 'acid',
      readiness: { score: 42, repro: '1/1', impact: 'Hardening', scope: 'Verified', duplicate: 'Clear', blocked: true, note: 'Hardening only. Submit only with a chained injection that proves impact.' },
      summary:
        'The marketing site omits CSP, HSTS, and <span class="mono">X-Content-Type-Options</span>. This is hardening, not an exploit. It is queued as a low-priority report unless a chained injection gives it impact.',
      request:
        '<span class="k">HEAD</span> / <span class="k">HTTP/1.1</span>\n' +
        '<span class="k">Host:</span> www.acme.com\n\n' +
        '<span class="c"># 200 OK · no CSP · no HSTS · nosniff absent</span>',
      evidence: [
        ['check', 'Header baseline recorded', 'seq 1470 · 13:58:12 · recon'],
        ['eye', 'Marked low / hardening', 'seq 1474 · 13:58:40 · chiron'],
        ['file', 'Report draft queued', 'quality pending']
      ]
    }
  };

  function evidenceHTML(items) {
    return items.map(([icon, title, meta]) =>
      `<div class="evidence-row"><svg class="icon"><use href="#i-${icon}"/></svg>` +
      `<div class="evidence-copy"><strong>${title}</strong><span>${meta}</span></div></div>`
    ).join('');
  }

  function detailMeta(finding) {
    return [finding.confidence, finding.impact, finding.bounty, finding.duplicate].map((value, index) => {
      if (index !== 3 || !finding.duplicateClass) return value;
      return `<span class="${finding.duplicateClass}">${value}</span>`;
    });
  }

  function updateDetailPanel(key) {
    const finding = findings[key];
    const panel = $('.detail');
    if (!finding || !panel) return;

    const top = $('.detail-top', panel);
    const sev = $('.sev', top);
    const chips = $$('.chip', top);
    sev.className = `sev ${finding.sev}`;
    sev.textContent = finding.sevLabel;
    if (chips[0]) {
      chips[0].className = `chip ${finding.statusClass}`.trim();
      chips[0].textContent = finding.status;
    }
    if (chips[1]) chips[1].textContent = finding.cwe;
    if (chips[2]) chips[2].textContent = finding.cvss;

    $('.detail-title', panel).textContent = finding.title;
    $('.detail-sub', panel).textContent =
      `${finding.id} · ${finding.asset} · ${finding.mission} · first seen ${finding.firstSeen}`;

    const metaValues = $$('.detail-meta-value', panel);
    detailMeta(finding).forEach((value, index) => {
      if (metaValues[index]) metaValues[index].innerHTML = value;
    });

    const summary = $('.detail-section p', panel);
    if (summary) summary.innerHTML = finding.summary;

    const code = $('.code-block', panel);
    if (code) code.innerHTML = finding.request;

    const chain = $$('.detail-section', panel)[2];
    if (chain) {
      const rows = $$('.evidence-row', chain);
      if (rows.length) rows[0].parentElement.innerHTML = `<h3>Evidence chain</h3>${evidenceHTML(finding.evidence)}`;
    }

    const readiness = finding.readiness;
    const readinessBox = $('.readiness', panel);
    if (readiness && readinessBox) {
      $('#readiness-score', readinessBox).textContent = readiness.score;
      $('#readiness-fill', readinessBox).style.width = `${readiness.score}%`;
      $('#readiness-repro', readinessBox).textContent = readiness.repro;
      $('#readiness-impact', readinessBox).textContent = readiness.impact;
      $('#readiness-scope', readinessBox).textContent = readiness.scope;
      $('#readiness-duplicate', readinessBox).textContent = readiness.duplicate;
      $('#readiness-note', readinessBox).textContent = readiness.note;
      readinessBox.classList.toggle('is-blocked', readiness.blocked);
      const noteIcon = $('.readiness-note use', readinessBox);
      if (noteIcon) noteIcon.setAttribute('href', readiness.blocked ? '#i-clock' : '#i-check');
    }

    if (!reducedMotion) {
      panel.classList.remove('screen-in');
      void panel.offsetWidth;
      panel.classList.add('screen-in');
    }
  }

  /* ------------------------------------------------------------------ */
  /* Finding drawer                                                      */
  /* ------------------------------------------------------------------ */

  const drawerWrap = $('#drawer-wrap');
  const drawerSev = $('#drawer-sev');
  const drawerTitle = $('#drawer-title');
  const drawerSub = $('#drawer-sub');
  const drawerSummary = $('#drawer-summary');
  const drawerEvidence = $('.drawer-body .evidence-row')?.parentElement;
  const drawerRequest = $('.drawer-body .code-block');
  let lastFocused = null;

  function openDrawer(key) {
    const finding = findings[key];
    if (!finding || !drawerWrap) return;
    lastFocused = document.activeElement;
    drawerSev.className = `sev ${finding.sev}`;
    drawerSev.textContent = finding.sevLabel;
    drawerTitle.textContent = finding.title;
    drawerSub.textContent = `${finding.id} · ${finding.asset} · ${finding.status}`;
    drawerSummary.innerHTML = finding.summary;
    const confidence = $('#drawer-confidence');
    const impact = $('#drawer-impact');
    const bounty = $('#drawer-bounty');
    const duplicate = $('#drawer-duplicate');
    if (confidence) confidence.textContent = finding.confidence;
    if (impact) impact.textContent = finding.impact;
    if (bounty) bounty.textContent = finding.bounty;
    if (duplicate) {
      duplicate.textContent = finding.duplicate;
      duplicate.className = finding.duplicateClass || '';
    }
    if (drawerEvidence) drawerEvidence.innerHTML = `<h3>Evidence</h3>${evidenceHTML(finding.evidence)}`;
    if (drawerRequest) drawerRequest.innerHTML = finding.request;
    drawerWrap.classList.add('open');
    drawerWrap.setAttribute('aria-hidden', 'false');
    window.requestAnimationFrame(() => $('[data-close-drawer]', drawerWrap)?.focus());
  }

  function closeDrawer() {
    if (!drawerWrap) return;
    drawerWrap.classList.remove('open');
    drawerWrap.setAttribute('aria-hidden', 'true');
    if (lastFocused && typeof lastFocused.focus === 'function') lastFocused.focus();
  }

  $$('[data-close-drawer]').forEach((btn) => btn.addEventListener('click', closeDrawer));

  $$('.table tbody tr[data-finding]').forEach((row) => {
    row.addEventListener('click', () => {
      $$('.table tbody tr[data-finding]').forEach((other) => other.classList.toggle('is-active', other === row));
      openDrawer(row.dataset.finding);
    });
  });

  $$('.inbox-item[data-finding]').forEach((item) => {
    item.addEventListener('click', () => {
      $$('.inbox-item').forEach((other) => other.classList.toggle('active', other === item));
      if (window.innerWidth < 980) {
        openDrawer(item.dataset.finding);
      } else {
        updateDetailPanel(item.dataset.finding);
      }
    });
  });

  /* Update the Findings detail panel to match the first inbox item on load. */
  updateDetailPanel('idor');

  function focusFinding(key) {
    if (!findings[key]) return;
    navigate('findings');
    const item = $(`.inbox-item[data-finding="${key}"]`);
    if (item) {
      $$('.inbox-item').forEach((other) => other.classList.toggle('active', other === item));
      item.scrollIntoView({ block: 'nearest', behavior: reducedMotion ? 'auto' : 'smooth' });
    }
    if (window.innerWidth < 980) openDrawer(key);
    else updateDetailPanel(key);
  }

  /* ------------------------------------------------------------------ */
  /* Copilot                                                             */
  /* ------------------------------------------------------------------ */

  const copilotWrap = $('#copilot-wrap');
  const copilotChat = $('#copilot-chat');
  const copilotInput = $('#copilot-input');
  let copilotLastFocus = null;

  function openCopilot() {
    if (!copilotWrap) return;
    closePalette();
    closeDrawer();
    copilotLastFocus = document.activeElement;
    copilotWrap.classList.add('open');
    copilotWrap.setAttribute('aria-hidden', 'false');
    window.requestAnimationFrame(() => {
      copilotInput?.focus();
      if (copilotChat) copilotChat.scrollTop = copilotChat.scrollHeight;
    });
  }

  function closeCopilot() {
    if (!copilotWrap) return;
    copilotWrap.classList.remove('open');
    copilotWrap.setAttribute('aria-hidden', 'true');
    if (copilotLastFocus && typeof copilotLastFocus.focus === 'function') copilotLastFocus.focus();
  }

  $$('[data-open-copilot]').forEach((btn) => btn.addEventListener('click', openCopilot));
  $$('[data-close-copilot]').forEach((btn) => btn.addEventListener('click', closeCopilot));
  copilotWrap?.addEventListener('click', (event) => {
    if (event.target === copilotWrap) closeCopilot();
  });

  function appendMessage(role, html, cites = []) {
    if (!copilotChat) return null;
    const msg = document.createElement('div');
    msg.className = `msg ${role}`;
    const roleEl = document.createElement('div');
    roleEl.className = 'msg-role';
    if (role === 'assistant') {
      roleEl.innerHTML = '<span class="status-dot"></span> copilot';
    } else {
      roleEl.textContent = 'you';
    }
    const body = document.createElement('p');
    if (role === 'user') body.textContent = html;
    else body.innerHTML = html;
    msg.append(roleEl, body);
    if (cites.length) {
      const citeWrap = document.createElement('div');
      citeWrap.className = 'msg-cites';
      cites.forEach((cite) => {
        const span = document.createElement('span');
        span.textContent = cite;
        citeWrap.append(span);
      });
      msg.append(citeWrap);
    }
    copilotChat.append(msg);
    copilotChat.scrollTop = copilotChat.scrollHeight;
    return msg;
  }

  function copilotReply(prompt) {
    const text = prompt.toLowerCase();
    if (text.includes('report') || text.includes('draft') || text.includes('submit')) {
      return {
        html: 'The HackerOne draft for <strong>H-014</strong> is ready. Quality score 94/100, evidence attached, duplicate check clean. It still needs your approval before submission, and the platform gate will hold it until then.',
        cites: ['quality 94', 'seq 1811', 'approval required']
      };
    }
    if (text.includes('next') || text.includes('test') || text.includes('should we') || text.includes('priority')) {
      return {
        html: 'Best next move: pivot <strong>H-014</strong> to the admin API. The same object reference appears in four privileged endpoints. Estimated 12 minutes, confidence 0.84, read-only until you approve the active test.',
        cites: ['confidence 0.84', '~12 min', 'read-only']
      };
    }
    if (text.includes('scope') || text.includes('safe') || text.includes('allowed') || text.includes('out of')) {
      return {
        html: 'Scope shield is enforcing <strong>12 assets</strong> and zero violations. Every tool call is checked against the signed mission capsule. Anything outside the capsule is refused before a request leaves the sandbox.',
        cites: ['12 assets', '0 violations', 'signed capsule']
      };
    }
    if (text.includes('oauth') || text.includes('h-019')) {
      return {
        html: '<strong>H-019</strong> is still verifying. The unregistered <span class="mono">redirect_uri</span> was accepted, but the second-identity replay is queued behind an approval gate. I would not submit it until that replay lands and the critic checks state binding.',
        cites: ['seq 1822', 'replay queued', 'confidence 0.91']
      };
    }
    if (text.includes('idor') || text.includes('h-014') || text.includes('critical') || text.includes('evidence') || text.includes('why')) {
      return {
        html: '<strong>H-014</strong> is a cross-tenant IDOR on <span class="mono">GET /api/v1/users/{id}</span>. Tenant <span class="mono">acme</span> can read tenant <span class="mono">beta</span> records including email, role, and MFA state. It was replayed 3/3 with a fresh session, scope passed, and duplicate scanning found no match.',
        cites: ['seq 1712', 'seq 1798', 'seq 1811', 'CVSS 9.1']
      };
    }
    if (text.includes('hello') || text.includes('hi') || text === 'hey') {
      return {
        html: 'I am here. I can explain any finding, rank the next tests, check scope, or turn evidence into a platform-ready draft. What do you want to look at?',
        cites: []
      };
    }
    return {
      html: 'I can help with evidence, scope, next tests, or a report draft. Try <strong>“what should we test next?”</strong> or <strong>“draft the HackerOne report”</strong>. I will always cite the mission events behind an answer.',
      cites: []
    };
  }

  function askCopilot(prompt) {
    const question = (prompt || '').trim();
    if (!question) return;
    appendMessage('user', question);
    if (copilotInput) {
      copilotInput.value = '';
      copilotInput.focus();
    }
    const typing = appendMessage('assistant', 'Thinking with mission context');
    if (typing) typing.classList.add('typing');
    window.setTimeout(() => {
      typing?.remove();
      const reply = copilotReply(question);
      appendMessage('assistant', reply.html, reply.cites);
    }, reducedMotion ? 120 : 640);
  }

  $('#copilot-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    askCopilot(copilotInput?.value || '');
  });

  $$('.copilot-chip').forEach((chip) => {
    chip.addEventListener('click', () => askCopilot(chip.dataset.prompt || chip.textContent));
  });

  /* ------------------------------------------------------------------ */
  /* Tabs: timeline and findings table                                   */
  /* ------------------------------------------------------------------ */

  $$('.timeline .tl-item').forEach((item) => {
    const meta = (item.querySelector('.tl-meta')?.textContent || '').toLowerCase();
    const chip = (item.querySelector('.tl-badge')?.textContent || '').toLowerCase();
    if (meta.includes('prober') || meta.includes('recon')) item.dataset.kind = 'tool';
    else if (chip.includes('evidence') || chip.includes('verified') || chip.includes('pass')) item.dataset.kind = 'evidence';
    else item.dataset.kind = 'agent';
  });

  const timelineCard = $('.timeline-card');
  $$('.tabs .tab', timelineCard).forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('.tabs .tab', timelineCard).forEach((other) => other.classList.toggle('active', other === tab));
      const label = tab.textContent.trim().toLowerCase();
      $$('.timeline .tl-item', timelineCard).forEach((item) => {
        const show = label === 'all' || item.dataset.kind === label;
        item.classList.toggle('hidden', !show);
      });
    });
  });

  const findingsTableCard = $('.findings-card');
  $$('.tabs .tab', findingsTableCard).forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('.tabs .tab', findingsTableCard).forEach((other) => other.classList.toggle('active', other === tab));
      const label = tab.textContent.trim().toLowerCase();
      const tbody = $('tbody', findingsTableCard);
      let visible = 0;
      $$('tr[data-finding]', tbody).forEach((row) => {
        const state = (row.querySelector('.chip')?.textContent || '').trim().toLowerCase();
        const show = label === 'open' || (label === 'verified' && state === 'verified');
        row.classList.toggle('hidden', !show);
        if (show) visible += 1;
      });
      let empty = $('.empty-row', tbody);
      if (label === 'submitted' || visible === 0) {
        if (!empty) {
          empty = document.createElement('tr');
          empty.className = 'empty-row';
          empty.innerHTML = `<td colspan="7"><strong>Nothing here yet.</strong> Approve the IDOR draft to send the first submission.</td>`;
          tbody.append(empty);
        }
        empty.classList.remove('hidden');
      } else if (empty) {
        empty.classList.add('hidden');
      }
    });
  });

  /* ------------------------------------------------------------------ */
  /* Agent Studio tabs                                                   */
  /* ------------------------------------------------------------------ */

  $$('.studio-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const name = tab.dataset.studioTab;
      $$('.studio-tab').forEach((other) => other.classList.toggle('active', other === tab));
      $$('.studio-panel').forEach((panel) => { panel.hidden = panel.dataset.studioPanel !== name; });
    });
  });

  /* ------------------------------------------------------------------ */
  /* Stub actions                                                        */
  /* ------------------------------------------------------------------ */

  document.addEventListener('click', (event) => {
    const stub = event.target.closest('[data-stub]');
    if (!stub) return;
    event.preventDefault();
    toast(
      stub.dataset.stub,
      'Mapped in the blueprint. This prototype focuses on Command Center, Findings, and Agent Studio; the rest is the next milestone.',
      { icon: 'sparkles', tone: 'info', duration: 4200 }
    );
  });

  /* ------------------------------------------------------------------ */
  /* KPI counters                                                        */
  /* ------------------------------------------------------------------ */

  function animateCounters() {
    if (reducedMotion) return;
    $$('[data-count]').forEach((el) => {
      const target = parseFloat(el.dataset.count || '0');
      const suffix = el.dataset.suffix || '';
      const decimals = String(el.dataset.count).includes('.') ? 1 : 0;
      const start = performance.now();
      const duration = 900;
      const step = (now) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3);
        el.textContent = `${(target * eased).toFixed(decimals)}${suffix}`;
        if (t < 1) window.requestAnimationFrame(step);
        else el.textContent = `${target.toFixed(decimals)}${suffix}`;
      };
      window.requestAnimationFrame(step);
    });
  }

  animateCounters();

  /* ------------------------------------------------------------------ */
  /* Ambient agent activity                                              */
  /* ------------------------------------------------------------------ */

  const agentMessages = [
    'Following a new bundle reference. 3 endpoints queued.',
    'Replaying the last proof with a fresh session.',
    'Ranking hypotheses. Cross-tenant path still leads.',
    'Checking scope. All 12 assets remain eligible.',
    'Mapping a new data-flow sink in the auth bundle.',
    'Waiting on your decision. No tool calls running.'
  ];

  if (!reducedMotion) {
    window.setInterval(() => {
      const cards = $$('.agent-card.active .agent-action');
      if (!cards.length) return;
      const card = cards[Math.floor(Math.random() * cards.length)];
      const next = agentMessages[Math.floor(Math.random() * agentMessages.length)];
      card.style.opacity = '0';
      window.setTimeout(() => {
        card.textContent = next;
        card.style.opacity = '1';
      }, 180);
    }, 7200);
  }

  /* ------------------------------------------------------------------ */
  /* Keyboard                                                            */
  /* ------------------------------------------------------------------ */

  let lastKey = '';
  let lastKeyAt = 0;

  document.addEventListener('keydown', (event) => {
    const target = event.target;
    const typing =
      target instanceof HTMLElement &&
      (target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT' ||
        target.isContentEditable);

    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      if (paletteOverlay?.classList.contains('open')) closePalette();
      else openPalette();
      return;
    }

    if (event.key === 'Escape') {
      if (paletteOverlay?.classList.contains('open')) closePalette();
      else if (missionOverlay?.classList.contains('open')) closeMission();
      else if (drawerWrap?.classList.contains('open')) closeDrawer();
      else if (copilotWrap?.classList.contains('open')) closeCopilot();
      return;
    }

    if (typing) return;

    if (event.key === '/') {
      event.preventDefault();
      openPalette();
      return;
    }

    if (event.key.toLowerCase() === 'n') {
      event.preventDefault();
      openMission();
      return;
    }

    if (event.key === '?') {
      toast('Keyboard', 'Ctrl K search · N new mission · G then C/M/F/A to jump · Esc to close. The Copilot button is in the top bar.', {
        icon: 'terminal', duration: 5200
      });
      return;
    }

    const now = Date.now();
    if (lastKey === 'g' && now - lastKeyAt < 900) {
      const map = { c: 'command', m: 'missions', f: 'findings', a: 'studio' };
      const view = map[event.key.toLowerCase()];
      if (view) {
        event.preventDefault();
        navigate(view);
        lastKey = '';
        return;
      }
    }
    lastKey = event.key.toLowerCase();
    lastKeyAt = now;
  });

  /* Cmd/Ctrl+Enter submits the mission composer. */
  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && missionOverlay?.classList.contains('open')) {
      event.preventDefault();
      $('[data-launch-mission]')?.click();
    }
  });

  /* ------------------------------------------------------------------ */
  /* First-run hint                                                      */
  /* ------------------------------------------------------------------ */

  window.setTimeout(() => {
    if (sessionStorage.getItem('nc-hint-shown')) return;
    sessionStorage.setItem('nc-hint-shown', '1');
    toast('Prototype controls are live', 'Try Ctrl K, the Copilot, the approval queue, the kill switch, or click a finding. Nav items beyond the three screens are placeholders.', {
      icon: 'sparkles', duration: 6800
    });
  }, 1400);
})();
