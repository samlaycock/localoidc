// localoidc claims wizard — shared by the login, device and token generator pages.
//
// Saved identities sit at the top for one-click reuse; below them a short wizard
// (provider -> claims -> custom claims [-> token options]) builds a new identity.
// The page's own submit buttons stay server-rendered so it works without JS too.
(function () {
  'use strict';
  const dataEl = document.getElementById('lo-data');
  if (!dataEl) return;
  const data = JSON.parse(dataEl.textContent);
  const presets = data.presets;
  const byId = Object.fromEntries(presets.map((p) => [p.id, p]));
  const LS_SAVED = 'localoidc.identities';
  const LS_LAST = 'localoidc.last';
  const root = document.getElementById('lo-editor');
  const form = document.getElementById('lo-form');
  const isDev = data.mode === 'dev';
  const $ = (id) => document.getElementById(id);

  const h = (tag, attrs = {}, ...children) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.className = v;
      else if (k === 'style') el.setAttribute('style', v);
      else if (k === 'value') el.value = v;
      else if (k in el && typeof v !== 'string') el[k] = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null) el.append(c.nodeType ? c : document.createTextNode(c));
    return el;
  };

  // ---------------------------------------------------------------- identity state
  const state = { preset: null, values: {}, custom: '', access: '', step: 0, showAll: false };

  const fieldText = (f, v) => {
    if (v === undefined || v === null) return f.kind === 'bool' ? false : '';
    if (f.kind === 'bool') return !!v;
    if (f.kind === 'json') {
      const compact = JSON.stringify(v);
      return compact.length <= 60 ? compact : JSON.stringify(v, null, 2);
    }
    return String(v);
  };

  /** Load an identity into the editor; with no claims, switch preset and keep custom claims. */
  function load(presetId, claims, accessClaims) {
    const p = byId[presetId] || byId[data.defaultPreset] || presets[0];
    state.preset = p.id;
    state.values = {};
    for (const f of p.fields) state.values[f.name] = fieldText(f, claims ? claims[f.name] : f.default);
    if (!claims) return;
    const names = new Set(p.fields.map((f) => f.name));
    const custom = {};
    for (const [k, v] of Object.entries(claims)) {
      if (names.has(k) || (k === 'sub' && p.sub_from)) continue;
      custom[k] = v;
    }
    state.custom = Object.keys(custom).length ? JSON.stringify(custom, null, 2) : '';
    state.access = accessClaims && Object.keys(accessClaims).length ? JSON.stringify(accessClaims, null, 2) : '';
  }

  function applyLoginHint(hint) {
    if (!hint) return;
    const has = (n) => byId[state.preset].fields.some((f) => f.name === n);
    if (hint.includes('@')) {
      if (has('email')) state.values.email = hint;
    } else {
      const key = ['preferred_username', 'login', 'username', 'nickname', 'cognito:username'].find(has);
      if (key) state.values[key] = hint;
    }
  }

  /** Build {claims, access, errors} from the editor state. */
  function build() {
    const p = byId[state.preset];
    const claims = {};
    const errors = [];
    for (const f of p.fields) {
      const v = state.values[f.name];
      if (f.kind === 'bool') claims[f.name] = !!v;
      else if (f.kind === 'number') {
        if (v !== '' && v != null) {
          const n = Number(v);
          if (Number.isNaN(n)) errors.push(`${f.label}: not a number`);
          else claims[f.name] = n;
        }
      } else if (f.kind === 'json') {
        if (v && String(v).trim()) {
          try { claims[f.name] = JSON.parse(v); } catch { errors.push(`${f.label}: invalid JSON`); }
        }
      } else if (v !== '' && v != null) claims[f.name] = v;
    }
    const parseObj = (text, label) => {
      if (!text || !text.trim()) return {};
      try {
        const o = JSON.parse(text);
        if (o && typeof o === 'object' && !Array.isArray(o)) return o;
        errors.push(`${label}: must be a JSON object`);
      } catch (e) { errors.push(`${label}: ${e.message}`); }
      return {};
    };
    for (const [k, v] of Object.entries(parseObj(state.custom, 'Custom claims'))) {
      if (v === null) delete claims[k]; else claims[k] = v;
    }
    if (!claims.sub && p.sub_from && claims[p.sub_from] != null) claims.sub = String(claims[p.sub_from]);
    return { claims, access: parseObj(state.access, 'Access token claims'), errors };
  }

  const describe = (claims) => claims.email || claims.name || claims.preferred_username || claims.login || claims.username || claims.sub || 'identity';

  // ---------------------------------------------------------------- saved identities
  const readJson = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
  const saved = () => readJson(LS_SAVED, []);
  const storeSaved = (list) => localStorage.setItem(LS_SAVED, JSON.stringify(list));
  const rememberLast = (identity) => localStorage.setItem(LS_LAST, JSON.stringify(identity));

  function saveCurrent(name) {
    const { claims, access, errors } = build();
    if (errors.length) { refresh(); return false; }
    const next = saved().filter((s) => s.name !== name);
    next.unshift({ name, preset: state.preset, claims, access });
    storeSaved(next);
    return true;
  }

  // ---------------------------------------------------------------- actions
  /** Sign in (login/device) or generate tokens (dev) with the current editor contents. */
  function go() {
    if (isDev) { $('dev-generate').click(); return; }
    form.requestSubmit(form.querySelector('button[value=approve]'));
  }

  function useIdentity(identity) {
    load(identity.preset, identity.claims, identity.access);
    render();
    go();
  }

  function editIdentity(identity) {
    load(identity.preset, identity.claims, identity.access);
    state.step = 1;
    render();
  }

  // ---------------------------------------------------------------- rendering
  const STEPS = [
    { id: 'provider', label: 'Provider' },
    { id: 'claims', label: 'Claims' },
    { id: 'custom', label: 'Custom claims' },
    ...(isDev ? [{ id: 'options', label: 'Token options' }] : []),
  ];
  const actionWord = isDev ? 'Generate as' : 'Sign in as';
  let previewEl, errorEl;

  function refresh() {
    const { claims, access, errors } = build();
    if (previewEl) {
      const preview = { ...claims };
      if (Object.keys(access).length) preview['(access token only)'] = access;
      previewEl.textContent = JSON.stringify(preview, null, 2);
    }
    if (errorEl) {
      errorEl.textContent = errors.join(' · ');
      errorEl.hidden = !errors.length;
    }
    const nameInput = $('lo-save-name');
    if (nameInput && !nameInput.dataset.touched) nameInput.value = describe(claims);
  }

  function quickSection() {
    const items = [];
    if (data.previous && !isDev) items.push({ kind: 'session', label: 'Active session', identity: { ...data.previous, access: data.previous.access_claims } });
    // Users declared in localoidc.toml, shared by everyone using this server.
    (data.users || []).forEach((u) => items.push({ kind: 'user', label: u.label || u.id, identity: u }));
    // "Last used" only when it isn't already offered as the session, a user or a saved identity.
    // Key order differs between the server (sorted) and the editor (field order), so sort it away.
    const stable = (v) => Array.isArray(v) ? `[${v.map(stable).join(',')}]`
      : v && typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`
      : JSON.stringify(v);
    const key = (i) => stable([i.preset, i.claims]);
    const last = readJson(LS_LAST, null);
    const offered = new Set([...items.map((i) => key(i.identity)), ...saved().map(key)]);
    if (last && !offered.has(key(last))) items.push({ kind: 'last', label: 'Last used', identity: last });
    saved().forEach((s, i) => items.push({ kind: 'saved', label: s.name, identity: s, index: i }));

    const cards = items.map((item) => {
      const p = byId[item.identity.preset] || presets[0];
      const who = describe(item.identity.claims || {});
      const named = item.kind === 'saved' || item.kind === 'user';
      return h('div', { class: `quick-card is-${item.kind}`, style: `--c:${p.color}` },
        h('div', { class: 'quick-meta' },
          h('span', { class: 'quick-label' }, named ? item.label : h('span', {}, h('em', {}, item.label), ` · ${who}`)),
          h('span', { class: 'quick-provider' }, h('span', { class: 'dot' }), p.name, named && item.label !== who ? ` · ${who}` : null,
            item.kind === 'user' ? h('span', { class: 'quick-tag', title: 'Declared in localoidc.toml' }, 'config') : null)),
        h('div', { class: 'quick-actions' },
          h('button', { type: 'button', class: 'btn small primary', onclick: () => useIdentity(item.identity) }, isDev ? 'Generate' : 'Sign in'),
          h('button', { type: 'button', class: 'btn small ghost', onclick: () => editIdentity(item.identity) }, 'Edit'),
          item.kind === 'saved'
            ? h('button', { type: 'button', class: 'btn small ghost icon', title: 'Delete', onclick: () => {
                const list = saved(); list.splice(item.index, 1); storeSaved(list); render();
              } }, '×')
            : null));
    });

    return h('section', { class: 'quick' },
      h('div', { class: 'section-title' }, isDev ? 'Saved identities' : 'Quick sign in'),
      cards.length
        ? h('div', { class: 'quick-list' }, cards)
        : h('p', { class: 'muted small' }, 'Identities you save (bottom of the page) show up here for one-click reuse.'));
  }

  function stepNav() {
    return h('nav', { class: 'steps' }, STEPS.map((s, i) =>
      h('button', {
        type: 'button',
        class: `step ${i === state.step ? 'current' : ''} ${i < state.step ? 'done' : ''}`,
        onclick: () => { state.step = i; render(); },
      }, h('span', { class: 'step-num' }, String(i + 1)), s.label)));
  }

  function fieldInput(f) {
    const v = state.values[f.name];
    const id = `f-${f.name.replace(/[^a-z0-9]/gi, '_')}`;
    const set = (val) => { state.values[f.name] = val; refresh(); };
    if (f.kind === 'bool') {
      return h('label', { class: 'field check-field', for: id, title: f.help || '' },
        h('input', { type: 'checkbox', id, checked: !!v, onchange: (e) => set(e.target.checked) }),
        h('span', {}, f.label), h('code', { class: 'claim-name' }, f.name));
    }
    let input;
    if (f.kind === 'json') {
      input = h('textarea', { id, rows: String(v).includes('\n') ? 4 : 1, spellcheck: false, oninput: (e) => set(e.target.value) });
      input.value = v;
    } else {
      input = h('input', { id, type: f.kind === 'number' ? 'number' : 'text', value: v, spellcheck: false, oninput: (e) => set(e.target.value) });
    }
    return h('label', { class: `field ${f.kind === 'json' ? 'wide' : ''}`, for: id },
      h('span', { class: 'field-label' }, f.label, h('code', { class: 'claim-name' }, f.name)),
      input,
      f.help ? h('small', { class: 'help' }, f.help) : null);
  }

  function providerStep() {
    const pinned = data.tenantPreset ? byId[data.tenantPreset] : null;
    return [
      h('p', { class: 'muted step-intro' }, 'Which identity provider should this look like? This sets the claim names and token formats.',
        pinned ? ` This issuer emulates ${pinned.name}.` : ''),
      h('div', { class: 'provider-grid' }, presets.map((q) =>
        h('button', {
          type: 'button',
          class: `provider-card ${q.id === state.preset ? 'active' : ''}`,
          style: `--c:${q.color}`,
          onclick: () => { if (q.id !== state.preset) load(q.id, null, null); state.step = 1; render(); },
        },
        h('span', { class: 'provider-name' }, h('span', { class: 'dot' }), q.name, q.protocol === 'oauth2' ? h('small', {}, 'OAuth2') : null),
        h('span', { class: 'provider-desc' }, q.description)))),
    ];
  }

  function claimsStep() {
    const p = byId[state.preset];
    const common = p.fields.filter((f) => !f.advanced);
    const advanced = p.fields.filter((f) => f.advanced);
    return [
      h('p', { class: 'muted step-intro' }, `${p.name} claims. Empty fields are left out of the token.`),
      h('div', { class: 'fields' }, common.map(fieldInput)),
      advanced.length
        ? h('button', { type: 'button', class: 'btn small ghost more', onclick: () => { state.showAll = !state.showAll; render(); } },
            state.showAll ? 'Hide extra claims' : `Show all claims (${advanced.length} more)`)
        : null,
      state.showAll && advanced.length ? h('div', { class: 'fields' }, advanced.map(fieldInput)) : null,
    ];
  }

  function customStep() {
    const custom = h('textarea', { rows: 6, spellcheck: false, placeholder: '{\n  "https://example.com/tenant": "acme",\n  "permissions": ["read", "write"],\n  "locale": null\n}', oninput: (e) => { state.custom = e.target.value; refresh(); } });
    custom.value = state.custom;
    const access = h('textarea', { rows: 4, spellcheck: false, placeholder: '{\n  "permissions": ["orders:write"]\n}', oninput: (e) => { state.access = e.target.value; refresh(); } });
    access.value = state.access;
    previewEl = h('pre', { class: 'code preview' });
    return [
      h('p', { class: 'muted step-intro' }, 'Optional. Add or override any claim; null removes one. Reserved claims like aud or exp can be overridden for negative tests.'),
      h('div', { class: 'customs' },
        h('label', { class: 'field wide' }, h('span', { class: 'field-label' }, 'Custom claims', h('small', { class: 'muted' }, 'ID token, userinfo and access token')), custom),
        h('label', { class: 'field wide' }, h('span', { class: 'field-label' }, 'Access-token-only claims'), access)),
      h('div', { class: 'section-title' }, 'Preview ', h('small', { class: 'muted' }, '(iss, aud, exp, nonce… are added by the server)')),
      previewEl,
    ];
  }

  let devOptions;
  // The token options panel is only in the document on its step, so look inside it directly.
  const opt = (id) => devOptions.querySelector(`#${id}`);
  function optionsStep() {
    devOptions.hidden = false;
    return [h('p', { class: 'muted step-intro' }, 'Who the tokens are for and how long they last.'), devOptions];
  }

  function render() {
    previewEl = null;
    const step = STEPS[state.step].id;
    const panel = { provider: providerStep, claims: claimsStep, custom: customStep, options: optionsStep }[step]();
    const last = state.step === STEPS.length - 1;
    errorEl = h('p', { class: 'notice error', hidden: true });
    root.replaceChildren(
      quickSection(),
      h('section', { class: 'wizard' },
        h('div', { class: 'section-title' }, isDev ? 'New token' : 'New identity'),
        stepNav(),
        h('div', { class: 'step-panel' }, panel),
        h('div', { class: 'step-footer' },
          state.step > 0 ? h('button', { type: 'button', class: 'btn small ghost', onclick: () => { state.step--; render(); } }, '← Back') : h('span'),
          !last ? h('button', { type: 'button', class: 'btn small', onclick: () => { state.step++; render(); } }, `Next: ${STEPS[state.step + 1].label} →`) : null)),
      errorEl);
    refresh();
  }

  /** "Save as …" sits next to the page's Sign in / Generate button, so it's visible at every step. */
  function mountSaveBar() {
    const actions = (form || root.parentElement).querySelector('.actions');
    const name = h('input', { id: 'lo-save-name', class: 'save-name', placeholder: 'Name', oninput: (e) => (e.target.dataset.touched = '1') });
    const btn = h('button', { type: 'button', class: 'btn ghost', onclick: () => {
      const label = name.value.trim() || describe(build().claims);
      if (saveCurrent(label)) { btn.textContent = 'Saved ✓'; setTimeout(() => (btn.textContent = 'Save identity'), 1400); render(); }
    } }, 'Save identity');
    actions.classList.add('action-bar');
    actions.append(h('div', { class: 'save-bar' }, name, btn));
  }

  function syncHidden() {
    const { claims, access, errors } = build();
    if (!errors.length) rememberLast({ preset: state.preset, claims, access });
    if (!form) return errors;
    form.elements.preset.value = state.preset;
    form.elements.claims.value = JSON.stringify(claims);
    form.elements.access_claims.value = JSON.stringify(access);
    return errors;
  }

  // ---------------------------------------------------------------- init
  if (isDev) {
    devOptions = $('dev-options');
    devOptions.remove();
  }
  const prev = data.previous;
  if (prev && byId[prev.preset] && !isDev) load(prev.preset, prev.claims, prev.access_claims);
  else load(data.defaultPreset, null, null);
  applyLoginHint(data.loginHint);
  if (data.tenantPreset) state.step = 1;
  render();
  mountSaveBar();
  refresh(); // fills in the save bar's suggested name

  if (form) {
    form.addEventListener('submit', (e) => {
      if (e.submitter && e.submitter.value === 'deny') return;
      const errors = syncHidden();
      if (errors.length) { e.preventDefault(); refresh(); errorEl.scrollIntoView({ block: 'center' }); }
    });
  }

  if (isDev) initDev();

  // ---------------------------------------------------------------- token generator
  function initDev() {
    const out = $('dev-result');
    $('dev-rotate').addEventListener('click', async (e) => {
      const btn = e.target;
      btn.disabled = true;
      try {
        const res = await fetch(data.rotateApi, { method: 'POST' });
        const json = await res.json();
        if (!res.ok) throw new Error(json.error_description || res.statusText);
        $('dev-kid').textContent = json.kid;
        btn.textContent = 'Rotated';
        setTimeout(() => (btn.textContent = 'Rotate signing key'), 1500);
      } catch (err) {
        alert(`Key rotation failed: ${err.message}`);
      } finally {
        btn.disabled = false;
      }
    });
    // Clock: every change reloads the page so the banner and status reflect it.
    const shiftClock = async (body) => {
      try {
        const res = await fetch(data.clockApi, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        const json = await res.json();
        if (!res.ok) throw new Error(json.error_description || res.statusText);
        sessionStorage.setItem('localoidc.clockAmount', $('dev-clock-amount').value);
        location.hash = 'clock';
        location.reload();
      } catch (err) {
        alert(`Changing the clock failed: ${err.message}`);
      }
    };
    // Keep the duration across the reload, so repeated moves don't need retyping.
    $('dev-clock-amount').value = sessionStorage.getItem('localoidc.clockAmount') || $('dev-clock-amount').value;
    const amount = () => $('dev-clock-amount').value.trim().replace(/^[+-]/, '');
    $('dev-clock-advance').addEventListener('click', () => shiftClock({ advance: amount() }));
    $('dev-clock-back').addEventListener('click', () => shiftClock({ advance: `-${amount()}` }));
    $('dev-clock-reset').addEventListener('click', () => shiftClock({ reset: true }));
    $('dev-generate').addEventListener('click', async () => {
      const { claims, access, errors } = build();
      if (errors.length) { refresh(); return; }
      syncHidden();
      const body = {
        preset: state.preset,
        client_id: opt('dev-client').value || undefined,
        audience: opt('dev-audience').value || undefined,
        scope: opt('dev-scope').value,
        expires_in: Number(opt('dev-ttl').value) || undefined,
        nonce: opt('dev-nonce').value || undefined,
        id_token: opt('dev-idtoken').checked,
        refresh_token: opt('dev-refresh').checked,
        defaults: false,
        claims,
        access_token_claims: access,
      };
      const btn = $('dev-generate');
      btn.disabled = true;
      try {
        const res = await fetch(data.api, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        const json = await res.json();
        showResult(json, body, res.ok);
      } catch (err) {
        showResult({ error: String(err) }, body, false);
      } finally {
        btn.disabled = false;
      }
    });

    function decode(token) {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const dec = (s) => JSON.parse(decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/')))));
      try { return { header: dec(parts[0]), payload: dec(parts[1]) }; } catch { return null; }
    }

    function copyBtn(text, label = 'Copy') {
      return h('button', { type: 'button', class: 'btn small', onclick: async (e) => {
        await navigator.clipboard.writeText(text);
        const b = e.target; const old = b.textContent; b.textContent = 'Copied'; setTimeout(() => (b.textContent = old), 1200);
      } }, label);
    }

    function tokenCard(title, token) {
      const d = decode(token);
      const exp = d && d.payload.exp ? new Date(d.payload.exp * 1000).toLocaleString() : null;
      return h('div', { class: 'token' },
        h('div', { class: 'token-head' }, h('b', {}, title), exp ? h('small', { class: 'muted' }, `expires ${exp}`) : h('small', { class: 'muted' }, d ? '' : 'opaque'), copyBtn(token)),
        h('textarea', { class: 'token-raw', readOnly: true, rows: 3, value: token, onclick: (e) => e.target.select() }),
        d ? h('details', {}, h('summary', {}, 'Decoded'), h('div', { class: 'decoded' },
          h('pre', { class: 'code' }, JSON.stringify(d.header, null, 2)),
          h('pre', { class: 'code' }, JSON.stringify(d.payload, null, 2)))) : null);
    }

    function showResult(json, req, ok) {
      out.hidden = false;
      out.replaceChildren();
      if (!ok) {
        out.append(h('div', { class: 'eyebrow error' }, 'Error'), h('pre', { class: 'code' }, JSON.stringify(json, null, 2)));
        return;
      }
      out.append(h('div', { class: 'eyebrow' }, 'Result'), h('h2', {}, 'Tokens'));
      if (json.access_token) out.append(tokenCard('Access token', json.access_token));
      if (json.id_token) out.append(tokenCard('ID token', json.id_token));
      if (json.refresh_token) out.append(tokenCard('Refresh token', json.refresh_token));

      const iss = json.issuer;
      const exports = [
        `export ACCESS_TOKEN='${json.access_token}'`,
        json.id_token ? `export ID_TOKEN='${json.id_token}'` : null,
        json.refresh_token ? `export REFRESH_TOKEN='${json.refresh_token}'` : null,
      ].filter(Boolean).join('\n');
      const curlUserinfo = `curl -s ${iss}/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"`;
      const curlRefresh = json.refresh_token
        ? `curl -s -X POST ${iss}/token -d grant_type=refresh_token -d client_id=${req.client_id || 'localoidc-dev'} -d refresh_token="$REFRESH_TOKEN"`
        : null;
      const curlApi = `curl -s -X POST ${data.api} -H 'content-type: application/json' -d '${JSON.stringify(req).replace(/'/g, "'\\''")}'`;
      const snippet = (title, text) => h('div', { class: 'snippet' }, h('div', { class: 'token-head' }, h('b', {}, title), copyBtn(text)), h('pre', { class: 'code' }, text));
      out.append(h('h2', {}, 'Use them'),
        snippet('Shell exports', exports),
        snippet('Call userinfo', curlUserinfo),
        curlRefresh ? snippet('Refresh', curlRefresh) : null,
        snippet('Reproduce via the dev API', curlApi),
        h('details', {}, h('summary', {}, 'Raw response'), h('pre', { class: 'code' }, JSON.stringify(json, null, 2))));
      out.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }
})();

// Request inspector (/dev/requests): polls the API and renders recent requests as a table whose
// rows expand to show their parameters and, for failures, the reason.
(function () {
  'use strict';
  const root = document.getElementById('lo-requests');
  if (!root) return;
  const api = root.dataset.api;
  const $ = (id) => document.getElementById(id);
  const h = (tag, attrs = {}, ...children) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null) el.append(c.nodeType ? c : document.createTextNode(c));
    return el;
  };

  let entries = []; // newest first
  let lastId = 0;
  let paused = false;
  const expanded = new Set();

  const failed = (e) => e.error || e.status >= 400;
  const time = (ms) => new Date(ms).toLocaleTimeString([], { hour12: false });

  function visible() {
    const client = $('req-client').value.trim();
    const errorsOnly = $('req-errors').checked;
    const all = $('req-all').checked;
    return entries.filter((e) => (all || e.category === 'flow')
      && (!client || (e.client_id || '').includes(client))
      && (!errorsOnly || failed(e)));
  }

  function details(e) {
    const rows = [];
    const add = (label, value) => { if (value) rows.push(h('dt', {}, label), h('dd', {}, value)); };
    if (e.error) add('Why', h('span', {}, h('b', { class: 'req-error' }, e.error), e.error_description ? ` — ${e.error_description}` : ''));
    add('Request', h('code', {}, `${e.method} ${e.path}`));
    add('Outcome', e.error ? null : e.outcome);
    add('Redirected to', e.redirect && h('code', {}, e.redirect));
    add('Authorization', e.authorization && h('code', {}, e.authorization));
    const params = Object.entries(e.params);
    add('Parameters', params.length
      ? h('dl', { class: 'req-params' }, params.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]))
      : h('span', { class: 'muted' }, 'none'));
    return h('dl', { class: 'req-details' }, rows);
  }

  function row(e) {
    const bad = failed(e);
    const toggle = () => { expanded.has(e.id) ? expanded.delete(e.id) : expanded.add(e.id); render(); };
    const tr = h('tr', { class: `req-row${bad ? ' failed' : ''}${expanded.has(e.id) ? ' open' : ''}`, onclick: toggle },
      h('td', { class: 'mono' }, time(e.at)),
      h('td', {}, e.method),
      h('td', { class: 'mono' }, e.issuer !== 'root' ? h('span', { class: 'req-issuer' }, e.issuer) : null, e.endpoint),
      h('td', { class: 'mono' }, e.client_id || '–'),
      h('td', {}, bad && e.error ? h('span', { class: 'req-error' }, e.error) : e.outcome),
      h('td', {}, h('span', { class: `chip ${bad ? 'bad' : 'ok'}` }, String(e.status))),
      h('td', { class: 'num' }, e.duration_ms ? String(e.duration_ms) : '<1'));
    return expanded.has(e.id) ? [tr, h('tr', { class: 'req-detail' }, h('td', { colspan: 7 }, details(e)))] : [tr];
  }

  let rendered = false;
  function render() {
    rendered = true;
    const rows = visible();
    if (!rows.length) {
      root.replaceChildren(h('p', { class: 'muted req-empty' }, entries.length
        ? 'No requests match these filters.'
        : `No requests yet. Point your app at ${root.dataset.issuer} and they'll show up here.`));
      return;
    }
    const head = ['Time', 'Method', 'Endpoint', 'Client', 'Outcome', 'Status', 'ms'].map((t) => h('th', {}, t));
    root.replaceChildren(h('table', { class: 'req-table' }, h('thead', {}, h('tr', {}, head)), h('tbody', {}, rows.flatMap(row))));
  }

  async function poll() {
    if (!paused) {
      try {
        const res = await fetch(`${api}?after=${lastId}`, { cache: 'no-store' });
        const json = await res.json();
        // Only re-render on changes: replacing the rows loses clicks and text selections.
        let changed = !rendered;
        if (json.latest_id < lastId) { entries = []; lastId = 0; changed = true; } // the server restarted
        if (json.entries.length) {
          lastId = json.entries[0].id;
          entries = json.entries.concat(entries).slice(0, json.capacity);
          changed = true;
        }
        if (changed) render();
      } catch { /* server unreachable; try again */ }
    }
    setTimeout(poll, 1500);
  }

  for (const id of ['req-client', 'req-errors', 'req-all']) $(id).addEventListener('input', render);
  $('req-pause').addEventListener('click', (ev) => {
    paused = !paused;
    ev.target.textContent = paused ? 'Resume' : 'Pause';
  });
  $('req-clear').addEventListener('click', async () => {
    await fetch(api, { method: 'DELETE' });
    entries = [];
    expanded.clear();
    render();
  });
  poll();
})();
