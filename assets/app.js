// localoidc claims editor — shared by the login, device and token generator pages.
(function () {
  'use strict';
  const dataEl = document.getElementById('lo-data');
  if (!dataEl) return;
  const data = JSON.parse(dataEl.textContent);
  const presets = data.presets;
  const byId = Object.fromEntries(presets.map((p) => [p.id, p]));
  const LS_KEY = 'localoidc.identities';
  const root = document.getElementById('lo-editor');

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

  // ---------------------------------------------------------------- state
  const state = { preset: null, values: {}, custom: '', access: '' };

  const fieldText = (f, v) => {
    if (v === undefined || v === null) return f.kind === 'bool' ? false : '';
    if (f.kind === 'bool') return !!v;
    if (f.kind === 'json') {
      const compact = JSON.stringify(v);
      return compact.length <= 60 ? compact : JSON.stringify(v, null, 2);
    }
    return String(v);
  };

  /** Load a claim set into the editor, splitting preset fields from custom claims. */
  function load(presetId, claims, accessClaims) {
    const p = byId[presetId] || byId[data.defaultPreset] || presets[0];
    state.preset = p.id;
    state.values = {};
    const names = new Set(p.fields.map((f) => f.name));
    for (const f of p.fields) {
      state.values[f.name] = fieldText(f, claims ? claims[f.name] : f.default);
    }
    const custom = {};
    if (claims) {
      for (const [k, v] of Object.entries(claims)) {
        if (names.has(k)) continue;
        if (k === 'sub' && p.sub_from) continue; // derived
        custom[k] = v;
      }
    }
    // Switching presets (claims == null) keeps whatever custom claims were typed.
    if (claims) {
      state.custom = Object.keys(custom).length ? JSON.stringify(custom, null, 2) : '';
      state.access = accessClaims && Object.keys(accessClaims).length ? JSON.stringify(accessClaims, null, 2) : '';
    }
  }

  function applyLoginHint(hint) {
    if (!hint) return;
    const p = byId[state.preset];
    const has = (n) => p.fields.some((f) => f.name === n);
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
          try { claims[f.name] = JSON.parse(v); } catch (e) { errors.push(`${f.label}: invalid JSON`); }
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
    const access = parseObj(state.access, 'Access token claims');
    return { claims, access, errors };
  }

  // ---------------------------------------------------------------- saved identities
  const saved = () => { try { return JSON.parse(localStorage.getItem(LS_KEY)) || []; } catch { return []; } };
  const store = (list) => localStorage.setItem(LS_KEY, JSON.stringify(list));

  // ---------------------------------------------------------------- render
  let previewEl, errorEl;

  function refresh() {
    const { claims, access, errors } = build();
    if (previewEl) {
      const p = byId[state.preset];
      const preview = { ...claims };
      if (Object.keys(access).length) preview['(access token only)'] = access;
      previewEl.textContent = JSON.stringify(preview, null, 2);
      previewEl.dataset.protocol = p.protocol;
    }
    if (errorEl) {
      errorEl.textContent = errors.join(' · ');
      errorEl.hidden = !errors.length;
    }
  }

  function fieldInput(f) {
    const v = state.values[f.name];
    const id = `f-${f.name.replace(/[^a-z0-9]/gi, '_')}`;
    const set = (val) => { state.values[f.name] = val; refresh(); };
    let input;
    if (f.kind === 'bool') {
      input = h('input', { type: 'checkbox', id, checked: !!v, onchange: (e) => set(e.target.checked) });
      return h('label', { class: 'field check-field', for: id, title: f.help || '' }, input, h('span', {}, f.label), h('code', { class: 'claim-name' }, f.name));
    }
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

  function render() {
    const p = byId[state.preset];
    root.replaceChildren();

    // Previous session shortcut (login / device).
    if (data.previous && data.mode !== 'dev') {
      const prev = data.previous;
      const who = prev.claims.email || prev.claims.name || prev.claims.preferred_username || prev.claims.login || prev.claims.sub;
      root.append(h('div', { class: 'previous' },
        h('span', {}, 'Active session: ', h('b', {}, who), ` (${(byId[prev.preset] || {}).name || prev.preset})`),
        h('button', { type: 'button', class: 'btn small', onclick: () => {
          load(prev.preset, prev.claims, prev.access_claims);
          const form = document.getElementById('lo-form');
          syncHidden();
          form.requestSubmit(form.querySelector('[value=approve]'));
        } }, 'Continue as this user')));
    }

    // Provider picker.
    root.append(h('div', { class: 'section-title' }, 'Emulate provider',
      data.tenantPreset ? h('small', { class: 'muted' }, ` — issuer is pinned to ${byId[data.tenantPreset].name}`) : null));
    root.append(h('div', { class: 'providers' }, presets.map((q) =>
      h('button', {
        type: 'button',
        class: `provider ${q.id === p.id ? 'active' : ''}`,
        style: `--c:${q.color}`,
        title: q.description,
        onclick: () => { if (q.id !== state.preset) { load(q.id, null, null); render(); } },
      }, h('span', { class: 'dot' }), q.name, q.protocol === 'oauth2' ? h('small', {}, 'OAuth2') : null))));
    root.append(h('p', { class: 'preset-desc muted' }, p.description));

    // Saved identities.
    const list = saved();
    const select = h('select', { class: 'saved-select' },
      h('option', { value: '' }, list.length ? 'Saved identities…' : 'No saved identities'),
      list.map((s, i) => h('option', { value: String(i) }, `${s.name} (${(byId[s.preset] || {}).name || s.preset})`)));
    root.append(h('div', { class: 'saved' },
      select,
      h('button', { type: 'button', class: 'btn small', onclick: () => {
        const s = list[Number(select.value)];
        if (s) { load(s.preset, s.claims, s.access); render(); }
      } }, 'Load'),
      h('button', { type: 'button', class: 'btn small', onclick: () => {
        const { claims, access, errors } = build();
        if (errors.length) return alert(errors.join('\n'));
        const name = prompt('Name this identity', claims.email || claims.name || claims.sub || 'identity');
        if (!name) return;
        const next = saved().filter((s) => s.name !== name);
        next.push({ name, preset: state.preset, claims, access });
        store(next); render();
      } }, 'Save current'),
      h('button', { type: 'button', class: 'btn small ghost', onclick: () => {
        const i = Number(select.value);
        if (select.value === '' || !list[i]) return;
        list.splice(i, 1); store(list); render();
      } }, 'Delete'),
      h('button', { type: 'button', class: 'btn small ghost', onclick: () => { load(state.preset, null, null); state.custom = ''; state.access = ''; render(); } }, 'Reset to defaults')));

    // Fields.
    root.append(h('div', { class: 'section-title' }, 'Claims'));
    root.append(h('div', { class: 'fields' }, p.fields.map(fieldInput)));

    // Custom claims.
    const custom = h('textarea', { rows: 5, spellcheck: false, placeholder: '{\n  "https://example.com/tenant": "acme",\n  "permissions": ["read", "write"],\n  "locale": null\n}', oninput: (e) => { state.custom = e.target.value; refresh(); } });
    custom.value = state.custom;
    const access = h('textarea', { rows: 4, spellcheck: false, placeholder: '{\n  "permissions": ["orders:write"]\n}', oninput: (e) => { state.access = e.target.value; refresh(); } });
    access.value = state.access;
    root.append(h('div', { class: 'customs' },
      h('label', { class: 'field wide' }, h('span', { class: 'field-label' }, 'Custom claims', h('small', { class: 'muted' }, ' merged into ID token, userinfo and access token · null removes a claim · reserved claims like aud/exp can be overridden')), custom),
      h('label', { class: 'field wide' }, h('span', { class: 'field-label' }, 'Access-token-only claims'), access)));

    errorEl = h('p', { class: 'notice error', hidden: true });
    previewEl = h('pre', { class: 'code preview' });
    root.append(errorEl, h('details', { class: 'preview-wrap', open: data.mode === 'dev' ? null : true },
      h('summary', {}, 'Claims preview ', h('small', { class: 'muted' }, '(iss, aud, exp, nonce… are added by the server)')), previewEl));
    refresh();
  }

  function syncHidden() {
    const form = document.getElementById('lo-form');
    if (!form) return [];
    const { claims, access, errors } = build();
    form.elements.preset.value = state.preset;
    form.elements.claims.value = JSON.stringify(claims);
    form.elements.access_claims.value = JSON.stringify(access);
    return errors;
  }

  // ---------------------------------------------------------------- init
  const prev = data.previous;
  if (prev && byId[prev.preset] && data.mode !== 'dev') load(prev.preset, prev.claims, prev.access_claims);
  else load(data.defaultPreset, null, null);
  applyLoginHint(data.loginHint);
  render();

  const form = document.getElementById('lo-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      if (e.submitter && e.submitter.value === 'deny') return;
      const errors = syncHidden();
      if (errors.length) { e.preventDefault(); refresh(); errorEl.scrollIntoView({ block: 'center' }); }
    });
  }

  if (data.mode === 'dev') initDev();

  // ---------------------------------------------------------------- token generator
  function initDev() {
    const $ = (id) => document.getElementById(id);
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
    $('dev-generate').addEventListener('click', async () => {
      const { claims, access, errors } = build();
      if (errors.length) { refresh(); return; }
      const body = {
        preset: state.preset,
        client_id: $('dev-client').value || undefined,
        audience: $('dev-audience').value || undefined,
        scope: $('dev-scope').value,
        expires_in: Number($('dev-ttl').value) || undefined,
        nonce: $('dev-nonce').value || undefined,
        id_token: $('dev-idtoken').checked,
        refresh_token: $('dev-refresh').checked,
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
