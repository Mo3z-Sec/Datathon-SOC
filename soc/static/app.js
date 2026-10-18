'use strict';
/* Hospital SOC Alert Center - single-page dashboard (vanilla JS, no external resources).
   SECURITY: every dynamic value is inserted as a text node (textContent). HTML strings are never built from data. */
(function () {
  const $ = (id) => document.getElementById(id);

  const SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const STATUS = { new: 'New', investigating: 'Investigating', contained: 'Contained', resolved: 'Resolved', false_positive: 'False positive' };
  const GROUPS = [['investigate', 'Investigate'], ['triage', 'Triage'], ['contain', 'Contain (carried out by people)'], ['escalate', 'Escalate']];

  const state = {
    token: '', role: null, config: null, options: null, view: 'overview', openAlertId: null,
    alerts: { filters: { status: 'open', sort: 'score_desc' }, offset: 0, limit: 25 },
    logs: { filters: {}, offset: 0, limit: 50 },
    audit: { offset: 0, limit: 50 },
  };
  try { state.token = sessionStorage.getItem('soc_token') || ''; } catch (e) { state.token = ''; }

  // ---------------------------------------------------------------- DOM helpers
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    let deferredValue;
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        const v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'value') deferredValue = v;
        else if (k === 'checked') el.checked = !!v;
        else if (k === 'disabled') el.disabled = true;
        else if (k === 'style') Object.assign(el.style, v);
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid && kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    if (deferredValue !== undefined) el.value = deferredValue; // after <option> children exist
    return el;
  }
  const setMain = (node) => $('main').replaceChildren(node);
  const hasClass = (el, c) => (' ' + el.className + ' ').indexOf(' ' + c + ' ') >= 0;
  const addClass = (el, c) => { if (!hasClass(el, c)) el.className = (el.className + ' ' + c).trim(); };
  const delClass = (el, c) => { el.className = (' ' + el.className + ' ').replace(' ' + c + ' ', ' ').trim(); };
  const toggleHidden = (el) => { if (hasClass(el, 'hidden')) delClass(el, 'hidden'); else addClass(el, 'hidden'); };

  const fmtTime = (iso) => (iso ? String(iso).replace('T', ' ').replace('Z', ' UTC') : '');
  const pct = (n, max) => (max > 0 ? Math.round((n / max) * 100) : 0);
  const isAnalyst = () => state.role === 'analyst';

  function qs(obj) {
    const p = [];
    for (const k of Object.keys(obj || {})) {
      const v = obj[k];
      if (v === '' || v === null || v === undefined) continue;
      p.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
    }
    return p.length ? '?' + p.join('&') : '';
  }

  // ---------------------------------------------------------------- API
  async function api(path, opts) {
    opts = opts || {};
    const headers = { Authorization: 'Bearer ' + state.token };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { method: opts.method || 'GET', headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
    if (res.status === 401) { showLogin('That token was not accepted or your session ended.'); throw new Error('Unauthorized'); }
    if (!res.ok) {
      let msg = res.status + ' ' + (res.statusText || 'Request failed');
      try { const j = await res.json(); if (j && j.detail) msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch (e) { /* keep default */ }
      throw new Error(msg);
    }
    return opts.raw ? res : res.json();
  }

  async function download(path, params, filename) {
    const res = await api(path + qs(params), { raw: true });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast('Downloaded ' + filename);
  }

  function toast(msg, kind) {
    const t = h('div', { class: 'toast ' + (kind === 'error' ? 'error' : ''), role: kind === 'error' ? 'alert' : 'status' }, msg);
    $('toasts').append(t);
    setTimeout(() => t.remove(), kind === 'error' ? 8000 : 4500);
  }
  const fail = (e) => { if (e && e.message !== 'Unauthorized') toast(e.message || String(e), 'error'); };

  // ---------------------------------------------------------------- small widgets
  function field(label, control, extra) { return h('label', { class: 'field ' + (extra || '') }, h('span', { class: 'field-label' }, label), control); }
  function select(pairs, value, onchange, attrs) {
    return h('select', Object.assign({ value, onchange }, attrs || {}), pairs.map(([v, l]) => h('option', { value: v }, l)));
  }
  const sevBadge = (sev, text) => h('span', { class: 'score sev-' + sev }, text);
  const statusPill = (s) => h('span', { class: 'status ' + s }, STATUS[s] || s);
  function emptyBox(text) { return h('div', { class: 'card empty' }, text); }
  function pager(total, offset, limit, onPage) {
    const from = total ? offset + 1 : 0;
    const to = Math.min(offset + limit, total);
    return h('div', { class: 'pager' },
      h('button', { class: 'btn small', type: 'button', disabled: offset <= 0, onclick: () => onPage(Math.max(0, offset - limit)) }, 'Previous'),
      h('span', { class: 'muted small' }, 'Showing ' + from + '-' + to + ' of ' + total),
      h('button', { class: 'btn small', type: 'button', disabled: to >= total, onclick: () => onPage(offset + limit) }, 'Next'));
  }
  function barList(map, order, fillFn, onClick, labelFn) {
    const keys = (order || Object.keys(map)).filter((k) => map[k] !== undefined);
    const max = Math.max(1, ...keys.map((k) => map[k]));
    if (!keys.length) return h('p', { class: 'muted' }, 'Nothing to show yet.');
    return h('div', { class: 'bars' }, keys.map((k) => h('div', { class: 'bar-row' + (onClick ? ' click' : ''), onclick: onClick ? () => onClick(k) : null },
      h('span', null, labelFn ? labelFn(k) : k),
      h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill ' + (fillFn ? fillFn(k) : ''), style: { width: pct(map[k], max) + '%' } })),
      h('strong', null, map[k]))));
  }
  const catName = (id) => { const c = (state.options.categories || []).find((x) => x.id === id); return c ? c.name : id; };

  // ---------------------------------------------------------------- login / boot
  function showLogin(msg) {
    state.token = '';
    try { sessionStorage.removeItem('soc_token'); } catch (e) { /* ignore */ }
    addClass($('app-view'), 'hidden');
    delClass($('login-view'), 'hidden');
    $('login-error').textContent = msg || '';
    closeDrawer();
  }

  async function boot() {
    if (!state.token) return showLogin('');
    try {
      state.role = (await api('/api/me')).role;
      state.config = await api('/api/config');
      state.options = await api('/api/options');
    } catch (e) {
      if (e.message !== 'Unauthorized') showLogin('Could not reach the server: ' + e.message);
      return;
    }
    addClass($('login-view'), 'hidden');
    delClass($('app-view'), 'hidden');
    $('role-badge').textContent = isAnalyst() ? 'Analyst' : 'Viewer (read-only)';
    $('ai-badge').textContent = state.config.ai_enabled ? 'AI explanations: ' + state.config.ai_model : 'AI explanations: offline rules';
    buildNav();
    go(state.view);
  }

  function buildNav() {
    const items = [['overview', 'Overview'], ['alerts', 'Alerts'], ['logs', 'Logs'], ['assets', 'Assets'], ['audit', 'Audit trail']];
    $('nav').replaceChildren(...items.map(([id, label]) => h('button', {
      type: 'button', id: 'nav-' + id, class: id === state.view ? 'active' : '', 'aria-current': id === state.view ? 'page' : null, onclick: () => go(id),
    }, label)));
  }

  function go(view) {
    state.view = view;
    for (const id of ['overview', 'alerts', 'logs', 'assets', 'audit']) {
      const b = $('nav-' + id);
      if (b) b.className = id === view ? 'active' : '';
    }
    return renderCurrent();
  }

  async function renderCurrent(silent) {
    try {
      if (state.view === 'overview') await renderOverview();
      else if (state.view === 'alerts') await renderAlerts();
      else if (state.view === 'logs') await renderLogs();
      else if (state.view === 'assets') await renderAssets();
      else if (state.view === 'audit') await renderAudit();
    } catch (e) {
      if (e.message === 'Unauthorized') return;
      if (!silent) setMain(h('div', { class: 'card' }, h('h2', null, 'Something went wrong'), h('p', { class: 'error' }, e.message)));
    }
  }

  // ---------------------------------------------------------------- overview
  function simulateModal() {
    const info = state.options.scenario_info || {};
    const names = state.options.scenarios || [];
    const seed = h('input', { type: 'number', id: 'sim-seed', min: 0, placeholder: 'random' });
    const benign = h('input', { type: 'number', id: 'sim-benign', min: 0, max: 5000, value: 300 });
    const replace = h('input', { type: 'checkbox', id: 'sim-replace', checked: true });
    const checks = names.map((n) => h('input', { type: 'checkbox', checked: true, 'data-scenario': n }));
    const run = h('button', { class: 'btn primary', type: 'button', id: 'sim-run' }, 'Generate');
    run.addEventListener('click', async () => {
      const chosen = checks.filter((c) => c.checked).map((c) => c.getAttribute('data-scenario'));
      if (!chosen.length) return toast('Pick at least one attack scenario.', 'error');
      const body = { benign: Number(benign.value === '' ? 300 : benign.value), replace: replace.checked, scenarios: chosen.length === names.length ? null : chosen };
      if (seed.value !== '') body.seed = Number(seed.value);
      run.disabled = true; run.textContent = 'Generating...';
      try {
        const r = await api('/api/simulate', { method: 'POST', body });
        closeModal();
        toast('Generated ' + r.logs_inserted + ' simulated logs and ' + r.alerts_total + ' alerts (seed ' + r.seed + ').');
        state.options = await api('/api/options');
        await renderCurrent();
      } catch (e) { run.disabled = false; run.textContent = 'Generate'; fail(e); }
    });
    openModal('Generate simulated hospital data', [
      h('p', { class: 'muted' }, 'Creates one day of realistic but entirely fictional hospital security logs, then runs the detection rules. Nothing leaves this server.'),
      h('div', { class: 'filters' }, field('Random seed (optional)', seed), field('Background events', benign)),
      h('div', { class: 'checks' }, names.map((n, i) => h('label', null, checks[i], h('span', null, h('strong', null, catName(n) === n ? n.replace(/_/g, ' ') : catName(n)), ' - ', info[n] || '')))),
      h('label', { class: 'checks' }, h('span', null, replace, ' Replace existing data (recommended)')),
      h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: closeModal }, 'Cancel'), run),
    ]);
  }

  function confirmModal(title, text, label, onConfirm) {
    openModal(title, [h('p', null, text), h('div', { class: 'actions' },
      h('button', { class: 'btn', type: 'button', onclick: closeModal }, 'Cancel'),
      h('button', { class: 'btn danger', type: 'button', id: 'confirm-ok', onclick: async () => { closeModal(); await onConfirm(); } }, label))]);
  }

  async function renderOverview() {
    const s = await api('/api/stats');
    const ro = !isAnalyst();
    const bar = h('div', { class: 'toolbar' },
      h('button', { class: 'btn primary', type: 'button', id: 'btn-generate', disabled: ro, title: ro ? 'Analyst role required' : null, onclick: simulateModal }, 'Generate simulated data'),
      h('button', { class: 'btn', type: 'button', id: 'btn-detect', disabled: ro, title: ro ? 'Analyst role required' : null, onclick: async () => {
        try { const r = await api('/api/detect', { method: 'POST' }); toast('Detection finished: ' + r.alerts_total + ' alerts (' + r.created + ' new).'); await renderCurrent(); } catch (e) { fail(e); }
      } }, 'Re-run detection'),
      h('button', { class: 'btn danger', type: 'button', id: 'btn-reset', disabled: ro, title: ro ? 'Analyst role required' : null, onclick: () => confirmModal('Delete all simulated data?',
        'This removes every simulated log, alert and analyst note from this system. The audit trail is kept.', 'Delete everything', async () => {
          try { await api('/api/reset', { method: 'POST', body: { confirm: true } }); toast('All simulated data deleted.'); await renderCurrent(); } catch (e) { fail(e); }
        }) }, 'Reset data'),
      h('span', { class: 'spacer' }),
      h('button', { class: 'btn', type: 'button', id: 'btn-refresh', onclick: () => renderCurrent() }, 'Refresh'));

    if (!s.logs_total) {
      setMain(h('div', null, h('div', { class: 'page-title' }, h('h2', null, 'Overview')), bar,
        emptyBox('No data yet. ' + (ro ? 'Ask an analyst to generate simulated data.' : 'Click "Generate simulated data" to create a realistic 24-hour hospital scenario.'))));
      return;
    }
    const kpis = h('div', { class: 'grid kpis' },
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-value' }, s.open_alerts), h('div', { class: 'kpi-label' }, 'Open alerts')),
      h('div', { class: 'kpi crit' }, h('div', { class: 'kpi-value' }, s.critical_open), h('div', { class: 'kpi-label' }, 'Critical and open')),
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-value' }, s.avg_open_score === null ? '-' : s.avg_open_score), h('div', { class: 'kpi-label' }, 'Average open risk score (1-10)')),
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-value' }, s.logs_total), h('div', { class: 'kpi-label' }, 'Simulated logs ingested')),
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-value' }, s.alerts_total), h('div', { class: 'kpi-label' }, 'Total alerts'), h('div', { class: 'kpi-sub' }, s.last_detection ? 'Last detection ' + fmtTime(s.last_detection) : '')));

    const goAlerts = (filters) => { state.alerts.filters = Object.assign({ status: 'open', sort: 'score_desc' }, filters); state.alerts.offset = 0; go('alerts'); };
    const sevPanel = h('div', { class: 'card' }, h('h3', null, 'Open alerts by severity'),
      barList(s.by_severity_open, ['critical', 'high', 'medium', 'low'], (k) => 'sev-' + k + '-fill', (k) => goAlerts({ severity: k }), (k) => SEV[k]));
    const catPanel = h('div', { class: 'card' }, h('h3', null, 'Open alerts by attack type'),
      barList(s.by_category_open, null, null, (k) => goAlerts({ category: k }), catName));
    const statusPanel = h('div', { class: 'card' }, h('h3', null, 'Incident status (all alerts)'),
      barList(s.by_status, ['new', 'investigating', 'contained', 'resolved', 'false_positive'], null, (k) => goAlerts({ status: k }), (k) => STATUS[k]));
    const assetsPanel = h('div', { class: 'card' }, h('h3', null, 'Most affected systems'),
      s.top_assets.length ? h('ul', { class: 'asset-list' }, s.top_assets.map((a) => h('li', { onclick: () => goAlerts({ asset: a.asset }) },
        h('span', null, a.asset), h('span', null, sevBadge(a.max_score >= 8 ? 'critical' : a.max_score >= 6 ? 'high' : a.max_score >= 4 ? 'medium' : 'low', a.max_score + '/10'), ' ', h('span', { class: 'muted small' }, a.alerts + ' open'))))) : h('p', { class: 'muted' }, 'No open alerts.'));

    const maxLogs = Math.max(1, ...s.timeline.map((t) => t.logs));
    const maxAl = Math.max(1, ...s.timeline.map((t) => t.alerts));
    const tl = h('div', { class: 'card' }, h('h3', null, 'Activity by hour (UTC): logs and alerts'),
      h('div', { class: 'timeline', role: 'img', 'aria-label': 'Bar chart of simulated log volume and alerts per hour' }, s.timeline.map((t) =>
        h('div', { class: 'tl-col', title: fmtTime(t.hour).slice(0, 16) + ' - ' + t.logs + ' logs, ' + t.alerts + ' alerts' },
          t.alerts ? h('div', { class: 'tl-alert', style: { height: Math.max(4, pct(t.alerts, maxAl) * 0.5) + '%' } }) : null,
          h('div', { class: 'tl-bar', style: { height: Math.max(2, pct(t.logs, maxLogs) * 0.6) + '%' } })))),
      h('div', { class: 'tl-labels' }, h('span', null, s.timeline.length ? fmtTime(s.timeline[0].hour).slice(0, 16) : ''), h('span', null, s.timeline.length ? fmtTime(s.timeline[s.timeline.length - 1].hour).slice(0, 16) : '')));

    setMain(h('div', null, h('div', { class: 'page-title' }, h('h2', null, 'Overview'), h('span', { class: 'muted small' }, 'All data on this screen is simulated.')),
      bar, kpis, h('div', { class: 'grid two', style: { marginTop: '1rem' } }, sevPanel, catPanel, statusPanel, assetsPanel),
      h('div', { style: { marginTop: '1rem' } }, tl)));
  }

  // ---------------------------------------------------------------- alerts list
  async function renderAlerts() {
    const st = state.alerts, f = st.filters, o = state.options;
    const apply = () => { st.offset = 0; renderAlerts(); };
    const q = h('input', { type: 'search', id: 'f-q', value: f.q || '', placeholder: 'Search title, system, user, IP, evidence...' });
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { f.q = q.value.trim(); apply(); } });
    const sel = (key, label, pairs) => field(label, select(pairs, f[key] || '', (e) => { f[key] = e.target.value; apply(); }, { id: 'f-' + key }));
    const filters = h('div', { class: 'filters' },
      field('Search', q, 'grow'),
      sel('status', 'Status', [['open', 'Open (not resolved)'], ['', 'All'], ...o.statuses.map((s) => [s, STATUS[s]])]),
      sel('category', 'Attack type', [['', 'All'], ...o.categories.map((c) => [c.id, c.name])]),
      sel('severity', 'Severity', [['', 'All'], ...o.severities.map((s) => [s, SEV[s]])]),
      sel('min_score', 'Min score', [['', 'Any'], ['4', '4+'], ['6', '6+'], ['8', '8+']]),
      sel('asset', 'System', [['', 'All'], ...o.assets.map((a) => [a, a])]),
      sel('sort', 'Sort by', [['score_desc', 'Highest score'], ['time_desc', 'Newest first'], ['time_asc', 'Oldest first'], ['status', 'Status']]),
      h('button', { class: 'btn primary', type: 'button', id: 'f-apply', onclick: () => { f.q = q.value.trim(); apply(); } }, 'Search'),
      h('button', { class: 'btn', type: 'button', id: 'f-reset', onclick: () => { st.filters = { status: 'open', sort: 'score_desc' }; apply(); } }, 'Reset'),
      h('button', { class: 'btn', type: 'button', id: 'f-export', onclick: () => download('/api/export/alerts.csv', Object.assign({}, f), 'simulated-alerts.csv').catch(fail) }, 'Export CSV'));

    const data = await api('/api/alerts' + qs(Object.assign({}, f, { limit: st.limit, offset: st.offset })));
    const rows = data.items.map((a) => h('tr', { class: 'clickable', tabindex: '0', 'data-alert-id': a.id, onclick: () => openAlert(a.id),
      onkeydown: (e) => { if (e.key === 'Enter') openAlert(a.id); } },
      h('td', { class: 'nowrap' }, sevBadge(a.severity, a.score + '/10')),
      h('td', null, h('strong', null, a.title), h('div', { class: 'muted small' }, a.rule_id + ' - ' + catName(a.category))),
      h('td', null, a.asset), h('td', { class: 'hide-sm' }, a.username || a.src_ip || '-'),
      h('td', { class: 'nowrap hide-sm' }, fmtTime(a.first_seen)), h('td', { class: 'hide-sm' }, a.confidence_label + ' (' + Math.round(a.confidence * 100) + '%)'),
      h('td', null, statusPill(a.status)), h('td', { class: 'hide-sm' }, a.notes ? String(a.notes) : '')));
    const table = data.items.length ? h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Score'), h('th', null, 'Alert'), h('th', null, 'System'), h('th', { class: 'hide-sm' }, 'User / source'),
        h('th', { class: 'hide-sm' }, 'First seen'), h('th', { class: 'hide-sm' }, 'Confidence'), h('th', null, 'Status'), h('th', { class: 'hide-sm' }, 'Notes'))),
      h('tbody', null, rows))) : emptyBox('No alerts match these filters.');
    setMain(h('div', null, h('div', { class: 'page-title' }, h('h2', null, 'Alerts'), h('span', { class: 'muted small' }, data.total + ' matching')),
      filters, table, pager(data.total, data.offset, data.limit, (o2) => { st.offset = o2; renderAlerts(); })));
  }

  // ---------------------------------------------------------------- alert drawer
  async function openAlert(id) {
    try {
      const d = await api('/api/alerts/' + id);
      state.openAlertId = id;
      renderDrawer(d);
    } catch (e) { fail(e); }
  }
  function closeDrawer() { state.openAlertId = null; const d = $('drawer'); if (d) { addClass(d, 'hidden'); d.replaceChildren(); } }

  function logTable(logs) {
    if (!logs.length) return h('p', { class: 'muted' }, 'No log lines found.');
    const rows = [];
    for (const l of logs) {
      const raw = h('tr', { class: 'hidden' }, h('td', { colspan: 5 }, h('pre', null, JSON.stringify(l, null, 2))));
      rows.push(h('tr', null, h('td', { class: 'nowrap small' }, fmtTime(l.timestamp)), h('td', null, l.source + ' / ' + l.event_type),
        h('td', null, l.username || '-'), h('td', { class: 'small' }, (l.src_ip || '-') + (l.dst_ip ? ' -> ' + l.dst_ip + (l.dst_port ? ':' + l.dst_port : '') : '')),
        h('td', null, h('div', { class: 'small' }, l.message), h('button', { class: 'btn small', type: 'button', onclick: () => toggleHidden(raw) }, 'Raw log'))));
      rows.push(raw);
    }
    return h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'Event'), h('th', null, 'User'), h('th', null, 'Network'), h('th', null, 'Message'))), h('tbody', null, rows)));
  }

  function renderDrawer(d) {
    const a = d.alert, asset = d.asset, exp = a.explanation || {}, drawer = $('drawer');
    const total = a.breakdown.reduce((t, b) => t + b.points, 0);
    const statusSel = select(Object.keys(STATUS).map((k) => [k, STATUS[k]]), a.status, () => {}, { id: 'status-select', disabled: !isAnalyst() });
    const note = h('textarea', { id: 'note-text', maxlength: 2000, placeholder: 'Add an analyst note (what you checked, who you contacted, decisions)...', disabled: !isAnalyst() });
    const reload = async () => { await openAlert(a.id); if (state.view === 'alerts' || state.view === 'overview') renderCurrent(true); };

    drawer.replaceChildren(
      h('div', { class: 'drawer-head' }, h('div', null, sevBadge(a.severity, a.score + '/10 ' + SEV[a.severity]), h('h2', { style: { marginTop: '.4rem' } }, a.title),
        h('div', { class: 'muted small' }, a.rule_id + ' - ' + catName(a.category) + ' - MITRE ' + a.mitre + ' (indicative)')),
        h('button', { class: 'btn', type: 'button', id: 'drawer-close', onclick: closeDrawer }, 'Close')),
      h('dl', { class: 'facts' },
        h('div', null, h('dt', null, 'Affected system'), h('dd', null, a.asset + (asset ? ' (' + asset.department + ', criticality ' + asset.criticality + '/5' + (asset.patient_care ? ', patient care' : '') + ')' : ''))),
        h('div', null, h('dt', null, 'User'), h('dd', null, a.username || '-')), h('div', null, h('dt', null, 'Source address'), h('dd', null, a.src_ip || '-')),
        h('div', null, h('dt', null, 'First seen'), h('dd', null, fmtTime(a.first_seen))), h('div', null, h('dt', null, 'Last seen'), h('dd', null, fmtTime(a.last_seen))),
        h('div', null, h('dt', null, 'Detection confidence'), h('dd', null, a.confidence_label + ' (' + Math.round(a.confidence * 100) + '%)')),
        h('div', null, h('dt', null, 'Incident status'), h('dd', null, statusPill(a.status))), h('div', null, h('dt', null, 'Log lines'), h('dd', null, String(a.log_count)))),

      h('section', null, h('h3', null, 'Incident status'),
        h('div', { class: 'status-row' }, field('Set status', statusSel),
          h('button', { class: 'btn primary', type: 'button', id: 'status-save', disabled: !isAnalyst(), onclick: async () => {
            try { await api('/api/alerts/' + a.id + '/status', { method: 'POST', body: { status: statusSel.value } }); toast('Status updated to ' + STATUS[statusSel.value] + '.'); await reload(); } catch (e) { fail(e); }
          } }, 'Update status'),
          isAnalyst() ? null : h('span', { class: 'muted small' }, 'Read-only access: analyst role needed to make changes.'))),

      h('section', { class: 'explain' }, h('h3', null, 'What happened (plain English)'),
        h('p', { id: 'exp-summary' }, exp.summary || 'No explanation stored yet.'), h('h4', null, 'Why it matters'), h('p', null, exp.why_it_matters || ''),
        h('p', { class: 'muted small' }, exp.confidence_note || ''),
        exp.ai_note ? h('div', { class: 'notice' }, exp.ai_note) : null,
        h('div', { class: 'steps' }, GROUPS.map(([k, title]) => h('div', null, h('h4', null, title), h('ul', null, ((exp.steps || {})[k] || []).map((s) => h('li', null, s)))))),
        h('p', { class: 'muted small' }, 'Source: ' + (exp.source === 'ai' ? 'AI-assisted explanation (' + (exp.ai_model || 'model') + ')' : 'built-in offline rules') + '. ' + (exp.disclaimer || '')),
        h('button', { class: 'btn small', type: 'button', id: 'btn-explain', disabled: !isAnalyst(), onclick: async () => {
          try { const r = await api('/api/alerts/' + a.id + '/explain', { method: 'POST' }); toast('Explanation refreshed (' + (r.source === 'ai' ? 'AI' : 'offline rules') + ').'); await reload(); } catch (e) { fail(e); }
        } }, state.config.ai_enabled ? 'Regenerate with AI' : 'Regenerate explanation')),

      h('section', null, h('h3', null, 'Why this score: ' + a.score + '/10'),
        a.breakdown.map((b) => h('div', { class: 'bd-row' }, h('div', null, h('strong', null, b.factor)),
          h('div', { class: 'bar-track bd-bar' }, h('div', { class: 'bar-fill', style: { width: pct(b.points, b.max) + '%' } })),
          h('div', { class: 'small' }, b.points.toFixed(2) + ' / ' + b.max), h('div', { class: 'bd-detail' }, b.detail))),
        h('div', { class: 'bd-total' }, 'Total ' + total.toFixed(2) + ' of 10 = score ' + a.score + '/10 (rounded, minimum 1)')),

      h('section', null, h('h3', null, 'Detection evidence'), h('ul', { class: 'plain' }, a.evidence.map((e) => h('li', null, e))),
        a.related.length ? h('p', { class: 'small' }, h('strong', null, 'Also detected nearby: '), a.related.map((r) => r.rule_id + ' ' + r.title).join('; ')) : null),

      h('section', null, h('div', { class: 'page-title' }, h('h3', null, 'Original log lines (simulated)'),
        h('button', { class: 'btn small', type: 'button', id: 'btn-export-alert-logs', onclick: () => download('/api/export/logs.csv', { alert_id: a.id }, 'alert-' + a.id + '-logs.csv').catch(fail) }, 'Export these logs (CSV)')),
        logTable(d.logs)),

      h('section', null, h('h3', null, 'Analyst notes'),
        d.notes.length ? d.notes.map((n) => h('div', { class: 'note' }, h('div', { class: 'meta' }, n.author + ' - ' + fmtTime(n.created_at)), h('div', null, n.text))) : h('p', { class: 'muted' }, 'No notes yet.'),
        note, h('div', { class: 'toolbar', style: { marginTop: '.4rem' } }, h('button', { class: 'btn primary', type: 'button', id: 'note-save', disabled: !isAnalyst(), onclick: async () => {
          const text = note.value.trim();
          if (!text) return toast('Write a note first.', 'error');
          try { await api('/api/alerts/' + a.id + '/notes', { method: 'POST', body: { text } }); toast('Note added.'); await reload(); } catch (e) { fail(e); }
        } }, 'Add note'))));
    delClass(drawer, 'hidden');
  }

  // ---------------------------------------------------------------- logs
  async function renderLogs() {
    const st = state.logs, f = st.filters, o = state.options;
    const apply = () => { st.offset = 0; renderLogs(); };
    const q = h('input', { type: 'search', id: 'l-q', value: f.q || '', placeholder: 'Search any text in the raw log...' });
    const user = h('input', { type: 'text', id: 'l-username', value: f.username || '' });
    const ip = h('input', { type: 'text', id: 'l-src_ip', value: f.src_ip || '' });
    const start = h('input', { type: 'date', id: 'l-start', value: f.start || '' });
    const end = h('input', { type: 'date', id: 'l-end', value: f.end || '' });
    const read = () => { f.q = q.value.trim(); f.username = user.value.trim(); f.src_ip = ip.value.trim(); f.start = start.value; f.end = end.value; };
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { read(); apply(); } });
    const sel = (key, label, pairs) => field(label, select(pairs, f[key] || '', (e) => { f[key] = e.target.value; apply(); }, { id: 'l-' + key }));
    const filters = h('div', { class: 'filters' }, field('Search', q, 'grow'),
      sel('source', 'Source', [['', 'All'], ...o.sources.map((s) => [s, s])]), sel('event_type', 'Event type', [['', 'All'], ...o.event_types.map((s) => [s, s])]),
      sel('asset', 'System', [['', 'All'], ...o.assets.map((s) => [s, s])]), sel('scenario', 'Scenario label', [['', 'All'], ...o.scenarios.map((s) => [s, s.replace(/_/g, ' ')])]),
      field('User', user), field('Source IP', ip), field('From', start), field('To (whole day)', end),
      h('button', { class: 'btn primary', type: 'button', id: 'l-apply', onclick: () => { read(); apply(); } }, 'Search'),
      h('button', { class: 'btn', type: 'button', id: 'l-reset', onclick: () => { st.filters = {}; apply(); } }, 'Reset'),
      h('button', { class: 'btn', type: 'button', id: 'l-export-csv', onclick: () => download('/api/export/logs.csv', f, 'simulated-logs.csv').catch(fail) }, 'Export CSV'),
      h('button', { class: 'btn', type: 'button', id: 'l-export-jsonl', onclick: () => download('/api/export/logs.jsonl', f, 'simulated-logs.jsonl').catch(fail) }, 'Export JSONL'));

    const data = await api('/api/logs' + qs(Object.assign({}, f, { limit: st.limit, offset: st.offset })));
    const rows = [];
    for (const l of data.items) {
      const raw = h('tr', { class: 'hidden' }, h('td', { colspan: 6 }, h('pre', null, JSON.stringify(l, null, 2))));
      rows.push(h('tr', null, h('td', { class: 'nowrap small' }, fmtTime(l.timestamp)), h('td', null, l.asset), h('td', null, l.source + ' / ' + l.event_type),
        h('td', { class: 'hide-sm' }, l.username || '-'), h('td', { class: 'small hide-sm' }, (l.src_ip || '-') + (l.dst_ip ? ' -> ' + l.dst_ip + (l.dst_port ? ':' + l.dst_port : '') : '')),
        h('td', null, h('div', { class: 'small' }, l.message), h('button', { class: 'btn small', type: 'button', onclick: () => toggleHidden(raw) }, 'Raw log'),
          l.sim_scenario ? h('span', { class: 'muted small' }, ' scenario: ' + l.sim_scenario) : null)));
      rows.push(raw);
    }
    const table = data.items.length ? h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'System'), h('th', null, 'Event'),
      h('th', { class: 'hide-sm' }, 'User'), h('th', { class: 'hide-sm' }, 'Network'), h('th', null, 'Message'))), h('tbody', null, rows))) : emptyBox('No logs match these filters.');
    setMain(h('div', null, h('div', { class: 'page-title' }, h('h2', null, 'Security logs'), h('span', { class: 'muted small' }, data.total + ' matching - all simulated')), filters, table,
      pager(data.total, data.offset, data.limit, (o2) => { st.offset = o2; renderLogs(); })));
  }

  // ---------------------------------------------------------------- assets & audit
  async function renderAssets() {
    const rows = await api('/api/assets');
    const goAsset = (name) => { state.alerts.filters = { status: 'open', sort: 'score_desc', asset: name }; state.alerts.offset = 0; go('alerts'); };
    setMain(h('div', null, h('div', { class: 'page-title' }, h('h2', null, 'Hospital systems (simulated inventory)')),
      h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'System'), h('th', null, 'Type'), h('th', { class: 'hide-sm' }, 'Department'),
        h('th', null, 'Criticality'), h('th', { class: 'hide-sm' }, 'Patient care'), h('th', null, 'Open alerts'), h('th', null, 'Highest score'))),
        h('tbody', null, rows.map((a) => h('tr', { class: 'clickable', tabindex: '0', onclick: () => goAsset(a.asset), onkeydown: (e) => { if (e.key === 'Enter') goAsset(a.asset); } },
          h('td', null, h('strong', null, a.asset), h('div', { class: 'muted small' }, a.description)), h('td', null, a.type.replace('_', ' ')), h('td', { class: 'hide-sm' }, a.department),
          h('td', null, a.criticality + '/5'), h('td', { class: 'hide-sm' }, a.patient_care ? 'Yes' : 'No'), h('td', null, String(a.open_alerts)),
          h('td', null, a.max_score ? sevBadge(a.max_score >= 8 ? 'critical' : a.max_score >= 6 ? 'high' : a.max_score >= 4 ? 'medium' : 'low', a.max_score + '/10') : '-'))))))));
  }

  async function renderAudit() {
    if (!isAnalyst()) { setMain(emptyBox('The audit trail is visible to analysts only.')); return; }
    const st = state.audit;
    const d = await api('/api/audit' + qs({ limit: st.limit, offset: st.offset }));
    setMain(h('div', null, h('div', { class: 'page-title' }, h('h2', null, 'Audit trail'), h('span', { class: 'muted small' }, 'Every change made through this application')),
      d.items.length ? h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Time'), h('th', null, 'Role'), h('th', null, 'Action'), h('th', null, 'Detail'))),
        h('tbody', null, d.items.map((r) => h('tr', null, h('td', { class: 'nowrap small' }, fmtTime(r.ts)), h('td', null, r.actor), h('td', null, r.action), h('td', null, r.detail || '')))))) : emptyBox('Nothing recorded yet.'),
      pager(d.total, d.offset, d.limit, (o) => { st.offset = o; renderAudit(); })));
  }

  // ---------------------------------------------------------------- modal
  function openModal(title, body) {
    $('modal').replaceChildren(h('div', { class: 'backdrop' }, h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, h('h2', null, title), body)));
  }
  function closeModal() { $('modal').replaceChildren(); }

  // ---------------------------------------------------------------- init
  function init() {
    $('login-form').addEventListener('submit', (e) => {
      e.preventDefault();
      state.token = $('token-input').value.trim();
      $('token-input').value = '';
      if (!state.token) return;
      try { sessionStorage.setItem('soc_token', state.token); } catch (err) { /* private mode */ }
      boot();
    });
    $('logout-btn').addEventListener('click', () => { closeModal(); showLogin('You have been signed out.'); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeModal(); closeDrawer(); } });
    setInterval(() => { if ($('auto-refresh').checked && !state.openAlertId && (state.view === 'overview' || state.view === 'alerts')) renderCurrent(true); }, 30000);
    boot();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
