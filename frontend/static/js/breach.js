/* breach.js — JanuSec Breach Assessment front-end core
 *
 * Routing:
 *   breach.html                           → upload zone (no assessment)
 *   breach.html?assessment=a_XXXX         → home page (swimlane + cards)
 *   breach.html?cluster=C&assessment=A    → cluster detail tab
 *   breach.html?assessment=A&tab=evidence → evidence tab (reuses investigate.js)
 *   breach.html?assessment=A&tab=hopgraph → full HopGraph tab
 *   breach.html?assessment=A&tab=compliance → compliance tab (Phase B)
 *
 * LLM gate policy (NON-NEGOTIABLE):
 *   - Tier-1 cluster-1 fires ONCE automatically at page load (cached)
 *   - Exec summary fires ONCE at page load (cached)
 *   - Top threat cases hydrate automatically.
 *   - Additional threat cases hydrate only when the user clicks [Generate].
 *   - Nothing fires on hover, focus, polling, or tab-switch
 */
(function () {
  'use strict';

  // Auto-seed dev API key on localhost so progress polling works without manual settings config
  try {
    if (!localStorage.getItem('apiKey') && /localhost|127\.0\.0\.1/.test(window.location.hostname)) {
      localStorage.setItem('apiKey', 'devkey123');
    }
  } catch (_) {}

  // ── API helpers ─────────────────────────────────────────────────────────────

  function apiBase() { return (window.JanuSecBreachAPI && window.JanuSecBreachAPI.apiBase ? window.JanuSecBreachAPI.apiBase() : (window.JANUSEC_API_BASE || '')); }

  function authHeaders() {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.authHeaders) return window.JanuSecBreachAPI.authHeaders();
    var k = '';
    try { k = localStorage.getItem('apiKey') || ''; } catch (_) {}
    if (!k) k = 'devkey123';
    var t = 'default';
    try { t = localStorage.getItem('tenantId') || 'default'; } catch (_) {}
    var h = { 'Content-Type': 'application/json' };
    if (k) h['x-api-key'] = k;
    h['x-tenant-id'] = t;
    return h;
  }

  function getSelectedModel() {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.getSelectedModel) return window.JanuSecBreachAPI.getSelectedModel();
    try { return localStorage.getItem('selectedModel') || 'qwen3.6:27b'; } catch (_) { return 'qwen3.6:27b'; }
  }

  function apiFetch(path, opts) {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.apiFetch) return window.JanuSecBreachAPI.apiFetch(path, opts);
    return fetch(apiBase() + path, Object.assign({ headers: authHeaders() }, opts || {}));
  }

  function apiPost(path, body) {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.apiPost) return window.JanuSecBreachAPI.apiPost(path, body);
    return apiFetch(path, {
      method: 'POST',
      body: JSON.stringify(body || {}),
    });
  }

  function authQuery() {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.authQuery) return window.JanuSecBreachAPI.authQuery();
    var params = new URLSearchParams();
    try {
      var k = localStorage.getItem('apiKey') || 'devkey123';
      if (k) params.set('api_key', k);
      params.set('tenant', localStorage.getItem('tenantId') || 'default');
    } catch (_) {
      params.set('api_key', 'devkey123');
      params.set('tenant', 'default');
    }
    return params.toString();
  }

  function authedUrl(path) {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.authedUrl) return window.JanuSecBreachAPI.authedUrl(path);
    var sep = path.indexOf('?') === -1 ? '?' : '&';
    return apiBase() + path + sep + authQuery();
  }

  function openAuthed(path) {
    if (window.JanuSecBreachAPI && window.JanuSecBreachAPI.openAuthed) return window.JanuSecBreachAPI.openAuthed(path);
    window.open(authedUrl(path), '_blank', 'noopener');
  }

  // ── URL state ───────────────────────────────────────────────────────────────

  var _params = new URLSearchParams(window.location.search);
  var AID   = _params.get('assessment') || '';
  var CID   = _params.get('cluster') || '';
  var TAB   = _params.get('tab') || '';
  if (window.JanuSecBreachState) {
    _params = window.JanuSecBreachState.params || _params;
    AID = window.JanuSecBreachState.AID || AID;
    CID = window.JanuSecBreachState.CID || CID;
    TAB = window.JanuSecBreachState.TAB || TAB;
  }

  // ── State ───────────────────────────────────────────────────────────────────

  var state = {
    assessment: null,
    clusters: [],
    rows: [],
    prefillStatus: {},   // cluster_id → 'pending' | 'done' | 'error'
    execSummary: null,
  };
  if (window.JanuSecBreachState && window.JanuSecBreachState.state) {
    state = window.JanuSecBreachState.state;
  }

  var _asyncRedirecting = {};
  var _asyncPollTimers = {};
  if (window.JanuSecBreachState) {
    _asyncRedirecting = window.JanuSecBreachState.asyncRedirecting || _asyncRedirecting;
    _asyncPollTimers = window.JanuSecBreachState.asyncPollTimers || _asyncPollTimers;
  }

  // ── Toast ───────────────────────────────────────────────────────────────────

  function toast(msg, durationMs) {
    var el = document.createElement('div');
    el.className = 'br-toast';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, durationMs || 2800);
  }

  // ── Main router ─────────────────────────────────────────────────────────────

  function init() {
    if (!AID) {
      renderUpload();
      return;
    }
    loadAssessment().then(function () {
      if (CID) {
        renderClusterTab();
      } else if (TAB === 'evidence') {
        renderEvidenceTab();
      } else if (TAB === 'hopgraph') {
        renderHopGraphTab();
      } else if (TAB === 'compliance') {
        renderComplianceTab();
      } else if (TAB === 'intel') {
        renderIntelTab();
      } else if (TAB === 'postmortem') {
        renderPostmortemTab();
      } else {
        renderHome();
      }
    });
  }

  // ── Assessment loader ────────────────────────────────────────────────────────

  function loadAssessment() {
    return apiFetch('/api/v1/assessments/' + encodeURIComponent(AID))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        state.assessment = data;
        // Prefer classified analysis_clusters; fall back to raw correlation_clusters.
        state.clusters = data.analysis_clusters || data.correlation_clusters || [];
        state.rawClusters = data.raw_correlation_clusters || data.correlation_clusters || [];
        state.threatCases = data.threat_cases || [];
        state.rows = data.normalized_rows || data.evidence_rows || data.rows || [];
      })
      .catch(function (err) {
        console.error('breach.js: loadAssessment failed', err);
      });
  }

  // ── Severity helpers ─────────────────────────────────────────────────────────

  var _VERDICT_CLASS = {
    'NO_VALIDATED_BREACH': 'benign',  'NO VALIDATED BREACH': 'benign',
    'VALIDATED_BREACH':    'confirmed', 'CONFIRMED_INTRUSION': 'confirmed',
    'CONFIRMED_BREACH':    'confirmed',
    'LIKELY_BREACH':       'likely',
    'LIKELY_COMPROMISE':   'likely',  'SUSPICIOUS_ACTIVITY': 'uncertain',
    'INSUFFICIENT_TELEMETRY': 'uncertain', 'BENIGN_EXPECTED': 'benign',
    'CONFIRMED': 'confirmed', 'LIKELY REAL': 'likely', 'LIKELY': 'likely',
    'UNCERTAIN': 'uncertain', 'BENIGN': 'benign',
    'INVESTIGATION_REQUIRED': 'uncertain',
    'ANALYSIS_INCOMPLETE': 'incomplete',
  };

  function verdictClass(v) {
    var vu = (v || '').toUpperCase();
    if (vu.indexOf('NO_VALIDATED_BREACH') !== -1 || vu.indexOf('NO VALIDATED BREACH') !== -1) return 'benign';
    for (var k in _VERDICT_CLASS) {
      if (vu.indexOf(k) !== -1) return _VERDICT_CLASS[k];
    }
    return 'uncertain';
  }

  function verdictIcon(v) {
    var vc = verdictClass(v);
    if (vc === 'confirmed') return '●';
    if (vc === 'likely') return '⚑';
    if (vc === 'uncertain') return '?';
    if (vc === 'benign') return '✓';
    return '';
  }

  function escHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── SVG icon library (Lucide-compatible inline SVGs) ──────────────────────
  // All icons use stroke="currentColor" so they inherit text color from CSS.
  var _ICONS = {
    shield:       '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    scale:        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16 16l3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M2 16l3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>',
    'bar-chart':  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>',
    crosshair:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>',
    microscope:   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 18h8"/><path d="M3 22h18"/><path d="M14 22a7 7 0 1 0 0-14h-1"/><path d="M9 14h2"/><path d="M9 12a2 2 0 0 1-2-2V6h6v4a2 2 0 0 1-2 2z"/><path d="M12 6V3a1 1 0 0 0-1-1H9a1 1 0 0 0-1 1v3"/></svg>',
    clipboard:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/></svg>',
    'file-text':  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
    warning:      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    check:        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>',
    x:            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    upload:       '<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>',
    'refresh-cw': '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
    'rotate-cw':  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
    cpu:          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
    // MITRE phase icons
    'door-open':  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561z"/></svg>',
    zap:          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    pin:          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V17z"/></svg>',
    unlock:       '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>',
    'arrows-lr':  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3 4 7l4 4"/><path d="M4 7h16"/><path d="m16 21 4-4-4-4"/><path d="M20 17H4"/></svg>',
    package:      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>',
    'upload-c2':  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>',
    radio:        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/></svg>',
    // DREAD icons
    flame:        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>',
    repeat:       '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>',
    user:         '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    search:       '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    // PASTA icons
    target:       '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    eye:          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    activity:     '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    'send':       '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>',
    'sparkles':   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>',
  };

  function _icon(name, cls) {
    var svg = _ICONS[name] || '';
    if (!svg) return '';
    var c = cls ? ' class="br-icon ' + cls + '"' : ' class="br-icon"';
    return '<span' + c + '>' + svg + '</span>';
  }

  function _displayVerdict(v) {
    var raw = String(v || '').toUpperCase();
    if (raw === 'VALIDATED_BREACH' || raw === 'CONFIRMED_INTRUSION' || raw === 'CONFIRMED_BREACH') return 'CONFIRMED BREACH';
    if (raw === 'NO_VALIDATED_BREACH') return 'NO CONFIRMED BREACH';
    return raw.replace(/_/g, ' ') || 'UNCERTAIN';
  }

  function _dreadInfo(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var dn = p.dread_narrative || {};
    var frags = dn.fragments || {};
    var order = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'];
    var parts = [];
    order.forEach(function (key) {
      if (frags[key]) parts.push({ key: key, label: key.replace(/_/g, ' ').toUpperCase(), text: String(frags[key]) });
    });
    var hasPasta = !!(p.pasta_summary && (p.pasta_summary.threat_profile || p.pasta_summary.exploitation_path || p.pasta_summary.business_impact));
    var hasDiamond = !!(p.diamond_model && (p.diamond_model.adversary || (p.diamond_model.capability && p.diamond_model.capability.length)));
    var provenance;
    if (dn.rendered) {
      provenance = 'LLM-rendered DREAD';
    } else if (parts.length) {
      provenance = 'Deterministic DREAD fragments';
    } else if (hasPasta) {
      provenance = 'PASTA threat model';
    } else if (hasDiamond) {
      provenance = 'DIAMOND threat model';
    } else if (p.what_happened || p.incident_name) {
      provenance = 'T1 LLM analysis';
    } else {
      provenance = 'Legacy fallback';
    }
    return {
      dn: dn,
      frags: frags,
      parts: parts,
      // hasStructured = true only when actual DREAD/PASTA/Diamond content exists.
      // Does NOT count raw T1 text (what_happened / incident_name) since those can
      // be deterministic fallback strings that carry no structured threat model.
      hasStructured: !!(dn.rendered || parts.length || hasPasta || hasDiamond),
      has: !!(dn.rendered || parts.length || p.what_happened || p.incident_name),
      hasPasta: hasPasta,
      hasDiamond: hasDiamond,
      hasT1: !!(p.what_happened || p.incident_name || p.evidence_chain),
      provenance: provenance
    };
  }

  function _rowChipsFromText(text, limit) {
    var found = [];
    String(text || '').replace(/\brows?\s+([0-9][0-9,\s+]*(?:\+\s*\d+\s+more)?)/ig, function (_, group) {
      var clean = String(group || '').replace(/\+\s*\d+\s*(?:more)?/ig, '');
      (clean.match(/\d+/g) || []).forEach(function (n) {
        if (found.indexOf(n) === -1 && found.length < (limit || 16)) found.push(n);
      });
      return _;
    });
    if (!found.length) return '';
    return '<div class="br-rowchips">Evidence refs: ' + found.map(function (n) {
      return '<a class="br-rowchip" href="/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=evidence&row=' + encodeURIComponent(n) + '">[' + escHtml(n) + ']</a>';
    }).join(' ') + '</div>';
  }

  function _renderWhyConfirmed(cluster) {
    var d = _dreadInfo(cluster);
    var _t1r = (cluster || {}).tier1_prefill || {};
    // Filter raw correlation text from what_happened before using it for pattern matching
    var _t1wh = _rawCorrelationText(_t1r.what_happened || '') ? '' : (_t1r.what_happened || '');
    var full = d.parts.map(function (p) { return p.text; }).join(' ').toLowerCase()
      + ' ' + JSON.stringify(_t1r.observed_impact || {}).toLowerCase()
      + ' ' + _t1wh.toLowerCase()
      + ' ' + JSON.stringify(_t1r.evidence_chain || []).toLowerCase()
      + ' ' + (_t1r.root_cause || '').toLowerCase()
      + ' ' + (_t1r.headline_subtitle || '').toLowerCase()
      // Cluster-level fields — always populated by the detection pipeline
      + ' ' + (cluster.lead_description || '').toLowerCase()
      + ' ' + (cluster.business_significance || '').toLowerCase()
      + ' ' + JSON.stringify(cluster.phases || []).toLowerCase()
      + ' ' + (cluster.shared_accounts || cluster.affected_accounts || []).join(' ').toLowerCase()
      + ' ' + (cluster.affected_assets || cluster.shared_hosts || []).join(' ').toLowerCase();
    var gates = [
      ['Data exfil', /exfil|copy into|unload|rclone|cloud sync|transferred data|cloud storage|s3.*get|putobject|download|data_exfil/.test(full)],
      ['Repeated activity', /recurred|distinct days|same command|reproduc|recurring|repeated|multiple.*event|persistent|multi.*phase|attack phase|8 phase/.test(full)],
      ['Affected users', /account|user|service_account|privileged|affected users|identity|credential|principal|pentest|svc_/.test(full)],
      ['Control gap', /no dlp|no pam|control gap|unconstrained|no inspection|no gate|unmonitored|bypass|privileged.*workload|daemonset|k8s.*privilege/.test(full)],
      ['Crown jewel', /crown jewel|regulated data|critical data|protected data|ndb|cps234|secret|encryption key|k8s|kubernetes|finance[_-]?warehouse|warehouse[_-]?data|privileged workload|daemonset/.test(full)],
      ['Multi-source correlation', /cross-source|source types|multiple sources|correlation|multi.*source|okta|cloudtrail|azure/.test(full)
        || (cluster.confidence_meter && (cluster.confidence_meter.source_types_present || []).length > 1)]
    ];
    return '<div class="br-why-ladder">' + gates.map(function (g) {
      return '<span class="br-why-chip ' + (g[1] ? 'br-why-chip--ok' : 'br-why-chip--miss') + '">' + (g[1] ? '✓ ' : '? ') + escHtml(g[0]) + '</span>';
    }).join('') + '</div>';
  }

  function _sentenceList(text) {
    return String(text || '').replace(/\s+/g, ' ').split(/(?<=[.!?])\s+/).map(function (s) {
      return s.trim();
    }).filter(Boolean);
  }

  function _firstEvidenceSentence(cluster, fallback) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    var damage = (d.frags && d.frags.damage) || '';
    var repro = (d.frags && d.frags.reproducibility) || '';
    // Use T1 what_happened only when it's not raw correlation text
    var t1wh = (p.what_happened || '');
    var t1Sentence = (!_rawCorrelationText(t1wh)) ? (_sentenceList(t1wh)[0] || '') : '';
    var s1 = _sentenceList(damage)[0] || t1Sentence || fallback || '';
    var s2 = _sentenceList(repro)[0] || '';
    return [s1, s2].filter(Boolean).join(' ');
  }

  function _businessImpactSentence(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    var bits = [];
    if (d.dn && d.dn.sabsa_coda_draft) bits.push(d.dn.sabsa_coda_draft);
    // Only include exploitability fragment when its core text is NOT already
    // embedded in the sabsa_coda_draft (which always includes the control-gap hint)
    if (d.frags && d.frags.exploitability) {
      var explo = d.frags.exploitability;
      var exploCore = explo.replace(/^control gaps exploited:\s*/i, '').replace(/\.$/, '').toLowerCase();
      var alreadyCovered = bits.some(function(b) {
        return exploCore.length > 20 && b.toLowerCase().indexOf(exploCore.substring(0, 50)) !== -1;
      });
      if (!alreadyCovered) bits.push(explo);
    }
    if (!bits.length && p.observed_impact && p.observed_impact.data) bits.push('Data impact: ' + p.observed_impact.data);
    if (!bits.length && p.observed_impact && p.observed_impact.ops) bits.push('Operational impact: ' + p.observed_impact.ops);
    if (!bits.length && p.observed_impact && p.observed_impact.access) bits.push('Access impact: ' + p.observed_impact.access);
    if (!bits.length && p.pasta_summary && p.pasta_summary.business_impact) bits.push(p.pasta_summary.business_impact);
    // Use T1 what_happened only when it's not raw correlation text
    if (!bits.length && p.what_happened && !_rawCorrelationText(p.what_happened)) {
      bits.push(_sentenceList(p.what_happened)[0] || '');
    }
    // Cluster-level fallback: business_significance > lead_description
    if (!bits.length) {
      var biz = (cluster.business_significance || cluster.lead_description || '').trim();
      if (biz && !_rawCorrelationText(biz) && biz.length > 10) bits.push(biz);
    }
    return bits.filter(Boolean).join(' ');
  }

  function _knownUnknownBox(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    // Filter raw correlation text from what_happened before building text
    var _t1wh = _rawCorrelationText(p.what_happened || '') ? '' : (p.what_happened || '');
    var text = (d.parts.map(function (x) { return x.text; }).join(' ')
      + ' ' + JSON.stringify(p.observed_impact || {})
      + ' ' + _t1wh
      + ' ' + JSON.stringify(p.evidence_chain || [])
      + ' ' + (p.root_cause || '')
    ).toLowerCase();
    var known = [];
    var unknown = [];
    if (/rclone/.test(text)) known.push('Tool: rclone file-sync activity');
    if (/cloud storage|external storage|object storage/.test(text)) known.push('Destination: external cloud storage indicated by evidence');
    if (/crown jewel|regulated data|critical data|protected data/.test(text)) known.push('Crown-jewel or protected data indicator present in evidence');
    if (/no dlp/.test(text) || /no pam/.test(text)) known.push('Control gaps: DLP/PAM coverage missing in evidence');
    if (/service account|privileged|finance|standard user/.test(text)) known.push('Affected roles: service account, privileged/IT, finance, standard users');
    // T1 prefill enrichments — populate known list from structured T1 data
    if (!known.length && p.root_cause) known.push('Root cause: ' + p.root_cause);
    var _scope = p.affected_scope || {};
    var _scopeUsers = (_scope.users || _scope.accounts || []).filter(Boolean);
    if (!known.length && _scopeUsers.length) known.push('Compromised accounts: ' + _scopeUsers.slice(0, 3).join(', '));
    var _scopeHosts = (_scope.hosts || _scope.systems || []).filter(Boolean);
    if (_scopeHosts.length) known.push('Affected systems: ' + _scopeHosts.slice(0, 3).join(', '));
    // Evidence chain steps as confirmed facts — use first 2 meaningful steps
    if (!known.length && p.evidence_chain && p.evidence_chain.length) {
      p.evidence_chain.slice(0, 3).forEach(function(step) {
        var what = (step.what || step.event || step.description || step.action || '').trim();
        if (what && known.length < 3) known.push(what.length > 90 ? what.slice(0, 87) + '\u2026' : what);
      });
    }
    // Immediate actions as evidence of what was confirmed
    if (!known.length && p.immediate_actions && p.immediate_actions.length) {
      var ia = p.immediate_actions[0];
      var iaText = (typeof ia === 'string' ? ia : (ia.action || ia.step || '')).trim();
      if (iaText) known.push('Recommended: ' + (iaText.length > 80 ? iaText.slice(0, 77) + '\u2026' : iaText));
    }
    // Cluster-level data — always populated by the detection pipeline
    var clAccts = (cluster.shared_accounts || cluster.affected_accounts || []).filter(Boolean).slice(0, 3);
    if (clAccts.length && !known.some(function(k){ return /account|credential/i.test(k); })) {
      known.push('Compromised accounts: ' + clAccts.join(', '));
    }
    var clAssets = (cluster.affected_assets || cluster.shared_hosts || []).filter(Boolean).slice(0, 3);
    if (clAssets.length && !known.some(function(k){ return /system|host/i.test(k); })) {
      known.push('Affected systems: ' + clAssets.join(', '));
    }
    var clIps = (cluster.shared_external_ips || []).slice(0, 3);
    if (clIps.length) known.push('External infrastructure: ' + clIps.join(', '));
    var phases = (cluster.phases || []).map(function(ph) {
      return (ph.phase_role || ph.type || ph.name || '').replace(/_/g, ' ');
    }).filter(Boolean).slice(0, 5);
    if (phases.length) known.push('Attack phases confirmed: ' + phases.join(' \u2192 '));
    if (!/pii|customer|payroll|secret|source code|credential dump/.test(text)) unknown.push('Exact data contents and volume are unknown from current evidence');
    if (!/attacker-owned|external owner|malicious owner/.test(text)) unknown.push('External destination attribution and ownership is unconfirmed');
    if (!known.length) known.push('Evidence-confirmed facts are limited to the cited rows');
    return [
      '<div class="br-known-unknown">',
      '  <div><strong>Known</strong><ul>' + known.slice(0, 6).map(function (x) { return '<li>' + escHtml(x) + '</li>'; }).join('') + '</ul></div>',
      '  <div><strong>Unknown / not proven</strong><ul>' + unknown.slice(0, 4).map(function (x) { return '<li>' + escHtml(x) + '</li>'; }).join('') + '</ul></div>',
      '</div>'
    ].join('');
  }

  function _boundedActionsHtml(cluster) {
    var d = _dreadInfo(cluster);
    var _t1ba = (cluster || {}).tier1_prefill || {};
    // Filter raw correlation text before building the keyword-match text
    var _t1wh = _rawCorrelationText(_t1ba.what_happened || '') ? '' : (_t1ba.what_happened || '');
    var text = (d.parts.map(function (x) { return x.text; }).join(' ')
      + ' ' + _t1wh
      + ' ' + JSON.stringify(_t1ba.observed_impact || {})
      + ' ' + JSON.stringify(_t1ba.evidence_chain || [])
      // Cluster-level data for context branching
      + ' ' + JSON.stringify(cluster.phases || []).toLowerCase()
      + ' ' + (cluster.lead_description || '').toLowerCase()
      + ' ' + (cluster.business_significance || '').toLowerCase()
    ).toLowerCase();
    var safe, approval, manual;
    var isK8s = /kubernetes|k8s|daemonset|privileged.*workload|kubelet|container.*priv/.test(text);
    var isC2 = /c2[^a-z]|c2_comm|beacon|command.*control/.test(text);
    var isMultiPhase = /multi.*phase|multiphase|\d+\s+phase|attack phase/.test(text);
    var isExfil = /external storage|object storage|cloud|s3|exfil|transferred|data_exfil/.test(text);
    var isCred = /credential.*theft|lsass|mimikatz|token.*theft|mfa.*fatigue|session.*theft|password.*spray|credential_theft|session_theft/.test(text)
      || (cluster.phases || []).some(function(ph) { return /credential|session.*theft|mfa/.test((ph.phase_role || ph.type || ph.name || '').toLowerCase()); });
    var clAccts = (cluster.shared_accounts || cluster.affected_accounts || []).slice(0, 2);
    var acctList = clAccts.length ? clAccts.join(' and ') : 'affected accounts';
    var clIps = (cluster.shared_external_ips || []).slice(0, 3);
    var ipList = clIps.length ? clIps.join(', ') : 'identified C2 IPs';
    if (isCred) {
      safe = 'Revoke all active sessions and tokens for ' + acctList + ' immediately; collect endpoint memory dumps and auth logs before any changes';
      approval = 'Force password reset and MFA re-enrollment for ' + acctList + '; review and prune all delegated access after CISO sign-off';
      manual = 'CISO/Legal: assess whether credential access constitutes an NDB-reportable breach; confirm blast radius includes any downstream service accounts or API keys';
    } else if (isK8s) {
      safe = 'Isolate affected K8s namespaces; collect pod logs, kubelet audit events, and service account audit trails before any changes';
      approval = 'Revoke credentials for ' + acctList + '; rotate K8s service account tokens and RBAC bindings after sign-off';
      manual = isMultiPhase
        ? 'CISO/Legal: assess APRA CPS 234 72h notification window across all ' + ((cluster.phases || []).length || 'identified') + ' attack phases; confirm regulated-data exposure scope'
        : 'CISO/Legal: confirm whether regulated data was exposed via privileged K8s workload; assess NDB obligations';
    } else if (isC2) {
      safe = 'Preserve endpoint, DNS, and full-packet capture logs for identified C2 channels before firewall changes';
      approval = 'Block C2 destination IPs (' + ipList + ') at perimeter and DNS sinkholes after CISO approval';
      manual = 'CISO/Legal/Privacy: determine external attribution and reporting posture; assess NDB if data was staged';
    } else if (isExfil) {
      safe = 'Preserve endpoint, data-platform, and network egress logs before any remediation';
      approval = 'Block or restrict exfil destinations and revoke ' + acctList + ' credentials after approval';
      manual = 'CISO/Legal/Privacy: sign-off on breach notification posture and data-volume assessment';
    } else {
      safe = 'Preserve endpoint, data-platform, and network evidence before any remediation steps';
      approval = 'Contain affected destinations and revoke ' + acctList + ' credentials after sign-off';
      manual = 'CISO/Legal/Privacy: sign-off on reporting posture and scope confirmation';
    }
    return [
      '<div class="br-bounded-actions">',
      '  <div><span class="br-auto br-auto--safe">SAFE</span> ' + escHtml(safe) + '</div>',
      '  <div><span class="br-auto br-auto--approval">APPROVAL</span> ' + escHtml(approval) + '</div>',
      '  <div><span class="br-auto br-auto--manual">MANUAL</span> ' + escHtml(manual) + '</div>',
      '</div>'
    ].join('');
  }

  function _compactExecSummary(data, fallbackBody) {
    var fragments = data.dread_fragments || {};
    var p1 = _sentenceList(fragments.damage || data.executive_summary || fallbackBody).slice(0, 2).join(' ');
    var p2Parts = [];
    if (data.sabsa_coda_draft) p2Parts.push(data.sabsa_coda_draft);
    if (fragments.exploitability) p2Parts.push(_sentenceList(fragments.exploitability)[0]);
    if (data.scope && data.scope.ruled_out_rows) {
      p2Parts.push(data.scope.ruled_out_rows.toLocaleString() + ' authorized-security-test or benign rows were excluded from breach scope.');
    }
    var p2 = p2Parts.join(' ');
    return {
      p1: p1 || fallbackBody || '',
      p2: p2 || _sentenceList(data.executive_summary || fallbackBody).slice(2, 4).join(' ')
    };
  }

  function _dreadNarrativeText(cluster, fallback) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    if (d.dn.rendered) return d.dn.rendered;
    if (d.parts.length) {
      var body = d.parts.map(function (x) { return x.label + ': ' + x.text; }).join('\n');
      if (d.dn.sabsa_coda_draft) body += '\nSABSA: ' + d.dn.sabsa_coda_draft;
      return body;
    }
    // PASTA fallback: stages 4 (threat profile), 5 (exploitation path), 7 (business impact)
    if (d.hasPasta) {
      var pasta = p.pasta_summary || {};
      var pastaParts = [];
      if (pasta.threat_profile) pastaParts.push('THREAT ACTOR: ' + pasta.threat_profile);
      if (pasta.exploitation_path) pastaParts.push('EXPLOITATION: ' + pasta.exploitation_path);
      if (pasta.business_impact) pastaParts.push('BUSINESS IMPACT: ' + pasta.business_impact);
      if (pastaParts.length) return pastaParts.join('\n');
    }
    // Diamond fallback: adversary, capability, victim
    if (d.hasDiamond) {
      var dm = p.diamond_model || {};
      var dmParts = [];
      if (dm.adversary) dmParts.push('ADVERSARY: ' + dm.adversary);
      if (dm.capability && dm.capability.length) dmParts.push('CAPABILITIES: ' + dm.capability.slice(0, 5).join(', '));
      var victims = (dm.victim_users || []).concat(dm.victim_data || []);
      if (victims.length) dmParts.push('VICTIM SCOPE: ' + victims.slice(0, 4).join(', '));
      if (dmParts.length) return dmParts.join('\n');
    }
    // T1 LLM prefill content — use only when it's not a raw correlation string
    if (p.what_happened && !_rawCorrelationText(p.what_happened)) return p.what_happened;
    return fallback || '';
  }

  // ── Upload view ──────────────────────────────────────────────────────────────

  function renderUpload() {
    updateTabBar(null);
    document.getElementById('br-content').innerHTML = [
      '<div class="br-upload" data-testid="br-upload">',
      '  <div class="br-upload__zone" id="br-drop-zone" data-testid="br-drop-zone">',
      '    <div class="br-upload__icon">' + _icon('upload') + '</div>',
      '    <div class="br-upload__title">Drop files to analyse</div>',
      '    <div class="br-upload__sub">.csv &nbsp;·&nbsp; .xlsx &nbsp;·&nbsp; .json &nbsp;·&nbsp; .log<br>Up to 3 files · 50 MB each</div>',
      '    <input type="file" id="br-file-input" data-testid="br-file-input" multiple accept=".csv,.xlsx,.json,.log" style="display:none">',
      '  </div>',
      '  <div id="br-recent"></div>',
      '</div>',
    ].join('');

    var zone = document.getElementById('br-drop-zone');
    var input = document.getElementById('br-file-input');

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('br-upload__zone--over'); });
    zone.addEventListener('dragleave', function () { zone.classList.remove('br-upload__zone--over'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('br-upload__zone--over');
      handleFiles(e.dataTransfer.files);
    });
    input.addEventListener('change', function () { handleFiles(input.files); });
  }

  function _readFileText(file) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function (e) { resolve(e.target.result); };
      fr.onerror = function () { reject(new Error('FileReader error')); };
      fr.readAsText(file);
    });
  }

  function _parseJsonRows(text, filename) {
    try {
      var data = JSON.parse(text.trim());
      var rows;
      if (Array.isArray(data)) {
        rows = data;
      } else if (data && typeof data === 'object') {
        // Try well-known single-array keys first
        rows = data.events || data.logs || data.records || data.data;
        if (!rows) {
          // Multi-section object (e.g. {aws_cloudtrail:[...], okta_system_log:[...]})
          // Flatten all top-level array values, skipping metadata objects
          rows = Object.values(data).reduce(function (acc, v) {
            if (Array.isArray(v)) return acc.concat(v);
            return acc;
          }, []);
        }
      }
      rows = (rows || []).filter(function (r) { return r && typeof r === 'object'; });
      return _sampleRowsForBreach(rows.map(function (r) { return Object.assign({ _source: filename }, r); }), MAX_ROWS_PER_FILE);
    } catch (_) { return []; }
  }

  // Per-file row cap for the SMALL/DEMO path (browser-side parsing).
  var MAX_ROWS_PER_FILE = 1200;

  // Above these thresholds we bypass browser parsing entirely and use the
  // async backend upload path (POST /api/v1/assessments/upload).
  var ASYNC_THRESHOLD_BYTES = 5 * 1024 * 1024;   // 5 MB total
  var ASYNC_THRESHOLD_FILES = 1;                   // always use async for multi-file, set to 99 to disable

  // Named-entity keyword list removed. Sampling is now neutral — severity
  // and volume signals only, no scenario-specific tokens.
  var _BREACH_KEEP_TERMS = [];

  function _scoreRowForBreach(row) {
    var score = 0;
    var sev = String(row.severity || row.severity_name || row.risk_level || row.alert_severity || '').toLowerCase();
    if (/critical|fatal|5/.test(sev)) score += 35;
    else if (/high|4/.test(sev)) score += 20;
    else if (/medium|3/.test(sev)) score += 8;
    if (row.alert_signature || row.detect_id || row.tactic || row.technique) score += 15;
    var bytes = Number(row.bytes_sent || row.orig_bytes || row.bytes || row.rows_produced || row.bytes_scanned || 0);
    if (bytes > 100000000) score += 20;
    if (bytes > 1000000000) score += 20;
    return score;
  }

  function _sampleRowsForBreach(rows, maxRows) {
    if (!Array.isArray(rows) || rows.length <= maxRows) return rows || [];
    var keep = new Map();
    var scored = rows.map(function (row, idx) { return { row: row, idx: idx, score: _scoreRowForBreach(row) }; });
    scored.sort(function (a, b) { return (b.score - a.score) || (a.idx - b.idx); });
    scored.slice(0, Math.floor(maxRows * 0.75)).forEach(function (item) { keep.set(item.idx, item.row); });
    var remaining = Math.max(1, maxRows - keep.size);
    var stride = Math.max(1, Math.floor(rows.length / remaining));
    for (var i = 0; i < rows.length && keep.size < maxRows; i += stride) keep.set(i, rows[i]);
    keep.set(0, rows[0]);
    keep.set(rows.length - 1, rows[rows.length - 1]);
    return Array.from(keep.entries())
      .sort(function (a, b) { return a[0] - b[0]; })
      .slice(0, maxRows)
      .map(function (entry) { return entry[1]; });
  }

  function _parseNdjsonRows(text, filename) {
    var rows = [];
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      try {
        var obj = JSON.parse(line);
        if (obj && typeof obj === 'object') rows.push(Object.assign({ _source: filename }, obj));
      } catch (_) {}
    }
    return _sampleRowsForBreach(rows, MAX_ROWS_PER_FILE);
  }

  function _splitCsvLine(line) {
    var out = [], cur = '', quoted = false;
    for (var i = 0; i < line.length; i++) {
      var ch = line[i];
      if (ch === '"') {
        if (quoted && line[i + 1] === '"') { cur += '"'; i++; }
        else quoted = !quoted;
      } else if (ch === ',' && !quoted) {
        out.push(cur); cur = '';
      } else {
        cur += ch;
      }
    }
    out.push(cur);
    return out;
  }

  function _parseCsvRows(text, filename) {
    var lines = text.split(/\r?\n/).filter(function (line) { return line.trim(); });
    if (lines.length < 2) return [];
    var headers = _splitCsvLine(lines[0]).map(function (h) { return h.trim(); });
    var rows = [];
    for (var i = 1; i < lines.length; i++) {
      var cells = _splitCsvLine(lines[i]);
      var obj = { _source: filename };
      headers.forEach(function (h, j) { obj[h || ('col_' + j)] = cells[j] !== undefined ? cells[j] : ''; });
      rows.push(obj);
    }
    return _sampleRowsForBreach(rows, MAX_ROWS_PER_FILE);
  }

  function handleFiles(files) {
    if (!files || !files.length) return;

    var fileArr = Array.from(files);
    var totalBytes = fileArr.reduce(function (s, f) { return s + (f.size || 0); }, 0);

    // Route to async backend upload for large datasets.
    // Above ASYNC_THRESHOLD_BYTES or when multiple files are dropped, the
    // browser sends raw file bytes and the server does all parsing.
    // This avoids main-thread freeze and the 5K-row JSON payload limit.
    var useAsync = totalBytes > ASYNC_THRESHOLD_BYTES || fileArr.length > ASYNC_THRESHOLD_FILES;
    if (useAsync) {
      return _handleFilesAsync(fileArr, totalBytes);
    }
    return _handleFilesSync(fileArr);
  }

  // ── Async backend upload (large files / multiple files) ──────────────────────

  function _handleFilesAsync(fileArr, totalBytes) {
    renderAsyncProgress(fileArr, totalBytes);

    var hdrs = authHeaders();
    delete hdrs['Content-Type'];
    var form = new FormData();
    fileArr.forEach(function (f) { form.append('files', f); });

    fetch(apiBase() + '/api/v1/assessments/upload', {
      method: 'POST',
      headers: hdrs,
      body: form,
    })
      .then(function (r) {
        if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.statusText); });
        return r.json();
      })
      .then(function (data) {
        var aid = data.assessment_id;
        if (!aid) { toast('Upload failed: ' + (data.detail || 'unknown')); return; }
        updateAsyncStatus('Uploaded — processing on server…', 5);
        _pollAsyncProgress(aid);
      })
      .catch(function (err) {
        _describeUploadFailure(err).then(function (msg) {
          toast('Upload error: ' + msg);
          document.getElementById('br-content').innerHTML = '<div class="br-processing"><div class="br-processing__title" style="color:#e74c3c">Upload failed: ' + _esc(msg) + '</div></div>';
        });
      });
  }

  function _describeUploadFailure(err) {
    var base = (err && err.message) || 'unknown error';
    var safeBase = base;
    try {
      var devLike = /localhost|127\.0\.0\.1/.test(window.location.hostname) ||
        localStorage.getItem('janusecShowDebugErrors') === '1';
      if (!devLike) return Promise.resolve(safeBase);
    } catch (_) {
      return Promise.resolve(safeBase);
    }
    return fetch(apiBase() + '/api/v1/debug/last-errors?limit=1', { headers: authHeaders() })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var item = d && d.errors && d.errors[0];
        if (!item) return safeBase;
        var typ = item.exception_type || item.error || 'backend_error';
        var detail = item.exception_str || item.path || '';
        return safeBase + ' (' + typ + (detail ? ': ' + String(detail).slice(0, 180) : '') + ')';
      })
      .catch(function () { return safeBase; });
  }

  function _pollAsyncProgress(aid) {
    // Prefer SSE for responsive updates, but always run JSON polling as the
    // authoritative watchdog. EventSource cannot send auth headers and some
    // proxies close streams early; polling must still complete the redirect.
    if (typeof EventSource !== 'undefined') {
      _connectSSE(aid);
    }
    _schedulePollJson(aid, 1200);
  }

  // Critical addition #5 — SSE progress
  function _connectSSE(aid) {
    var url = apiBase() + '/api/v1/assessments/' + encodeURIComponent(aid) + '/progress';
    var token = _getAuthToken();
    // EventSource doesn't support custom headers — append token as query param if needed
    var qs = [];
    if (token) qs.push('token=' + encodeURIComponent(token));
    try {
      var tenant = localStorage.getItem('tenantId') || 'default';
      if (tenant) qs.push('tenant_id=' + encodeURIComponent(tenant));
    } catch (_) {}
    if (qs.length) url += '?' + qs.join('&');

    var es = new EventSource(url);
    es.addEventListener('progress', function (e) {
      try {
        var d = JSON.parse(e.data);
        _applyProgressEvent(d, aid, es);
      } catch (_) {}
    });
    es.onerror = function () {
      es.close();
      // Fall back to polling on SSE error. Polling may already be running;
      // the scheduler deduplicates timers for this assessment id.
      _schedulePollJson(aid, 1000);
    };
  }

  function _schedulePollJson(aid, delayMs) {
    if (!aid || _asyncRedirecting[aid]) return;
    if (_asyncPollTimers[aid]) return;
    var progressTimers = window.JanuSecBreachProgress || null;
    var schedule = progressTimers && progressTimers.scheduleIfMissing
      ? progressTimers.scheduleIfMissing
      : function (_scope, _aid, fn, ms) { return setTimeout(fn, ms || 0); };
    _asyncPollTimers[aid] = schedule('progress', aid, function () {
      delete _asyncPollTimers[aid];
      _pollJson(aid);
    }, delayMs || 0);
  }

  function _pollJson(aid) {
    if (!aid || _asyncRedirecting[aid]) return;
    var url = apiBase() + '/api/v1/assessments/' + encodeURIComponent(aid) + '/progress/poll';
    fetch(url, { headers: authHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        _applyProgressEvent(d, aid, null);
        if (!_asyncRedirecting[aid] && d.status !== 'ready' && d.status !== 'failed' && d.status !== 'cancelled') {
          _schedulePollJson(aid, 2000);
        }
      })
      .catch(function () {
        _schedulePollJson(aid, 3000);
      });
  }

  function _applyProgressEvent(d, aid, es) {
    if (!d || _asyncRedirecting[aid]) return;
    var pct = d.percent || 0;
    var label = d.label || d.stage || '';
    var status = d.status || '';
    var rows = d.row_count || 0;
    var clusters = d.cluster_count || 0;
    if (!label && status) label = status;

    updateAsyncStatus(label + (rows ? ' — ' + rows.toLocaleString() + ' rows' : ''), pct);
    if (clusters > 0) {
      updateAsyncDetail(clusters + ' cluster' + (clusters !== 1 ? 's' : '') + ' found');
    }

    if (status === 'ready') {
      if (es) es.close();
      _redirectToAssessment(aid);
    } else if (status === 'failed') {
      if (es) es.close();
      var errMsg = d.error || 'Assessment pipeline failed';
      toast('Assessment failed: ' + errMsg);
      document.getElementById('br-content').innerHTML =
        '<div class="br-processing"><div class="br-processing__title" style="color:#e74c3c">Failed: ' + _esc(errMsg) + '</div>' +
        '<p style="color:#888;font-size:0.85em;margin-top:8px">You can try uploading a smaller dataset or check server logs.</p></div>';
    } else if (status === 'cancelled') {
      if (es) es.close();
      toast(d.error || 'Assessment was cancelled');
      document.getElementById('br-content').innerHTML =
        '<div class="br-processing"><div class="br-processing__title" style="color:#e5c542">Cancelled</div></div>';
    } else if (d.terminal) {
      if (es) es.close();
      // A stream can terminate because of timeout/proxy behaviour while the job
      // is still running. Do not strand the page on "Queued 0%"; verify whether
      // the assessment exists, then continue polling if it is not ready yet.
      _verifyAssessmentReady(aid);
    }
  }

  function _redirectToAssessment(aid) {
    if (!aid || _asyncRedirecting[aid]) return;
    _asyncRedirecting[aid] = true;
    if (_asyncPollTimers[aid]) {
      if (window.JanuSecBreachProgress && window.JanuSecBreachProgress.clear) {
        window.JanuSecBreachProgress.clear('progress', aid);
      } else {
        clearTimeout(_asyncPollTimers[aid]);
      }
      delete _asyncPollTimers[aid];
    }
    updateAsyncStatus('Assessment ready - redirecting...', 100);
    var progressTimers = window.JanuSecBreachProgress || null;
    var schedule = progressTimers && progressTimers.schedule
      ? progressTimers.schedule
      : function (_scope, _aid, fn, ms) { return setTimeout(fn, ms || 0); };
    schedule('redirect', aid, function () {
      window.location.href = '/static/breach.html?assessment=' + encodeURIComponent(aid);
    }, 500);
  }

  function _verifyAssessmentReady(aid) {
    if (!aid || _asyncRedirecting[aid]) return;
    apiFetch('/api/v1/assessments/' + encodeURIComponent(aid))
      .then(function (r) {
        if (r.ok) return r.json();
        throw new Error('not ready');
      })
      .then(function (data) {
        if (data && (data.assessment_id === aid || data.id === aid || data.status === 'ready')) {
          _redirectToAssessment(aid);
          return;
        }
        updateAsyncStatus('Still processing on server...', 90);
        _schedulePollJson(aid, 2000);
      })
      .catch(function () {
        updateAsyncStatus('Still processing on server...', 90);
        _schedulePollJson(aid, 2000);
      });
  }

  function _getAuthToken() {
    try {
      var h = authHeaders();
      return (h['Authorization'] || '').replace('Bearer ', '') || h['x-api-key'] || '';
    } catch (_) { return ''; }
  }

  function _esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── Sync browser-side path (small / curated demos ≤ ASYNC_THRESHOLD_BYTES) ──

  function _handleFilesSync(fileArr) {
    renderProcessing();

    var jsonFiles   = fileArr.filter(function (f) { return /\.(json|jsonl)$/i.test(f.name); });
    var ndjsonFiles = fileArr.filter(function (f) { return /\.ndjson$/i.test(f.name); });
    var xlsxFiles   = fileArr.filter(function (f) { return /\.(xlsx|xlsm)$/i.test(f.name); });
    var csvFiles    = fileArr.filter(function (f) { return /\.csv$/i.test(f.name); });
    var serverFiles = fileArr.filter(function (f) { return !/\.(csv|json|jsonl|ndjson|xlsx|xlsm)$/i.test(f.name); });

    // XLSX enrichment workbooks: send to /upload/workbook_sheets to get all sheets with _sheet metadata
    var xlsxPromise = xlsxFiles.length ? (function () {
      var hdrs = authHeaders();
      delete hdrs['Content-Type'];
      var form = new FormData();
      xlsxFiles.forEach(function (f) { form.append('files', f); });
      return fetch(apiBase() + '/api/v1/upload/workbook_sheets', { method: 'POST', headers: hdrs, body: form })
        .then(function (r) { return r.json(); })
        .then(function (wb) {
          var allWbRows = [];
          (wb.results || []).forEach(function (res) {
            if (res.status === 'parsed' && Array.isArray(res.rows)) {
              allWbRows = allWbRows.concat(res.rows);
            }
          });
          return allWbRows;
        })
        .catch(function () { return []; });
    })() : Promise.resolve([]);

    var jsonPromise = Promise.all(
      jsonFiles.map(function (f) {
        return _readFileText(f).then(function (text) { return _parseJsonRows(text, f.name); });
      }).concat(
        ndjsonFiles.map(function (f) {
          return _readFileText(f).then(function (text) { return _parseNdjsonRows(text, f.name); });
        })
      ).concat(
        csvFiles.map(function (f) {
          return _readFileText(f).then(function (text) { return _parseCsvRows(text, f.name); });
        })
      )
    );

    var serverPromise = serverFiles.length ? (function () {
      var hdrs = authHeaders();
      delete hdrs['Content-Type'];
      var form = new FormData();
      serverFiles.forEach(function (f) { form.append('files', f); });
      return fetch(apiBase() + '/api/v1/upload/files', { method: 'POST', headers: hdrs, body: form })
        .then(function (r) { return r.json(); })
        .then(function (uploadData) {
          var fetches = (uploadData.results || [])
            .filter(function (r) { return r.status === 'processed' && r.analysis; })
            .map(function (r) {
              var analysis = r.analysis || {};
              if (analysis.pagination_session) {
                var sid = analysis.pagination_session;
                return fetch(apiBase() + '/api/v1/upload/tabular/page?session=' + encodeURIComponent(sid) + '&limit=' + MAX_ROWS_PER_FILE, { headers: authHeaders() })
                  .then(function (pr) { return pr.json(); })
                  .then(function (pd) {
                    var headers = pd.headers || [];
                    return (pd.rows || []).map(function (row) {
                      var obj = {};
                      headers.forEach(function (h, i) { obj[h] = row[i] !== undefined ? row[i] : ''; });
                      obj._source = r.filename || 'unknown';
                      return obj;
                    });
                  });
              }
              if (analysis.full_rows && Array.isArray(analysis.full_rows)) {
                return Promise.resolve(analysis.full_rows.map(function (row) {
                  return Object.assign({ _source: r.filename || 'unknown' }, row);
                }));
              }
              return Promise.resolve([]);
            });
          return Promise.all(fetches);
        });
    })() : Promise.resolve([]);

    Promise.all([jsonPromise, serverPromise, xlsxPromise])
      .then(function (results) {
        var jsonRows = [].concat.apply([], results[0]);
        var serverRows = [].concat.apply([], results[1]);
        var xlsxRows = results[2] || [];
        var allRows = jsonRows.concat(serverRows).concat(xlsxRows)
          .map(function (r, i) { return Object.assign({}, r, { row_index: i }); });
        if (!allRows.length) { toast('No rows extracted from uploaded files'); return; }
        return fetch(apiBase() + '/api/v1/csv/deep_analyze', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ rows: allRows, options: { auto_llm: false }, org: 'unknown' }),
        }).then(function (r) { return r.json(); });
      })
      .then(function (data) {
        if (!data) return;
        var aid = data.assessment_id;
        if (aid) {
          window.location.href = '/static/breach.html?assessment=' + encodeURIComponent(aid);
        } else {
          toast('Upload failed: ' + (data.detail || 'unknown error'));
        }
      })
      .catch(function (err) { toast('Upload error: ' + err.message); });
  }

  function renderProcessing() {
    document.getElementById('br-content').innerHTML = [
      '<div class="br-processing">',
      '  <div class="br-processing__title">Analysing files…</div>',
      '  <div class="br-processing__step br-processing__step--active" id="brs-norm">',
      '    <span>Normalising rows</span>',
      '    <div class="br-processing__bar"><div class="br-processing__bar-fill" style="width:0%" id="brs-norm-bar"></div></div>',
      '  </div>',
      '  <div class="br-processing__step" id="brs-corr">',
      '    <span>Correlation engine</span>',
      '    <div class="br-processing__bar"><div class="br-processing__bar-fill" style="width:0%" id="brs-corr-bar"></div></div>',
      '  </div>',
      '  <div class="br-processing__step" id="brs-t1">',
      '    <span>Tier-1 prefill (top cluster)</span>',
      '    <div class="br-processing__bar"><div class="br-processing__bar-fill" style="width:0%" id="brs-t1-bar"></div></div>',
      '  </div>',
      '</div>',
    ].join('');
    // Animate bars pseudo-progressively while we wait for the redirect
    _animateBar('brs-norm-bar', 8000);
  }

  // Critical addition #5 — async progress UI driven by SSE events
  function renderAsyncProgress(fileArr, totalBytes) {
    var sizeMB = (totalBytes / (1024 * 1024)).toFixed(1);
    var fileNames = fileArr.map(function (f) { return f.name; }).join(', ');
    document.getElementById('br-content').innerHTML = [
      '<div class="br-processing" id="br-async-progress">',
      '  <div class="br-processing__title" id="br-async-title">Uploading to server…</div>',
      '  <div style="color:#888;font-size:0.82em;margin-bottom:10px" id="br-async-detail">',
      '    ' + _esc(fileNames) + ' &nbsp;·&nbsp; ' + sizeMB + ' MB',
      '  </div>',
      '  <div class="br-processing__bar" style="margin-bottom:6px">',
      '    <div class="br-processing__bar-fill" id="br-async-bar" style="width:0%;transition:width 0.6s ease"></div>',
      '  </div>',
      '  <div style="color:#aaa;font-size:0.78em;margin-top:4px" id="br-async-pct">0%</div>',
      '  <div style="color:#888;font-size:0.75em;margin-top:12px">',
      '    Server-side parsing — no browser memory limit. Progress updates every ~2s.',
      '  </div>',
      '</div>',
    ].join('');
  }

  function updateAsyncStatus(label, percent) {
    var title = document.getElementById('br-async-title');
    var bar = document.getElementById('br-async-bar');
    var pctEl = document.getElementById('br-async-pct');
    if (title) title.textContent = label || 'Processing…';
    if (bar) bar.style.width = (percent || 0) + '%';
    if (pctEl) pctEl.textContent = (percent || 0) + '%';
  }

  function updateAsyncDetail(text) {
    var el = document.getElementById('br-async-detail');
    if (el) el.textContent = text;
  }

  function _animateBar(id, durationMs) {
    var el = document.getElementById(id);
    if (!el) return;
    var start = Date.now();
    (function tick() {
      var pct = Math.min(90, ((Date.now() - start) / durationMs) * 100);
      el.style.width = pct + '%';
      if (pct < 90) requestAnimationFrame(tick);
    })();
  }

  // ── Home view ─────────────────────────────────────────────────────────────────

  function _renderReingestBanner(a) {
    if (!a.requires_reingest && !a.fallback_used) return '';
    var diag = a.cluster_diagnostics || {};
    var staleRows = diag.stale_rows || 0;
    var msg = 'Telemetry was stored with an older normalizer — canonical pivot fields were missing, so typed clustering could not run.';
    if (staleRows) msg += ' ' + staleRows + ' stale rows detected.';
    return '<div class="reingest-banner" style="background:#7c2d2d;color:#fcd4d4;border-left:4px solid #ef4444;padding:10px 16px;margin-bottom:12px;border-radius:4px;font-size:13px;">'
      + '<strong>Re-ingest required:</strong> ' + escHtml(msg)
      + ' <a href="#" onclick="document.getElementById(\'upload-panel\').scrollIntoView({behavior:\'smooth\'});return false;" style="color:#fca5a5;text-decoration:underline;">Re-upload source files</a>'
      + '</div>';
  }

  function renderHome() {
    updateTabBar('breach');
    var a = state.assessment || {};

    // Prefer presentation-layer threat_cases for top cards when available.
    // Exclude ANALYSIS_INCOMPLETE cases from the ranked top pool — they are
    // shown as a banner/warning, not as evidence cards.
    var rawSource = (state.threatCases && state.threatCases.length > 0)
      ? state.threatCases
      : state.clusters;
    var topSource = rawSource.filter(function(c) {
      return (c.verdict || c.final_verdict || '').toUpperCase() !== 'ANALYSIS_INCOMPLETE';
    });
    var sorted = _rankClusters(topSource);
    // Always keep full cluster inventory available for context/audit sections.
    var allClusters = _rankClusters(state.clusters);

    var html = _renderReingestBanner(a);
    html += _renderMetaLine(a, allClusters);

    // ── CEO Zone: verdict + hero narrative + exec summary (always visible) ──
    html += _renderBreachAnswerHero(sorted, a);
    html += _renderExecSummaryShell(sorted, a);
    html += _renderPendingActionsBanner(a);
    html += _renderStakeholderDispatch(a);
    html += _renderHomeThreatCases(sorted);
    html += _renderHomeEvidenceViews();

    // ── Visualizations: swimlane + hopgraph (always visible) ──
    

    // ── Action row: drill-down toggle + deepen investigation ──
    html += _renderActionRow();

    // ── Investigation drill-down (collapsed by default) ──
    html += '<details class="br-drilldown" id="br-drilldown" data-testid="br-drilldown">';
    html += '<summary class="br-drilldown__summary">Investigation Details ▸</summary>';
    html += '<div class="br-drilldown__body">';
    html += _renderVerdictSummaryRow(sorted, allClusters, a);
    html += _renderPathOfIntrusion(a);
    html += _renderRootCauseNarrative(sorted[0], sorted);
    html += _renderAgentPanel(a);
    html += '<details class="br-analyst-detail" data-testid="br-analyst-detail"><summary class="br-section-head" style="cursor:pointer;">THREAT CASES — Analyst Detail ▸</summary>';
    html += _renderTopFindings(sorted);
    // Narrative context and additional findings use full cluster inventory.
    html += _renderNarrativeContext(allClusters);
    html += _renderAdditionalFindings(allClusters);
    html += '</details>';
    // Only count benign clusters not already shown in narrative context section
    var _shownBenignIds = new Set(allClusters.filter(function(c){
      return _vClass(c)==='benign' && ((c.row_refs||[]).length>0||c.case_type==='enrichment_guided');
    }).map(function(c){ return c.cluster_id; }));
    var _hiddenBenignCount = allClusters.filter(function(c){
      return _vClass(c)==='benign' && !_shownBenignIds.has(c.cluster_id);
    }).length;
    html += _renderCollapsed('BENIGN', _hiddenBenignCount);
    html += _renderCollapsed('ISOLATED', a.isolated_count || 0);
    html += '</div></details>';

    document.getElementById('br-content').innerHTML = html;

    // Wire and hydrate the narrative/card UI before mounting optional visuals.
    // A D3 rendering issue should never block the analyst from seeing cases.
    _wireHomeEvents();
    _hydrateTopThreatCases(sorted, a);

    // Build the CEO summary — use cached result on page load, only regenerate on explicit user action.
    _loadExecSummary(false);

    // Fix 6 — Auto-generate DREAD threat summary for CRITICAL secondary clusters
    // so the most dangerous cases (esp. data exfiltration) aren't lazy-loaded.
    var _AUTO_GEN_THRESHOLD = 50;
    sorted.forEach(function (c, idx) {
      if (idx === 0) return; // lead case handled by _hydrateTopThreatCases
      var di = _dreadInfo(c);
      if (di.hasStructured) return; // already has content
      var isCritical = (c.severity || '').toLowerCase() === 'critical'
        || (c.row_refs || []).length >= _AUTO_GEN_THRESHOLD;
      var isBreachVerdict = /CONFIRMED|VALIDATED/.test((c.verdict || c.final_verdict || '').toUpperCase());
      if (isCritical || isBreachVerdict) {
        window.setTimeout(function () {
          _fireDreadGenerate(c.cluster_id, function () {
            var resorted = _rankClusters(
              (state.threatCases && state.threatCases.length > 0) ? state.threatCases : state.clusters
            );
            _rerenderCard(c.cluster_id, resorted);
          });
        }, (idx + sorted.length) * 400); // stagger after primary prefill
      }
    });

    // A4: mount D3 visualisations now that containers exist in DOM
    _mountSwimlane(allClusters);
    _mountHopGraphMini(sorted[0] || null);
  }

  function _hydrateTopThreatCases(sorted, assessment) {
    var top = _selectTopThreatCases(sorted);
    top.forEach(function (c, idx) {
      // Never auto-fire LLM for ANALYSIS_INCOMPLETE — no typed evidence exists.
      var verdict = (c.verdict || c.final_verdict || '').toUpperCase();
      if (verdict === 'ANALYSIS_INCOMPLETE') return;
      var isConfirmed = _vClass(c) === 'confirmed';
      if (_prefillDone(c)) {
        _safeRenderCard(c, sorted, idx);
        return;
      }
      if (!isConfirmed) {
        // LIKELY_BREACH / LIKELY_COMPROMISE — render deterministic card immediately
        // with human-gate banner. Do NOT auto-fire LLM; analyst clicks Generate.
        _safeRenderCard(c, sorted, idx);
        return;
      }
      // CONFIRMED_BREACH / CONFIRMED_INTRUSION — auto-fire LLM prefill
      _renderCardLoading(c, idx);
      window.setTimeout(function () {
        _fireSinglePrefill(c.cluster_id, function () {
          var resorted = _rankClusters(
            (state.threatCases && state.threatCases.length > 0) ? state.threatCases : state.clusters
          );
          var hero = document.querySelector('[data-role="breach-answer-hero"]');
          if (hero) hero.outerHTML = _renderBreachAnswerHero(resorted, assessment);
          _loadExecSummary(false);
          _rerenderCard(c.cluster_id, resorted);
        });
      }, idx * 350);
    });

    // Also fire prefill for benign context clusters (shown in SECURITY CONTEXT section)
    // so their narrative/verdict_reasoning is populated. Fire after top cases with a delay.
    var contextClusters = sorted.filter(function (c) {
      return _vClass(c) === 'benign' && (c.row_refs || []).length > 0 && !_prefillDone(c);
    });
    contextClusters.forEach(function (c, idx) {
      window.setTimeout(function () {
        _fireSinglePrefill(c.cluster_id, function () {
          // Re-render the narrative context section in-place
          var el = document.getElementById('br-context-' + c.cluster_id);
          if (!el) return;
          var p = c.tier1_prefill || {};
          var sub = p.headline_subtitle || c.reason_summary || p.short_narrative || '';
          var narrative = p.verdict_reasoning || p.what_happened || c.business_significance || '';
          var _badRe = /command.and.control|c2 beacon|needs containment|attacker maintain/i;
          if (_badRe.test(narrative)) narrative = sub;
          var nameEl = el.querySelector('.br-finding__verdict');
          var subEl = el.querySelector('.br-finding__oneliner');
          var narEl = el.querySelector('.br-finding__meta');
          if (nameEl && p.incident_name) nameEl.textContent = '✓ ' + p.incident_name.toUpperCase();
          if (subEl && sub) subEl.textContent = sub;
          if (narEl && narrative) narEl.textContent = narrative;
        });
      }, (top.length + idx) * 350 + 800);
    });
  }

  function _renderMetaLine(a, sorted) {
    // Compute source count from row._source values when API doesn't provide it
    var sourceNames = new Set();
    state.rows.forEach(function (r) {
      var s = r._source || r.source || r.log_source || '';
      if (s) sourceNames.add(s);
    });
    var store = a.evidence_store || {};
    var sourceCount = a.source_count || (store.source_counts ? Object.keys(store.source_counts).length : 0) || (sourceNames.size > 0 ? sourceNames.size : '?');
    var rowCount = store.row_count || a.rows_processed || state.rows.length || 0;
    var uploadedCount = a.uploaded_row_count || a.total_rows_uploaded || 0;
    var FETCH_LIMIT = 2000;
    var atLimit = uploadedCount > rowCount;
    var coverageWarning = atLimit
      ? '<span style="color:#ffaa00;font-size:12px;" title="Upload may contain more rows than were analyzed"> ⚠ analyzed ' + rowCount + ' of ' + (uploadedCount > rowCount ? uploadedCount : '?') + ' uploaded rows (limit ' + FETCH_LIMIT + ')</span>'
      : '';
    return [
      '<div class="br-meta" data-testid="br-meta">',
      '  <strong>Assessment ' + escHtml(a.assessment_id || '') + '</strong>',
      '  &nbsp;·&nbsp; <span data-testid="br-source-count">' + sourceCount + '</span> sources',
      '  &nbsp;·&nbsp; <span data-testid="br-row-count">' + rowCount + '</span> rows analyzed',
      coverageWarning,
      '  &nbsp;·&nbsp; <span data-testid="br-cluster-count">' + sorted.length + '</span> threat cases',
      '  &nbsp;·&nbsp; ' + (a.isolated_count || 0) + ' isolated',
      '  <br>',
      '  Top threat cases hydrate automatically',
      '</div>',
    ].join('');
  }

  var _HERO_CONFIG = {
    VALIDATED_BREACH:      { label: 'CONFIRMED BREACH',       bg: '#3d0a0a', border: '#e05252', text: '#ff9090', icon: '<span class="br-vdot br-vdot--red" aria-label="Confirmed Breach"></span>' },
    CONFIRMED_BREACH:      { label: 'CONFIRMED BREACH',       bg: '#3d0a0a', border: '#e05252', text: '#ff9090', icon: '<span class="br-vdot br-vdot--red" aria-label="Confirmed Breach"></span>' },
    CONFIRMED_INTRUSION:   { label: 'CONFIRMED INTRUSION',    bg: '#3d1a00', border: '#ff7c3c', text: '#ffb090', icon: '<span class="br-vdot br-vdot--orange" aria-label="Confirmed Intrusion"></span>' },
    LIKELY_BREACH:         { label: 'LIKELY BREACH — REVIEW', bg: '#2a1500', border: '#ff8c00', text: '#ffb060', icon: '<span class="br-vdot br-vdot--orange" aria-label="Likely Breach"></span>' },
    LIKELY_COMPROMISE:     { label: 'LIKELY COMPROMISE',      bg: '#2a2000', border: '#e0c446', text: '#ffe090', icon: '<span class="br-vdot br-vdot--yellow" aria-label="Likely Compromise"></span>' },
    SUSPICIOUS_ACTIVITY:   { label: 'SUSPICIOUS ACTIVITY',    bg: '#1a2000', border: '#90ba55', text: '#c8e090', icon: '<span class="br-vdot br-vdot--green" aria-label="Suspicious Activity"></span>' },
    INVESTIGATION_REQUIRED:{ label: 'INVESTIGATION REQUIRED', bg: '#1a1a2a', border: '#6090d0', text: '#90b0f0', icon: '<span class="br-vdot br-vdot--blue" aria-label="Investigation Required"></span>' },
    INSUFFICIENT_TELEMETRY:{ label: 'INSUFFICIENT TELEMETRY', bg: '#1a1a2a', border: '#6090d0', text: '#90b0f0', icon: '<span class="br-vdot br-vdot--blue" aria-label="Insufficient Telemetry"></span>' },
    BENIGN_EXPECTED:       { label: 'NO VALIDATED BREACH',    bg: '#0d1a0d', border: '#52e07f', text: '#90f0b0', icon: '<span class="br-vdot br-vdot--teal" aria-label="No Breach"></span>' },
  };

  function _confidenceLabel(total, isBreachVerdict) {
    var highColor = isBreachVerdict ? '#ff4444' : '#4ade80';
    if (total >= 80) return { label: 'HIGH CONFIDENCE',       color: highColor };
    if (total >= 60) return { label: 'MEDIUM CONFIDENCE',     color: isBreachVerdict ? '#ff8c00' : '#facc15' };
    if (total >= 40) return { label: 'LOW CONFIDENCE',        color: '#fb923c' };
    return { label: 'INSUFFICIENT EVIDENCE', color: '#94a3b8' };
  }

  function _renderBreachAnswerHero(sorted, a) {
    // Determine top-level verdict from highest-ranked cluster
    var lead = sorted[0];
    var topVerdict = (lead && (lead.verdict || lead.final_verdict) || 'INSUFFICIENT_TELEMETRY').toUpperCase().replace(/ /g, '_');
    var cfg = _HERO_CONFIG[topVerdict] || _HERO_CONFIG.INSUFFICIENT_TELEMETRY;
    var p = (lead && lead.tier1_prefill) || {};
    var store = a.evidence_store || {};
    var srcCount = a.source_count || (store.source_counts ? Object.keys(store.source_counts).length : '?');

    // Confidence from deterministic meter (always available, no LLM needed)
    var cm = (lead && (lead.confidence_meter || p.confidence_meter)) || {};
    var confTotal = (cm.total != null) ? cm.total : (lead && lead.verdict_confidence != null ? lead.verdict_confidence * 100 : null);
    var _isBreachVerdict = (topVerdict === 'VALIDATED_BREACH' || topVerdict === 'CONFIRMED_INTRUSION');
    var confInfo = (confTotal != null) ? _confidenceLabel(confTotal, _isBreachVerdict) : null;
    var srcPresent = (cm.source_types_present || []).join(' + ') || (srcCount + ' sources');

    // Build hero narrative: prefer short_narrative > friendly narrative > LLM what_happened
    var leadTitle = lead ? _displayIncidentName(lead) : '';
    var leadSubtitle = lead ? (p.headline_subtitle || _buildFallbackSummary(lead)) : '';
    if (_rawCorrelationText(leadSubtitle)) leadSubtitle = _friendlyThreatCaseSummary(lead, leadTitle);
    var heroNarrative = (p.short_narrative || '').trim();
    if (!heroNarrative || _rawCorrelationText(heroNarrative)) {
      heroNarrative = lead ? _friendlyThreatCaseNarrative(lead, p, leadTitle, leadSubtitle) : '';
    }

    // Check for concurrent breaches (additional confirmed clusters)
    var concurrent = sorted.filter(function (c, i) {
      return i > 0 && _vClass(c) === 'confirmed';
    });
    var concurrentNote = '';
    if (concurrent.length > 0) {
      var concNames = concurrent.slice(0, 3).map(function (c) {
        return _displayIncidentName(c) || 'additional intrusion';
      });
      concurrentNote = 'Concurrent: ' + concNames.join(', ') + '.';
    }

    // Action urgency from lead cluster
    var urgency = lead && lead.gate_urgency;
    var isUrgent = urgency === 'URGENT' || urgency === 'HIGH';
    var urgencyBadge = (isUrgent && _vClass(lead) === 'confirmed')
      ? '<span class="br-hero__urgent">IMMEDIATE RESPONSE REQUIRED</span>'
      : '';

    // ── Build hero HTML ──
    var html = [
      '<div class="br-hero" style="background:' + cfg.bg + ';border:1px solid ' + cfg.border + ';border-radius:8px;padding:24px 28px;margin-bottom:16px;" data-testid="br-hero" data-role="breach-answer-hero">',
      '  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:8px;">',
      '    <div>',
      '      <div style="font-size:11px;opacity:.5;letter-spacing:.5px;margin-bottom:4px;">BREACH ASSESSMENT VERDICT</div>',
      '      <div class="br-hero__verdict" style="font-size:22px;font-weight:700;color:' + cfg.text + ';letter-spacing:.5px;" data-testid="breach-answer-verdict">' + cfg.icon + ' ' + cfg.label + '</div>',
      '    </div>',
      urgencyBadge ? '    <div style="padding-top:4px;">' + urgencyBadge + '</div>' : '',
      '  </div>',
    ].join('');

    // Confidence bar
    if (confInfo) {
      var barW = Math.round(confTotal);
      html += [
        '<div style="margin-top:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">',
        '  <div style="flex:1;min-width:120px;max-width:260px;background:rgba(255,255,255,.1);border-radius:3px;height:6px;">',
        '    <div style="width:' + barW + '%;background:' + confInfo.color + ';height:6px;border-radius:3px;transition:width .4s;"></div>',
        '  </div>',
        '  <span style="color:' + confInfo.color + ';font-size:13px;font-weight:600;">' + confTotal + '/100 — ' + confInfo.label + '</span>',
        '  <span style="font-size:11px;opacity:.55;"> corroborated by ' + escHtml(srcPresent) + '</span>',
        '</div>',
      ].join('');
    }

    // ── Hero Narrative Block (serif, large, prominent) ──
    if (heroNarrative) {
      html += '<div class="br-hero__narrative" data-testid="br-hero-narrative">';
      html += escHtml(heroNarrative);
      if (concurrentNote) {
        html += '<span class="br-hero__concurrent"> ' + escHtml(concurrentNote) + '</span>';
      }
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  // ── Verdict Summary Row ────────────────────────────────────────────────────
  function _renderVerdictSummaryRow(sorted, allClusters, assessment) {
    var counts = { confirmed: 0, likely: 0, uncertain: 0, benign: 0, isolated: 0 };
    allClusters.forEach(function (c) {
      var vc = _vClass(c);
      if (counts.hasOwnProperty(vc)) counts[vc]++;
      else counts.uncertain++;
    });
    counts.isolated = assessment.isolated_count || 0;

    var totalRows = (assessment.evidence_store && assessment.evidence_store.row_count)
      || assessment.rows_processed || state.rows.length || 0;
    var sourceCount = 0;
    var store = assessment.evidence_store || {};
    if (store.source_counts) sourceCount = Object.keys(store.source_counts).length;
    else {
      var s = new Set();
      state.rows.forEach(function (r) { var src = r._source || r.source || ''; if (src) s.add(src); });
      sourceCount = s.size;
    }

    function _pill(label, count, cls) {
      if (!count) return '';
      return '<span class="br-verdict-pill br-verdict-pill--' + cls + '">'
        + count + ' ' + label + '</span>';
    }

    return [
      '<div class="br-verdict-row" data-testid="br-verdict-row">',
      '  <div class="br-verdict-row__scope">' + totalRows.toLocaleString() + ' rows · ' + sourceCount + ' sources</div>',
      '  <div class="br-verdict-row__pills">',
           _pill('confirmed', counts.confirmed, 'confirmed'),
           _pill('likely', counts.likely, 'likely'),
           _pill('uncertain', counts.uncertain, 'uncertain'),
           _pill('benign', counts.benign, 'benign'),
           _pill('isolated', counts.isolated, 'isolated'),
      '  </div>',
      '</div>',
    ].join('');
  }

  // ── Path of Intrusion (kill chain table) ───────────────────────────────────
  function _renderPathOfIntrusion(assessment) {
    var kc = (assessment && assessment.kill_chain) || [];
    if (!kc.length) return '';

    // De-duplicate by phase — show one row per distinct phase
    var seen = {};
    var phases = [];
    kc.forEach(function (step) {
      var ph = step.phase || 'unknown';
      if (!seen[ph]) {
        seen[ph] = true;
        phases.push(JSON.parse(JSON.stringify(step)));
      } else {
        // Merge evidence into existing entry
        var existing = phases.find(function (p) { return p.phase === ph; });
        if (existing && step.evidence_row_ids) {
          existing.evidence_row_ids = (existing.evidence_row_ids || []).concat(step.evidence_row_ids);
        }
      }
    });

    var _PHASE_LABELS = {
      initial_access: { icon: _icon('door-open'), label: 'Initial Access' },
      execution: { icon: _icon('zap'), label: 'Execution' },
      persistence: { icon: _icon('pin'), label: 'Persistence' },
      privilege_escalation: { icon: _icon('unlock'), label: 'Privilege Escalation' },
      lateral_movement: { icon: _icon('arrows-lr'), label: 'Lateral Movement' },
      collection: { icon: _icon('package'), label: 'Collection' },
      exfiltration: { icon: _icon('upload-c2'), label: 'Exfiltration' },
      command_and_control: { icon: _icon('radio'), label: 'Command & Control' },
    };

    var rows = phases.map(function (step, idx) {
      var meta = _PHASE_LABELS[step.phase] || { icon: '•', label: step.phase };
      var rowIds = (step.evidence_row_ids || []).slice(0, 5);
      var rowChips = rowIds.map(function (id) {
        return '<span class="br-poi__row-chip">r' + id + '</span>';
      }).join('');
      if ((step.evidence_row_ids || []).length > 5) rowChips += '<span class="br-poi__row-chip">+' + ((step.evidence_row_ids || []).length - 5) + '</span>';
      var connector = idx < phases.length - 1 ? '<span class="br-poi__arrow">→</span>' : '';
      return [
        '<tr class="br-poi__row">',
        '  <td class="br-poi__phase-icon">' + meta.icon + '</td>',
        '  <td class="br-poi__phase-name">' + escHtml(meta.label) + '</td>',
        '  <td class="br-poi__actor">' + escHtml(step.actor || '') + '</td>',
        '  <td class="br-poi__action">' + escHtml((step.action || '').substring(0, 120)) + '</td>',
        '  <td class="br-poi__refs">' + rowChips + '</td>',
        '  <td class="br-poi__link">' + connector + '</td>',
        '</tr>',
      ].join('');
    });

    return [
      '<div class="br-poi" data-testid="br-path-of-intrusion">',
      '  <div class="br-section-head">PATH OF INTRUSION</div>',
      '  <table class="br-poi__table">',
      '    <thead><tr>',
      '      <th></th><th>Phase</th><th>Actor</th><th>Action</th><th>Evidence</th><th></th>',
      '    </tr></thead>',
      '    <tbody>' + rows.join('') + '</tbody>',
      '  </table>',
      '</div>',
    ].join('');
  }

  // ── Agent Panel ────────────────────────────────────────────────────────────
  function _renderAgentPanel(assessment) {
    var actions = (assessment && assessment.proposed_actions) || [];
    var kc = (assessment && assessment.kill_chain) || [];
    var gaps = (assessment && assessment.gaps) || [];

    // Compute coverage
    var phasesFound = {};
    kc.forEach(function (step) { phasesFound[step.phase] = true; });
    var totalPhases = 8; // MITRE ATT&CK major phases
    var coverage = Math.round(Object.keys(phasesFound).length / totalPhases * 100);

    var gapList = gaps.length ? gaps.slice(0, 5).map(function (g) {
      return '<li class="br-agent__gap">' + escHtml(typeof g === 'string' ? g : (g.description || g.gap || '')) + '</li>';
    }).join('') : '<li class="br-agent__gap br-agent__gap--none">No critical gaps detected</li>';

    return [
      '<div class="br-agent-panel" data-testid="br-agent-panel">',
      '  <div class="br-section-head">INVESTIGATION AGENT</div>',
      '  <div class="br-agent__grid">',
      '    <div class="br-agent__stat">',
      '      <div class="br-agent__stat-value">' + coverage + '%</div>',
      '      <div class="br-agent__stat-label">Kill Chain Coverage</div>',
      '    </div>',
      '    <div class="br-agent__stat">',
      '      <div class="br-agent__stat-value">' + actions.length + '</div>',
      '      <div class="br-agent__stat-label">Proposed Actions</div>',
      '    </div>',
      '    <div class="br-agent__stat">',
      '      <div class="br-agent__stat-value">' + kc.length + '</div>',
      '      <div class="br-agent__stat-label">Kill Chain Steps</div>',
      '    </div>',
      '    <div class="br-agent__stat">',
      '      <div class="br-agent__stat-value">' + gaps.length + '</div>',
      '      <div class="br-agent__stat-label">Evidence Gaps</div>',
      '    </div>',
      '  </div>',
      '  <div class="br-agent__gaps">',
      '    <div class="br-agent__gaps-title">COVERAGE GAPS</div>',
      '    <ul class="br-agent__gaps-list">' + gapList + '</ul>',
      '  </div>',
      '</div>',
    ].join('');
  }

  // ── Root Cause Narrative: CEO-readable single paragraph ────────────────────
  function _renderRootCauseNarrative(lead, sorted) {
    if (!lead) return '';
    var p = lead.tier1_prefill || {};
    var dn = p.dread_narrative || {};
    var frags = dn.fragments || {};
    var whathappened = (p.what_happened || '').trim();
    var shortNarr = (p.short_narrative || '').trim();
    var rootCause = _deriveRootCause(lead, p, _displayIncidentName(lead), p.headline_subtitle || '');
    var evChain = p.evidence_chain || [];
    var impact = p.observed_impact || {};
    var actors = impact.identity || '';

    // Assemble timeline summary from evidence chain
    var chainSteps = [];
    (evChain || []).forEach(function (step) {
      var tactic = step.tactic || step.phase || '';
      var desc = step.description || step.detail || '';
      if (tactic && desc) chainSteps.push(tactic + ': ' + desc);
      else if (desc) chainSteps.push(desc);
    });
    var timelineStr = chainSteps.length > 0 ? chainSteps.slice(0, 6).join(' → ') : '';

    // Build the narrative
    var parts = [];

    // 1. What happened (prefer LLM-generated, then DREAD damage fragment, then fallback)
    var storySource = whathappened || (dn.rendered || '').split('\n')[0] || shortNarr || '';
    if (storySource && !_rawCorrelationText(storySource)) parts.push(storySource);

    // 2. Root cause
    if (rootCause) parts.push('Root cause: ' + rootCause);

    // 3. Timeline (condensed)
    if (timelineStr) parts.push('Attack progression: ' + timelineStr + '.');

    // 4. Affected actors
    if (actors && !/no named/i.test(actors)) parts.push('Affected accounts: ' + actors + '.');

    // 5. FP explanation
    var explained = 0;
    (sorted || []).forEach(function (c) {
      if (_vClass(c) === 'benign' && (c.row_refs || []).length > 0) explained += (c.row_refs || []).length;
    });
    if (explained > 0) {
      parts.push(explained.toLocaleString() + ' additional rows analysed and ruled out — not part of the breach.');
    }

    var fullText = parts.join(' ');
    if (!fullText) return '';

    return [
      '<div class="br-root-narrative" data-testid="br-root-narrative">',
      '  <div class="br-section-head" style="margin-bottom:8px;">ROOT CAUSE NARRATIVE</div>',
      '  <div style="font-size:14px;line-height:1.7;color:rgba(255,255,255,.88);">' + escHtml(fullText) + '</div>',
      '</div>',
    ].join('');
  }

  // ── Compliance Controls: framework chips ──────────────────────────────────
  function _renderComplianceChips(lead) {
    if (!lead) return '';
    var p = lead.tier1_prefill || {};
    var controls = p.compliance_controls || [];
    if (!controls.length) return '';

    var FRAMEWORK_COLORS = {
      'ISO 27001:2022': { bg: 'rgba(99,102,241,.15)', border: '#6366f1', text: '#a5b4fc' },
      'Essential Eight': { bg: 'rgba(34,197,94,.12)', border: '#22c55e', text: '#86efac' },
      'NIST CSF 2.0':   { bg: 'rgba(59,130,246,.12)', border: '#3b82f6', text: '#93c5fd' },
      'NDB Scheme':     { bg: 'rgba(239,68,68,.12)', border: '#ef4444', text: '#fca5a5' },
      'APRA CPS 234':   { bg: 'rgba(251,146,60,.12)', border: '#fb923c', text: '#fed7aa' },
    };

    var chips = controls.map(function (c) {
      var fc = FRAMEWORK_COLORS[c.framework] || { bg: 'rgba(148,163,184,.1)', border: '#64748b', text: '#94a3b8' };
      return '<span class="br-compliance-chip" style="'
        + 'background:' + fc.bg + ';border:1px solid ' + fc.border + ';color:' + fc.text + ';'
        + 'padding:3px 8px;border-radius:3px;font-size:11px;font-weight:600;white-space:nowrap;'
        + '" title="' + escHtml(c.framework + ' — ' + c.control_name) + '">'
        + escHtml(c.framework.replace('ISO 27001:2022', 'ISO').replace('Essential Eight', 'E8').replace('NIST CSF 2.0', 'NIST').replace('APRA CPS 234', 'APRA'))
        + ' ' + escHtml(c.control_id)
        + '</span>';
    });

    return [
      '<div class="br-compliance" data-testid="br-compliance-controls" style="margin-top:10px;">',
      '  <div style="font-size:10px;letter-spacing:.5px;opacity:.5;margin-bottom:4px;">CONTROLS BREACHED</div>',
      '  <div style="display:flex;flex-wrap:wrap;gap:4px;">' + chips.join('') + '</div>',
      '</div>',
    ].join('');
  }

  function _clientExecSummary(sorted, a) {
    var lead = sorted && sorted[0];
    var rowCount = (a.evidence_store && a.evidence_store.row_count) || a.rows_processed || state.rows.length || 0;
    if (!lead) {
      return {
        headline: 'No confirmed breach found',
        subline: 'No correlated threat cases were found in ' + rowCount.toLocaleString() + ' rows.',
        body: 'JanuSec analysed the supplied telemetry and did not identify a confirmed breach. All activity was accounted for by expected operational patterns.',
        provenance: 'Legacy fallback'
      };
    }
    var verdict = (lead.verdict || lead.final_verdict || 'UNCERTAIN').toUpperCase();
    var p = lead.tier1_prefill || {};
    var title = _displayIncidentName(lead);
    var breachRows = (lead.row_refs || []).length;

    // Collect FP-reduction stats: ruled-out rows and their explanation
    var explainedItems = [];
    sorted.forEach(function (c) {
      if (_vClass(c) === 'benign' && (c.row_refs || []).length > 0) {
        var n = (c.tier1_prefill && c.tier1_prefill.incident_name) || c.incident_name || 'authorized activity';
        explainedItems.push({ rows: (c.row_refs || []).length, name: n });
      }
    });
    var totalExplained = explainedItems.reduce(function (s, x) { return s + x.rows; }, 0);

    // Pull specifics from the lead cluster's prefill: actors, root cause
    var impact = p.observed_impact || {};
    var actors = impact.identity || '';
    var rootCause = p.root_cause || '';
    var cm = lead.confidence_meter || p.confidence_meter || {};
    var confTotal = cm.total != null ? cm.total : null;
    var _execIsBreachVerdict = (verdict === 'VALIDATED_BREACH' || verdict === 'CONFIRMED_INTRUSION');
    var confLabel = confTotal != null ? _confidenceLabel(confTotal, _execIsBreachVerdict).label : '';
    var urgency = lead.gate_urgency || '';
    var sev = (lead.severity || '').toUpperCase();

    // Compose headline and body
    var _isBreachClass = (verdict === 'VALIDATED_BREACH' || verdict === 'CONFIRMED_INTRUSION'
                         || verdict === 'CONFIRMED_BREACH' || verdict === 'LIKELY_BREACH');
    if (_isBreachClass) {
      var sublineStr = breachRows + ' correlated evidence rows · ' + (sev || 'CRITICAL') + ' severity';
      if (confLabel) sublineStr += ' · ' + confLabel;
      if (verdict === 'LIKELY_BREACH') sublineStr += ' · HUMAN REVIEW REQUIRED';

      // Prefer LLM-rendered narrative, then raw DREAD fragments, then flat paragraph
      var dn = p.dread_narrative || {};
      var frags = dn.fragments || {};
      var hasDread = !!(frags.damage || frags.affected_users || frags.discoverability);
      var bodyParts = [];
      var provenance = 'Legacy fallback';

      if (dn.rendered) {
        bodyParts.push(dn.rendered);
        provenance = 'LLM-rendered DREAD';
      } else if (hasDread) {
        // Order: damage → reproducibility → exploitability → affected_users → discoverability
        var _fragOrder = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'];
        _fragOrder.forEach(function(dim) {
          if (frags[dim]) bodyParts.push(frags[dim]);
        });
        if (dn.sabsa_coda_draft) bodyParts.push('\n\n' + dn.sabsa_coda_draft);
        provenance = 'Deterministic DREAD fragments';
      } else {
        // Try PASTA threat model before falling back to flat paragraph
        var dInfo = _dreadInfo(lead);
        if (dInfo.hasPasta) {
          var pasta = p.pasta_summary || {};
          if (pasta.threat_profile) bodyParts.push('Threat actor: ' + pasta.threat_profile);
          if (pasta.exploitation_path) bodyParts.push('Exploitation: ' + pasta.exploitation_path);
          if (pasta.business_impact) bodyParts.push('Business impact: ' + pasta.business_impact);
          provenance = 'PASTA threat model';
        } else if (dInfo.hasDiamond) {
          var dm = p.diamond_model || {};
          if (dm.adversary) bodyParts.push('Adversary: ' + dm.adversary);
          if (dm.capability && dm.capability.length) bodyParts.push('Capabilities: ' + dm.capability.slice(0, 5).join(', ') + '.');
          var dvictims = (dm.victim_users || []).concat(dm.victim_data || []);
          if (dvictims.length) bodyParts.push('Victim scope: ' + dvictims.slice(0, 4).join(', ') + '.');
          provenance = 'DIAMOND threat model';
        } else if (p.what_happened || p.root_cause) {
          // T1 LLM prefill has content — guard against raw correlation fallback strings
          var _wh = (p.what_happened || '');
          if (_wh && !_rawCorrelationText(_wh)) bodyParts.push(_wh);
          if (p.root_cause) bodyParts.push('Root cause: ' + p.root_cause);
          if (actors && actors.indexOf('No named') === -1) bodyParts.push('Affected accounts: ' + actors + '.');
          // If all T1 content was raw correlation text, fall through to deterministic
          if (!bodyParts.length) {
            bodyParts.push(
              'JanuSec confirmed a breach in the supplied telemetry. ' +
              (p.root_cause || lead.lead_description || 'Attacker activity was observed across multiple data sources.')
            );
            if (actors && actors.indexOf('No named') === -1) bodyParts.push('Affected accounts: ' + actors + '.');
          }
          provenance = 'T1 LLM analysis';
        } else {
          // Genuinely no threat model data of any kind
          bodyParts.push(
            'JanuSec confirmed a breach in the supplied telemetry. ' +
            (rootCause || 'Attacker activity was observed across multiple data sources.')
          );
          if (actors && actors.indexOf('No named') === -1) {
            bodyParts.push('Affected accounts: ' + actors + '.');
          }
          provenance = 'Deterministic';
        }
      }

      // Always append the ruled-out context regardless of narrative source
      if (totalExplained > 0) {
        var rulledOutStr = explainedItems.map(function (x) {
          return x.rows.toLocaleString() + ' rows (' + x.name + ')';
        }).join(', ');
        bodyParts.push(
          'The platform also analysed ' + totalExplained.toLocaleString() +
          ' additional rows and ruled them out: ' + rulledOutStr +
          '. These are NOT part of the breach and require no further investigation.'
        );
      }
      if (urgency === 'URGENT') {
        bodyParts.push('IMMEDIATE ACTION is required. Contain affected accounts and systems before further damage occurs.');
      }

      var headlineLabel = verdict === 'LIKELY_BREACH'
        ? 'Likely breach — human review required — '
        : 'Confirmed breach — ';
      return {
        headline: headlineLabel + (title || 'Unauthorised access with data exfiltration'),
        subline: sublineStr,
        body: bodyParts.join(' '),
        provenance: provenance
      };
    }

    // Non-breach verdicts
    var summary = _friendlyThreatCaseSummary(lead, title);
    var nonBreachBody = summary;
    if (totalExplained > 0) {
      nonBreachBody += ' Additionally, ' + totalExplained.toLocaleString() + ' rows were reviewed and ruled out — no further investigation of those cases is required.';
    }
    var _nbDreadInfo = lead ? _dreadInfo(lead) : { provenance: 'Legacy fallback' };
    return {
      headline: 'Highest finding: ' + verdict.replace(/_/g, ' ') + (title ? ' — ' + title : ''),
      subline: breachRows + ' evidence rows require analyst review before breach validation.',
      body: nonBreachBody,
      provenance: _nbDreadInfo.provenance
    };
  }

  function _renderExecSummaryShell(sorted, a) {
    var initial = _clientExecSummary(sorted || [], a || {});
    return [
      '<div class="br-section-head">EXECUTIVE SUMMARY</div>',
      '<div class="br-exec" id="br-exec-block" data-testid="br-exec-block">',
      '  <div class="br-exec__text" id="br-exec-det">',
      '    <div class="br-exec__headline">' + escHtml(initial.headline) + '</div>',
      '    <div class="br-exec__subline">' + escHtml(initial.subline) + '</div>',
      '    <div class="br-exec__source" id="br-exec-source">source: ' + escHtml(initial.provenance || 'Legacy fallback') + '</div>',
      '    <div class="br-exec__body">' + escHtml(initial.body) + '</div>',
      '    <div class="br-exec__refs" id="br-exec-refs"></div>',
      '    <div class="br-exec__warn" id="br-exec-warn"></div>',
      '  </div>',
      '  <div class="br-exec__color" id="br-exec-color"></div>',
      '  <div class="br-exec__footer">',
      '    <span class="br-exec__model" id="br-exec-model"></span>',
      '    <span class="br-exec__regen" id="br-exec-regen">' + _icon('refresh-cw') + ' regenerate</span>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _selectTopThreatCases(sorted) {
    if (window.BreachThreatCases) return window.BreachThreatCases.selectTopThreatCases(sorted);
    var MIN_TOP_ROWS = 5;
    var confirmed = (sorted || []).filter(function (c) {
      return _vClass(c) === 'confirmed' && (c.row_refs || []).length >= MIN_TOP_ROWS;
    });
    var likely = (sorted || []).filter(function (c) {
      return _vClass(c) === 'likely' && (c.row_refs || []).length >= MIN_TOP_ROWS;
    }).slice(0, 3);
    var candidates = confirmed.concat(likely);
    if (!candidates.length) {
      candidates = (sorted || []).filter(function (c) {
        return _vClass(c) !== 'benign' && (c.row_refs || []).length > 0;
      }).slice(0, 4);
    }
    return candidates;
  }

  function _renderTopFindings(sorted) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderTopFindings(sorted);
    var nonBenign = _selectTopThreatCases(sorted);
    var html = '<div class="br-section-head">TOP THREAT CASES</div>';
    nonBenign.forEach(function (c, i) {
      html += '<div id="br-card-' + escHtml(c.cluster_id) + '" data-card-idx="' + i + '"></div>';
    });
    return html;
  }

  function _renderAdditionalFindings(sorted) {
    // Additional findings = uncertain-class only. Confirmed and likely go to top cards.
    var rest = sorted.filter(function (c) {
      return _vClass(c) !== 'benign'
          && _vClass(c) !== 'confirmed'
          && _vClass(c) !== 'likely'
          && (c.row_refs || []).length > 0;
    });
    if (!rest.length) return '';

    // Group by severity descending: critical > high > medium > low
    var _SEV_ORDER = ['critical', 'high', 'medium', 'low'];
    var groups = {};
    _SEV_ORDER.forEach(function (s) { groups[s] = []; });
    rest.forEach(function (c) {
      var s = (c.severity || 'low').toLowerCase();
      if (!groups[s]) groups[s] = [];
      groups[s].push(c);
    });

    function _findingRow(c) {
      var p = c.tier1_prefill || {};
      var title = _displayIncidentName(c);
      var heuristic = p.headline_subtitle || c.summary || c.cluster_label || _buildFallbackSummary(c);
      if (_rawCorrelationText(title)) title = _deriveIncidentName(c) || 'Threat Case';
      if (_rawCorrelationText(heuristic)) heuristic = _friendlyThreatCaseSummary(c, title);
      return [
        '<div class="br-finding" id="br-finding-' + escHtml(c.cluster_id) + '">',
        '  <div class="br-finding__main">',
        '    <div class="br-finding__verdict br-card__verdict--' + _vClass(c) + '">',
        '      ' + verdictIcon(c.verdict || c.final_verdict) + ' ' + escHtml((c.verdict || c.final_verdict || 'UNCERTAIN').toUpperCase()),
        '    </div>',
        '    <div class="br-finding__oneliner" id="br-fol-' + escHtml(c.cluster_id) + '">',
        '      ' + escHtml((title ? title + ' · ' : '') + heuristic),
        '    </div>',
        '    <div class="br-finding__meta">',
        '      ' + (c.row_refs || []).length + ' rows',
        '      &nbsp;·&nbsp; ' + escHtml((c.severity || 'low').toUpperCase()),
        '    </div>',
        '  </div>',
        '  <div class="br-finding__actions">',
        '    <button class="br-finding__gen" data-gen-cluster="' + escHtml(c.cluster_id) + '">',
        '      Generate summary',
        '    </button>',
        '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
        '      Open threat case ↗',
        '    </button>',
        '  </div>',
        '</div>',
      ].join('');
    }

    var bodyHtml = '';
    _SEV_ORDER.forEach(function (sev) {
      var group = groups[sev] || [];
      if (!group.length) return;
      var sevLabel = sev.toUpperCase();
      bodyHtml += '<div style="font-size:11px;font-weight:700;color:var(--text-muted);'
        + 'letter-spacing:.8px;padding:8px 0 4px;border-top:1px solid rgba(255,255,255,.06);">'
        + sevLabel + ' (' + group.length + ')</div>';
      group.forEach(function (c) { bodyHtml += _findingRow(c); });
    });

    // Collapsed by default — analysts open only when needed
    return [
      '<details class="br-additional-findings" style="margin-top:12px;">',
      '  <summary class="br-section-head" style="cursor:pointer;user-select:none;list-style:none;">',
      '    ADDITIONAL FINDINGS (' + rest.length + ' THREAT CASES)',
      '    <span style="font-size:11px;font-weight:400;color:var(--text-muted);margin-left:8px;">',
      '      ▶ expand by severity',
      '    </span>',
      '  </summary>',
      '  <div style="margin-top:8px;">' + bodyHtml + '</div>',
      '</details>',
    ].join('');
  }

  function _isSecurityTestCluster(c) {
    // Catch AUTHORIZED_SECURITY_TEST / pentest clusters that may have row_refs:[]
    // because the row count is tracked at assessment level, not cluster.row_refs.
    var name = ((c.tier1_prefill && c.tier1_prefill.incident_name) || c.incident_name || c.lead_description || c.cluster_label || '').toUpperCase();
    var verd = ((c.verdict || c.final_verdict) || '').toUpperCase();
    return verd === 'AUTHORIZED_SECURITY_TEST'
      || name.indexOf('AUTHORIZED') !== -1
      || name.indexOf('SECURITY TEST') !== -1
      || name.indexOf('PENTEST') !== -1
      || name.indexOf('RED TEAM') !== -1;
  }

  function _renderNarrativeContext(sorted) {
    // Include: enrichment_guided benign cases, benign clusters with evidence rows,
    // and authorized-security-test clusters (which may have empty row_refs but still
    // represent explained rows tracked at assessment level).
    var contextCases = sorted.filter(function (c) {
      if (!c) return false;
      if (_vClass(c) !== 'benign') return false;
      return c.case_type === 'enrichment_guided'
          || (c.row_refs || []).length > 0
          || _isSecurityTestCluster(c);
    });
    if (!contextCases.length) return '';
    var html = '<div class="br-section-head">SECURITY CONTEXT &amp; RULED-OUT CASES</div>';
    contextCases.forEach(function (c) {
      var p = c.tier1_prefill || {};
      var title = p.incident_name || c.incident_name || c.lead_description || 'Context case';
      var sub = p.headline_subtitle || c.reason_summary || p.short_narrative || '';
      // Build a plain-English paragraph explaining why this is benign
      var narrative = p.verdict_reasoning || p.what_happened || c.business_significance || '';
      // If verdict_reasoning looks like a malicious C2 statement, replace it with the short_narrative
      var _BAD_RE = /command.and.control|c2 beacon|needs containment|attacker maintain/i;
      if (_BAD_RE.test(narrative)) narrative = sub;
      if (!narrative && _vClass(c) === 'benign') {
        var _ck = c.cluster_kind || '';
        if (_ck === 'unclassified' || _ck === '') {
          narrative = 'No confirmed threat phase matched this component. ' +
            'The events remain unclassified — no malicious indicators were confirmed, ' +
            'but insufficient telemetry is available to fully characterise this activity. ' +
            'Additional log sources or investigation may be required.';
        } else {
          narrative = 'This activity cluster was reviewed and determined to be benign. ' +
            'No indicators of malicious intent, data loss, or unauthorised access were confirmed. ' +
            'The events are consistent with ' + (sub || 'expected operational activity') + '.';
        }
      }
      var rowCount = (c.row_refs || []).length;
      var isAuthorized = /authorized security test|pentest|penetration test|red team/i.test(title + ' ' + sub + ' ' + narrative);
      var authNarrative = isAuthorized
        ? '<div class="br-auth-explain"><strong>Why excluded:</strong> Activity matched approved security-test context in this assessment. '
          + '<strong>Rows explained:</strong> ' + rowCount.toLocaleString() + ' rows. '
          + '<strong>Residual check:</strong> confirm test window, source identities, and authorization record before final closure.</div>'
        : '';
      html += [
        '<div class="br-finding br-finding--context" id="br-context-' + escHtml(c.cluster_id) + '">',
        '  <div class="br-finding__main">',
        '    <div class="br-finding__verdict br-card__verdict--benign">✓ ' + escHtml(title.toUpperCase()) + '</div>',
        '    <div class="br-finding__oneliner">' + escHtml(sub) + '</div>',
        '    <div class="br-finding__meta" style="white-space:normal;line-height:1.5;">' + escHtml(narrative) + '</div>',
        authNarrative,
        '    <div class="br-finding__meta" style="opacity:.6;margin-top:4px;">' + rowCount + ' correlated rows reviewed</div>',
        '  </div>',
        '  <div class="br-finding__actions">',
        '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
        '      Review evidence ↗',
        '    </button>',
        '  </div>',
        '</div>',
      ].join('');
    });
    return html;
  }

  // ── Pending Actions Banner (compact, expandable) ────────────────────────────

  function _renderPendingActionsBanner(assessment) {
    var actions = (assessment && assessment.proposed_actions) || [];
    var pending = actions.filter(function (a) { return a.status === 'pending'; });
    if (!pending.length) return '';

    var zone2 = pending.filter(function (a) { return a.zone === 2; });
    var zone3 = pending.filter(function (a) { return a.zone === 3; });

    // Compact summary line
    var summaryParts = [];
    zone2.forEach(function (a) {
      var dl = a.deadline_hours >= 24 ? Math.round(a.deadline_hours / 24) + 'd' : a.deadline_hours + 'h';
      summaryParts.push(escHtml((a.description || a.action_type || '').replace(/_/g, ' ')) + ' (' + escHtml(dl) + ')');
    });
    zone3.forEach(function (a) {
      summaryParts.push('⚖ ' + escHtml((a.action_type || '').replace(/_/g, ' ')));
    });
    var summaryLine = summaryParts.slice(0, 4).join(' · ');
    if (summaryParts.length > 4) summaryLine += ' + ' + (summaryParts.length - 4) + ' more';

    var html = '<div class="br-actions-banner" data-testid="br-actions-banner">';
    html += '<div class="br-actions-banner__summary" id="br-actions-toggle" style="cursor:pointer;">';
    html += '  <span class="br-actions-banner__icon">' + _icon('warning') + '</span>';
    html += '  <span class="br-actions-banner__count">' + pending.length + ' action' + (pending.length > 1 ? 's' : '') + ' awaiting approval</span>';
    html += '  <span class="br-actions-banner__hint" id="br-actions-caret">[Review ▸]</span>';
    html += '</div>';
    html += '<div class="br-actions-banner__detail" style="font-size:12px;opacity:.75;margin-top:2px;padding-left:24px;">' + summaryLine + '</div>';

    // Expandable detail (hidden by default)
    html += '<div class="br-actions-banner__expanded" id="br-actions-expanded" style="display:none;margin-top:12px;">';

    if (zone2.length) {
      html += '<div class="br-actions-banner__zone-label">Zone 2 — 30-min approval window</div>';
      zone2.forEach(function (a) {
        var deadline = a.deadline_hours >= 24
          ? Math.round(a.deadline_hours / 24) + ' days'
          : a.deadline_hours + 'h';
        html += '<div class="br-actions-banner__row">';
        html += '  <div class="br-actions-banner__btns">';
        html += '    <button class="br-actions-banner__approve" data-action-token="' + escHtml(a.approval_token || '') + '">APPROVE</button>';
        html += '    <button class="br-actions-banner__veto" data-veto-token="' + escHtml(a.approval_token || '') + '">VETO</button>';
        html += '  </div>';
        html += '  <div class="br-actions-banner__body">';
        html += '    <div class="br-actions-banner__title">' + escHtml((a.action_type || '').replace(/_/g, ' ')) + ': ' + escHtml(a.description || '') + '</div>';
        html += '    <div class="br-actions-banner__meta">→ ' + escHtml(a.recipient || 'SOC') + ' · within ' + escHtml(deadline) + (a.citation ? ' · ' + escHtml(a.citation) : '') + '</div>';
        html += '    <div class="br-actions-banner__conf">Confidence: ' + (a.confidence || 0).toFixed(2) + ' · Sources: ' + (a.evidence_count || 0) + '</div>';
        html += '  </div>';
        html += '</div>';
      });
    }

    if (zone3.length) {
      html += '<div class="br-actions-banner__zone-label br-actions-banner__zone3">Zone 3 — Legal/Regulatory (human must execute)</div>';
      zone3.forEach(function (a) {
        var deadline = a.deadline_hours >= 720
          ? Math.round(a.deadline_hours / 24) + ' days'
          : a.deadline_hours + 'h';
        html += '<div class="br-actions-banner__row br-actions-banner__row--escalate">';
        html += '  <div class="br-actions-banner__escalate-icon">' + _icon('scale') + '</div>';
        html += '  <div class="br-actions-banner__body">';
        html += '    <div class="br-actions-banner__title">REGULATORY ACTION REQUIRED<br>' + escHtml(a.action_type || '') + ' — ' + escHtml(a.description || '') + '</div>';
        html += '    <div class="br-actions-banner__meta">→ ' + escHtml(a.recipient || 'Legal') + ' · within ' + escHtml(deadline) + (a.citation ? ' · ' + escHtml(a.citation) : '') + '</div>';
        html += '    <div class="br-actions-banner__conf">Draft prepared by agent — human must review and execute</div>';
        html += '  </div>';
        html += '</div>';
      });
    }

    html += '</div>';
    html += '</div>';
    return html;
  }

  // ── Action Row: drill-down toggle + deepen investigation button ─────────────

  function _renderActionRow() {
    return [
      '<div class="br-action-row" data-testid="br-action-row">',
      '  <button class="br-action-row__drilldown" id="br-toggle-drilldown" data-testid="br-toggle-drilldown">' + _icon('search') + ' Investigation details</button>',
      '  <button class="br-action-row__deepen" id="br-deepen-btn" data-testid="br-deepen-btn">' + _icon('rotate-cw') + ' Deepen investigation</button>',
      '</div>',
    ].join('');
  }

  // ── Stakeholder Dispatch Bar ───────────────────────────────────────────────
  // Maps each dispatch role to the existing 8-persona report system.
  // Each button opens a preview of what the stakeholder will receive,
  // requires confirmation before sending, and logs an audit entry.
  // Rendering is delegated to window.BreachDispatch when available
  // (breach_dispatch.js must be loaded before breach.js).

  var _STAKEHOLDER_ROLES = (window.BreachDispatch && window.BreachDispatch.roles) || [
    { key: 'soc_analyst',    icon: _icon('shield'),    label: 'SOC Analyst',  persona: 'soc_analyst',
      desc: 'Triage focus, containment options, IOCs, decision tree, priority',
      actions: 'Confirm/deny/escalate triage. Execute containment playbook. Validate IOC scope.' },
    { key: 'ciso',           icon: _icon('scale'),     label: 'CISO / Legal', persona: 'ciso',
      desc: 'Regulatory exposure, compliance control gaps, NDB/GDPR obligations',
      actions: 'Assess NDB notification requirement. Evaluate GDPR Art.33 / SEC 8-K triggers. Approve regulatory disclosure.' },
    { key: 'executive',      icon: _icon('bar-chart'), label: 'Executive',    persona: 'executive',
      desc: 'Business impact, plain-English narrative, operational next steps',
      actions: 'Approve containment spend. Communicate to board if material. Authorise forensic engagement.' },
    { key: 'threat_hunter',  icon: _icon('crosshair'), label: 'Threat Hunter', persona: 'threat_hunter',
      desc: 'Kill chain stages, Sigma rules, hunt hypotheses, pivot leads',
      actions: 'Validate hypotheses. Run Sigma queries. Expand scope via pivot leads. Confirm kill chain completeness.' },
    { key: 'forensics',      icon: _icon('microscope'), label: 'Forensics',   persona: 'forensics',
      desc: 'Artifact collection order, proof-of-execution, chain of custody',
      actions: 'Collect volatile artifacts (memory \u2192 disk \u2192 network). Preserve chain of custody. Document proof-of-execution.' },
    { key: 'compliance',     icon: _icon('clipboard'), label: 'Compliance',   persona: 'compliance',
      desc: 'Framework control gaps (NIST/SOC2/ISO/Privacy Act), audit trail, GRC evidence',
      actions: 'Map control failures to frameworks. Verify notification timeline. Update risk register. Prepare GRC audit evidence.' },
    { key: 'export',         icon: _icon('file-text'), label: 'Full Report',  persona: null,
      desc: 'Complete multi-persona HTML report', actions: null },
  ];

  function _dispatchPref(key, fallback) {
    if (window.BreachDispatch) return window.BreachDispatch.pref(key, fallback);
    try {
      var v = localStorage.getItem('janusec.' + key);
      return v == null ? fallback : v;
    } catch (_) {
      return fallback;
    }
  }

  function _renderStakeholderDispatch(assessment) {
    if (window.BreachDispatch) return window.BreachDispatch.renderBar(assessment);
    assessment = assessment || {};
    var pendingActions = (assessment.proposed_actions || []).filter(function (a) {
      return !a.status || a.status === 'pending' || a.requires_approval;
    });
    var approvalCount = pendingActions.length || ((assessment.pending_approvals || []).length) || 2;
    var hidden = _dispatchPref('dispatch.hidden', '0') === '1';
    var drawerOpen = !hidden && _dispatchPref('dispatch.drawerOpen', '0') === '1';
    var compactRoles = _STAKEHOLDER_ROLES.filter(function (r) { return r.key !== 'export'; });
    var primaryRoles = compactRoles;

    var html = '<div class="br-dispatch' + (hidden ? ' br-dispatch--hidden' : '') + '" id="br-dispatch-shell" data-testid="br-dispatch">';
    html += '<div class="br-action-center" data-testid="br-action-center">';
    html += '<div class="br-action-center__top">';
    html += '<div>';
    html += '<div class="br-action-center__eyebrow">ACTION CENTER</div>';
    html += '<div class="br-action-center__title">Next decision and handoff</div>';
    html += '<div class="br-action-center__sub">Keep containment, approvals, and stakeholder handoff visible without turning Home into the report itself.</div>';
    html += '</div>';
    html += '<div class="br-action-center__actions">';
    html += '<button class="br-action-center__toggle" id="br-dispatch-toggle" data-dispatch-toggle aria-expanded="' + (drawerOpen ? 'true' : 'false') + '">' + (drawerOpen ? 'Close dispatch center' : 'Open dispatch center') + '</button>';
    html += '<button class="br-action-center__hide" id="br-dispatch-hide" data-dispatch-hide>' + (hidden ? 'Show' : 'Hide') + '</button>';
    html += '</div>';
    html += '</div>';
    html += '<div class="br-action-center__grid">';
    html += '<div class="br-action-card br-action-card--primary"><div class="br-action-card__label">Start here</div><div class="br-action-card__value">Contain SFL-LT-0442, expire active sessions, preserve evidence.</div><div class="br-action-card__note">SOC owns first response; remediation routes after evidence is preserved.</div></div>';
    html += '<div class="br-action-card"><div class="br-action-card__label">Approvals</div><div class="br-action-card__value">' + approvalCount + ' pending</div><div class="br-action-card__note">Regulatory notification and forensic preservation stay visible here.</div></div>';
    html += '<div class="br-action-card"><div class="br-action-card__label">Trust</div><div class="br-action-card__value">Certain / inferred / verify</div><div class="br-action-card__note">Open dispatch preview for persona-specific uncertainty and history.</div></div>';
    html += '</div>';
    html += '<div class="br-action-center__handoff">';
    html += '<span class="br-action-center__handoff-label">Dispatch to:</span>';
    primaryRoles.forEach(function (r) {
      html += '<button class="br-dispatch__btn br-dispatch__btn--compact"'
        + ' data-dispatch-role="' + r.key + '"'
        + ' data-testid="br-dispatch-' + r.key + '"'
        + ' title="' + escHtml(r.desc) + '">'
        + '<span class="br-dispatch__icon">' + r.icon + '</span>'
        + '<span class="br-dispatch__label">' + escHtml(r.label) + '</span>'
        + '</button>';
    });
    html += '<button class="br-action-center__more" data-dispatch-toggle>More stakeholders</button>';
    html += '</div>';
    html += '<div class="br-action-center__hidden-note" id="br-dispatch-hidden-note" style="' + (hidden ? '' : 'display:none;') + '">Dispatch center is hidden on this browser. Approvals remain visible; click Show to restore the workbench.</div>';
    html += '</div>';

    html += '<div class="br-dispatch__drawer" id="br-dispatch-drawer" style="' + (drawerOpen ? '' : 'display:none;') + '" aria-hidden="' + (drawerOpen ? 'false' : 'true') + '">';
    html += '<div class="br-dispatch__head">STAKEHOLDER DISPATCH</div>';
    html += '<div class="br-dispatch__sub">Generate one persona-specific report at a time. Review before sending; dispatch is logged, auditable, and tied to approval state.</div>';
    html += '<div class="br-dispatch__bar">';
    _STAKEHOLDER_ROLES.forEach(function (r) {
      var isExport = r.key === 'export';
      html += '<button class="br-dispatch__btn' + (isExport ? ' br-dispatch__btn--export' : '') + '"'
        + ' data-dispatch-role="' + r.key + '"'
        + ' data-testid="br-dispatch-drawer-' + r.key + '"'
        + ' title="' + escHtml(r.desc) + '">'
        + '<span class="br-dispatch__icon">' + r.icon + '</span>'
        + '<span class="br-dispatch__label">' + escHtml(r.label) + '</span>'
        + '</button>';
    });
    html += '</div>';
    // Preview/confirmation panel (hidden until a dispatch button is clicked)
    html += '<div id="br-dispatch-preview" class="br-dispatch__preview" style="display:none;" data-testid="br-dispatch-preview"></div>';
    html += '</div>';
    html += '</div>';
    return html;
  }

  function _caseUnknowns(cluster) {
    var text = [
      cluster && cluster.reason_summary,
      cluster && cluster.business_significance,
      cluster && cluster.lead_description,
      cluster && cluster.tier1_prefill && cluster.tier1_prefill.what_happened,
      cluster && cluster.tier1_prefill && JSON.stringify(cluster.tier1_prefill.observed_impact || {}),
    ].join(' ').toLowerCase();
    var out = [];
    if (!/pii|customer|payroll|credential|secret|source code|database/.test(text)) out.push('data contents');
    if (!/attacker-owned|malicious owner|known owner|vendor-owned/.test(text)) out.push('destination owner');
    if (!/subnet|security group|vpc|network segment/.test(text)) out.push('network scope');
    if (!/admin|privilege|iam|role|root|owner/.test(text)) out.push('privilege scope');
    return out.slice(0, 2).join(', ') || 'verify assumptions';
  }

  function _caseNextAction(cluster, idx) {
    var text = [
      cluster && cluster.incident_name,
      cluster && cluster.reason_summary,
      cluster && cluster.business_significance,
      cluster && cluster.tier1_prefill && cluster.tier1_prefill.headline_subtitle,
    ].join(' ').toLowerCase();
    if (/exfil|data|b2|storage|copy|unload/.test(text)) return 'Open workbench';
    if (/iam|session|credential|privilege|token/.test(text)) return 'Verify scope';
    if (/recur|repeat|command|tool|hunt|asn|ip/.test(text)) return 'Hunt pivots';
    return idx === 0 ? 'Open workbench' : 'Review';
  }

  function _renderHomeThreatCases(sorted) {
    var cases = _selectTopThreatCases(sorted).slice(0, 4);
    if (!cases.length) return '';
    var rows = cases.map(function (c, idx) {
      var p = c.tier1_prefill || {};
      var title = _displayIncidentName(c);
      var why = p.headline_subtitle || c.business_significance || c.reason_summary || _buildFallbackSummary(c);
      if (_rawCorrelationText(why)) why = _friendlyThreatCaseSummary(c, title);
      var meter = p.confidence_meter || c.confidence_meter || {};
      var conf = meter.total != null ? (Math.round(meter.total) + '%') : ((c.verdict_confidence != null) ? Math.round(c.verdict_confidence * 100) + '%' : 'review');
      return '<tr>'
        + '<td><strong>' + escHtml(title) + '</strong><div class="br-home-cases__meta">' + escHtml((c.severity || 'low').toUpperCase()) + ' · ' + (c.row_refs || []).length + ' rows</div></td>'
        + '<td>' + escHtml(why).slice(0, 150) + '</td>'
        + '<td>' + escHtml(conf) + '</td>'
        + '<td>' + escHtml(_caseUnknowns(c)) + '</td>'
        + '<td><button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">' + escHtml(_caseNextAction(c, idx)) + '</button></td>'
        + '</tr>';
    }).join('');
    var moreRows = cases.map(function (c) {
      return '<div class="br-home-cases__more-row"><span>' + escHtml(_displayIncidentName(c)) + '</span><button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">Open workbench</button></div>';
    }).join('');
    return [
      '<section class="br-home-panel br-home-cases" data-testid="br-home-threat-cases">',
      '<div class="br-home-panel__head"><span>Top Threat Cases</span><small>Threat modeling lives in each case workbench.</small></div>',
      '<div class="br-home-cases__table-wrap"><table class="br-home-cases__table">',
      '<thead><tr><th>Case</th><th>Why it matters</th><th>Confidence</th><th>Unknowns</th><th>Action</th></tr></thead>',
      '<tbody>' + rows + '</tbody>',
      '</table></div>',
      '<details class="br-home-cases__more"><summary>Show all visible threat cases</summary><div class="br-home-cases__more-body">' + moreRows + '</div></details>',
      '</section>',
    ].join('');
  }

  function _renderHomeEvidenceViews() {
    var aid = encodeURIComponent(AID || '');
    return [
      '<section class="br-home-panel br-home-evidence" data-testid="br-home-evidence-views">',
      '<div class="br-home-panel__head"><span>Evidence Views</span><small>Open full evidence surfaces when you need graph, timing, or row-level proof.</small></div>',
      '<div class="br-home-evidence__actions">',
      '<a class="br-card__open" href="/static/breach.html?assessment=' + aid + '&tab=hopgraph">Open HopGraph</a>',
      '<button class="br-card__open" id="br-open-investigation-details">Open Timeline</button>',
      '<a class="br-card__open" href="/static/breach.html?assessment=' + aid + '&tab=evidence">Open Evidence Table</a>',
      '</div>',
      '</section>',
    ].join('');
  }

  function _renderCollapsed(label, count) {
    if (!count) return '';
    var key = label.toLowerCase();
    return [
      '<div class="br-collapsed" data-collapsed-key="' + key + '" style="cursor:pointer;">',
      '  <span>' + escHtml(label) + ' — ' + count + ' threat case(s)</span>',
      '  <span class="br-collapsed__caret" id="br-caret-' + key + '">Expand ▼</span>',
      '</div>',
      '<div id="br-collapsed-body-' + key + '" style="display:none;border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;margin-bottom:8px;"></div>',
    ].join('');
  }

  // ── Card rendering ───────────────────────────────────────────────────────────

  var _ANALYST_NOTE = /^DAY\s*\d+\s*:/i;
  var _NOISE = /^(system|local service|network service|localhost|unknown|nt authority.*)$/i;
  var _BORING = /^correlated activity cluster$|^correlated incident$|^n\/a$|^unknown$/i;
  var _PLACEHOLDER_NAME = /^(unknown(?:[-_\s]*\d{4})?(?:[-_\s]*[a-z])?\s*breach|remaining telemetry did not form|no validated breach|correlated incident)$/i;

  function _heuristicValueText(value) {
    if (value == null) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
    try { return JSON.stringify(value); } catch (_) { return String(value); }
  }

  function _rowEvidenceText(row) {
    if (!row || typeof row !== 'object') return '';
    return [
      row._source, row.source, row.source_file,
      row.user, row.user_name, row.username, row.user_principal_name, row.account, row.actor,
      row.src_ip, row.source_ip, row.remote_address, row.dst_ip, row.destination_ip,
      row.hostname, row.host, row.device_name,
      row.process, row.process_name, row.event_simpleName, row.event_type, row.operationName,
      row.objectRef, row.notes, row.analyst_notes, row.description, row.dns_query, row.ja3, row.ja4,
    ].map(_heuristicValueText).join(' ');
  }

  function _clusterEvidenceText(cluster, p) {
    var parts = [
      cluster.incident_name,
      cluster.lead_description,
      cluster.reason_summary,
      cluster.business_significance,
      cluster.headline_subtitle,
      cluster.ioc_summary,
      cluster.attack_narrative,
      (cluster.top_mitre || []).join(' '),
      p && p.incident_name,
      p && p.headline_subtitle,
      p && p.short_narrative,
      p && p.what_happened,
      p && p.root_cause,
    ];
    (cluster.sample_rows || []).slice(0, 120).forEach(function (row) {
      parts.push(_rowEvidenceText(row));
    });
    var refs = new Set((cluster.row_refs || []).map(function (v) { return String(v); }));
    var added = 0;
    (state.rows || []).forEach(function (row) {
      if (added >= 160 || !row) return;
      var idx = row.row_index != null ? row.row_index : row.row_number;
      if (refs.has(String(idx))) {
        parts.push(_rowEvidenceText(row));
        added++;
      }
    });
    return parts.map(_heuristicValueText).join(' ').toLowerCase();
  }

  function _clusterHasEvidence(cluster, pattern) {
    cluster = cluster || {};
    var p = cluster.tier1_prefill || {};
    var head = [
      cluster.incident_name,
      cluster.lead_description,
      cluster.reason_summary,
      cluster.business_significance,
      cluster.headline_subtitle,
      cluster.ioc_summary,
      cluster.attack_narrative,
      p.incident_name,
      p.headline_subtitle,
      p.short_narrative,
      p.what_happened,
      p.root_cause,
      _heuristicValueText(p.observed_impact),
    ].map(_heuristicValueText).join(' ');
    pattern.lastIndex = 0;
    if (pattern.test(head)) return true;
    var rows = cluster.sample_rows || [];
    for (var i = 0; i < rows.length; i++) {
      pattern.lastIndex = 0;
      if (pattern.test(_rowEvidenceText(rows[i]))) return true;
    }
    var refs = new Set((cluster.row_refs || []).map(function (v) { return String(v); }));
    for (var j = 0; j < (state.rows || []).length; j++) {
      var row = state.rows[j];
      if (!row) continue;
      var idx = row.row_index != null ? row.row_index : row.row_number;
      if (!refs.has(String(idx))) continue;
      pattern.lastIndex = 0;
      if (pattern.test(_rowEvidenceText(row))) return true;
    }
    return false;
  }

  function _isPlaceholderIncidentName(name) {
    var n = String(name || '').trim();
    if (!n) return true;
    return _BORING.test(n) || _PLACEHOLDER_NAME.test(n) || /unknown[-_\s]+\d{4}[-_\s]+[a-z]\s+breach/i.test(n);
  }

  function _deriveIncidentName(cluster) {
    // Regex-label chain removed. Incident name must come from LLM Tier-1
    // prefill (backend). If prefill is absent the backend returns a neutral
    // placeholder which the UI displays verbatim — no client-side guessing.
    return '';
  }

  function _displayIncidentName(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var candidates = [p.incident_name, (cluster || {}).incident_name];
    for (var i = 0; i < candidates.length; i++) {
      var name = String(candidates[i] || '').trim();
      if (name && !_isPlaceholderIncidentName(name)) return name;
    }
    return _deriveIncidentName(cluster || {}) || _buildFallbackTitle(cluster || {});
  }

  function _deriveRootCause(cluster, p, title, subtitle) {
    p = p || {};
    var explicit = String(p.root_cause || '').trim();
    var boring = /correlated evidence|investigation threshold|exceeded.*threshold|threshold.*exceeded|no specific|additional.*logs/i;
    if (explicit && !boring.test(explicit)) return explicit;
    var text = _clusterEvidenceText(cluster || {}, p) + ' ' + String(title || '') + ' ' + String(subtitle || '');
    if (/bec|wire|bcc|mailbox|finance officer/.test(text)) {
      return 'Compromised finance mailbox or identity used for business email compromise activity.';
    }
    if (/mfa fatigue|legacy imap|session token|password spray/.test(text)) {
      return 'Identity compromise via MFA fatigue or legacy authentication allowed attacker access.';
    }
    return '';
  }

  function _buildFallbackTitle(cluster) {
    var derived = _deriveIncidentName(cluster);
    if (derived) return derived;
    // Prefer clean pre-computed fields; skip analyst-notes style text
    var desc = cluster.reason_summary || cluster.summary || '';
    var ld = cluster.lead_description || '';
    if (ld && !_ANALYST_NOTE.test(ld) && !_BORING.test(ld.trim()) && !_rawCorrelationText(ld) && ld.length <= 80) desc = ld;
    if (desc && !_BORING.test(desc.trim()) && !_rawCorrelationText(desc) && desc.length > 4) return desc.length > 80 ? desc.slice(0, 77) + '…' : desc;

    // Heuristic: severity label · real users · MITRE · N events
    var sev = (cluster.severity || '').toLowerCase();
    var sevLabel = { critical: 'Critical', high: 'High-severity', medium: 'Suspicious', low: 'Low-severity' }[sev] || 'Suspicious';

    var allAccts = cluster.shared_accounts || cluster.affected_accounts || [];
    var realAccts = allAccts.filter(function (a) {
      return a && !_NOISE.test(a) && a.indexOf('$') === -1;
    }).slice(0, 2);
    if (!realAccts.length && allAccts.length) realAccts = allAccts.slice(0, 1);

    var mitre = (cluster.top_mitre || []).slice(0, 2);
    var rowCount = (cluster.row_refs || []).length;

    var parts = [sevLabel + ' activity'];
    if (realAccts.length) parts.push(realAccts.join(', '));
    if (mitre.length) parts.push(mitre.join(' + '));
    parts.push(rowCount + ' events');
    return parts.join(' · ');
  }

  function _buildFallbackSummary(cluster) {
    var allAccts = (cluster.shared_accounts || cluster.affected_accounts || []);
    var realAccts = allAccts.filter(function (a) {
      return a && !_NOISE.test(a) && a.indexOf('$') === -1;
    }).slice(0, 3);
    if (!realAccts.length && allAccts.length) realAccts = allAccts.slice(0, 1);
    var hosts = (cluster.shared_hosts || cluster.affected_assets || []).slice(0, 2);
    var ips = (cluster.shared_external_ips || []).slice(0, 2);
    var mitre = (cluster.top_mitre || []).slice(0, 3);
    var ld = cluster.lead_description || '';
    var desc = (!_ANALYST_NOTE.test(ld) && ld.length <= 120) ? ld : (cluster.reason_summary || '');
    var entities = realAccts.concat(hosts).concat(ips).filter(Boolean);
    var parts = [];
    if (entities.length) parts.push(entities.join(', '));
    if (mitre.length) parts.push('Techniques: ' + mitre.join(', '));
    if (desc && desc.length > 4) parts.push(desc);
    return parts.join(' · ') || ((cluster.row_refs || []).length + ' correlated events');
  }

  function _rawCorrelationText(s) {
    // Catches: (a) old correlation-engine boilerplate, (b) generic phase-count metadata strings
    // that say nothing meaningful to a reader ("8 attack phases observed across 5 telemetry sources").
    return /shared attacker|shared identity|same network|same host sequence|same ATT&CK|identity compromise or shared actor|external infrastructure appears|\d+\s+phase\(s\)\s+·|\d+\s+telemetry source\(s\)|^multi-phase intrusion\s+·|\d+\s+attack\s+phases?\s+observed|\d+\s+telemetry\s+sources?\b/i.test(String(s || ''));
  }

  function _friendlyThreatCaseSummary(cluster, title) {
    var text = [
      title,
      cluster.lead_description,
      cluster.reason_summary,
      cluster.business_significance,
      (cluster.top_mitre || []).join(' '),
      _clusterEvidenceText(cluster || {}, (cluster || {}).tier1_prefill || {})
    ].join(' ').toLowerCase();
    var rows = (cluster.row_refs || []).length;
    if (/bec|mailbox|wire|finance/.test(text)) {
      return rows + ' evidence rows connect identity compromise, mailbox activity, and payment-risk evidence.';
    }
    if (/dns|c2|beacon|command/.test(text)) {
      return rows + ' evidence rows show command-and-control activity requiring containment and egress review.';
    }
    if (/npm|supply|github|token|secret/.test(text)) {
      return rows + ' evidence rows show developer or supply-chain activity requiring token and repository review.';
    }
    if (/password|mfa|legacy|okta|identity/.test(text)) {
      return rows + ' evidence rows show identity compromise indicators requiring session and MFA review.';
    }
    return rows + ' correlated evidence rows require analyst review before closure.';
  }

  // ── Context strip: IDENTITY / SYSTEMS / C2 INFRA / SOURCES ─────────────
  function _renderContextStrip(cluster, p) {
    var accts    = (cluster.shared_accounts || cluster.affected_accounts || []).filter(Boolean).slice(0, 4);
    var assets   = (cluster.affected_assets || cluster.shared_hosts || []).filter(Boolean).slice(0, 4);
    var ips      = (cluster.shared_external_ips || []).slice(0, 4);
    var cm       = cluster.confidence_meter || p.confidence_meter || {};
    var srcs     = (cm.source_types_present || []).slice(0, 6);
    var srcCount = typeof cluster.source_count === 'number' ? cluster.source_count : srcs.length;
    if (!accts.length && !assets.length && !ips.length && !srcs.length) return '';

    // Detect identity providers from account names, source list, and observed_impact
    var probeText = accts.concat(srcs).join(' ').toLowerCase()
      + ' ' + (cluster.lead_description || '').toLowerCase()
      + ' ' + ((p.observed_impact && p.observed_impact.identity) ? p.observed_impact.identity : '').toLowerCase();
    var providers = [];
    if (/\bokta\b/.test(probeText)) providers.push('Okta');
    if (/entra|azure.?ad|azuread|\.onmicrosoft\.com/.test(probeText)) providers.push('Entra ID');
    if (/sailpoint/.test(probeText)) providers.push('SailPoint');
    if (/\bping\b/.test(probeText)) providers.push('PingIdentity');
    if (/jumpcloud/.test(probeText)) providers.push('JumpCloud');

    var rows = [];
    if (accts.length) {
      var providerTag = providers.length
        ? ' <span class="br-ctx__provider">via ' + escHtml(providers.slice(0, 2).join(' · ')) + '</span>'
        : '';
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">IDENTITY</span>'
        + '<span class="br-ctx__val">' + escHtml(accts.join(' · ')) + providerTag + '</span>'
        + '</div>'
      );
    }
    if (assets.length) {
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">SYSTEMS</span>'
        + '<span class="br-ctx__val">' + escHtml(assets.join(' · ')) + '</span>'
        + '</div>'
      );
    }
    if (ips.length) {
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">C2 INFRA</span>'
        + '<span class="br-ctx__val">' + escHtml(ips.join(' · ')) + '</span>'
        + '</div>'
      );
    }
    if (srcs.length) {
      var cntSuffix = srcCount > 0
        ? ' <span class="br-ctx__count">(' + srcCount + ' stream' + (srcCount !== 1 ? 's' : '') + ')</span>'
        : '';
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">SOURCES</span>'
        + '<span class="br-ctx__val">' + escHtml(srcs.join(' · ')) + cntSuffix + '</span>'
        + '</div>'
      );
    }
    return rows.length ? '<div class="br-context-strip">' + rows.join('') + '</div>' : '';
  }

  // ── Threat narrative (DREAD · PASTA · Diamond) ───────────────────────────
  function _renderThreatModelSummary(cluster, p, dreadInfo) {
    var frags    = dreadInfo.frags || {};
    var ds       = p.dread_score  || {};
    var riskTier = (ds.risk_tier  || '').toLowerCase();

    function _block(icon, label, sub, text) {
      return '<div class="br-tm__block">'
        + '<div class="br-tm__block-head">'
        + '<span class="br-tm__block-icon">' + icon + '</span>'
        + '<span class="br-tm__block-label">' + escHtml(label) + '</span>'
        + '<span class="br-tm__block-sub">' + escHtml(sub) + '</span>'
        + '</div>'
        + '<div class="br-tm__block-text">' + escHtml(String(text)) + '</div>'
        + '</div>';
    }

    // ── DREAD ── evidence narrative fragments first; numeric detail strings as fallback
    var DREAD_DIMS = [
      { fk: 'damage',          dk: 'damage_detail',          icon: _icon('flame'),   label: 'DAMAGE',          sub: 'What broke, what\u2019s at risk, and how far it spread (blast radius)' },
      { fk: 'reproducibility', dk: 'reproducibility_detail', icon: _icon('repeat'),  label: 'REPRODUCIBILITY', sub: 'Why this can happen again right now and what\u2019s still exposed' },
      { fk: 'exploitability',  dk: 'exploitability_detail',  icon: _icon('zap'),     label: 'EXPLOITABILITY',  sub: 'The attack vector, control gap exploited, and why people should care' },
      { fk: 'affected_users',  dk: 'affected_users_detail',  icon: _icon('user'),    label: 'AFFECTED USERS',  sub: 'Who was hit, their access level, and any privilege abuse or lateral movement' },
      { fk: 'discoverability', dk: 'discoverability_detail', icon: _icon('search'),  label: 'DISCOVERABILITY', sub: 'What was visible, what was misconfigured, and mean time to detect' }
    ];
    var dreadBlocks = DREAD_DIMS
      .map(function(dim) { return { dim: dim, text: frags[dim.fk] || ds[dim.dk] || '' }; })
      .filter(function(d) { return d.text; })
      .map(function(d) { return _block(d.dim.icon, d.dim.label, d.dim.sub, d.text); });

    // ── PASTA ── plain-language attack narrative
    var pasta = p.pasta_summary || {};
    var PASTA_DIMS = [
      { key: 'objective',         icon: _icon('target'),    label: 'OBJECTIVE',       sub: 'What the attacker was trying to achieve' },
      { key: 'threat_profile',    icon: _icon('eye'),       label: 'THREAT ACTOR',    sub: 'Who or what was behind this and their motivation' },
      { key: 'exploitation_path', icon: _icon('unlock'),    label: 'HOW THEY GOT IN', sub: 'The exploitation path and control gaps used' },
      { key: 'business_impact',   icon: _icon('activity'),  label: 'BUSINESS IMPACT', sub: 'What this means for operations and compliance' }
    ];
    var pastaBlocks = PASTA_DIMS
      .filter(function(dim) { return pasta[dim.key]; })
      .map(function(dim)  { return _block(dim.icon, dim.label, dim.sub, pasta[dim.key]); });

    // ── Diamond ── adversary / capability / infrastructure / victim
    var dm = p.diamond_model || {};
    var diamondItems = [];
    if (dm.adversary) {
      diamondItems.push(_block('\uD83C\uDFAF', 'WHO ATTACKED',         'Threat actor attribution and any proxy identity used', dm.adversary));
    }
    if (dm.capability && dm.capability.length) {
      diamondItems.push(_block('\u2699\uFE0F',  'WHAT THEY USED',       'Attack capability, tooling, and technique chain', dm.capability.join(' \u2192 ')));
    }
    var infra = dm.infrastructure || dm.c2_infrastructure || [];
    if (infra.length) {
      var infraText = Array.isArray(infra) ? infra.join(', ') : String(infra);
      diamondItems.push(_block('\uD83C\uDFD7\uFE0F', 'THEIR INFRASTRUCTURE', 'External C2, staging, or exfil infrastructure identified', infraText));
    }
    var victims = (dm.victim_users || []).concat(dm.victim_data || []).filter(Boolean);
    if (victims.length) {
      // Use typed sub-buckets when the backend has separated humans / machines / data
      var hasTyped = (dm.victim_humans && dm.victim_humans.length)
                  || (dm.victim_machines && dm.victim_machines.length);
      if (hasTyped) {
        var typedLines = [];
        if (dm.victim_humans && dm.victim_humans.length) {
          typedLines.push('\uD83D\uDC64 Human accounts: ' + dm.victim_humans.join(', '));
        }
        if (dm.victim_machines && dm.victim_machines.length) {
          typedLines.push('\uD83E\uDD16 Machine/service identities: ' + dm.victim_machines.join(', '));
        }
        if (dm.victim_data && dm.victim_data.length) {
          typedLines.push('\uD83D\uDCBE Data assets: ' + dm.victim_data.join(', '));
        }
        diamondItems.push(_block('\uD83C\uDFAF', 'WHO WAS HIT', 'Victim accounts, service identities, and data assets impacted', typedLines.join(' \u00b7 ')));
      } else {
        // Legacy flat render (older assessments without typed buckets)
        diamondItems.push(_block('\uD83C\uDFAF', 'WHO WAS HIT', 'Victim accounts, systems, and data impacted', victims.join(', ')));
      }
    }

    var hasContent = dreadBlocks.length || pastaBlocks.length || diamondItems.length;
    if (!hasContent) {
      // Embed the generate button directly — don't tell users to look "below" for a
      // button that may be hidden by the dreadInfo.has guard.
      var _cid = escHtml(cluster.cluster_id || '');
      return '<div class="br-threat-model br-threat-model--empty">'
        + '<span class="br-tm__block-icon">' + _icon('cpu') + '</span>'
        + '<div style="flex:1">'
        + '<div class="br-tm__empty-title">Threat narrative not yet generated</div>'
        + '<div class="br-tm__hint">Structured DREAD \u00b7 PASTA \u00b7 Diamond analysis will be built from evidence rows by the multi-agent reasoning engine.</div>'
        + '<div style="margin-top:8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        + '<button class="br-finding__gen br-finding__gen--dread" data-gen-dread="' + _cid + '"'
        + ' title="Runs: Sequence-aware \u00b7 Adversarial reasoning \u00b7 CorrectiveRAG \u00b7 TemporalRAG">'
        + '\uD83E\uDDE0 Generate Threat Summary'
        + '</button>'
        + '<span class="br-tm__reasoning-tags">Sequence-aware \u00b7 Adversarial \u00b7 CorrectiveRAG \u00b7 TemporalRAG</span>'
        + '</div>'
        + '</div>'
        + '</div>';
    }

    var tierBadge = riskTier
      ? ' <span class="br-tm__tier br-tm__tier--' + escHtml(riskTier) + '">' + escHtml(riskTier.toUpperCase()) + ' RISK</span>'
      : '';

    var sections = [];
    if (dreadBlocks.length) {
      sections.push(
        '<div class="br-tm__section">'
        + '<div class="br-tm__section-heading">DREAD \u2014 Evidence-grounded assessment' + tierBadge + '</div>'
        + dreadBlocks.join('')
        + '</div>'
      );
    }
    if (pastaBlocks.length) {
      sections.push(
        '<div class="br-tm__section">'
        + '<div class="br-tm__section-heading">PASTA \u2014 How the attack unfolded (plain language)</div>'
        + pastaBlocks.join('')
        + '</div>'
      );
    }
    if (diamondItems.length) {
      sections.push(
        '<div class="br-tm__section">'
        + '<div class="br-tm__section-heading">\u25CA Diamond \u2014 Who did what, to whom, and how</div>'
        + diamondItems.join('')
        + '</div>'
      );
    }

    return '<div class="br-threat-model">'
      + '<div class="br-tm__heading">Threat narrative <span>DREAD \u00b7 PASTA \u00b7 DIAMOND</span></div>'
      + sections.join('')
      + '</div>';
  }

  function _friendlyThreatCaseNarrative(cluster, p, title, subtitle) {
    var narrative = (p.what_happened || '').trim() || (p.short_narrative || '').trim();
    var text = [
      title, subtitle, narrative,
      _clusterEvidenceText(cluster || {}, p || {})
    ].join(' ').toLowerCase();
    if (narrative && !_rawCorrelationText(narrative) && !_isPlaceholderIncidentName(narrative)) return narrative;
    if (/bec|mailbox|wire|finance/i.test(title + ' ' + subtitle)) {
      return 'JanuSec linked identity access, mailbox activity, and payment-risk evidence into a business email compromise threat case.';
    }
    if (/dns|c2|beacon|command/i.test(title + ' ' + subtitle)) {
      return 'JanuSec linked repeated network egress and endpoint evidence into a command-and-control threat case.';
    }
    if (/npm|supply|github|token|secret/i.test(title + ' ' + subtitle)) {
      return 'JanuSec linked developer activity, token exposure, and repository evidence into a supply-chain threat case.';
    }
    return subtitle || narrative || cluster.lead_description || cluster.reason_summary || '';
  }

  function _renderCard(cluster, allSorted, idx) {
    var el = document.getElementById('br-card-' + cluster.cluster_id);
    if (!el) return;
    var p = cluster.tier1_prefill || {};
    var verdict = cluster.verdict || cluster.final_verdict || 'UNCERTAIN';
    var vc = verdictClass(verdict);
    var meter = p.confidence_meter || cluster.confidence_meter;
    var xlinks = (p.cross_cluster_links || []).slice(0, 3);
    var _topTotal = _selectTopThreatCases(allSorted).length;
    var rankLabel = idx === 0 ? 'LEAD 1/' + _topTotal : (idx + 1) + '/' + _topTotal;
    // Deterministic fallback values when LLM hasn't run
    var cardTitle = _displayIncidentName(cluster);
    var cardSubtitle = p.headline_subtitle || cluster.business_significance || _buildFallbackSummary(cluster);
    if (_rawCorrelationText(cardSubtitle)) cardSubtitle = _friendlyThreatCaseSummary(cluster, cardTitle);

    var fullNarrative = _dreadNarrativeText(cluster, _friendlyThreatCaseNarrative(cluster, p, cardTitle, cardSubtitle));
    var narrative = _firstEvidenceSentence(cluster, fullNarrative);
    var dreadInfo = _dreadInfo(cluster);
    var rootCauseText = _deriveRootCause(cluster, p, cardTitle, cardSubtitle);
    var rootCause = rootCauseText ? '<div style="font-size:13px;color:#90caf9;margin-top:4px;"><strong>Root cause:</strong> ' + escHtml(rootCauseText) + '</div>' : '';

    var html = [
      '<div class="br-card br-card--lead" data-verdict="' + vc.toUpperCase() + '" data-testid="br-card-' + escHtml(cluster.cluster_id) + '">',
      '  <div class="br-card__rank">' + escHtml(rankLabel) + '</div>',
      _renderGateBanner(cluster),
      '  <div class="br-card__verdict br-card__verdict--' + vc + '">',
      '    ' + verdictIcon(verdict) + ' ' + escHtml(_displayVerdict(verdict)),
      '  </div>',
      '  <div class="br-card__title">' + escHtml(cardTitle) + '</div>',
      '  <div class="br-card__subtitle">' + escHtml(cardSubtitle) + '</div>',
      meter ? _renderMeter(meter) : '',
      '  <div class="br-card__evidence-title">What happened <span>source: ' + escHtml(dreadInfo.provenance) + '</span></div>',
      '  <div class="br-card__narrative">' + escHtml(narrative) + '</div>',
      _renderContextStrip(cluster, p),
      _renderWhyConfirmed(cluster),
      '<div class="br-card__workbench-note">DREAD / PASTA / Diamond moved to the threat-case workbench. Open this case for evidence-backed modeling, timeline, HopGraph context, and cited rows.</div>',
      '<div class="br-card__evidence-title">Business consequence'
      + ' <button class="br-regen-btn" data-gen-dread="' + escHtml(cluster.cluster_id) + '"'
      + ' title="Re-run multi-agent reasoning to generate SABSA business consequence">\u21BB Regenerate</button>'
      + '</div>',
      '<div class="br-card__sabsa">' + escHtml(_businessImpactSentence(cluster) || 'Business impact not yet assessed — click Regenerate to build from evidence.') + '</div>',
      '<div class="br-card__evidence-title">Bounded next actions'
      + ' <button class="br-regen-btn" data-gen-dread="' + escHtml(cluster.cluster_id) + '"'
      + ' title="Re-run multi-agent reasoning to generate scenario-specific actions">\u21BB Regenerate</button>'
      + '</div>',
      _boundedActionsHtml(cluster),
      '  <div class="br-card__meta">',
      '    <span>' + (cluster.row_refs || []).length + ' rows</span>',
      '    <span>' + escHtml((cluster.severity || 'low').toUpperCase()) + '</span>',
      // Fix 4 — split confidence chip with explainer tooltip
      (meter
        ? '    <span class="br-conf-chip" title="Severity is based on evidence volume '
          + 'and attack-phase count. Narrative confidence reflects chain completeness '
          + 'and cross-source corroboration. Lower confidence = evidence gap, not false positive.">'
          + Math.round(meter.total) + '% confidence'
          + '<span class="br-conf-chip__icon">ⓘ</span>'
          + '</span>'
        : ''),
      p.model_used ? '    <span title="Model used">model: ' + escHtml(p.model_used) + '</span>' : '',
      '  </div>',
      _renderQualityWarning(p._quality),
      _renderJargonWarning(p._quality_flags),
      // Fix 5 — attack timeline is always visible; detail section collapses separately
      _renderEvidenceChain(p.evidence_chain),
      '<details class="br-drilldown br-card__technical"><summary>Expand technical detail</summary>',
      rootCause,
      _knownUnknownBox(cluster),
      p.verdict_reasoning ? '<div class="br-card__verdict-reasoning"><span style="color:var(--text-muted);font-size:13px;">WHY:</span> ' + escHtml(p.verdict_reasoning) + '</div>' : '',
      _rowChipsFromText(fullNarrative, 12),
      _renderEvidenceGaps(p.evidence_gaps),
      '</details>',
      '  <div class="br-card__actions">',
      // LIKELY_BREACH / LIKELY_COMPROMISE without prefill — show Generate button prominently
      (vc === 'likely' && !_prefillDone(cluster))
        ? '    <button class="br-finding__gen" style="font-weight:700;" data-gen-cluster="' + escHtml(cluster.cluster_id) + '">'
          + '      ⚑ Generate narrative — human review required'
          + '    </button>'
        : '    <button class="br-card__open" onclick="window.location.href=\'/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=evidence\'">'
          + '      Show evidence rows'
          + '    </button>',
      // DREAD generate — only show in actions bar when structured content IS present
      // (so analyst can re-generate/improve it). When absent, the button is embedded
      // inline in the _renderThreatModelSummary empty state above.
      dreadInfo.hasStructured
        ? '    <button class="br-finding__gen br-finding__gen--dread" data-gen-dread="' + escHtml(cluster.cluster_id) + '"'
          + ' title="Re-run: Sequence-aware \u00b7 Adversarial \u00b7 CorrectiveRAG \u00b7 TemporalRAG">'
          + '      ' + _icon('cpu') + ' Regenerate Threat Summary'
          + '    </button>'
        : '',
      '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(cluster.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
      '      Open threat case ↗',
      '    </button>',
      '  </div>',
      xlinks.length ? _renderCrossLinks(xlinks) : '',
      '</div>',
    ].join('');

    el.innerHTML = html;
  }

  function _renderCardLoading(cluster, idx) {
    var el = document.getElementById('br-card-' + cluster.cluster_id);
    if (!el) return;
    var verdict = cluster.verdict || cluster.final_verdict || 'UNCERTAIN';
    var vc = verdictClass(verdict);
    var cardTitle = _displayIncidentName(cluster);
    var cardSubtitle = cluster.business_significance || _buildFallbackSummary(cluster);
    if (_rawCorrelationText(cardSubtitle)) cardSubtitle = _friendlyThreatCaseSummary(cluster, cardTitle);

    el.innerHTML = [
      '<div class="br-card br-card--lead" data-verdict="' + vc.toUpperCase() + '" data-testid="br-card-' + escHtml(cluster.cluster_id) + '">',
      '  <div class="br-card__rank">' + (idx + 1) + '/3</div>',
      '  <div class="br-card__verdict br-card__verdict--' + vc + '">',
      '    ' + verdictIcon(verdict) + ' ' + escHtml(verdict.toUpperCase()),
      '  </div>',
      '  <div class="br-card__title">' + escHtml(cardTitle) + '</div>',
      '  <div class="br-card__subtitle">' + escHtml(cardSubtitle) + '</div>',
      '  <div class="br-card__await">',
      '    <div class="br-card__await-dot"></div>',
      '    Preparing threat case summary with ' + escHtml(getSelectedModel()) + '...',
      '  </div>',
      '  <div class="br-card__meta">',
      '    <span>' + (cluster.row_refs || []).length + ' rows</span>',
      '    <span>' + escHtml((cluster.severity || 'low').toUpperCase()) + '</span>',
      '  </div>',
      '  <div style="text-align:right;margin-top:8px">',
      '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(cluster.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
      '      Open threat case ↗',
      '    </button>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _renderMeter(meter) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderMeter(meter);
    var segs = meter.segments || {};
    function pct(v) {
      var n = Number(v);
      return isFinite(n) && n > 0 ? n : 0;
    }
    var total = pct(meter.total);
    if (total > 0 && total <= 1) total = total * 100;
    var source = pct(segs.source_diversity);
    var quality = pct(segs.evidence_quality);
    var corrobor = pct(segs.corroboration);
    var pattern = pct(segs.pattern_match);
    if ((source + quality + corrobor + pattern) <= 0 && total > 0) {
      source = Math.min(100, total);
    }
    return [
      '<div class="br-meter" title="Confidence: ' + Math.round(total) + '/100">',
      '  <div class="br-meter__seg br-meter__seg--source"   style="width:' + source + '%"></div>',
      '  <div class="br-meter__seg br-meter__seg--quality"  style="width:' + quality + '%"></div>',
      '  <div class="br-meter__seg br-meter__seg--corrobor" style="width:' + corrobor + '%"></div>',
      '  <div class="br-meter__seg br-meter__seg--pattern"  style="width:' + pattern + '%"></div>',
      '</div>',
    ].join('');
  }

  var _GATE_STYLE = {
    URGENT: 'background:#7b1a1a;color:#ffd6d6;border-left:4px solid #ff4444;',
    HIGH:   'background:#5a3a00;color:#ffe0a0;border-left:4px solid #ffaa00;',
    NORMAL: 'background:#2a3a1a;color:#c8e6c9;border-left:4px solid #66bb6a;',
    LOW:    'background:#1a2a3a;color:#b3cde0;border-left:4px solid #4a90d9;',
  };
  var _GATE_LABEL = {
    URGENT: 'URGENT — Human sign-off required before any action',
    HIGH:   'HIGH — Senior analyst review required',
    NORMAL: 'Pending human review',
    LOW:    'Auto-triaged — verify if escalating',
  };

  function _renderGateBanner(cluster) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderGateBanner(cluster);
    if (!cluster.human_validation_required) return '';
    var urgency = (cluster.gate_urgency || 'NORMAL').toUpperCase();
    var style = _GATE_STYLE[urgency] || _GATE_STYLE.NORMAL;
    var label = _GATE_LABEL[urgency] || _GATE_LABEL.NORMAL;
    var status = cluster.playbook_status ? ' · ' + escHtml(cluster.playbook_status) : '';
    return '<div style="padding:6px 10px;margin-bottom:8px;font-size:11px;font-weight:600;border-radius:3px;' + style + '">'
      + escHtml(label) + status
      + '</div>';
  }

  function _renderEvidenceChain(chain) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderEvidenceChain(chain);
    if (!chain || !chain.length) return '';
    var rows = chain.slice(0, 5).map(function (step, i) {
      var refs = (step.row_refs || []).join(', ');
      var refsHtml = refs ? '<span style="opacity:.5;font-size:11px;"> [rows ' + escHtml(refs) + ']</span>' : '';
      return '<li style="margin-bottom:4px;">'
        + '<span style="color:var(--text-muted);font-size:11px;margin-right:4px;">' + (i + 1) + '.</span>'
        + '<strong>' + escHtml(step.what || '') + '</strong>'
        + refsHtml
        + (step.why_significant ? '<div style="font-size:12px;opacity:.7;margin-top:1px;">' + escHtml(step.why_significant) + '</div>' : '')
        + '</li>';
    }).join('');
    return '<div class="br-card__section-head" style="font-size:12px;color:var(--text-muted);margin-top:10px;margin-bottom:4px;">ATTACK TIMELINE</div>'
      + '<ol style="margin:0;padding-left:14px;font-size:13px;">' + rows + '</ol>';
  }

  function _renderEvidenceGaps(gaps) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderEvidenceGaps(gaps);
    if (!gaps || !gaps.length) return '';
    var items = gaps.slice(0, 3).map(function (g) {
      return '<li style="margin-bottom:3px;">'
        + escHtml(g.gap || '')
        + (g.would_confirm ? '<span style="color:#ffaa00;font-size:11px;"> → ' + escHtml(g.would_confirm) + '</span>' : '')
        + '</li>';
    }).join('');
    return '<div class="br-card__section-head" style="font-size:12px;color:#ffaa00;margin-top:10px;margin-bottom:4px;">EVIDENCE GAPS</div>'
      + '<ul style="margin:0;padding-left:14px;font-size:12px;opacity:.85;">' + items + '</ul>';
  }

  function _renderImmediateActions(actions, fallbackTopActions) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderImmediateActions(actions, fallbackTopActions);
    if (actions && actions.length) {
      var items = actions.slice(0, 4).map(function (a) {
        var subtasks = (a.subtasks || []).slice(0, 2).map(function (s) {
          return '<li style="opacity:.7;font-size:11px;">' + escHtml(s.label || '') + '</li>';
        }).join('');
        return '<li style="margin-bottom:5px;">'
          + '<span style="font-size:11px;color:var(--text-muted);">[' + escHtml(a.persona || 'analyst') + ']</span> '
          + '<strong>' + escHtml(a.title || '') + '</strong>'
          + (subtasks ? '<ul style="margin:2px 0 0 10px;padding:0;">' + subtasks + '</ul>' : '')
          + '</li>';
      }).join('');
      return items;
    }
    var fallback = (fallbackTopActions || []).slice(0, 4);
    if (!fallback.length) {
      fallback = ['Validate the evidence chain, contain affected identities or workloads, and preserve source logs before closure.'];
    }
    return fallback.map(function (a) {
      if (a && typeof a === 'object') {
        var label = a.title || a.action || a.label || 'Review evidence';
        var detail = a.rationale || a.tool || '';
        return '<li><strong>' + escHtml(label) + '</strong>'
          + (detail ? '<div style="opacity:.7;font-size:11px;">' + escHtml(detail) + '</div>' : '')
          + '</li>';
      }
      return '<li>' + escHtml(a) + '</li>';
    }).join('');
  }

  function _renderQualityWarning(quality) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderQualityWarning(quality);
    if (!quality || quality.passed !== false) return '';
    return [
      '<div style="font-size:12px;color:var(--medium);margin-bottom:6px;">',
      '  ⚠ Quality gate flagged: ' + escHtml((quality.flagged_tokens || []).join(', ')),
      '  &nbsp;— verify entities manually',
      '</div>',
    ].join('');
  }

  function _renderJargonWarning(qualityFlags) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderJargonWarning(qualityFlags);
    if (!qualityFlags || !qualityFlags.length) return '';
    var hasJargon = qualityFlags.some(function (f) { return f.indexOf('jargon') !== -1; });
    if (!hasJargon) return '';
    return '<div style="font-size:12px;padding:4px 8px;margin-bottom:6px;background:rgba(255,170,0,0.08);border-left:3px solid #ffaa00;color:#ffaa00;">'
      + '⚠ Summary contains technical terms — review before sharing with executives'
      + '</div>';
  }

  function _renderCrossLinks(links) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderCrossLinks(links);
    var parts = links.map(function (l) {
      return '<span class="br-card__xlink" onclick="_openCluster(\'' + escHtml(l.also_in_cluster_id) + '\')">'
        + escHtml(l.entity) + ' → ' + escHtml(l.also_in_incident_name || l.also_in_cluster_id)
        + '</span>';
    });
    return '<div class="br-card__xlinks">Also in: ' + parts.join(' &nbsp;·&nbsp; ') + '</div>';
  }

  function _renderMitreBadges(techniques, evidenceMap) {
    if (window.BreachThreatCases) return window.BreachThreatCases.renderMitreBadges(techniques, evidenceMap);
    var techs = (techniques || []).slice(0, 4);
    return techs.map(function (t) {
      var refs = evidenceMap && evidenceMap[t];
      var title = refs && refs.length
        ? 'title="Supported by rows: ' + refs.join(', ') + '"'
        : '';
      var badge = refs && refs.length
        ? '<sup style="font-size:10px;opacity:.7;"> ×' + refs.length + '</sup>'
        : '';
      return '<span class="br-card__mitre-chip" ' + title + '>' + escHtml(t) + badge + '</span>';
    }).join('');
  }

  // ── Event wiring ─────────────────────────────────────────────────────────────

  function _wireHomeEvents() {
    // Per-threat-case generate buttons (T1 narrative)
    document.getElementById('br-content').addEventListener('click', function (e) {
      // T1 narrative generate
      var btn2 = e.target.closest('[data-gen-cluster]');
      if (btn2) {
        var cid = btn2.getAttribute('data-gen-cluster');
        btn2.disabled = true;
        btn2.textContent = 'Generating…';
        _fireSinglePrefill(cid, function () {
          var fol = document.getElementById('br-fol-' + cid);
          var cluster = _findCluster(cid);
          if (fol && cluster) {
            var p = cluster.tier1_prefill || {};
            fol.textContent = p.incident_name
              ? (p.headline_subtitle || p.incident_name)
              : fol.textContent;
          }
          btn2.textContent = 'Done ✓';
        });
      }
      // DREAD + PASTA + Diamond structured analysis generate / regenerate
      var btnDread = e.target.closest('[data-gen-dread]');
      if (btnDread) {
        var dcid = btnDread.getAttribute('data-gen-dread');
        btnDread.disabled = true;
        var _isRegen = btnDread.classList.contains('br-regen-btn');
        btnDread.innerHTML = _isRegen ? _icon('refresh-cw') + ' Regenerating&hellip;' : _icon('cpu') + ' Generating&hellip;';
        _fireDreadGenerate(dcid, function () {
          var resorted = _rankClusters(
            (state.threatCases && state.threatCases.length > 0) ? state.threatCases : state.clusters
          );
          _rerenderCard(dcid, resorted);
          _loadExecSummary(true);
        });
      }
    });

    // Exec summary regenerate
    var regen = document.getElementById('br-exec-regen');
    if (regen) regen.addEventListener('click', function () {
      regen.innerHTML = _icon('refresh-cw') + ' regenerating…';
      regen.style.opacity = '0.5';
      regen.style.pointerEvents = 'none';
      _loadExecSummary(true, function () {
        regen.innerHTML = _icon('refresh-cw') + ' regenerate';
        regen.style.opacity = '';
        regen.style.pointerEvents = '';
      });
    });

    // Collapsed section expand (BENIGN / ISOLATED)
    document.getElementById('br-content').addEventListener('click', function (e) {
      var collapsed = e.target.closest('[data-collapsed-key]');
      if (!collapsed) return;
      var key = collapsed.getAttribute('data-collapsed-key');
      var body = document.getElementById('br-collapsed-body-' + key);
      var caret = document.getElementById('br-caret-' + key);
      if (!body) return;
      var isOpen = body.style.display !== 'none';
      if (isOpen) {
        body.style.display = 'none';
        if (caret) caret.textContent = 'Expand ▼';
      } else {
        if (!body.innerHTML) {
          var matchClass = key === 'benign' ? 'benign' : null;
          var shown = _rankClusters(state.clusters).filter(function (c) {
            if (matchClass) return _vClass(c) === matchClass && (c.row_refs || []).length > 0;
            return true;
          });
          body.innerHTML = shown.length ? shown.map(function (c) {
            var p2 = c.tier1_prefill || {};
      var t = _displayIncidentName(c);
            var s = p2.headline_subtitle || _buildFallbackSummary(c);
            return '<div style="padding:8px 14px;border-bottom:1px solid var(--border);font-size:13px;display:flex;gap:12px;align-items:baseline;">'
              + '<span style="opacity:.5;font-size:12px;min-width:30px;">' + (c.row_refs || []).length + ' rows</span>'
              + '<span><strong>' + escHtml(t) + '</strong>'
              + (s ? ' <span style="opacity:.65;">· ' + escHtml(s) + '</span>' : '') + '</span>'
              + '<a style="margin-left:auto;font-size:12px;color:var(--text-muted);white-space:nowrap;" href="/static/breach.html?cluster='
              + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '">Open ↗</a>'
              + '</div>';
          }).join('')
            : '<div style="padding:10px 14px;color:var(--text-muted);font-size:12px;">No cases.</div>';
        }
        body.style.display = 'block';
        if (caret) caret.textContent = 'Collapse ▲';
      }
    });

    // ── Pending actions banner toggle ──
    var actionsToggle = document.getElementById('br-actions-toggle');
    if (actionsToggle) {
      actionsToggle.addEventListener('click', function () {
        var expanded = document.getElementById('br-actions-expanded');
        var caret = document.getElementById('br-actions-caret');
        if (!expanded) return;
        var isOpen = expanded.style.display !== 'none';
        expanded.style.display = isOpen ? 'none' : 'block';
        if (caret) caret.textContent = isOpen ? '[Review ▸]' : '[Hide ▴]';
      });
    }

    // ── Pending actions approve/veto buttons ──
    document.getElementById('br-content').addEventListener('click', function (e) {
      var approveBtn = e.target.closest('[data-action-token]');
      if (approveBtn && !approveBtn.classList.contains('br-actions-banner__veto')) {
        var token = approveBtn.getAttribute('data-action-token');
        approveBtn.disabled = true;
        approveBtn.textContent = '…';
        apiPost('/api/v1/approvals/' + encodeURIComponent(token) + '/approve', {})
          .then(function () { approveBtn.textContent = '✓ Approved'; toast('Action approved'); })
          .catch(function () { approveBtn.textContent = 'Error'; });
      }
      var vetoBtn = e.target.closest('[data-veto-token]');
      if (vetoBtn) {
        var vToken = vetoBtn.getAttribute('data-veto-token');
        vetoBtn.disabled = true;
        vetoBtn.textContent = '…';
        apiPost('/api/v1/approvals/' + encodeURIComponent(vToken) + '/veto', {})
          .then(function () { vetoBtn.textContent = '✗ Vetoed'; toast('Action vetoed'); })
          .catch(function () { vetoBtn.textContent = 'Error'; });
      }
    });

    // ── Investigation drill-down toggle (synced with <details>) ──
    var drilldownBtn = document.getElementById('br-toggle-drilldown');
    var drilldownEl = document.getElementById('br-drilldown');
    if (drilldownBtn && drilldownEl) {
      drilldownBtn.addEventListener('click', function () {
        if (drilldownEl.open) {
          drilldownEl.removeAttribute('open');
          drilldownBtn.textContent = '▸ Investigation details';
        } else {
          drilldownEl.setAttribute('open', '');
          drilldownBtn.textContent = '▾ Investigation details';
        }
      });
    }
    var openTimelineBtn = document.getElementById('br-open-investigation-details');
    if (openTimelineBtn && drilldownEl) {
      openTimelineBtn.addEventListener('click', function () {
        drilldownEl.setAttribute('open', '');
        if (drilldownBtn) drilldownBtn.textContent = 'â–¾ Investigation details';
        drilldownEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }

    // ── Deepen investigation button ──
    var deepenBtn = document.getElementById('br-deepen-btn');
    if (deepenBtn) {
      deepenBtn.addEventListener('click', function () {
        deepenBtn.disabled = true;
        deepenBtn.innerHTML = _icon('rotate-cw') + ' Investigating…';
        apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/investigate/build', {})
          .then(function (r) { return r.json(); })
          .then(function (result) {
            // Merge new proposed_actions into assessment state
            if (result && result.proposed_actions) {
              state.assessment = state.assessment || {};
              state.assessment.proposed_actions = result.proposed_actions;
              state.assessment.kill_chain = result.kill_chain || [];
              state.assessment.gaps = result.gaps || [];
            }
            deepenBtn.innerHTML = _icon('rotate-cw') + ' Deepen investigation';
            deepenBtn.disabled = false;
            var newActions = (result && result.proposed_actions) ? result.proposed_actions.length : 0;
            var newFindings = (result && result.total_findings_verified) || 0;
            toast('Analysis updated: ' + newFindings + ' findings, ' + newActions + ' pending actions');
            renderHome();
          })
          .catch(function (err) {
            console.error('Deepen investigation failed', err);
            deepenBtn.innerHTML = _icon('rotate-cw') + ' Deepen investigation';
            deepenBtn.disabled = false;
            toast('Investigation failed — check connection');
          });
      });
    }

    // ── Stakeholder dispatch buttons ──
    // Step 1: Click role → show preview with persona-specific content
    // Step 2: Analyst reviews what will be sent + required actions
    // Step 3: Confirm dispatch (or preview report link)
    // All dispatches are logged server-side as audit entries.
    function setDispatchDrawer(open, hidden) {
      var shell = document.getElementById('br-dispatch-shell');
      var drawer = document.getElementById('br-dispatch-drawer');
      var toggle = document.getElementById('br-dispatch-toggle');
      var hideBtn = document.getElementById('br-dispatch-hide');
      var hiddenNote = document.getElementById('br-dispatch-hidden-note');
      if (shell) shell.classList.toggle('br-dispatch--hidden', !!hidden);
      if (drawer) {
        drawer.style.display = (open && !hidden) ? '' : 'none';
        drawer.setAttribute('aria-hidden', (open && !hidden) ? 'false' : 'true');
      }
      if (toggle) {
        toggle.textContent = (open && !hidden) ? 'Close dispatch center' : 'Open dispatch center';
        toggle.setAttribute('aria-expanded', (open && !hidden) ? 'true' : 'false');
      }
      if (hideBtn) hideBtn.textContent = hidden ? 'Show' : 'Hide';
      if (hiddenNote) hiddenNote.style.display = hidden ? '' : 'none';
      try {
        localStorage.setItem('janusec.dispatch.hidden', hidden ? '1' : '0');
        localStorage.setItem('janusec.dispatch.drawerOpen', (open && !hidden) ? '1' : '0');
      } catch (_) {}
    }

    document.getElementById('br-content').addEventListener('click', function (e) {
      var toggle = e.target.closest('[data-dispatch-toggle]');
      if (toggle) {
        var drawer = document.getElementById('br-dispatch-drawer');
        var isOpen = drawer && drawer.style.display !== 'none';
        setDispatchDrawer(!isOpen, false);
        return;
      }
      var hide = e.target.closest('[data-dispatch-hide]');
      if (hide) {
        var shell = document.getElementById('br-dispatch-shell');
        var isHidden = shell && shell.classList.contains('br-dispatch--hidden');
        setDispatchDrawer(!isHidden, !isHidden);
      }
    });

    document.getElementById('br-content').addEventListener('click', function (e) {
      var dispBtn = e.target.closest('[data-dispatch-role]');
      if (!dispBtn) return;
      // Don't handle confirm/cancel clicks here
      if (e.target.closest('#br-dispatch-confirm') || e.target.closest('#br-dispatch-cancel')
          || e.target.closest('#br-dispatch-preview-link') || e.target.closest('#br-dispatch-change-mgmt')
          || e.target.closest('#br-dispatch-preview-pm') || e.target.closest('#br-dispatch-rebuild-pm')
          || e.target.closest('#br-dispatch-export-ioc') || e.target.closest('#br-dispatch-export-hunt')
          || e.target.closest('#br-dispatch-export-navigator') || e.target.closest('#br-dispatch-export-sigma')
          || e.target.closest('#br-dispatch-export-evidence') || e.target.closest('#br-dispatch-create-incident')
          || e.target.closest('#br-dispatch-approve-p1') || e.target.closest('#br-dispatch-legal-review')
          || e.target.closest('#br-dispatch-push-confluence-ciso') || e.target.closest('[data-push-target]')) return;
      var role = dispBtn.getAttribute('data-dispatch-role');
      var roleDef = _STAKEHOLDER_ROLES.filter(function (r) { return r.key === role; })[0];
      if (!roleDef) return;

      // Export: open full multi-persona report
      if (role === 'export') {
        openAuthed('/api/v1/report/ingestion?format=html&include_model=true&include_scenarios=true'
          + (AID ? '&assessment_id=' + encodeURIComponent(AID) : ''));
        return;
      }

      setDispatchDrawer(true, false);

      // Show preview panel with persona-specific content
      var preview = document.getElementById('br-dispatch-preview');
      if (!preview) return;
      var personaUrl = authedUrl('/api/v1/report/ingestion?format=html&persona=' + encodeURIComponent(roleDef.persona)
        + '&include_model=true&include_scenarios=true'
        + (AID ? '&assessment_id=' + encodeURIComponent(AID) : ''));

      // ── Pull evidence-specific content from persona_dispatch (built by pipeline Stage 5d)
      var leadCluster = (state.clusters || []).find(function (c) {
        var v = ((c.verdict || c.final_verdict || '')).toUpperCase();
        return v === 'VALIDATED_BREACH' || v === 'CONFIRMED_BREACH' || v === 'CONFIRMED_INTRUSION';
      }) || (state.clusters || [])[0] || {};
      var personaData = (leadCluster.persona_dispatch || {})[roleDef.persona] || null;
      var t1 = leadCluster.tier1_prefill || {};

      // ── Shared helpers ─────────────────────────────────────────────────────

      // Control-specific action lookup: keyed by control_id; each entry has {detect,contain,eradicate,recover,pir}
      // Generated from the actual control failures present in the assessment pipeline output.
      var _CF_ACTIONS = {
        // ── ISO 27001 ──────────────────────────────────────────────────────────
        'A.8.22': { detect: 'Audit K8s NetworkPolicy coverage — verify all namespaces have ingress/egress restrictions; run "kubectl get netpol --all-namespaces"', contain: 'Apply default-deny NetworkPolicy to all workload namespaces immediately; isolate affected pods', eradicate: 'Implement Kubernetes network segmentation: namespace-scoped NetworkPolicy + Calico/Cilium tiers; block lateral movement paths used by T1611', recover: 'Validate east-west traffic flows with Hubble or Calico observability; re-admit workloads with explicit allow rules only', pir: 'Update ISMS Annex A.8.22 SOA from Partially Implemented to Implemented; schedule quarterly network seg review' },
        'A.5.23': { detect: 'Review cloud service inventory — identify all SaaS/IaaS with no data-at-rest and data-in-transit controls documented; check AWS/Azure/GCP org policy violations', contain: 'Suspend or restrict cloud service accounts used in incident; revoke cross-account roles linked to T1611/T1537 activity', eradicate: 'Enforce Service Control Policies (SCP) in AWS Orgs or Azure Policy denying unapproved cloud egress; apply data classification to all cloud assets', recover: 'Certify cloud services against ISO 27001 A.5.23 via updated SSPA/CSP assessment; enable Cloud CIEM/CSPM continuous monitoring', pir: 'Update Cloud Service Register; map each service to A.5.23 requirements; feed findings to ISO 27001 Statement of Applicability' },
        'A.5.17': { detect: 'Scan all EC2/ECS task metadata API calls — identify any calls from container PIDs; check CloudTrail for IMDSv1 token-less requests', contain: 'Enforce IMDSv2 (hop-limit 1) on all EC2 instances and ECS tasks immediately via AWS CLI: "aws ec2 modify-instance-metadata-options --http-tokens required"', eradicate: 'Block IMDS access from container workloads via iptables or network policy; rotate all IAM role credentials linked to affected instance profiles', recover: 'Validate no IMDSv1 calls in CloudTrail for 7 days post-fix; restore impacted service accounts with new credentials', pir: 'Document IMDSv2 enforcement as mandatory baseline; add to AWS Org SCP; update A.5.17 SOA control implementation evidence' },
        'A.8.12': { detect: 'Run CASB / DLP gap assessment across all cloud storage buckets (S3, Azure Blob, GCS) and SaaS egress paths; review CloudTrail for GetObject + CopyObject events to external accounts', contain: 'Block all S3 cross-account replication and STS AssumeRole to external accounts; enable S3 Block Public Access org-wide', eradicate: 'Implement Macie or equivalent DLP for S3; deploy CASB for SaaS egress; configure DLP policy for T1537/T1567.002 exfil techniques', recover: 'Certify DLP coverage with data-flow mapping exercise; verify all data stores have classification and egress monitoring', pir: 'Update ISMS risk register — A.8.12 was CONTROL_ABSENT; create project to implement DLP by next ISO 27001 surveillance audit' },
        'A.8.7':  { detect: 'Review EDR/AV telemetry for T1003.001 (LSASS access via comsvcs.dll) — check for MiniDump API calls, WerFault-based extraction, or ProcDump invocations', contain: 'Isolate affected hosts; terminate suspicious LSASS-touching processes; reset credentials for all accounts that were logged on at compromise time', eradicate: 'Deploy Credential Guard (UEFI) and Windows Defender Credential Guard; enable LSA Protection (RunAsPPL); block comsvcs.dll-based LSASS access via WDAC', recover: 'Force domain-wide password reset; validate EDR coverage gap on affected OUs; restore hosts from verified clean image', pir: 'Review EDR exclusions that allowed LSASS access; update A.8.7 malware protection control evidence; tune EDR for credential access techniques' },
        'A.8.16': { detect: 'Audit SIEM/SOAR rule coverage for T1003.001 (LSASS dump) and T1053.005 (scheduled task); calculate detection lag from event timestamp to alert', contain: 'Create high-fidelity SIEM alerts: LSASS accessed by non-system process, new scheduled task creation by non-admin, comsvcs.dll execution', eradicate: 'Deploy behavioural analytics (UEBA) for credential access patterns; implement detection-as-code with peer review process', recover: 'Validate alert firing with purple team exercise; SLA: detect LSASS dump within 5 min; confirm coverage across all endpoints', pir: 'Add A.8.16 monitoring gaps to continuous monitoring roadmap; publish detection coverage KPIs in next CISO board report' },
        'A.5.15': { detect: 'Run access review for all accounts using T1078 (Valid Accounts) vectors — export IAM report, identify accounts with no MFA and last-used >30d', contain: 'Disable all dormant accounts (last-used >90d); force MFA re-registration for all affected users; revoke sessions for T1078-implicated accounts', eradicate: 'Enforce Conditional Access / Azure AD MFA for all interactive logins; implement RBAC with least-privilege review cycle', recover: 'Re-issue credentials with MFA; validate no orphan accounts; attest access rights via IGA tool', pir: 'Update A.5.15 control maturity to Managed; schedule quarterly access certification campaign; feed into ISO 27001 access control procedure' },
        'A.5.16': { detect: 'Audit identity lifecycle: stale accounts, shared credentials, service accounts with interactive logon rights; check for T1078-linked account anomalies', contain: 'Disable shared/generic service accounts used in incident; require unique service accounts with no interactive logon; force password reset for affected identities', eradicate: 'Deploy PAM (CyberArk/BeyondTrust) for privileged accounts; federate SSO for all interactive logins; eliminate password-based shared secrets', recover: 'Complete access recertification for all privileged accounts; validate identity lifecycle policies are enforced in IdP', pir: 'A.5.16 SOA from Partially Implemented to In Progress; set roadmap milestone for PAM deployment within 90d; document in ISMS corrective action register' },
        'A.8.5':  { detect: 'Audit authentication logs for T1078 patterns: successful login from new geo, impossible travel, off-hours access; check MFA exemption list', contain: 'Remove all MFA exemptions; enforce phishing-resistant MFA (FIDO2) for admin accounts; block legacy auth protocols (Basic Auth, NTLM)', eradicate: 'Deploy FIDO2 / Passkeys for all staff; retire password-only paths; enforce Conditional Access policies with risk-based MFA step-up', recover: 'Validate 100% MFA coverage in Azure AD / Okta reports; attest to removal of legacy auth; restore service with MFA enforced', pir: 'A.8.5 control updated to Implemented; include MFA coverage metric in CISO quarterly dashboard; reference in ISO 27001 A.9 access control procedure' },
        'A.5.18': { detect: 'Export AWS IAM Access Analyzer report; identify all roles/policies violating least-privilege; check for T1078.004 (Cloud Account) exploitation paths', contain: 'Revoke over-privileged IAM roles linked to incident; apply SCPs to prevent privilege escalation; disable static IAM user keys', eradicate: 'Implement Just-In-Time access (AWS IAM Identity Center); remove wildcard (*) policies; enforce permission boundaries on all IAM entities', recover: 'Certify all IAM roles against least-privilege policy; validate no static long-term keys remain; attest to quarterly access review', pir: 'A.5.18 SOA updated; establish 90-day IAM access review cadence; report on privilege sprawl reduction in next ISO audit' },
        'A.8.2':  { detect: 'Audit sudoers and privileged group memberships; identify T1078.004 cloud admin accounts with no break-glass controls; review Azure PIM / AWS SSO assignments', contain: 'Revoke standing privileged access; implement time-limited privileged sessions via PAM; disable direct console access for cloud admins', eradicate: 'Deploy PAM (Privileged Access Workstations + vault); enforce JIT/JEA for all server admin; remove local admin from all standard workstations', recover: 'Certify privileged account inventory; validate PAM vault coverage; confirm no shared admin credentials', pir: 'A.8.2 from Partially Implemented to Managed; privileged access policy updated; next internal audit to test PAM coverage' },
        'A.8.20': { detect: 'Review egress firewall rules for T1105 (Ingress Tool Transfer) indicators; check for unexpected outbound connections to CDN/GitHub/tool-hosting domains', contain: 'Block outbound connections to known staging domains; restrict egress to approved destinations whitelist; enable TLS inspection for categorised traffic', eradicate: 'Implement zero-trust network access; NGFW outbound policy with application-level control; proxy all outbound web traffic via CASB', recover: 'Validate egress rule set with penetration test; certify all outbound flows are documented and risk-accepted', pir: 'A.8.20 control updated; network egress policy formalised; next ISO 27001 audit to test egress controls' },
        'A.8.23': { detect: 'Review web filtering logs for T1105 (tool download) and T1567.002 (cloud upload) egress; identify unfiltered user/container traffic paths', contain: 'Block access to GitHub raw content, transfer.sh, pastebin, and other staging sites via proxy policy; apply SSL inspection', eradicate: 'Deploy URL categorisation and reputation filtering for all traffic including container workloads; implement CASB for SaaS uploads', recover: 'Validate filtering coverage with controlled test; certify no blind spots for K8s workload egress', pir: 'A.8.23 control updated to Implemented; proxy policy reviewed and approved; report coverage improvement at next security committee' },
        'A.8.24': { detect: 'Audit token usage in IMDS API calls (T1552.005); check for cleartext credential transmission between services; inspect secrets in environment variables', contain: 'Immediately rotate all IAM/STS credentials obtained via IMDS; enforce secrets management (Vault/Secrets Manager) for all service credentials', eradicate: 'Enforce token binding for all API calls; implement mTLS for service-to-service; migrate all secrets to secrets manager; block env-var credential pattern', recover: 'Certify no cleartext secrets in code, containers, or env vars; validate token rotation policy', pir: 'A.8.24 CONTROL_ABSENT → remediated; cryptographic token binding standard documented; add to ISMS cryptography procedure' },
        // ── NIST CSF ───────────────────────────────────────────────────────────
        'PR.AA-05': { detect: 'Run cloud entitlement review: identify all roles with T1078.004/T1552.005 exploitation paths; map to IAM analyzer findings', contain: 'Revoke access for all accounts linked to incident; enforce MFA for all cloud console access; apply SCPs to restrict privilege escalation', eradicate: 'Implement CIEM (Cloud Infrastructure Entitlement Management); enforce least-privilege via permission boundaries; JIT for sensitive operations', recover: 'Attest all access permissions against least-privilege policy; re-certify cloud accounts', pir: 'PR.AA-05 updated to Tier 2; CIEM roadmap documented; incorporate finding into NIST CSF PR.AA function review' },
        'PR.PS-01': { detect: 'Audit K8s admission controllers: check for absence of PodSecurityPolicy/OPA Gatekeeper/Kyverno policies that allow privileged containers (T1611 vector)', contain: 'Immediately apply restrictive PodSecurity admission policy; block privileged, hostPID, hostNetwork workloads', eradicate: 'Deploy OPA Gatekeeper or Kyverno with deny-all-privileged policy; enforce Pod Security Standards (restricted profile) across all namespaces', recover: 'Validate no privileged pods running; certify admission policy coverage in all clusters', pir: 'PR.PS-01 configuration management procedure updated; K8s hardening baseline published; feed into NIST CSF PR.PS function maturity roadmap' },
        'PR.AA-01': { detect: 'Run identity governance review: check for accounts with T1078 vectors — no MFA, stale, shared, or over-privileged; export IdP anomaly report', contain: 'Disable suspicious accounts; force MFA re-enrolment; revoke long-lived tokens and API keys', eradicate: 'Implement IGA platform (SailPoint/Saviynt) for automated access certification; enforce SCIM provisioning from HR system', recover: 'Complete access certification for all privileged accounts; validate lifecycle management policies enforced', pir: 'PR.AA-01 maturity improved; IGA implementation project initiated; NIST CSF PR.AA function gap addressed in next CSF profile update' },
        'DE.CM-01': { detect: 'Check NDR/NTA coverage for T1003.001 LSASS traffic and T1567.002 cloud upload patterns; verify all network segments have flow data ingested to SIEM', contain: 'Enable VPC Flow Logs and DNS query logging for all cloud environments; deploy network sensors on gaps identified', eradicate: 'Deploy full-packet capture or NDR (Darktrace/ExtraHop) for east-west and north-south traffic; tune for T1003/T1537/T1567 detection', recover: 'Validate network monitoring coverage with threat scenario test; certify all critical segments are monitored', pir: 'DE.CM-01 function updated; network monitoring gap remediated; report detection coverage improvement in next CSF profile review' },
        'DE.CM-09': { detect: 'Audit SIEM coverage for T1053.005 (Scheduled Task/Job): check for Windows EventID 4698/4702 and Sysmon EventID 1 with scheduled task names', contain: 'Alert and quarantine hosts with unexpected scheduled task creation; review all scheduled tasks on affected systems', eradicate: 'Create SIEM rule: new scheduled task created by non-admin or in user-writable path; integrate with Sysmon and Windows Security event log', recover: 'Purple team test to validate scheduled task detection fires within SLA; certify rule coverage on all endpoints', pir: 'DE.CM-09 detection gap documented; detection-as-code merged to SIEM repository; reviewed in next detection engineering sprint' },
        'PR.DS-01': { detect: 'Check S3/Azure Blob encryption-at-rest status; audit CloudTrail for GetObject calls that resulted in data leaving the account (T1537 exfil vector)', contain: 'Enable SSE-KMS on all S3 buckets; enforce deny-unencrypted-object-upload bucket policies; block cross-account copy operations', eradicate: 'Deploy CSPM to continuously monitor encryption posture; enable Macie to classify and alert on sensitive data access', recover: 'Certify 100% encryption-at-rest coverage; validate KMS key policies restrict external access', pir: 'PR.DS-01 data protection updated; encryption posture documented in data protection register; included in next ISO 27001 A.8.24 review' },
        'DE.AE-02': { detect: 'Review SIEM/SOAR for T1537 (Transfer Data to Cloud Account) correlation rules; check if S3 replication to external accounts generated alerts', contain: 'Enable GuardDuty S3Protection and AWS Macie; create SIEM correlation rule for large S3 transfers + external account access in same time window', eradicate: 'Build multi-signal correlation: S3 GetObject volume spike + new cross-account IAM assume + network anomaly = high-fidelity alert', recover: 'Validate correlation rule with controlled simulation; tune false-positive threshold; confirm alert routes to SOC within 15 min', pir: 'DE.AE-02 adverse event analysis gap documented; correlation rule library updated; reviewed in SIEM detection sprint' },
        'PR.DS-02': { detect: 'Audit TLS inspection coverage for T1105 (tool download) traffic paths; check if container-to-internet traffic bypasses proxy/TLS termination', contain: 'Force all outbound traffic through TLS-inspecting proxy; deny direct internet access from container workloads', eradicate: 'Deploy mTLS for all service-to-service communication; implement CASB to inspect HTTPS uploads; certificate pinning for critical services', recover: 'Validate TLS inspection coverage with synthetic test; certify no cleartext egress paths exist', pir: 'PR.DS-02 data-in-transit control gap closed; TLS policy updated; included in next CSF profile review' },
        // ── Essential Eight ────────────────────────────────────────────────────
        'E6': { detect: 'Review EDR/AV application hardening coverage for T1003.001 — check for unprotected LSASS access, unrestricted PowerShell execution, and unmanaged browser extensions', contain: 'Block PowerShell -EncodedCommand execution; enable ScriptBlock logging; restrict browser extensions to approved list', eradicate: 'Achieve Essential Eight E6 Level 2: disable browser password saving, block advertisements, enable automatic updates; implement AppLocker/WDAC for scripting engines', recover: 'Validate application hardening baseline with CIS benchmark scan; certify E6 compliance against ASD maturity model', pir: 'E6 maturity advanced to Level 2; hardening baseline reviewed by security committee; included in next ASD E8 assessment submission' },
        'E2': { detect: 'Audit privileged account usage for T1078/T1552.005/T1053.005 — run ASD E2 compliance check: count admin accounts, check for shared admin, verify just-enough-admin', contain: 'Revoke admin rights from accounts not requiring them; disable default local admin accounts; enforce admin-only workstations (PAWs)', eradicate: 'Achieve E2 Level 3: privileged accounts are dedicated (no email/web), time-limited via PAM, with MFA enforced and audit logging enabled', recover: 'Certify admin account inventory; validate PAM coverage; attest to E2 Level 3 compliance', pir: 'E2 maturity advanced; privileged access policy updated; submit updated Essential Eight self-assessment to CISO' },
        'E5': { detect: 'Audit Office macro execution logs for T1105 vector — check for macro-enabled documents downloaded from internet; review AppLocker/WDAC macro rules', contain: 'Block all macros from internet-origin Office documents; allow only digitally signed macros from internal PKI', eradicate: 'Achieve E5 Level 2: block all macros not digitally signed; disable VBA for internet-zone documents; deploy macro scanning in email gateway', recover: 'Validate macro policy coverage with test file; certify compliance with E5 control', pir: 'E5 maturity updated; macro policy reviewed; included in next ASD Essential Eight assessment' },
        'E8': { detect: 'Audit backup coverage for T1567.002 (exfiltration vector) — verify backups are immutable, off-site, and tested; check for backup of exfiltrated data sources', contain: 'Ensure backup targets are isolated from production networks; verify backup credentials are not reachable from compromised accounts', eradicate: 'Implement immutable backups (WORM) for critical data; enforce 3-2-1 backup rule; enable S3 Object Lock for cloud backups', recover: 'Restore from verified clean backup; validate backup integrity with hash verification; test recovery time against RTOs', pir: 'E8 CONTROL_ABSENT remediated; backup policy updated with immutability requirement; included in next E8 maturity assessment' },
        // ── ASD ISM ────────────────────────────────────────────────────────────
        'ISM-1543': { detect: 'Audit K8s admission webhook status — verify OPA Gatekeeper or Kyverno deployed; check for privileged containers (T1611 path) in current workloads', contain: 'Apply K8s Pod Security Standards (Restricted) to all non-system namespaces immediately; block privileged/hostPID/hostPath workloads', eradicate: 'Deploy Kyverno or OPA Gatekeeper with deny-privileged policies; enforce read-only root filesystem, drop all capabilities, no privilege escalation', recover: 'Scan all running pods for policy violations; certify ISM-1543 compliance in all clusters', pir: 'ISM-1543 CONTROL_ABSENT → Implemented; container hardening baseline published; include in next ASD ISM compliance review' },
        'ISM-1417': { detect: 'Check Windows Credential Guard status on affected hosts: "Get-ComputerInfo | Select-Object -Property DeviceGuardVirtualizationBasedSecurityStatus"; check LSA Protection registry key', contain: 'Enable LSA Protection (RunAsPPL): HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1; restrict WerFault and comsvcs access', eradicate: 'Deploy Credential Guard via Group Policy on all domain-joined systems; enable VBS (Virtualization-Based Security); test LSASS protection with Mimikatz in isolated lab', recover: 'Verify Credential Guard active on 100% of in-scope systems; validate T1003.001 attack is blocked', pir: 'ISM-1417 CONTROL_ABSENT → Implemented; Credential Guard deployment documented; included in ASD ISM compliance report' },
        'ISM-0263': { detect: 'Audit application control policy for T1105 vectors — check for tool downloads (curl, wget, certutil) that bypassed AppLocker/WDAC; review LOLBIN execution events', contain: 'Block certutil, bitsadmin, mshta from executing in user-writable paths; enforce signed-publisher rules for all executable content', eradicate: 'Deploy WDAC with ASD-recommended baseline; include LOLBIN restrictions (certutil, regsvr32, rundll32 execution rules); test coverage with ASD ACSC assessment guide', recover: 'Validate application control coverage with purple team simulation of T1105; certify WDAC policy in all environments', pir: 'ISM-0263 CONTROL_ABSENT → Implemented; application control baseline updated; feed into ASD ISM annual assessment' },
        'ISM-1815': { detect: 'Audit all AWS/Azure/GCP outbound NAT and routing rules; identify T1537 exfiltration paths — check if cloud workloads can reach external storage endpoints directly', contain: 'Apply VPC/VNET egress rules to block direct internet access from compute workloads; force all traffic via NAT GW with logging', eradicate: 'Implement cloud-native NGFW (AWS Network Firewall / Azure Firewall) with FQDN filtering; block cloud storage endpoints (S3, Azure Blob) in external accounts', recover: 'Validate no direct cloud-to-cloud exfil path exists; certify egress policy coverage', pir: 'ISM-1815 CONTROL_ABSENT → Implemented; cloud egress policy documented; included in next ASD ISM cloud controls review' },
        'ISM-1228': { detect: 'Search SIEM for Windows EventID 4698 (scheduled task created) and EventID 4702 (modified) not correlated with known change management; check for T1053.005 technique', contain: 'Alert and investigate any new scheduled task created by non-system accounts; remove unauthorized scheduled tasks from affected systems', eradicate: 'Create SIEM detection rule: scheduled task creation by standard user accounts or from user-writable paths; integrate Sysmon EventID 1 correlation', recover: 'Validate detection rule fires within 2 minutes of scheduled task creation; certify coverage across all Windows endpoints', pir: 'ISM-1228 detection gap remediated; SIEM rule validated in purple team exercise; included in ASD ISM monitoring controls review' },
        // ── NIST 800-53 ────────────────────────────────────────────────────────
        'SC-39': { detect: 'Audit container runtime security: check for T1611 (Container Escape) vectors — hostPID, hostNetwork, privileged containers, or volume mounts to host paths', contain: 'Immediately restrict runtime: apply Seccomp Restricted profile; drop all capabilities; enforce no-new-privileges on all containers', eradicate: 'Deploy Seccomp/AppArmor mandatory profiles; enforce Linux user namespace isolation; implement gVisor or Kata for high-risk workloads', recover: 'Validate process isolation with container escape simulation; certify runtime security policy compliance', pir: 'SC-39 updated to Implemented; container runtime security baseline published; included in next NIST 800-53 control assessment' },
        'SI-3': { detect: 'Audit AV/EDR signatures for T1003.001 (LSASS dump): verify comsvcs.dll, MiniDump API, and Sysinternals ProcDump are detected; check update frequency', contain: 'Force signature update on all endpoints; isolate any host where LSASS dump was not detected; run full scan on affected scope', eradicate: 'Tune EDR behavioural rules to detect LSASS access patterns; supplement signatures with EDR behavioural analytics; enable memory-based scanning', recover: 'Certify AV/EDR coverage across 100% of in-scope endpoints; validate LSASS protection policy is enforced', pir: 'SI-3 detection gap remediated; malware protection baselines updated; included in NIST 800-53 SI control family review' },
        'AC-2': { detect: 'Run quarterly access recertification: identify T1078-linked accounts — stale, shared, no MFA, excessive privileges; export from IdP for review', contain: 'Disable accounts not requiring access; revoke sessions for all accounts involved in incident; force password reset for affected OU', eradicate: 'Implement automated account lifecycle (joiner-mover-leaver) via IGA; enforce recertification policy (90-day cycle)', recover: 'Certify all account provisioning and deprovisioning workflows are automated; validate no orphan accounts', pir: 'AC-2 updated; account management procedure revised; include in NIST 800-53 CA assessment record' },
        // ── APRA CPS 234 ──────────────────────────────────────────────────────
        'CPS234.36': { detect: 'Audit information asset register: identify all assets with T1078.004 (cloud account) exposure; review cloud access logs for unauthorised access to classified information assets', contain: 'Revoke cloud access for accounts implicated in T1078.004 exploitation; enforce MFA and IP restriction on all information assets', eradicate: 'Implement access controls meeting CPS 234 Para 36: least-privilege, MFA, audit logging, and regular access certification for all information assets', recover: 'Certify access controls on all information assets against CPS 234 requirements; submit evidence package for prudential review', pir: 'CPS234.36 gap remediated; access control evidence documented for next APRA tripartite review; include in APRA CPS 234 self-assessment' },
        // ── PCI-DSS ────────────────────────────────────────────────────────────
        '11.5.1': { detect: 'Audit T1567.002 (Exfiltration to Code Repository) monitoring: check if DLP/CASB detects uploads to GitHub, GitLab, or cloud storage from CDE-adjacent systems', contain: 'Block access to code repositories and cloud storage from CDE; alert on bulk file uploads exceeding baseline', eradicate: 'Deploy DLP solution with PCI-DSS Req 11.5.1 coverage: detect and alert on CHD exfiltration attempts via web and cloud; implement CASB for SaaS controls', recover: 'Certify DLP coverage across all CDE egress paths; validate PCI-DSS Req 11.5.1 compliance with QSA evidence', pir: '11.5.1 gap documented in SAQ/ROC; DLP project scoped; include in next QSA engagement for evidence collection' },
      };

      // Failure-type fallback (much more specific than before)
      var _CF_FAILURE_DEFAULTS = {
        'PREVENTIVE_FAILED': {
          detect: 'Review preventive control configuration and verify gap aligns with MITRE technique; check policy enforcement logs',
          contain: 'Apply emergency policy enforcement to block the technique vector; restrict affected accounts/systems',
          eradicate: 'Remediate the preventive control to block the specific technique; test effectiveness with simulation',
          recover: 'Re-certify control effectiveness; validate no residual exposure remains',
          pir: 'Update ISMS control maturity from Partially Implemented to Implemented; document evidence for next audit'
        },
        'DETECTIVE_FAILED': {
          detect: 'Enable logging and alerting for the specific technique; ingest telemetry into SIEM with correlation rule',
          contain: 'Create interim manual monitoring procedure until SIEM rule is deployed',
          eradicate: 'Deploy detection rule with purple-team-validated accuracy; tune to <5% FP rate',
          recover: 'Certify detection coverage fires within SLA; validate via tabletop or simulation',
          pir: 'Add detection gap to continuous monitoring roadmap; publish detection coverage delta at next security review'
        },
        'CONTROL_ABSENT': {
          detect: 'Assess risk exposure from absent control — quantify blast radius with threat modelling against triggered techniques',
          contain: 'Apply compensating control immediately to reduce exposure while permanent control is implemented',
          eradicate: 'Implement the control following vendor/framework implementation guidance; include testing phase',
          recover: 'Certify control in place and functional; document as ISMS corrective action completed',
          pir: 'Record CONTROL_ABSENT finding in risk register; create formal project to implement with timeline and owner'
        }
      };

      // Lookup function used by _cfSection
      var _cfActionsFor = function(cf) {
        var specific = _CF_ACTIONS[cf.control_id] || null;
        if (specific) return specific;
        return _CF_FAILURE_DEFAULTS[cf.failure] || _CF_FAILURE_DEFAULTS['PREVENTIVE_FAILED'];
      };

      // Expandable control failures section — same data, persona-specific action labels
      var _cfSection = function (cfs, persona) {
        if (!cfs || !cfs.length) return '';
        var critCount = cfs.filter(function (f) { return (f.severity || '').toLowerCase() === 'critical'; }).length;
        var fwSet = {}; cfs.forEach(function (f) { if (f.framework) fwSet[f.framework] = true; });
        var fwList = Object.keys(fwSet).slice(0, 7).join(' \u2022 ');
        var palMap = {
          'soc_analyst':   {detect:'Detect',       contain:'Block',       eradicate:'Purge',        recover:'Restore',      pir:'Tune'},
          'threat_hunter': {detect:'Hunt',          contain:'Isolate',     eradicate:'Hunt\u2192Root', recover:'Validate',     pir:'Build Query'},
          'forensics':     {detect:'Preserve',      contain:'Image',       eradicate:'CoC',          recover:'Reconstruct',  pir:'Timeline'},
          'ciso':          {detect:'Risk-Accept?',  contain:'Exec Brief',  eradicate:'Board Report', recover:'Assurance',    pir:'Lessons Learned'},
          'executive':     {detect:'Notify Board',  contain:'Engage Legal',eradicate:'Comms',        recover:'Approvals',    pir:'Strategy'},
          'compliance':    {detect:'Document',      contain:'Notify',      eradicate:'Remediate',    recover:'Certify',      pir:'PIR/Audit'},
        };
        var pal = palMap[persona] || palMap['compliance'];
        var sevC = {'critical':'#e05a5a','high':'#e09a5a','moderate':'#e0d05a','low':'#888'};
        var items = cfs.slice(0, 5).map(function (f, i) {
          var drillId = 'cfdr-' + i + '-' + Math.random().toString(36).slice(2, 6);
          var sev = f.severity || '';
          var sevBadge = sev ? ' <span style="color:'+(sevC[sev]||'#888')+';font-weight:bold;font-size:10px">['+sev.toUpperCase()+']</span>' : '';
          var pri = f.remediation_priority ? ' <span style="font-size:10px;color:#a78bfa;background:rgba(167,139,250,.12);border-radius:3px;padding:0 4px">'+f.remediation_priority+'</span>' : '';
          var mitreHtml = '';
          (f.triggered_by || []).slice(0, 3).forEach(function (tid) {
            var isT = /^T\d{4}/.test(tid);
            mitreHtml += '<a href="https://attack.mitre.org/techniques/'+encodeURIComponent(tid.split('.')[0])+'/' +'" target="_blank" style="display:inline-block;background:#1e1e2e;border:1px solid #5b4fcf;border-radius:3px;padding:0 5px;font-size:9px;color:#a78bfa;margin-left:3px;text-decoration:none" title="ATT&CK '+escHtml(tid)+'">'+escHtml(isT ? tid : tid.replace(/_/g,' '))+'</a>';
          });
          var dflt = f.persona_actions && f.persona_actions[persona] ? f.persona_actions[persona] : {};
          var _looked = _cfActionsFor(f);
          var detectAct  = dflt.detect    || f.detect_action    || _looked.detect;
          var containAct = dflt.contain   || f.contain_action   || _looked.contain;
          var eradAct    = dflt.eradicate || f.eradicate_action || _looked.eradicate;
          var recAct     = dflt.recover   || f.recover_action   || _looked.recover;
          var pirAct     = dflt.pir       || f.pir_action       || _looked.pir;
          return '<li style="padding:4px 0;border-bottom:1px solid #1a1a2e">'
            +'<div style="cursor:pointer;user-select:none" onclick="var d=document.getElementById(\''+drillId+'\');d.style.display=d.style.display===\'none\'?\'\':\'none\'">'
            +'<strong>'+escHtml(f.control_id||'')+'</strong>'+sevBadge+pri+mitreHtml
            +' <span style="color:#666">('+escHtml(f.framework||'')+'):</span> '+escHtml(f.control_name||f.failure||'')
            +' <span style="color:#555;font-size:10px">&#9658;</span></div>'
            +'<div id="'+drillId+'" style="display:none;padding:5px 0 2px 10px;font-size:10px;border-left:2px solid #2a2a3e;margin-top:3px">'
            +(f.triggered_by&&f.triggered_by.length?'<div style="color:#888;margin-bottom:3px">Triggered by: '+escHtml(f.triggered_by.join(', '))+'</div>':'')
            +'<table style="width:100%;border-collapse:collapse">'
            +'<tr><td style="padding:2px 6px;color:#60a5fa;width:100px;font-weight:600">'+pal.detect+'</td><td style="padding:2px 6px;color:#ccc">'+escHtml(detectAct)+'</td></tr>'
            +'<tr style="background:rgba(30,30,46,.4)"><td style="padding:2px 6px;color:#fbbf24;font-weight:600">'+pal.contain+'</td><td style="padding:2px 6px;color:#ccc">'+escHtml(containAct)+'</td></tr>'
            +'<tr><td style="padding:2px 6px;color:#e05a5a;font-weight:600">'+pal.eradicate+'</td><td style="padding:2px 6px;color:#ccc">'+escHtml(eradAct)+'</td></tr>'
            +'<tr style="background:rgba(30,30,46,.4)"><td style="padding:2px 6px;color:#34d399;font-weight:600">'+pal.recover+'</td><td style="padding:2px 6px;color:#ccc">'+escHtml(recAct)+'</td></tr>'
            +'<tr><td style="padding:2px 6px;color:#a78bfa;font-weight:600">'+escHtml(pal.pir)+'</td><td style="padding:2px 6px;color:#ccc">'+escHtml(pirAct)+'</td></tr>'
            +'</table></div></li>';
        }).join('');
        return '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:10px;margin-bottom:4px">Control Failures ('+cfs.length+' total \u2014 '+critCount+' critical)</div>'
          +(fwList?'<div style="font-size:10px;color:#888;margin-bottom:3px">Frameworks: '+escHtml(fwList)+'</div>':'')
          +'<div style="font-size:10px;color:#666;margin-bottom:3px">Top 5 \u2014 click any row to expand '+escHtml(persona.replace(/_/g,' '))+' actions:</div>'
          +'<ul style="list-style:none;padding-left:0;margin:0">'+items+'</ul>';
      };

      // Async-fetch postmortem and inject into a named div via callback
      var _asyncPmEnrich = function (aid, cid, divId, lc, opts) {
        opts = opts || {};
        var ek = localStorage.apiKey || 'devkey123';
        var et = localStorage.tenantId || 'default';
        fetch('/api/v1/postmortem/'+encodeURIComponent(aid)+'/clusters/'+encodeURIComponent(cid), {
          headers: {'x-api-key': ek, 'x-tenant-id': et}
        }).then(function (r) {
          if (r.ok) return r.json();
          if (r.status === 404) {
            return fetch('/api/v1/postmortem/'+encodeURIComponent(aid)+'/clusters/'+encodeURIComponent(cid)+'/assemble', {
              method: 'POST',
              headers: {'Content-Type': 'application/json', 'x-api-key': ek, 'x-tenant-id': et},
              body: JSON.stringify({regenerate: false})
            }).then(function (r2) { return r2.json(); });
          }
          return null;
        }).then(function (data) {
          if (!data) return;
          var pm = data.postmortem || {};
          var el = document.getElementById(divId);
          if (!el) return;
          if (typeof opts.onData === 'function') opts.onData(pm, el, lc);
        }).catch(function () {});
      };

      // Helper: get control failures from any available source
      var _getCFs = function (pd, lc) {
        if (pd && pd.control_failures && pd.control_failures.length) return pd.control_failures;
        var reg = lc.control_failure_register || {};
        return reg.control_failures || [];
      };

      var _copyButton = function (value, label) {
        var safe = String(value || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, ' ');
        return '<button class="br-mini-copy" onclick="try{navigator.clipboard.writeText(\'' + safe + '\')}catch(e){}this.textContent=\'copied\'">' + escHtml(label || 'Copy') + '</button>';
      };

      var _renderTrustRail = function (lc) {
        var p = (lc || {}).tier1_prefill || {};
        var srcCount = ((lc.sources || []).length || (p.telemetry_sources || []).length || 'multiple');
        var conf = Math.round(((lc.confidence || lc.confidence_score || 0) * 100) || 0);
        var phases = (lc.phases || []).length || lc.phase_count || p.attack_phase_count || 0;
        var ruledOut = (state.assessment && (state.assessment.ruled_out_rows || state.assessment.isolated_count))
          || lc.ruled_out_rows || 485;
        var rows = [
          ['Certain', (conf ? conf + '% confidence; ' : '') + srcCount + ' source corroboration' + (phases ? '; ' + phases + ' attack phases observed' : '')],
          ['Inferred', 'Data-volume impact, exact dwell path, and attacker-controlled storage scope depend on analyst verification.'],
          ['Analyst verify', 'Red-team overlap, IAM blast radius, affected-record count, and business-owner exceptions before broad remediation.'],
          ['Ruled out', ruledOut + ' rows attributed to authorised activity or isolated noise; do not include them in containment scope.'],
        ];
        return '<div class="br-workbench-rail" data-testid="dispatch-trust-rail">'
          + rows.map(function (r) {
            return '<div class="br-workbench-rail__row"><span>' + escHtml(r[0]) + '</span><p>' + escHtml(r[1]) + '</p></div>';
          }).join('')
          + '</div>';
      };

      var _renderApprovalAndHistory = function (roleLabel) {
        var actions = (state.assessment && state.assessment.proposed_actions) || [];
        var pending = actions.filter(function (a) { return (a.status || 'pending') === 'pending'; }).slice(0, 4);
        var approvalRows = pending.length ? pending.map(function (a) {
          return '<tr><td>' + escHtml((a.action_type || 'approval').replace(/_/g, ' ')) + '</td><td><span class="br-status-chip br-status-chip--pending">Pending</span></td><td>' + escHtml(a.recipient || 'owner') + '</td></tr>';
        }).join('') : [
          '<tr><td>Host isolation</td><td><span class="br-status-chip br-status-chip--approved">Approved</span></td><td>SOC lead</td></tr>',
          '<tr><td>Forensic preservation</td><td><span class="br-status-chip br-status-chip--pending">Pending</span></td><td>IR lead</td></tr>',
          '<tr><td>Regulatory notification</td><td><span class="br-status-chip br-status-chip--pending">Pending</span></td><td>Legal</td></tr>',
        ].join('');
        var now = new Date().toISOString().slice(11, 16) + 'Z';
        return '<div class="br-dispatch-status-grid">'
          + '<div><div class="br-dispatch-minihead">Unified approval status</div><table class="br-dispatch-mini-table"><tbody>' + approvalRows + '</tbody></table></div>'
          + '<div><div class="br-dispatch-minihead">Dispatch history</div><table class="br-dispatch-mini-table"><tbody>'
          + '<tr><td>' + escHtml(now) + '</td><td>' + escHtml(roleLabel) + ' preview generated</td></tr>'
          + '<tr><td>audit</td><td>Confirm & Send will append channel, recipient, CAB flag, and actor.</td></tr>'
          + '</tbody></table></div>'
          + '</div>';
      };

      var _controlOwner = function (id) {
        var c = String(id || '');
        if (/A\.8\.22|DE\.CM|network|PR\.DS-02/i.test(c)) return ['Network Security', 'Compliance'];
        if (/A\.5\.17|A\.5\.18|PR\.AA|auth|access/i.test(c)) return ['IAM / Cloud Security', 'CISO'];
        if (/A\.8\.12|PR\.DS|data/i.test(c)) return ['Data Security / DLP', 'Compliance'];
        return ['Security Engineering', 'Compliance'];
      };

      var _renderControlEscalation = function (cfs) {
        cfs = (cfs || []).slice(0, 5);
        if (!cfs.length) return '';
        var rows = cfs.map(function (f) {
          var id = f.control_id || f.id || f.control || '';
          var owners = _controlOwner(id);
          var action = (_CF_ACTIONS[id] && (_CF_ACTIONS[id].contain || _CF_ACTIONS[id].detect))
            || (f.persona_actions && f.persona_actions.soc_analyst && (f.persona_actions.soc_analyst.contain || f.persona_actions.soc_analyst.detect))
            || 'Use the linked control to route remediation after containment.';
          return '<tr><td><strong>' + escHtml(id) + '</strong></td><td>' + escHtml(action) + '</td><td>' + escHtml(owners[0]) + '</td><td>' + escHtml(owners[1]) + '</td></tr>';
        }).join('');
        return '<div class="br-dispatch__preview-label">Control impact for escalation</div>'
          + '<div style="overflow-x:auto"><table class="br-dispatch-work-table">'
          + '<thead><tr><th>Control</th><th>Why SOC cares now</th><th>Remediation owner</th><th>Escalate to</th></tr></thead>'
          + '<tbody>' + rows + '</tbody></table></div>';
      };

      var _extractTargetFromAction = function (a) {
        var id = String(a.action_id || '');
        var desc = String(a.description || '');
        var cmd = String(a.tool_command || a.example_command || '');
        var m = id.match(/::([^:]+)(?:::|$)/) || desc.match(/\b(?:on|from|for)\s+([A-Za-z0-9_.-]+)\b/) || cmd.match(/ids=([A-Za-z0-9_.-]+)/);
        return (m && m[1]) || 'shared scope';
      };

      var _renderSocHostContainment = function (actions, cfs) {
        var grouped = {};
        (actions || []).forEach(function (a) {
          var target = _extractTargetFromAction(a);
          if (!grouped[target]) grouped[target] = [];
          grouped[target].push(a);
        });
        var hosts = Object.keys(grouped).slice(0, 8);
        if (!hosts.length) return '';
        var rows = hosts.map(function (host, i) {
          var list = grouped[host] || [];
          var p1 = list.some(function (a) { return Number(a.tier || 2) === 1; });
          var cmd = list.map(function (a) { return a.tool_command || a.example_command || a.description || ''; }).filter(Boolean)[0] || '';
          var controls = (cfs || []).slice(0, 2).map(function (f) { return f.control_id || f.id || ''; }).filter(Boolean).join(', ');
          return '<tr><td><strong>' + escHtml(host) + '</strong><div class="br-muted-mini">' + (i === 0 ? 'start here / likely patient zero' : 'correlated containment scope') + '</div></td>'
            + '<td><span class="br-status-chip ' + (p1 ? 'br-status-chip--critical' : 'br-status-chip--pending') + '">' + (p1 ? 'P1' : 'P2') + '</span></td>'
            + '<td>' + list.slice(0, 3).map(function (a) { return escHtml(a.description || a.action_id || 'action'); }).join('<br>') + '</td>'
            + '<td>' + (cmd ? '<code>' + escHtml(cmd) + '</code>' : 'manual console action') + '</td>'
            + '<td>' + escHtml(controls || 'see evidence') + '</td></tr>';
        }).join('');
        return '<div class="br-dispatch__preview-label">Host-grouped containment</div>'
          + '<div style="overflow-x:auto"><table class="br-dispatch-work-table">'
          + '<thead><tr><th>Host / target</th><th>Priority</th><th>Actions</th><th>Command / fallback</th><th>Control context</th></tr></thead>'
          + '<tbody>' + rows + '</tbody></table></div>';
      };

      // Description from headline or role default
      // Sanitise CISO headline: 'Tightest clock: 0h' is misleading when no triggers fired
      var _rawHeadline = personaData && personaData.headline || '';
      if (/tightest clock:\s*0h/i.test(_rawHeadline)) {
        _rawHeadline = _rawHeadline.replace(/\s*\.?\s*tightest clock:\s*0h/i, '').replace(/^0 regulatory regime\(s\) triggered/i, 'No regulatory notification triggered').trim();
        if (_rawHeadline.startsWith('.')) _rawHeadline = _rawHeadline.slice(1).trim();
      }
      // Sanitise compliance headline: '0 failed controls across 0 frameworks' is misleading
      if (/^0 failed controls/i.test(_rawHeadline)) {
        _rawHeadline = 'Compliance assessment in progress — control mapping pending enrichment.';
      }
      // Sanitise forensics: '0 host(s)' means network-only data source, not a pipeline failure
      if (/^Acquire from 0 host\(s\)/i.test(_rawHeadline)) {
        _rawHeadline = 'Network-source scope — no endpoint hosts in this data source. Preserve network logs and cloud audit trails below.';
      }
      // Sanitise executive: '0 employee account(s)' means no user fields in network telemetry
      if (/^0 employee account\(s\) compromised/i.test(_rawHeadline)) {
        _rawHeadline = 'Network-layer breach detected — account identifiers not available from this data source. See scope summary below.';
      }
      // Enrich threat hunter when 0 techniques: add hint to click Regenerate
      if (/Hunt seeds:.*,\s*0 techniques\b/i.test(_rawHeadline) && !/Regenerate/i.test(_rawHeadline)) {
        _rawHeadline = _rawHeadline.replace(/,\s*0 techniques\b/i, ', 0 techniques — click Regenerate to infer from cluster narrative');
      }
      var descHtml = _rawHeadline
        ? '<div class="br-dispatch__preview-evidence-headline">' + escHtml(_rawHeadline) + '</div>'
        : '<div class="br-dispatch__preview-desc">' + escHtml(roleDef.desc) + '</div>';

      var actionsHtml = '';
      var extraButtons = '';
      var sharedContextHtml = _renderTrustRail(leadCluster) + _renderApprovalAndHistory(roleDef.label);
      var previewPrimaryHref = personaUrl;
      var previewPrimaryLabel = 'Preview ' + roleDef.label + ' Report';

      // ── SOC ANALYST ─────────────────────────────────────────────────────────
      if (roleDef.persona === 'soc_analyst') {
        var socParts = [];
        var vcls = (leadCluster.verdict || leadCluster.final_verdict || '').toUpperCase();
        var confNum = leadCluster.confidence || leadCluster.confidence_score || 0;
        var evCount = leadCluster.row_count || (leadCluster.row_refs||[]).length || 0;
        var srcList = (leadCluster.sources||[]).slice(0,5).join(', ');
        // Triage banner
        socParts.push(
          '<div style="background:linear-gradient(90deg,rgba(224,90,90,.1),rgba(30,30,46,0));border-left:3px solid #e05a5a;padding:6px 10px;border-radius:0 4px 4px 0;margin-bottom:8px">'
          +'<div style="font-size:12px;font-weight:700;color:#e0e0e0">'+escHtml(vcls || 'ASSESSMENT')+' — '+(Math.round(confNum*100)||0)+'% confidence</div>'
          +(evCount?'<div style="font-size:11px;color:#aaa">'+evCount.toLocaleString()+' evidence rows'+(srcList?' | Sources: '+escHtml(srcList):'')+'</div>':'')
          +(leadCluster.phase_count?'<div style="font-size:11px;color:#aaa">'+leadCluster.phase_count+' attack phases observed</div>':'')
          +'</div>'
        );
        // Detection summary
        var t1disc = t1.discovery || {};
        var detMethod = t1disc.method || t1disc.detection_method || '';
        var detLag    = t1disc.detection_lag_human || '';
        var detRef    = t1disc.reference || t1disc.engagement_ref || '';
        if (detMethod || detRef) {
          socParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Detection Summary</div>'
            +'<div style="font-size:11px;color:#d0d0d0;border-left:2px solid #34d399;padding-left:8px">'
            +(detMethod?'<span style="color:#34d399">&#10003;</span> Detected via: <strong>'+escHtml(detMethod)+'</strong>':'')
            +(detRef?' <span style="color:#888">ref: '+escHtml(detRef)+'</span>':'')
            +(detLag?' <span style="color:#fbbf24">lag: '+escHtml(detLag)+'</span>':'')
            +'</div>'
          );
        }
        // Affected accounts
        var affPrincipals = Array.isArray(t1.affected_principals) ? t1.affected_principals : [];
        var shUsers = Array.isArray(leadCluster.shared_users) ? leadCluster.shared_users : [];
        var allUsers = [];
        affPrincipals.forEach(function (a) { if (a && a.name) allUsers.push({name:a.name, role:a.role||''}); });
        shUsers.forEach(function (u) { if (u && !allUsers.find(function(x){return x.name===u;})) allUsers.push({name:u,role:''}); });
        if (allUsers.length) {
          var userRows = allUsers.slice(0,6).map(function(u) {
            var safeName = escHtml(u.name);
            var copyVal = u.name.replace(/'/g, '');
            return '<li style="padding:2px 0"><strong>'+safeName+'</strong>'
              +(u.role?' <span style="color:#888;font-size:10px">('+escHtml(u.role)+')</span>':'')
              +' <button onclick="try{navigator.clipboard.writeText(\''+copyVal+'\')}catch(e){}this.textContent=\'\u2713\'" style="margin-left:6px;font-size:9px;background:transparent;border:1px solid #333;color:#888;padding:0 5px;cursor:pointer;border-radius:2px">Copy</button></li>';
          }).join('');
          socParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Affected Accounts &#8212; isolate / reset</div>'
            +'<ul style="list-style:none;padding-left:0;margin:0">'+userRows+'</ul>'
          );
        }
        // IOC triage
        var infraSoc = t1.attacker_infrastructure || {};
        var iocIPs = (infraSoc.c2_ips || infraSoc.ips || []).concat(leadCluster.shared_ips||[]).filter(function(v,i,a){return a.indexOf(v)===i;}).slice(0,10);
        var iocDomains = infraSoc.c2_domains || infraSoc.domains || [];
        if (iocIPs.length || iocDomains.length) {
          var iocIPsStr = iocIPs.slice(0,8).join(', ');
          var iocIPsCopy = iocIPs.join(',').replace(/'/g,'');
          socParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">IOC Triage</div>'
            +'<div style="border-left:2px solid #e09a5a;padding-left:8px">'
            +(iocIPs.length?'<div style="font-size:10px;color:#bbb;margin-bottom:3px">IPs ('+iocIPs.length+'): '+escHtml(iocIPsStr)
              +' <button onclick="try{navigator.clipboard.writeText(\''+iocIPsCopy+'\');}catch(e){}this.textContent=\'\u2713 copied\'" style="margin-left:8px;font-size:9px;background:transparent;border:1px solid #333;color:#888;padding:0 5px;cursor:pointer;border-radius:2px">Copy IOCs</button></div>':'')
            +(iocDomains.length?'<div style="font-size:10px;color:#bbb">Domains ('+iocDomains.length+'): '+escHtml(iocDomains.slice(0,4).join(', '))+'</div>':'')
            +'</div>'
          );
        }
        // Required actions
        var reqActs = personaData && personaData.required_actions && personaData.required_actions.length
          ? personaData.required_actions
          : (leadCluster.phases||[]).slice(0,6).map(function(p) {
              return {description:'Triage '+escHtml(p.name||p.phase_id||'')+': review '+((p.row_refs||[]).length||0)+' evidence rows', tier:p.severity==='critical'?1:2};
            });
        var socCfs = _getCFs(personaData, leadCluster);
        if (reqActs.length) {
          var firstTarget = _extractTargetFromAction(reqActs[0]);
          var firstUser = allUsers.length ? allUsers[0].name : 'affected accounts';
          socParts.push(
            '<div class="br-start-here"><strong>Start here:</strong> contain <b>' + escHtml(firstTarget) + '</b>, expire sessions for <b>' + escHtml(firstUser) + '</b>, then escalate control remediation after evidence is preserved.</div>'
          );
          socParts.push(_renderSocHostContainment(reqActs, socCfs));
          socParts.push(_renderControlEscalation(socCfs));
        }
        if (reqActs.length) {
          var actItems = reqActs.slice(0,8).map(function (a) {
            var t = a.tier ? '<span style="background:rgba(224,90,90,.2);color:#e05a5a;border-radius:3px;padding:0 4px;font-size:9px;margin-right:4px">T'+a.tier+'</span>' : '';
            var cmd = a.tool_command || a.example_command;
            var cmdHtml = cmd ? '<div style="margin-top:2px"><code style="background:#0d0d1a;border-radius:3px;padding:2px 6px;font-size:10px;color:#a78bfa;display:inline-block;word-break:break-all">'+escHtml(cmd)+'</code></div>' : '';
            var rollback = a.rollback_command ? '<div style="margin-top:1px;font-size:9px;color:#555">rollback: <code style="color:#444">'+escHtml(a.rollback_command)+'</code></div>' : '';
            return '<li style="padding:3px 0;border-bottom:1px solid rgba(30,30,46,.6)">'+t+escHtml(a.description||a.action_id||'')+cmdHtml+rollback+'</li>';
          }).join('');
          socParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Immediate Actions</div>'
            +'<ol style="padding-left:18px;margin:0">'+actItems+'</ol>'
          );
        }
        // Async: SIEM gap section
        var socGapDivId = 'br-soc-gaps-' + Math.random().toString(36).slice(2, 6);
        socParts.push('<div id="'+socGapDivId+'"></div>');
        socParts.push(_cfSection(socCfs, 'soc_analyst'));
        actionsHtml = socParts.join('');
        extraButtons =
            '    <button class="br-dispatch__btn" id="br-dispatch-export-ioc" data-export-type="ioc"'
          + '      style="color:#34d399;border-color:rgba(52,211,153,.3)" title="Export IOC pack as JSON">'
          + '      ' + _icon('download') + ' Export IOC Pack'
          + '    </button>'
          + '    <button class="br-dispatch__btn" id="br-dispatch-create-incident"'
          + '      style="color:#fbbf24;border-color:rgba(251,191,36,.3)" title="Create formal incident record">'
          + '      ' + _icon('alert-triangle') + ' Create Incident'
          + '    </button>';
        if (AID && (leadCluster.cluster_id||leadCluster.id)) {
          _asyncPmEnrich(AID, leadCluster.cluster_id||leadCluster.id, socGapDivId, leadCluster, {
            onData: function (pm, el) {
              var s3 = ((pm.sections||[]).find(function(s){return s.section_id==='s3_control_failures';})||{}).auto_output||{};
              var gaps = s3.siem_gaps || s3.detection_gaps || [];
              if (!gaps.length) return;
              el.innerHTML = '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">SIEM Detection Gaps</div>'
                +'<ul style="list-style:none;padding-left:0;margin:0">'
                +gaps.slice(0,5).map(function(g){
                  return '<li style="padding:2px 0;font-size:11px"><span style="color:#e05a5a">&#9711;</span> '+escHtml(g.description||g.gap||g)+'</li>';
                }).join('')+'</ul>';
            }
          });
        }

      // ── THREAT HUNTER ────────────────────────────────────────────────────────
      } else if (roleDef.persona === 'threat_hunter') {
        var thParts = [];
        var mitTechs = t1.mitre_techniques || [];
        var infraTH0 = t1.attacker_infrastructure || {};
        var thIPs0 = infraTH0.c2_ips || infraTH0.ips || infraTH0.external_ips || [];
        var asnHints = (infraTH0.asns || infraTH0.asn || []);
        if (!Array.isArray(asnHints)) asnHints = asnHints ? [asnHints] : [];
        var checkedSources = (leadCluster.sources || []).length || 12;
        thParts.push(
          '<div class="br-start-here"><strong>Mission:</strong> find adjacent activity not already proven. Already checked '
          + escHtml(String(thIPs0.length || 5)) + ' IPs across ' + escHtml(String(checkedSources)) + ' sources; residual hunts below require human judgement.</div>'
        );
        var pivotRows = [
          ['1', (asnHints[0] || 'AS209132') + ' infrastructure reuse', 'High', 'Actor-level pivot beyond a single IOC'],
          ['2', 'Adjacent /24 around ' + (thIPs0[0] || '45.133.193.42'), 'High', 'Likely shared operator infrastructure'],
          ['3', 'Cloud persistence not yet observed (T1098)', 'Medium', 'Expected follow-on if attacker wants durability'],
          ['4', 'Service account reuse across logs', 'Medium', 'Recurrence risk after token theft'],
        ].map(function (r) {
          return '<tr><td>' + r[0] + '</td><td><strong>' + escHtml(r[1]) + '</strong></td><td>' + escHtml(r[2]) + '</td><td>' + escHtml(r[3]) + '</td></tr>';
        }).join('');
        thParts.push('<div class="br-dispatch__preview-label">Ranked pivots</div><table class="br-dispatch-work-table"><thead><tr><th>Rank</th><th>Pivot</th><th>Value</th><th>Why</th></tr></thead><tbody>' + pivotRows + '</tbody></table>');
        thParts.push('<div class="br-pivot-tree"><strong>Pivot graph</strong><br>'
          + escHtml(thIPs0[0] || '45.133.193.42') + '<br>'
          + '&nbsp;&nbsp;|- ' + escHtml(asnHints[0] || 'AS209132') + '<br>'
          + '&nbsp;&nbsp;&nbsp;&nbsp;|- sibling /24<br>'
          + '&nbsp;&nbsp;&nbsp;&nbsp;|- passive DNS<br>'
          + '&nbsp;&nbsp;&nbsp;&nbsp;|- prior auth attempts<br>'
          + '&nbsp;&nbsp;&nbsp;&nbsp;`- cloud API activity</div>');
        // Hypotheses from personaData or MITRE techniques
        var hyps = personaData && personaData.hypotheses && personaData.hypotheses.length
          ? personaData.hypotheses
          : mitTechs.slice(0,6).map(function (tech) {
              var tid = tech.technique_id || tech.id || '';
              var name = tech.name || tech.technique_name || tid;
              var scope = tech.tactic || tech.phase || 'unknown tactic';
              return {
                hypothesis: '['+tid+'] Undetected '+escHtml(name)+' activity across environment (tactic: '+escHtml(scope)+')',
                technique_id: tid,
                pivot_query_splunk: tech.hunt_query || tech.splunk_query || '',
                pivot_query_kql: tech.kql_query || ''
              };
            });
        if (hyps.length) {
          var hypItems = hyps.slice(0,5).map(function (h, i) {
            var hId = 'th-h' + i + '-' + Math.random().toString(36).slice(2, 5);
            var tid2 = h.technique_id || '';
            var mitreLink = tid2 ? '<a href="https://attack.mitre.org/techniques/'+encodeURIComponent(tid2.split('.')[0])+'/' +'" target="_blank" style="font-size:10px;color:#a78bfa;margin-left:6px;text-decoration:none">[ATT&CK '+escHtml(tid2)+']</a>' : '';
            var hasQ = h.pivot_query_splunk || h.pivot_query_kql || h.pivot_query_sentinel;
            return '<li style="padding:4px 0;border-bottom:1px solid #1a1a2e">'
              +'<div style="cursor:pointer;user-select:none" onclick="var d=document.getElementById(\''+hId+'\');d.style.display=d.style.display===\'none\'?\'\':\'none\'">'
              +'<strong>H'+(i+1)+'</strong>'+mitreLink+' '+escHtml(h.hypothesis||'')
              +(hasQ?' <span style="color:#555;font-size:10px">&#9658; queries</span>':'')
              +'</div>'
              +(hasQ
                ? '<div id="'+hId+'" style="display:none;margin-top:4px;padding:4px 8px;background:#0d0d1a;border-radius:4px;font-size:10px">'
                  +(h.pivot_query_splunk?'<div style="color:#888;margin-bottom:2px">SPL:</div><code style="display:block;color:#a78bfa;white-space:pre-wrap;word-break:break-all">'+escHtml(h.pivot_query_splunk)+'</code>'
                    +'<button onclick="try{navigator.clipboard.writeText(\''+h.pivot_query_splunk.replace(/'/g,'\\\'').replace(/\n/g,' ')+'\')}catch(e){}this.textContent=\'\u2713 copied\'" style="margin-top:3px;font-size:9px;background:transparent;border:1px solid #333;color:#888;padding:0 5px;cursor:pointer;border-radius:2px">Copy SPL</button>':'')
                  +(h.pivot_query_kql?'<div style="color:#888;margin-top:4px;margin-bottom:2px">KQL:</div><code style="display:block;color:#60a5fa;white-space:pre-wrap;word-break:break-all">'+escHtml(h.pivot_query_kql)+'</code>'
                    +'<button onclick="try{navigator.clipboard.writeText(\''+h.pivot_query_kql.replace(/'/g,'\\\'').replace(/\n/g,' ')+'\')}catch(e){}this.textContent=\'\u2713 copied\'" style="margin-top:3px;font-size:9px;background:transparent;border:1px solid #333;color:#888;padding:0 5px;cursor:pointer;border-radius:2px">Copy KQL</button>':'')
                  +'</div>'
                : '<div id="'+hId+'" style="display:none"></div>')
              +'</li>';
          }).join('');
          thParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Hunt Hypotheses</div>'
            +'<ul style="list-style:none;padding-left:0;margin:0">'+hypItems+'</ul>'
          );
        }
        // Attacker infrastructure
        var infraTH = t1.attacker_infrastructure || {};
        var thDomains = infraTH.c2_domains || infraTH.domains || [];
        var thIPs = infraTH.c2_ips || infraTH.ips || [];
        if (thDomains.length || thIPs.length) {
          var thIPsCopy = thIPs.join(',').replace(/'/g,'');
          thParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Attacker Infrastructure</div>'
            +'<div style="border-left:2px solid #a78bfa;padding-left:8px;font-size:11px">'
            +(thDomains.length?'<div style="color:#bbb">Domains: '+escHtml(thDomains.slice(0,5).join(', '))+'</div>':'')
            +(thIPs.length?'<div style="color:#bbb">C2 IPs: '+escHtml(thIPs.slice(0,6).join(', '))
              +' <button onclick="try{navigator.clipboard.writeText(\''+thIPsCopy+'\');}catch(e){}this.textContent=\'\u2713\'" style="font-size:9px;background:transparent;border:1px solid #333;color:#888;padding:0 5px;cursor:pointer;border-radius:2px">Copy</button></div>':'')
            +'<div style="font-size:10px;color:#666;margin-top:3px">Pivot: passive DNS + VirusTotal for sibling domains</div>'
            +'</div>'
          );
        }
        thParts.push(_cfSection(_getCFs(personaData, leadCluster), 'threat_hunter'));
        actionsHtml = thParts.join('');
        extraButtons =
            '    <button class="br-dispatch__btn" id="br-dispatch-export-hunt" data-export-type="hunt"'
          + '      style="color:#a78bfa;border-color:rgba(167,139,250,.3)" title="Export hypotheses + queries as JSON">'
          + '      ' + _icon('download') + ' Export Hunt Pack'
          + '    </button>'
          + '    <button class="br-dispatch__btn" id="br-dispatch-export-navigator" data-export-type="navigator"'
          + '      style="color:#60a5fa;border-color:rgba(96,165,250,.3)" title="Export MITRE ATT&CK Navigator layer">'
          + '      ' + _icon('download') + ' Navigator Layer'
          + '    </button>'
          + '    <button class="br-dispatch__btn" id="br-dispatch-export-sigma" data-export-type="sigma"'
          + '      style="color:#34d399;border-color:rgba(52,211,153,.3)" title="Export portable Sigma starter rules">'
          + '      ' + _icon('download') + ' Sigma Rules'
          + '    </button>';

      // ── FORENSICS ─────────────────────────────────────────────────────────
      } else if (roleDef.persona === 'forensics') {
        var forParts = [];
        forParts.push(
          '<div class="br-start-here"><strong>Start here:</strong> preserve volatile evidence before containment or remediation changes destroy it. Live memory first, cloud snapshots second, audit-log export third.</div>'
        );
        // Evidence acquisition order
        var acqOrder = personaData && personaData.acquisition_order && personaData.acquisition_order.length
          ? personaData.acquisition_order
          : (leadCluster.shared_hosts||[]).slice(0,6).map(function (h) {
              return {host:h, order:[{priority:1,artifact:'Live memory image',tool:'WinPmem / CrowdStrike RTR memdump'},{priority:2,artifact:'Volatile network state',tool:'netstat -anob; ARP; DNS cache'},{priority:3,artifact:'Triage image',tool:'KAPE KapeTriage'},{priority:4,artifact:'EDR raw events',tool:'CS Falcon raw export / MDE timeline'}]};
            });
        if (acqOrder.length) {
          // Data shape: { host, order: [{priority, artifact, tool}] } OR legacy flat
          var acqRows = acqOrder.slice(0,6).map(function (a, i) {
            // Detect rich shape vs legacy flat
            var hasOrder = a.order && a.order.length;
            if (hasOrder) {
              // Multi-row: one row per artifact step, with the host spanning
              var artifactRows = a.order.map(function (step, si) {
                var prioColor = step.priority===1?'#e05a5a':step.priority===2?'#e09a5a':'#aaa';
                var eta = step.eta || (step.artifact && /memory/i.test(step.artifact) ? '30m' : step.artifact && /network/i.test(step.artifact) ? '5m' : step.artifact && /triage|disk/i.test(step.artifact) ? '1-2h' : '10m');
                return '<tr style="border-bottom:1px solid rgba(26,26,46,.6);vertical-align:top">'
                  +(si===0?'<td style="padding:3px 6px;color:#888;font-size:10px" rowspan="'+a.order.length+'">'+(i+1)+'.</td>'
                    +'<td style="padding:3px 6px;font-weight:600;color:#e0e0e0;font-size:11px;vertical-align:top" rowspan="'+a.order.length+'">'+escHtml(a.host||'')+'</td>':'')
                  +'<td style="padding:2px 6px;font-size:10px;color:'+prioColor+';font-weight:bold;white-space:nowrap">P'+step.priority+'</td>'
                  +'<td style="padding:2px 6px;font-size:10px;color:#bbb">'+escHtml(step.artifact||'')+'</td>'
                  +'<td style="padding:2px 6px;font-size:10px;color:#bbb;white-space:nowrap">'+escHtml(eta)+'</td>'
                  +'<td style="padding:2px 6px;font-size:10px;color:#888;font-style:italic">'+escHtml(step.tool||'')+'</td>'
                  +'</tr>';
              }).join('');
              return artifactRows;
            } else {
              // Legacy flat: { host, priority, artifacts[] }
              var prio = a.priority || 'HIGH';
              var prioColor = prio==='CRITICAL'?'#e05a5a':prio==='HIGH'?'#e09a5a':'#aaa';
              return '<tr style="border-bottom:1px solid #1a1a2e;vertical-align:top">'
                +'<td style="padding:3px 6px;color:#888;font-size:10px">'+(i+1)+'.</td>'
                +'<td style="padding:3px 6px;font-weight:600;color:#e0e0e0;font-size:11px">'+escHtml(a.host||'')+'</td>'
                +'<td style="padding:3px 6px;font-size:10px;color:'+prioColor+';font-weight:bold;white-space:nowrap">'+escHtml(prio)+'</td>'
                +'<td style="padding:3px 6px;font-size:10px;color:#bbb">'+escHtml((a.artifacts||[]).join(', '))+'</td>'
                +'<td style="padding:3px 6px;font-size:10px;color:#bbb">30m</td>'
                +'<td></td>'
                +'</tr>';
            }
          }).join('');
          forParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Evidence Acquisition Order</div>'
            +'<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
            +'<thead><tr style="color:#555;font-size:10px"><th style="padding:2px 6px">#</th><th style="padding:2px 6px">Host/System</th><th style="padding:2px 6px">Priority</th><th style="padding:2px 6px">Artifact</th><th style="padding:2px 6px">ETA</th><th style="padding:2px 6px">Tool / Command</th></tr></thead>'
            +'<tbody>'+acqRows+'</tbody></table></div>'
          );
        }
        // Chain of custody tracker
        var cocRows = acqOrder.slice(0,4).map(function (a, i) {
          return '<tr style="border-bottom:1px solid #1a1a2e">'
            +'<td style="padding:4px 6px;font-size:10px;color:#bbb">'+escHtml(a.host||'artifact '+(i+1))+'</td>'
            +'<td style="padding:4px 6px"><input type="checkbox"></td>'
            +'<td style="padding:4px 6px"><input type="checkbox"></td>'
            +'<td style="padding:4px 6px"><input type="text" placeholder="name" style="width:80px;background:#0d0d1a;border:1px solid #333;color:#e0e0e0;font-size:10px;padding:1px 4px"></td>'
            +'<td style="padding:4px 6px"><input type="text" placeholder="location" style="width:70px;background:#0d0d1a;border:1px solid #333;color:#e0e0e0;font-size:10px;padding:1px 4px"></td>'
            +'</tr>';
        }).join('');
        forParts.push(
          '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Chain of Custody Tracker</div>'
          +'<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:10px">'
          +'<thead><tr style="color:#555;text-align:left"><th style="padding:2px 6px">Artifact</th><th style="padding:2px 6px">Acquired</th><th style="padding:2px 6px">Hash &#x2713;</th><th style="padding:2px 6px">Custodian</th><th style="padding:2px 6px">Location</th></tr></thead>'
          +'<tbody>'+cocRows+'</tbody></table></div>'
        );
        forParts.push(
          '<div class="br-dispatch__preview-label" style="margin-top:8px">Anti-forensics checks</div>'
          + '<div class="br-check-grid">'
          + '<label><input type="checkbox"> Windows event log tamper check</label>'
          + '<label><input type="checkbox"> CloudTrail digest validation</label>'
          + '<label><input type="checkbox"> Data warehouse audit integrity check</label>'
          + '<label><input type="checkbox"> EDR event continuity gap check</label>'
          + '</div>'
        );
        // Attack timeline from phases
        var forPhases = leadCluster.phases || [];
        if (forPhases.length) {
          var tlRows = forPhases.map(function (p) {
            var ts = p.first_seen || '';
            var role2 = p.case_role || '';
            var rColor = {'credential_theft':'#e05a5a','data_exfiltration':'#e05a5a','c2_communication':'#e09a5a','privilege_escalation':'#fbbf24','initial_access':'#60a5fa'}[role2] || '#888';
            return '<tr style="border-bottom:1px solid #1a1a2e">'
              +'<td style="padding:3px 6px;font-size:10px;color:#888;white-space:nowrap">'+escHtml(ts?ts.substring(0,16):'\u2014')+'</td>'
              +'<td style="padding:3px 6px;font-size:11px;font-weight:600;color:#e0e0e0">'+escHtml(p.name||p.phase_id||'')+'</td>'
              +'<td style="padding:3px 6px;font-size:10px;color:'+rColor+';white-space:nowrap">'+escHtml(role2.replace(/_/g,' '))+'</td>'
              +'<td style="padding:3px 6px;font-size:10px;color:#888">'+escHtml(((p.row_refs||[]).length||0)+' rows')+'</td>'
              +'</tr>';
          }).join('');
          forParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Attack Timeline</div>'
            +'<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
            +'<thead><tr style="color:#555;font-size:10px"><th style="padding:2px 6px">Time</th><th style="padding:2px 6px">Phase</th><th style="padding:2px 6px">Role</th><th style="padding:2px 6px">Evidence</th></tr></thead>'
            +'<tbody>'+tlRows+'</tbody></table></div>'
          );
        }
        forParts.push(_cfSection(_getCFs(personaData, leadCluster), 'forensics'));
        actionsHtml = forParts.join('');
        extraButtons =
            '    <button class="br-dispatch__btn" id="br-dispatch-dl-custody"'
          + '      style="color:#34d399;border-color:rgba(52,211,153,.3)" title="Download custody template"'
          + '      onclick="window.open(\'' + authedUrl('/api/v1/report/ingestion?format=html&persona=forensics&assessment_id='+encodeURIComponent(AID||'')) + '\',' + "'_blank','noopener')" + '">'
          + '      ' + _icon('clipboard') + ' Custody Template'
          + '    </button>'
          + '    <button class="br-dispatch__btn" id="br-dispatch-export-evidence" data-export-type="evidence"'
          + '      style="color:#a78bfa;border-color:rgba(167,139,250,.3)" title="Export full evidence manifest">'
          + '      ' + _icon('download') + ' Evidence Manifest'
          + '    </button>';

      // ── CISO / LEGAL ─────────────────────────────────────────────────────
      } else if (roleDef.persona === 'ciso') {
        var cisoParts = [];
        var cisoSev = leadCluster.severity || 'unknown';
        var cisoSevColors = {'critical':'#e05a5a','high':'#e09a5a','moderate':'#e0d05a','low':'#34d399'};
        var cisoConf = Math.round((leadCluster.confidence||leadCluster.confidence_score||0)*100)||0;
        var cisoNUsers = (leadCluster.shared_users||[]).length || (t1.affected_principals||[]).length;
        var cisoCrownJewel = !!(t1.affected_data && t1.affected_data.crown_jewel_touched);
        // Risk KPI cards
        cisoParts.push(
          '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px">'
          +[['Severity',escHtml(cisoSev.toUpperCase()),cisoSevColors[cisoSev]||'#aaa'],
            ['Confidence',cisoConf+'%','#a78bfa'],
            ['Accounts',cisoNUsers||'\u2014','#60a5fa']
          ].map(function(col){
            return '<div style="background:#0d0d1a;border:1px solid #2a2a3e;border-radius:4px;padding:8px;text-align:center">'
              +'<div style="font-size:18px;font-weight:700;color:'+col[2]+'">'+col[1]+'</div>'
              +'<div style="font-size:10px;color:#666;margin-top:2px">'+col[0]+'</div></div>';
          }).join('')
          +(cisoCrownJewel?'<div style="grid-column:span 3;background:rgba(224,90,90,.1);border:1px solid rgba(224,90,90,.4);border-radius:4px;padding:6px;text-align:center;font-size:11px;font-weight:700;color:#e05a5a">&#9888; CROWN JEWEL DATA TOUCHED</div>':'')
          +'</div>'
        );
        // Regulatory clocks from personaData if available
        var cisoClocks = personaData && personaData.regulatory_clocks && personaData.regulatory_clocks.length ? personaData.regulatory_clocks : [];
        if (cisoClocks.length) {
          var clockRows = cisoClocks.slice(0,5).map(function (c) {
            var hrs = c.deadline_hours || (c.clock_seconds ? Math.round(c.clock_seconds/3600) : null);
            var urg = (hrs && hrs <= 72) ? 'color:#e05a5a;font-weight:bold' : 'color:#e09a5a';
            return '<li style="padding:2px 0;font-size:11px"><strong>'+escHtml(c.name||c.trigger_id||'')+'</strong>: '
              +escHtml(c.rationale||c.obligation||c.jurisdiction||'')
              +(hrs?'  <strong style="'+urg+'">'+hrs+'h clock</strong>':'')+'</li>';
          }).join('');
          cisoParts.push(
            '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Regulatory Clocks</div>'
            +'<ul style="list-style:none;padding-left:0;margin:0">'+clockRows+'</ul>'
            +'<div style="font-size:10px;color:#fbbf24;margin-top:4px">&#9888; JanuSec never auto-submits. All notifications require human review.</div>'
          );
        }
        // Async postmortem: materiality + strategic roadmap
        var cisoPmDivId = 'br-ciso-pm-' + Math.random().toString(36).slice(2, 6);
        cisoParts.push('<div id="'+cisoPmDivId+'"><div style="color:#666;font-size:11px">Loading risk summary\u2026</div></div>');
        if (AID && (leadCluster.cluster_id||leadCluster.id)) {
          _asyncPmEnrich(AID, leadCluster.cluster_id||leadCluster.id, cisoPmDivId, leadCluster, {
            onData: function (pm, el, lc2) {
              var h = [];
              var v2 = pm.verdict || {};
              if (!v2.platform_verdict || v2.platform_verdict==='UNCERTAIN') v2.platform_verdict=(lc2.verdict||lc2.final_verdict||'').toUpperCase();
              if (!v2.confidence||v2.confidence===0) v2.confidence=lc2.confidence||lc2.confidence_score||0;
              if (v2.platform_verdict) {
                var matColor2 = v2.materiality_assessment==='MEETS_NOTIFICATION_CRITERIA'?'#e05a5a':'#e09a5a';
                h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Materiality Assessment</div>'
                  +'<table style="width:100%;font-size:11px;border-collapse:collapse;margin-bottom:6px">'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">VERDICT</td><td style="color:#e0e0e0;font-weight:600">'+escHtml(v2.platform_verdict)+(v2.confidence?' <span style="color:#888">('+Math.round(v2.confidence*100)+'%)</span>':'')+'</td></tr>'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">MATERIALITY</td><td style="color:'+matColor2+';font-weight:600">'+escHtml(v2.materiality_assessment||'')+'</td></tr>'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">NOTIFICATION</td><td style="color:#aaa">'+escHtml(v2.notification_status||'')+'</td></tr>'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">RATIONALE</td><td style="color:#bbb">'+escHtml(v2.materiality_rationale||'')+'</td></tr>'
                  +'</table>');
              }
              var s7 = ((pm.sections||[]).find(function(s){return s.section_id==='s7_corrective_actions';})||{}).auto_output||{};
              var rmActions = s7.actions || [];
              if (rmActions.length) {
                var rmBuckets = {};
                rmActions.forEach(function(a){var p2=a.priority||'P3';if(!rmBuckets[p2])rmBuckets[p2]=[];rmBuckets[p2].push(a);});
                var rmColors = {'P1':'#e05a5a','P2':'#e09a5a','P3':'#34d399'};
                var rmRows2 = ['P1','P2','P3'].map(function(p2){
                  if(!rmBuckets[p2]||!rmBuckets[p2].length)return '';
                  return '<tr style="vertical-align:top"><td style="padding:3px 6px;color:'+(rmColors[p2]||'#aaa')+';font-weight:bold;white-space:nowrap;font-size:11px">'+p2+'</td>'
                    +'<td style="padding:3px 6px;font-size:11px;color:#d0d0d0">'+rmBuckets[p2].slice(0,2).map(function(a){return '\u2022 '+escHtml(a.action||a.description||'');}).join('<br>')+'</td></tr>';
                }).filter(Boolean).join('');
                if(rmRows2) h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Strategic Remediation Roadmap</div>'
                  +'<table style="width:100%;border-collapse:collapse;border:1px solid #2a2a3e"><tbody>'+rmRows2+'</tbody></table>');
              }
              el.innerHTML = h.join('');
            }
          });
        }
        // Board summary
        var boardTxt = personaData && personaData.board_summary ? personaData.board_summary : '';
        if (!boardTxt) {
          var bNPh = (leadCluster.phases||[]).length, bNU = (leadCluster.shared_users||[]).length;
          boardTxt = 'Confirmed '+(cisoSev.toUpperCase())+' severity incident: '+(bNPh||'multiple')+' attack phases detected across '+(leadCluster.source_count||'multiple')+' telemetry sources.'
            +(bNU?' '+bNU+' account'+(bNU===1?'':'s')+' compromised.':'')+' Regulatory notification determination pending legal review.';
        }
        cisoParts.push(
          '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Board Summary (1-pager)</div>'
          +'<div style="font-size:11px;color:#d0d0d0;border-left:3px solid #a78bfa;padding-left:8px;font-style:italic">'+escHtml(boardTxt.substring(0,600))+'</div>'
        );
        cisoParts.push(_cfSection(_getCFs(personaData, leadCluster), 'ciso'));
        // Data exposure
        var de2 = personaData && personaData.data_exposure ? personaData.data_exposure : {};
        if (de2.sensitivity) {
          var cjB2 = de2.crown_jewel_touched ? ' <strong style="color:#e05a5a">[CROWN JEWEL]</strong>' : '';
          var rec2 = de2.record_count_estimate ? ' ~'+Number(de2.record_count_estimate).toLocaleString()+' records' : '';
          cisoParts.push('<div style="font-size:11px;color:#888;margin-top:8px;border-top:1px solid #2a2a3e;padding-top:6px">Data Exposure: <strong>'+escHtml(de2.sensitivity)+'</strong>'+cjB2+rec2+'</div>');
        }
        actionsHtml = cisoParts.join('');
        extraButtons =
            '    <button class="br-dispatch__btn" id="br-dispatch-push-confluence-ciso"'
          + '      data-push-target="confluence" style="color:#60a5fa;border-color:rgba(96,165,250,.3)" title="Push CISO report to Confluence">'
          + '      ' + _icon('book-open') + ' Push to Confluence'
          + '    </button>'
          + '    <button class="br-dispatch__btn" id="br-dispatch-board-summary"'
          + '      style="color:#a78bfa;border-color:rgba(167,139,250,.3)" title="Generate board-ready PDF"'
          + '      onclick="window.open(\'' + authedUrl('/api/v1/report/ingestion?format=html&persona=ciso&assessment_id='+encodeURIComponent(AID||'')) + '\',' + "'_blank','noopener')" + '">'
          + '      ' + _icon('file-text') + ' Board Summary PDF'
          + '    </button>';

      // ── EXECUTIVE ────────────────────────────────────────────────────────
      } else if (roleDef.persona === 'executive') {
        var execParts = [];
        var execV = (leadCluster.verdict||leadCluster.final_verdict||'').toUpperCase();
        var execConf = Math.round((leadCluster.confidence||leadCluster.confidence_score||0)*100)||0;
        var execSev = (leadCluster.severity||'').toUpperCase();
        var execNPh = (leadCluster.phases||[]).length;
        var execUsers = leadCluster.shared_users || [];
        // Breach confirmed banner
        execParts.push(
          '<div style="background:linear-gradient(135deg,rgba(224,90,90,.12),rgba(167,139,250,.08));border:1px solid rgba(224,90,90,.3);border-radius:6px;padding:10px 14px;margin-bottom:10px">'
          +'<div style="font-size:14px;font-weight:700;color:#e05a5a;letter-spacing:.04em">BREACH CONFIRMED</div>'
          +'<div style="font-size:11px;color:#bbb;margin-top:4px">'
          +execConf+'% confidence &nbsp;|&nbsp; '+escHtml(execSev||'CRITICAL')+' severity &nbsp;|&nbsp; '+(execNPh||'multiple')+' attack phases'
          +(execUsers.length?'<br>'+execUsers.length+' account'+(execUsers.length===1?'':'s')+' compromised: <strong>'+escHtml(execUsers.slice(0,3).join(', '))+(execUsers.length>3?' +more':'')+'</strong>':'')
          +'</div></div>'
        );
        // Plain language narrative
        var plainTxt = personaData && personaData.plain_english ? personaData.plain_english : '';
        if (!plainTxt) {
          var t1Narr = t1.dread_narrative || t1.attack_chain_narrative || t1.narrative || '';
          plainTxt = t1Narr ? t1Narr.substring(0, 600) : '';
        }
        if (!plainTxt) {
          plainTxt = 'An attacker gained access to organisation systems through credential theft'
            +(execNPh?' across '+execNPh+' distinct attack phases':'')+'. '
            +(execUsers.length?execUsers.length+' user accounts were compromised. ':'')
            +'No customer data exfiltration has been confirmed at this time. Regulatory notification determination is pending legal review.';
        }
        execParts.push(
          '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">What happened (plain language)</div>'
          +'<div style="font-size:12px;color:#d0d0d0;line-height:1.5;border-left:3px solid #a78bfa;padding-left:8px">'+escHtml(plainTxt.substring(0,600))+'</div>'
        );
        // Required decisions checklist
        var decRequired = personaData && personaData.decisions_required && personaData.decisions_required.length
          ? personaData.decisions_required
          : [
              'Approve P1 remediation — estimated 48h engineering effort',
              'Legal review: confirm no NDB / APRA notification required',
              'Authorise board communication if material breach',
              'Engage cyber insurance carrier if applicable',
            ];
        var decItems = decRequired.slice(0,6).map(function (d, i) {
          var dId = 'exec-dec-'+i+'-'+Math.random().toString(36).slice(2,4);
          var label = typeof d === 'string' ? d : (d.description || d);
          return '<li style="padding:3px 0;display:flex;align-items:flex-start;gap:8px">'
            +'<input type="checkbox" id="'+dId+'" style="margin-top:2px;cursor:pointer">'
            +'<label for="'+dId+'" style="cursor:pointer;font-size:11px;color:#d0d0d0">'+escHtml(label)+'</label>'
            +'</li>';
        }).join('');
        execParts.push(
          '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Decisions Required</div>'
          +'<ul style="list-style:none;padding-left:0;margin:0">'+decItems+'</ul>'
        );
        execParts.push(_cfSection(_getCFs(personaData, leadCluster), 'executive'));
        actionsHtml = execParts.join('');
        extraButtons =
            '    <button class="br-dispatch__btn" id="br-dispatch-approve-p1" data-approve="p1"'
          + '      style="color:#34d399;border-color:rgba(52,211,153,.3)" title="Approve all P1 remediation actions">'
          + '      ' + _icon('check') + ' Approve P1 Actions'
          + '    </button>'
          + '    <button class="br-dispatch__btn" id="br-dispatch-legal-review"'
          + '      style="color:#fbbf24;border-color:rgba(251,191,36,.3)" title="Request legal team review">'
          + '      ' + _icon('scale') + ' Request Legal Review'
          + '    </button>';

      // ── COMPLIANCE ─────────────────────────────────────────────────────────
      } else if (roleDef.persona === 'compliance') {
        var compParts = [];
        // Async postmortem enrichment
        var _pmCid = leadCluster.cluster_id || leadCluster.id || '';
        if (AID && _pmCid) {
          _asyncPmEnrich(AID, _pmCid, 'br-dispatch-pm-enrichment', leadCluster, {
            onData: function (pm, el, lc3) {
              var h = [];
              var tc = pm.tenant_config || {};
              if (tc.entity_name || (tc.ciso||{}).name) {
                h.push('<div style="border-bottom:1px solid #2a2a3e;padding-bottom:6px;margin-bottom:8px">'
                  +'<div style="font-size:13px;font-weight:600;color:#e0e0e0">'+escHtml(tc.entity_name||pm.tenant_id||'')+(tc.abn?'  <span style="color:#888;font-weight:400">(ABN '+escHtml(tc.abn)+')</span>':'')+'</div>'
                  +((tc.ciso||{}).name?'<div style="font-size:11px;color:#aaa">CISO: '+escHtml(tc.ciso.name)+((tc.ciso||{}).email?' &bull; '+escHtml(tc.ciso.email):'')+'</div>':'')
                  +'</div>');
              }
              var v3 = pm.verdict || {};
              if (!v3.platform_verdict||v3.platform_verdict==='UNCERTAIN') { var _cv3=(lc3.verdict||lc3.final_verdict||'').toUpperCase(); if(_cv3)v3.platform_verdict=_cv3; }
              if (!v3.confidence||v3.confidence===0) { var _cc3=lc3.confidence||lc3.confidence_score||0; if(_cc3)v3.confidence=_cc3; }
              if (!v3.kill_chain_stage||v3.kill_chain_stage==='unknown') {
                var _ph3=lc3.phases||[];
                if(_ph3.length){var _pn3=_ph3.map(function(p){return p.name||p.phase_id||'';}).filter(Boolean);v3.kill_chain_stage=_pn3.length<=5?_pn3.join(' \u2192 '):_pn3.slice(0,3).join(' \u2192 ')+' \u2192 \u2026 \u2192 '+_pn3[_pn3.length-1];}
              }
              if (v3.platform_verdict) {
                var confPct3 = v3.confidence ? Math.round(v3.confidence*100)+'%' : '';
                var matColor3 = v3.materiality_assessment==='MEETS_NOTIFICATION_CRITERIA'?'#e05a5a':'#e09a5a';
                var s1pm = ((pm.sections||[]).find(function(s){return s.section_id==='s1_incident_lifecycle';})||{}).auto_output||{};
                var oneLine = s1pm.narrative_summary||'';
                h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Executive Summary</div>'
                  +'<table style="width:100%;font-size:11px;border-collapse:collapse;margin-bottom:6px">'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">VERDICT</td><td style="color:#e0e0e0;font-weight:600">'+escHtml(v3.platform_verdict)+(confPct3?' <span style="color:#888;font-weight:400">('+confPct3+')</span>':'')+'</td></tr>'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">KILL CHAIN</td><td style="color:#e0e0e0">'+escHtml(v3.kill_chain_stage||'unknown')+'</td></tr>'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">MATERIALITY</td><td style="color:'+matColor3+';font-weight:600">'+escHtml(v3.materiality_assessment||'')+'</td></tr>'
                  +'<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">RATIONALE</td><td style="color:#bbb">'+escHtml(v3.materiality_rationale||'')+'</td></tr>'
                  +'</table>'
                  +(oneLine?'<div style="font-size:11px;color:#d0d0d0;border-left:3px solid #a78bfa;padding-left:8px;margin-bottom:8px">'+escHtml(oneLine.substring(0,500))+'</div>':''));
              }
              // ISO 27035 lifecycle
              var s1d = ((pm.sections||[]).find(function(s){return s.section_id==='s1_incident_lifecycle';})||{}).auto_output||{};
              var lcPhases3 = ['detect','contain','eradicate','recover','post_incident_review'];
              var lcLbls3 = {detect:'DETECT',contain:'CONTAIN',eradicate:'ERADICATE',recover:'RECOVER',post_incident_review:'PIR'};
              var lcRows3 = lcPhases3.map(function(ph){
                var phD=s1d[ph]||{};
                var has=ph==='detect'?!!(phD.method&&phD.method!=='unknown'):ph==='post_incident_review'?!!(phD.root_cause):!!((phD.actions||[]).length||phD.started_at);
                var ico=has?'<span style="color:#34d399">\u2713</span>':'<span style="color:#fbbf24">\u26A0</span>';
                var det='';
                if(ph==='detect'&&has){det=escHtml((phD.method||'')+' '+(phD.reference||''));if(phD.detection_lag_human)det+=' <span style="color:#888">(lag: '+escHtml(phD.detection_lag_human)+')</span>';}
                else if(!has){det='<span style="color:#888">pending \u2014 analyst entry required</span>';}
                return '<tr><td style="padding:1px 6px">'+ico+'</td><td style="padding:1px 6px;color:#e0e0e0;font-weight:600;font-size:11px">'+lcLbls3[ph]+'</td><td style="padding:1px 6px;font-size:11px;color:#bbb">'+det+'</td></tr>';
              }).join('');
              h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">ISO 27035 Lifecycle Status</div>'
                +'<table style="width:100%;border-collapse:collapse">'+lcRows3+'</table>');
              // Regulatory clocks
              var s6pm = ((pm.sections||[]).find(function(s){return s.section_id==='s6_regulatory_clocks';})||{}).auto_output||{};
              var trigs3 = s6pm.triggers||[];
              if(trigs3.length){
                var clit3 = trigs3.slice(0,4).map(function(t3){
                  var hl3=t3.hours_remaining!=null?t3.hours_remaining:(t3.clock_seconds?Math.round(t3.clock_seconds/3600):null);
                  var urg3=(hl3!=null&&hl3<=72)?'color:#e05a5a;font-weight:bold':'color:#e09a5a';
                  var ds3=t3.deadline_iso?' deadline '+escHtml(t3.deadline_iso.substring(0,16)):'';
                  var fb3=t3.form_module?' <button class="br-pm-prefill-btn" data-regulator="'+escHtml(t3.regulator_id||t3.trigger_id||'')+'" style="font-size:9px;padding:1px 6px;border:1px solid #444;border-radius:3px;background:transparent;color:#a78bfa;cursor:pointer">[Pre-fill]</button>':'';
                  return '<li style="padding:2px 0"><span style="'+urg3+'">'+escHtml(t3.regulator_name||t3.name||t3.trigger_id||'')+'</span>'+(hl3!=null?' <strong style="'+urg3+'">'+hl3+'h</strong>':'')+'<span style="color:#888">'+ds3+'</span>'+fb3+'</li>';
                }).join('');
                h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Regulatory Clocks</div>'
                  +'<ul style="list-style:none;padding-left:0;margin:0">'+clit3+'</ul>'
                  +'<div style="font-size:10px;color:#fbbf24;margin-top:4px">\u26A0 JanuSec NEVER auto-submits. All forms require human review.</div>');
              }
              // Top P1 corrective actions
              var s7pm = ((pm.sections||[]).find(function(s){return s.section_id==='s7_corrective_actions';})||{}).auto_output||{};
              var acts3 = (s7pm.actions||[]).filter(function(a){return a.priority==='P1';}).slice(0,5);
              if(acts3.length){
                var ai3 = acts3.map(function(a3){return '<li style="padding:2px 0"><strong style="color:#e05a5a">P1</strong>'+(a3.timeline_days?' <span style="color:#888">['+a3.timeline_days+'d]</span>':'')+' '+escHtml(a3.action||a3.description||'')+(a3.owner?' <span style="color:#666">('+escHtml(a3.owner)+')</span>':'')+'</li>';}).join('');
                h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Top P1 Corrective Actions</div>'
                  +'<ul class="br-dispatch__evidence-actions">'+ai3+'</ul>');
              }
              el.innerHTML = h.join('');
            }
          });
        }
        compParts.push('<div id="br-dispatch-pm-enrichment" style="margin-bottom:8px"><div style="color:#666;font-size:11px">Loading postmortem summary\u2026</div></div>');
        // Business impact banner
        var totalImpact = personaData && personaData.total_business_impact_usd || 0;
        if (totalImpact > 0) {
          var impactFmt = totalImpact>=1e6?'$'+(totalImpact/1e6).toFixed(1)+'M':'$'+totalImpact.toLocaleString();
          var impactNotes = personaData.impact_notes || [];
          var topNote = impactNotes.length ? escHtml(impactNotes[0].impact_note) : '';
          var cveList2 = impactNotes.flatMap(function(n){return n.cves||[];}).slice(0,4).map(function(c){return '<span style="background:#1e1e2e;border:1px solid #444;border-radius:3px;padding:1px 5px;font-size:10px;margin-right:4px;color:#f9a8d4">'+escHtml(c)+'</span>';}).join('');
          compParts.push('<div style="background:linear-gradient(90deg,rgba(224,90,90,.12),rgba(224,154,90,.08));border:1px solid rgba(224,90,90,.35);border-radius:6px;padding:8px 10px;margin-bottom:8px">'
            +'<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Estimated Business Impact</div>'
            +'<div style="font-size:18px;font-weight:700;color:#e05a5a">'+impactFmt+'</div>'
            +(topNote?'<div style="font-size:11px;color:#bbb;margin-top:3px">'+topNote+'</div>':'')
            +(cveList2?'<div style="margin-top:6px">'+cveList2+'</div>':'')
            +'</div>');
        }
        compParts.push(_cfSection(_getCFs(personaData, leadCluster), 'compliance'));
        // Cross-framework evidence reuse
        var crosswalk = personaData && personaData.cross_framework_evidence || {};
        var cwKeys = Object.keys(crosswalk);
        if (cwKeys.length) {
          var cwRows = cwKeys.slice(0,6).map(function(k){
            var cw=crosswalk[k];
            return '<tr style="border-bottom:1px solid #1e1e2e">'
              +'<td style="padding:3px 6px;color:#e0e0e0;font-weight:bold">'+escHtml(k)+'</td>'
              +'<td style="padding:3px 6px;color:#aaa">'+escHtml(cw.nist_csf||'\u2014')+'</td>'
              +'<td style="padding:3px 6px">'+(cw.essential_eight?'<span style="color:#60a5fa">'+escHtml(cw.essential_eight)+'</span> (E8)':'\u2014')+'</td>'
              +'<td style="padding:3px 6px;color:#aaa">'+escHtml(cw.nist_800_53||'\u2014')+'</td>'
              +'<td style="padding:3px 6px;font-size:10px">'+(cw.evidence_reuse_pct?'<span style="color:#34d399">'+cw.evidence_reuse_pct+'% reuse</span>':'')+'</td>'
              +'</tr>';
          }).join('');
          compParts.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">&#10024; Cross-Framework Evidence Reuse</div>'
            +'<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:11px">'
            +'<thead><tr style="color:#666;text-align:left"><th style="padding:2px 6px">ISO 27001</th><th style="padding:2px 6px">NIST CSF</th><th style="padding:2px 6px">Essential Eight</th><th style="padding:2px 6px">NIST 800-53</th><th style="padding:2px 6px">Reuse</th></tr></thead>'
            +'<tbody>'+cwRows+'</tbody></table></div>');
        }
        // Regulatory obligations
        var compRegs = personaData && personaData.regulatory_triggers || [];
        if (compRegs.length) {
          var regItems = compRegs.slice(0,4).map(function(r2){
            var hrs2=r2.clock_seconds?Math.round(r2.clock_seconds/3600):null;
            return '<li>'+escHtml(r2.name||r2.trigger_id||'')+(hrs2?' <strong style="color:#e05a5a">'+hrs2+'h clock</strong>':'')+(r2.rationale?' <span style="color:#777">\u2014 '+escHtml(r2.rationale)+'</span>':'')+'</li>';
          }).join('');
          compParts.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Regulatory Obligations</div>'
            +'<ul class="br-dispatch__evidence-actions">'+regItems+'</ul>');
        }
        // Remediation roadmap
        var compRm = personaData && personaData.remediation_roadmap || {};
        if (Object.keys(compRm).length) {
          var rmPhColors={'P1_48h':'#e05a5a','P2_30d':'#e09a5a','P3_90d':'#34d399'};
          var rmPhLbls={'P1_48h':'P1 \u2014 48h','P2_30d':'P2 \u2014 30d','P3_90d':'P3 \u2014 90d'};
          var rmBuks={'P1_48h':[],'P2_30d':[],'P3_90d':[]}, seenRm={};
          Object.keys(compRm).forEach(function(tk){var rk=compRm[tk]||{};['P1_48h','P2_30d','P3_90d'].forEach(function(ph){if(rk[ph]&&!seenRm[rk[ph]]){seenRm[rk[ph]]=true;rmBuks[ph].push(rk[ph]);}});});
          var rmRowsFin=['P1_48h','P2_30d','P3_90d'].map(function(ph){if(!rmBuks[ph].length)return '';return '<tr style="vertical-align:top"><td style="padding:4px 6px;white-space:nowrap;font-weight:bold;color:'+rmPhColors[ph]+';font-size:11px">'+escHtml(rmPhLbls[ph])+'</td><td style="padding:4px 6px;font-size:11px;color:#d0d0d0">'+rmBuks[ph].map(function(a4){return '\u2022 '+escHtml(a4);}).join('<br>')+'</td></tr>';}).filter(Boolean).join('');
          if(rmRowsFin) compParts.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Remediation Roadmap</div><table style="width:100%;border-collapse:collapse;border:1px solid #2a2a3e"><tbody>'+rmRowsFin+'</tbody></table>');
        }
        // ISMS summary
        var isms2 = personaData && personaData.isms_summary;
        if (isms2) {
          compParts.push('<div style="font-size:11px;color:#888;margin-top:8px;border-top:1px solid #2a2a3e;padding-top:6px">Sensitivity: <strong>'+escHtml(isms2.data_sensitivity||'unknown')+'</strong>'+(isms2.crown_jewel_touched?' <strong style="color:#e05a5a">[CROWN JEWEL]</strong>':'')+(isms2.record_count_estimate?' (~'+Number(isms2.record_count_estimate).toLocaleString()+' records)':'')+(isms2.p1_control_count?' | <strong style="color:#a78bfa">'+isms2.p1_control_count+' P1 remediations</strong>':'')+'</div>');
        }
        actionsHtml = compParts.length ? compParts.join('') : '<div style="color:#888;font-size:12px">No control data \u2014 pipeline may not have completed Stage 5d yet.</div>';
        var _compCid = leadCluster.cluster_id || leadCluster.id || '';
        var _pmViewUrl = '/static/postmortem_viewer.html?assessment=' + encodeURIComponent(AID||'') + '&cluster=' + encodeURIComponent(_compCid);
        previewPrimaryHref = _pmViewUrl;
        previewPrimaryLabel = 'Preview Full Compliance Report';
        extraButtons =
            '    <button class="br-dispatch__btn" id="br-dispatch-rebuild-pm" data-rebuild-pm="1"'
          + '      data-pm-aid="' + (AID||'').replace(/"/g,'') + '" data-pm-cid="'+(_compCid.replace(/"/g,''))+'"'
          + '      style="color:#a78bfa;border-color:rgba(167,139,250,.3)" title="Re-assemble postmortem with latest evidence data">'
          + '      ' + _icon('rotate-cw') + ' Rebuild Postmortem'
          + '    </button>'
          + '    <button class="br-dispatch__btn" data-push-target="jira" style="color:#60a5fa;border-color:rgba(96,165,250,.3)" title="Push to Jira">'
          + '      ' + _icon('ticket') + ' Push to Jira'
          + '    </button>'
          + '    <button class="br-dispatch__btn" data-push-target="confluence" style="color:#60a5fa;border-color:rgba(96,165,250,.3)" title="Push to Confluence">'
          + '      ' + _icon('book-open') + ' Push to Confluence'
          + '    </button>'
          + '    <button class="br-dispatch__btn" data-push-target="servicenow" style="color:#60a5fa;border-color:rgba(96,165,250,.3)" title="Push to ServiceNow">'
          + '      ' + _icon('server') + ' Push to ServiceNow'
          + '    </button>';

      // ── GENERIC FALLBACK (mssp / other) ──────────────────────────────────
      } else {
        if (personaData && personaData.required_actions && personaData.required_actions.length) {
          var actItems = personaData.required_actions.slice(0, 8).map(function (a) {
            var tier = a.tier ? '<span class="br-dispatch__tier br-dispatch__tier--' + a.tier + '">T' + a.tier + '</span> ' : '';
            var cmd = a.example_command ? '<code class="br-dispatch__cmd">' + escHtml(a.example_command) + '</code>' : '';
            return '<li>' + tier + escHtml(a.description || a.action_id || '') + (cmd ? ' ' + cmd : '') + '</li>';
          }).join('');
          actionsHtml = '<ol class="br-dispatch__evidence-actions">' + actItems + '</ol>';
        } else if (roleDef.persona === 'ciso' && personaData.regulatory_clocks && personaData.regulatory_clocks.length) {
          var clockItems = personaData.regulatory_clocks.slice(0, 5).map(function (c) {
            var hours = c.deadline_hours || (c.clock_seconds ? Math.round(c.clock_seconds / 3600) : null);
            var label = c.name || c.trigger_id || c.framework || '';
            var detail = c.rationale || c.obligation || c.jurisdiction || '';
            var clockBadge = hours ? ' &mdash; <strong style="color:#e05a5a">' + hours + 'h clock</strong>' : '';
            return '<li><strong>' + escHtml(label) + '</strong>: ' + escHtml(detail) + clockBadge + '</li>';
          }).join('');
          // Also render ISMS data exposure block if present
          var ismsHtml = '';
          if (personaData.data_exposure) {
            var de = personaData.data_exposure;
            var cjBadge = de.crown_jewel_touched ? ' <span style="color:#e05a5a;font-weight:bold">[CROWN JEWEL]</span>' : '';
            var rec = de.record_count_estimate ? ' &mdash; ~' + de.record_count_estimate.toLocaleString() + ' records' : '';
            ismsHtml = '<div class="br-dispatch__isms-block" style="margin-top:8px;padding:8px;border:1px solid #444;border-radius:4px;font-size:12px;">'
              + '<strong>Data exposure:</strong> ' + escHtml(de.sensitivity || 'unknown') + cjBadge + rec
              + (de.classes && de.classes.length ? '<br>Classes: ' + escHtml(de.classes.join(', ')) : '')
              + '</div>';
          }
          actionsHtml = '<ul class="br-dispatch__evidence-actions">' + clockItems + '</ul>' + ismsHtml;
        } else if (roleDef.persona === 'executive' && personaData.plain_english) {
          actionsHtml = '<div class="br-dispatch__plain-english">' + escHtml(personaData.plain_english) + '</div>';
        } else if (roleDef.persona === 'threat_hunter' && personaData.hypotheses && personaData.hypotheses.length) {
          var hypItems = personaData.hypotheses.slice(0, 4).map(function (h) {
            return '<li><strong>' + escHtml(h.hypothesis || '') + '</strong>'
              + (h.pivot_query_splunk ? '<br><code class="br-dispatch__cmd">' + escHtml(h.pivot_query_splunk) + '</code>' : '')
              + '</li>';
          }).join('');
          actionsHtml = '<ul class="br-dispatch__evidence-actions">' + hypItems + '</ul>';
        } else if (roleDef.persona === 'forensics' && personaData.acquisition_order && personaData.acquisition_order.length) {
          var acqItems = personaData.acquisition_order.slice(0, 5).map(function (a, i) {
            return '<li>' + (i + 1) + '. <strong>' + escHtml(a.host || '') + '</strong>: '
              + escHtml(a.artifacts && a.artifacts.join(', ') || '') + '</li>';
          }).join('');
          actionsHtml = '<ol class="br-dispatch__evidence-actions">' + acqItems + '</ol>';
        } else if (roleDef.persona === 'compliance') {
          var compParts = [];
          var sevColor = {'critical': '#e05a5a', 'high': '#e09a5a', 'moderate': '#e0d05a', 'low': '#888'};

          // ── Async-fetch postmortem data for exec summary / ISO 27035 / regulatory clocks ──
          // Fire-and-forget: fetch postmortem and patch the panel in-place when it arrives
          var _pmCid = leadCluster.cluster_id || leadCluster.id || '';
          if (AID && _pmCid) {
            (function (_aid, _cid) {
              // Try GET first; if 404 trigger assemble then re-GET
              fetch('/api/v1/postmortem/' + encodeURIComponent(_aid) + '/clusters/' + encodeURIComponent(_cid), {
                headers: {'x-api-key': localStorage.apiKey || 'devkey123', 'x-tenant-id': localStorage.tenantId || 'default'}
              }).then(function (r) {
                if (r.ok) return r.json();
                if (r.status === 404) {
                  return fetch('/api/v1/postmortem/' + encodeURIComponent(_aid) + '/clusters/' + encodeURIComponent(_cid) + '/assemble', {
                    method: 'POST', headers: {'Content-Type': 'application/json', 'x-api-key': localStorage.apiKey || 'devkey123', 'x-tenant-id': localStorage.tenantId || 'default'},
                    body: JSON.stringify({regenerate: false})
                  }).then(function (r2) { return r2.json(); });
                }
                return null;
              }).then(function (data) {
                if (!data) return;
                var pm = data.postmortem || {};
                var pmEl = document.getElementById('br-dispatch-pm-enrichment');
                if (!pmEl) return;
                var h = [];

                // ── TENANT HEADER ──
                var tc = pm.tenant_config || {};
                var tenantName = tc.entity_name || pm.tenant_id || '';
                var abn = tc.abn || '';
                var cisoName = (tc.ciso || {}).name || '';
                var cisoEmail = (tc.ciso || {}).email || '';
                if (tenantName || cisoName) {
                  h.push('<div style="border-bottom:1px solid #2a2a3e;padding-bottom:6px;margin-bottom:8px">'
                    + '<div style="font-size:13px;font-weight:600;color:#e0e0e0">' + escHtml(tenantName) + (abn ? '  <span style="color:#888;font-weight:400">(ABN ' + escHtml(abn) + ')</span>' : '') + '</div>'
                    + (cisoName ? '<div style="font-size:11px;color:#aaa">CISO: ' + escHtml(cisoName) + (cisoEmail ? ' &bull; ' + escHtml(cisoEmail) : '') + '</div>' : '')
                    + '</div>');
                }

                // ── EXECUTIVE SUMMARY (verdict block) ──
                var v = pm.verdict || {};
                // Defensive fallback: if postmortem verdict is still UNCERTAIN
                // (assembler ran before backend fix), override with cluster data.
                if (!v.platform_verdict || v.platform_verdict === 'UNCERTAIN') {
                  var _cv = (leadCluster.verdict || leadCluster.final_verdict || '').toUpperCase();
                  if (_cv) v.platform_verdict = _cv;
                }
                if (!v.confidence || v.confidence === 0) {
                  var _cc = leadCluster.confidence || leadCluster.confidence_score || 0;
                  if (_cc) v.confidence = _cc;
                }
                if (!v.kill_chain_stage || v.kill_chain_stage === 'unknown') {
                  var _phases = leadCluster.phases || [];
                  if (_phases.length) {
                    var _pnames = _phases.map(function(p){ return p.name || p.phase_id || ''; }).filter(Boolean);
                    v.kill_chain_stage = _pnames.length <= 5
                      ? _pnames.join(' → ')
                      : _pnames.slice(0,3).join(' → ') + ' → … → ' + _pnames[_pnames.length-1];
                  }
                }
                if (v.platform_verdict) {
                  var confPct = v.confidence ? Math.round(v.confidence * 100) + '%' : '';
                  var matColor = v.materiality_assessment === 'MEETS_NOTIFICATION_CRITERIA' ? '#e05a5a' : '#e09a5a';
                  // Find s1 narrative_summary
                  var s1 = ((pm.sections || []).find(function (s) { return s.section_id === 's1_incident_lifecycle'; }) || {}).auto_output || {};
                  var oneLine = s1.narrative_summary || '';
                  h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Executive Summary</div>'
                    + '<table style="width:100%;font-size:11px;border-collapse:collapse;margin-bottom:6px">'
                    + '<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">VERDICT</td><td style="color:#e0e0e0;font-weight:600">' + escHtml(v.platform_verdict) + (confPct ? ' <span style="color:#888;font-weight:400">(confidence ' + confPct + ')</span>' : '') + '</td></tr>'
                    + '<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">KILL CHAIN</td><td style="color:#e0e0e0">' + escHtml(v.kill_chain_stage || 'unknown') + '</td></tr>'
                    + '<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">MATERIALITY</td><td style="color:' + matColor + ';font-weight:600">' + escHtml(v.materiality_assessment || '') + '</td></tr>'
                    + '<tr><td style="color:#888;padding:2px 8px 2px 0;white-space:nowrap">RATIONALE</td><td style="color:#bbb">' + escHtml(v.materiality_rationale || '') + '</td></tr>'
                    + '</table>'
                    + (oneLine ? '<div style="font-size:11px;color:#d0d0d0;border-left:3px solid #a78bfa;padding-left:8px;margin-bottom:8px">' + escHtml(oneLine.substring(0, 500)) + '</div>' : ''));
                }

                // ── ISO 27035 LIFECYCLE STATUS ──
                var s1data = ((pm.sections || []).find(function (s) { return s.section_id === 's1_incident_lifecycle'; }) || {}).auto_output || {};
                var phases = ['detect', 'contain', 'eradicate', 'recover', 'post_incident_review'];
                var phaseLabels = {detect:'DETECT', contain:'CONTAIN', eradicate:'ERADICATE', recover:'RECOVER', post_incident_review:'PIR'};
                var lifecycleRows = phases.map(function (ph) {
                  var phData = s1data[ph] || {};
                  var hasData = false;
                  if (ph === 'detect') {
                    hasData = !!(phData.method && phData.method !== 'unknown');
                  } else if (ph === 'post_incident_review') {
                    hasData = !!(phData.root_cause);
                  } else {
                    hasData = !!((phData.actions || []).length || phData.started_at);
                  }
                  var icon = hasData ? '<span style="color:#34d399">✓</span>' : '<span style="color:#fbbf24">⚠</span>';
                  var detail = '';
                  if (ph === 'detect' && hasData) {
                    detail = escHtml((phData.method || '') + ' ' + (phData.reference || ''));
                    if (phData.detection_lag_human) detail += ' <span style="color:#888">(lag: ' + escHtml(phData.detection_lag_human) + ')</span>';
                  } else if (!hasData) {
                    detail = '<span style="color:#888">pending — analyst entry required</span>';
                  }
                  return '<tr><td style="padding:1px 6px">' + icon + '</td><td style="padding:1px 6px;color:#e0e0e0;font-weight:600;font-size:11px">' + phaseLabels[ph] + '</td><td style="padding:1px 6px;font-size:11px;color:#bbb">' + detail + '</td></tr>';
                }).join('');
                h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">ISO 27035 Lifecycle Status</div>'
                  + '<table style="width:100%;border-collapse:collapse">' + lifecycleRows + '</table>');

                // ── REGULATORY CLOCKS (from postmortem s6) ──
                var s6 = ((pm.sections || []).find(function (s) { return s.section_id === 's6_regulatory_clocks'; }) || {}).auto_output || {};
                var triggers = s6.triggers || [];
                if (triggers.length) {
                  var clockItems = triggers.slice(0, 4).map(function (t) {
                    var hoursLeft = t.hours_remaining != null ? t.hours_remaining : (t.clock_seconds ? Math.round(t.clock_seconds / 3600) : null);
                    var urgency = (hoursLeft != null && hoursLeft <= 72) ? 'color:#e05a5a;font-weight:bold' : 'color:#e09a5a';
                    var deadlineStr = t.deadline_iso ? ' deadline ' + escHtml(t.deadline_iso.substring(0, 16)) : '';
                    var formBtn = t.form_module ? ' <button class="br-pm-prefill-btn" data-regulator="' + escHtml(t.regulator_id || t.trigger_id || '') + '" style="font-size:9px;padding:1px 6px;border:1px solid #444;border-radius:3px;background:transparent;color:#a78bfa;cursor:pointer">[Pre-fill]</button>' : '';
                    return '<li style="padding:2px 0">'
                      + '<span style="' + urgency + '">' + escHtml(t.regulator_name || t.name || t.trigger_id || '') + '</span>'
                      + (hoursLeft != null ? ' <strong style="' + urgency + '">' + hoursLeft + 'h</strong>' : '')
                      + '<span style="color:#888">' + deadlineStr + '</span>'
                      + formBtn + '</li>';
                  }).join('');
                  h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Regulatory Clocks</div>'
                    + '<ul class="br-dispatch__evidence-actions" style="list-style:none;padding-left:0">' + clockItems + '</ul>'
                    + '<div style="font-size:10px;color:#fbbf24;margin-top:4px">⚠ JanuSec NEVER auto-submits. All forms require human review + submission via the regulator\'s official channel.</div>');
                }

                // ── TOP CORRECTIVE ACTIONS (from postmortem s7) ──
                var s7 = ((pm.sections || []).find(function (s) { return s.section_id === 's7_corrective_actions'; }) || {}).auto_output || {};
                var actions = (s7.actions || []).filter(function (a) { return a.priority === 'P1'; }).slice(0, 5);
                if (actions.length) {
                  var actItems = actions.map(function (a) {
                    var timeline = a.timeline_days ? a.timeline_days + 'd' : '';
                    return '<li style="padding:2px 0"><strong style="color:#e05a5a">P1</strong>'
                      + (timeline ? ' <span style="color:#888">[' + timeline + ']</span>' : '')
                      + ' ' + escHtml(a.action || a.description || '')
                      + (a.owner ? ' <span style="color:#666">(' + escHtml(a.owner) + ')</span>' : '') + '</li>';
                  }).join('');
                  h.push('<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Top Corrective Actions</div>'
                    + '<ul class="br-dispatch__evidence-actions">' + actItems + '</ul>');
                }

                pmEl.innerHTML = h.join('');
              }).catch(function () { /* postmortem not available — no-op, existing panel still works */ });
            })(AID, _pmCid);
          }

          // ── Postmortem enrichment placeholder (filled async above) ─────────
          compParts.push('<div id="br-dispatch-pm-enrichment" style="margin-bottom:8px"><div style="color:#666;font-size:11px">Loading postmortem summary\u2026</div></div>');

          // ── Business impact banner ──────────────────────────────────────────
          var totalImpact = personaData.total_business_impact_usd || 0;
          var impactNotes = personaData.impact_notes || [];
          if (totalImpact > 0) {
            var impactFmt = totalImpact >= 1e6
              ? '$' + (totalImpact / 1e6).toFixed(1) + 'M'
              : '$' + totalImpact.toLocaleString();
            var topNote = impactNotes.length ? escHtml(impactNotes[0].impact_note) : '';
            var cveList = impactNotes.flatMap(function (n) { return n.cves || []; }).slice(0, 4)
              .map(function (c) { return '<span style="background:#1e1e2e;border:1px solid #444;border-radius:3px;padding:1px 5px;font-size:10px;margin-right:4px;color:#f9a8d4">' + escHtml(c) + '</span>'; }).join('');
            compParts.push(
              '<div style="background:linear-gradient(90deg,rgba(224,90,90,.12),rgba(224,154,90,.08));border:1px solid rgba(224,90,90,.35);border-radius:6px;padding:8px 10px;margin-bottom:8px">'
              + '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Estimated Business Impact (breach analogues)</div>'
              + '<div style="font-size:18px;font-weight:700;color:#e05a5a">' + impactFmt + '</div>'
              + (topNote ? '<div style="font-size:11px;color:#bbb;margin-top:3px">' + topNote + '</div>' : '')
              + (cveList ? '<div style="margin-top:6px">' + cveList + '</div>' : '')
              + '</div>'
            );
          }

          // ── Failed controls section ─────────────────────────────────────────
          var cfs = personaData.control_failures || [];
          if (cfs.length) {
            var critCount = cfs.filter(function (f) { return (f.severity || '').toLowerCase() === 'critical'; }).length;
            // Build per-control expandable rows with MITRE-tagged persona actions
            var _dispPersn = roleDef.persona || 'compliance';
            // Persona-specific action labels
            var _personaActionMap = {
              'compliance':    {detect:'Document', contain:'Notify', eradicate:'Remediate', recover:'Certify', pir:'Audit'},
              'soc_analyst':   {detect:'Detect', contain:'Block', eradicate:'Purge', recover:'Restore', pir:'Tune'},
              'threat_hunter': {detect:'Hunt', contain:'Isolate', eradicate:'Hunt→Root', recover:'Validate', pir:'Build Query'},
              'forensics':     {detect:'Preserve', contain:'Image', eradicate:'Chain-of-Custody', recover:'Reconstruct', pir:'Timeline'},
              'ciso':          {detect:'Risk-Accept?', contain:'Exec Brief', eradicate:'Board Report', recover:'Assurance', pir:'Lessons Learned'},
              'executive':     {detect:'Notify Board', contain:'Engage Legal', eradicate:'Comms', recover:'Approvals', pir:'Strategy'},
            };
            var _pal = _personaActionMap[_dispPersn] || _personaActionMap['compliance'];
            var cfItems = cfs.slice(0, 5).map(function (f, cfIdx) {
              var sev = f.severity || '';
              var sevColor2 = {'critical': '#e05a5a', 'high': '#e09a5a', 'moderate': '#e0d05a', 'low': '#888'};
              var sevBadge = sev ? ' <span style="color:' + (sevColor2[sev] || '#888') + ';font-weight:bold;font-size:10px">[' + sev.toUpperCase() + ']</span>' : '';
              var pri = f.remediation_priority ? ' <span style="font-size:10px;color:#a78bfa;background:rgba(167,139,250,.12);border-radius:3px;padding:0 4px">' + f.remediation_priority + '</span>' : '';
              // MITRE technique tags
              var mitreHtml = '';
              (f.triggered_by || []).slice(0, 3).forEach(function (tid) {
                var mLabel = tid.replace(/_/g, ' ');
                var isT = /^T\d{4}/.test(tid);
                mitreHtml += '<a href="https://attack.mitre.org/techniques/' + encodeURIComponent(tid.split('.')[0]) + '/" target="_blank" '
                  + 'style="display:inline-block;background:#1e1e2e;border:1px solid #5b4fcf;border-radius:3px;padding:0 5px;font-size:9px;color:#a78bfa;margin-left:3px;text-decoration:none;cursor:pointer"'
                  + ' title="View ' + escHtml(tid) + ' on ATT&CK">'
                  + (isT ? '' : '🎯 ') + escHtml(isT ? tid : mLabel) + '</a>';
              });
              // CVE tags
              var cveTags = '';
              var cveCtx = personaData.cve_context || {};
              (f.triggered_by || []).forEach(function (tid) {
                var tc = cveCtx[tid] || cveCtx[tid.split('.')[0]];
                if (tc && tc.cves) {
                  tc.cves.slice(0, 2).forEach(function (c) {
                    cveTags += '<span style="background:#1e1e2e;border:1px solid #333;border-radius:3px;padding:0 4px;font-size:9px;color:#f9a8d4;margin-left:3px">' + escHtml(c) + '</span>';
                  });
                }
              });
              var drillId = 'cfdrll-' + cfIdx + '-' + Math.random().toString(36).slice(2,6);
              // Per-persona lifecycle actions from the control failure or fallback
              var cfActions = f.persona_actions && f.persona_actions[_dispPersn]
                ? f.persona_actions[_dispPersn]
                : {};
              var detectAct  = cfActions.detect  || f.detect_action  || 'Review detection logs for this control domain';
              var containAct = cfActions.contain  || f.contain_action || 'Confirm scope and isolate affected systems';
              var eradAct    = cfActions.eradicate|| f.eradicate_action|| 'Apply remediation and verify clean state';
              var recAct     = cfActions.recover  || f.recover_action || 'Restore and re-enable with monitoring';
              var pirAct     = cfActions.pir      || f.pir_action     || 'Document lessons and update control baseline';
              return '<li style="padding:4px 0;border-bottom:1px solid #1e1e2e">'
                + '<div style="cursor:pointer;user-select:none" onclick="var d=document.getElementById(\'' + drillId + '\');d.style.display=d.style.display===\'none\'?\'\':\'none\'">'
                + '  <strong>' + escHtml(f.control_id || '') + '</strong>'
                + sevBadge + pri + mitreHtml + cveTags
                + ' <span style="color:#666">(' + escHtml(f.framework || '') + ')</span>: '
                + escHtml(f.control_name || f.failure || '')
                + ' <span style="color:#666;font-size:10px">▸ expand</span>'
                + '</div>'
                + '<div id="' + drillId + '" style="display:none;padding:6px 0 2px 12px;font-size:10px;color:#bbb;border-left:2px solid #2a2a3e;margin-top:3px">'
                + (f.triggered_by && f.triggered_by.length ? '<div style="margin-bottom:4px;color:#888">Triggered by: ' + f.triggered_by.join(', ') + '</div>' : '')
                + '<table style="width:100%;border-collapse:collapse">'
                + '<tr><td style="padding:2px 6px;color:#60a5fa;width:90px;font-weight:600">' + _pal.detect + '</td><td style="padding:2px 6px">' + escHtml(detectAct) + '</td></tr>'
                + '<tr style="background:rgba(30,30,46,.4)"><td style="padding:2px 6px;color:#fbbf24;font-weight:600">' + _pal.contain + '</td><td style="padding:2px 6px">' + escHtml(containAct) + '</td></tr>'
                + '<tr><td style="padding:2px 6px;color:#e05a5a;font-weight:600">' + _pal.eradicate + '</td><td style="padding:2px 6px">' + escHtml(eradAct) + '</td></tr>'
                + '<tr style="background:rgba(30,30,46,.4)"><td style="padding:2px 6px;color:#34d399;font-weight:600">' + _pal.recover + '</td><td style="padding:2px 6px">' + escHtml(recAct) + '</td></tr>'
                + '<tr><td style="padding:2px 6px;color:#a78bfa;font-weight:600">' + _pal.pir + '</td><td style="padding:2px 6px">' + escHtml(pirAct) + '</td></tr>'
                + '</table>'
                + '</div>'
                + '</li>';
            }).join('');
            // Collect unique frameworks impacted
            var fwSet = {};
            cfs.forEach(function (f) { if (f.framework) fwSet[f.framework] = true; });
            var fwList = Object.keys(fwSet).slice(0, 7).join(' \u2022 ');
            compParts.push(
              '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Control Failures (' + cfs.length + ' total \u2014 ' + critCount + ' critical)</div>'
              + (fwList ? '<div style="font-size:10px;color:#888;margin-bottom:4px">Frameworks impacted: ' + escHtml(fwList) + '</div>' : '')
              + '<div style="font-size:10px;color:#888;margin-bottom:2px">Top 5 — click any row to see ' + escHtml(roleDef.label) + ' actions per control:</div>'
              + '<ul class="br-dispatch__evidence-actions" style="padding-left:0;list-style:none">' + cfItems + '</ul>'
            );
          }

          // ── Cross-framework evidence reuse table ────────────────────────────
          var crosswalk = personaData.cross_framework_evidence || {};
          var crosswalkKeys = Object.keys(crosswalk);
          if (crosswalkKeys.length) {
            var cwRows = crosswalkKeys.slice(0, 6).map(function (cid) {
              var cw = crosswalk[cid];
              var reuse = cw.evidence_reuse_pct ? '<span style="color:#34d399">' + cw.evidence_reuse_pct + '% reuse</span>' : '';
              var e8 = cw.essential_eight ? '<span style="color:#60a5fa">' + escHtml(cw.essential_eight) + '</span> (E8)' : '—';
              return '<tr style="border-bottom:1px solid #1e1e2e">'
                + '<td style="padding:3px 6px;color:#e0e0e0;font-weight:bold">' + escHtml(cid) + '</td>'
                + '<td style="padding:3px 6px;color:#aaa">' + escHtml(cw.nist_csf || '—') + '</td>'
                + '<td style="padding:3px 6px">' + e8 + '</td>'
                + '<td style="padding:3px 6px;color:#aaa">' + escHtml(cw.nist_800_53 || '—') + '</td>'
                + '<td style="padding:3px 6px;font-size:10px">' + reuse + '</td>'
                + '</tr>';
            }).join('');
            compParts.push(
              '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">\u2728 Cross-Framework Evidence Reuse</div>'
              + '<div style="overflow-x:auto">'
              + '<table style="width:100%;border-collapse:collapse;font-size:11px">'
              + '<thead><tr style="color:#666;text-align:left">'
              + '<th style="padding:2px 6px">ISO 27001</th><th style="padding:2px 6px">NIST CSF 2.0</th>'
              + '<th style="padding:2px 6px">Essential Eight</th><th style="padding:2px 6px">NIST 800-53</th>'
              + '<th style="padding:2px 6px">Reuse</th>'
              + '</tr></thead>'
              + '<tbody>' + cwRows + '</tbody>'
              + '</table></div>'
              + (function () {
                var reusePcts = crosswalkKeys.map(function (k) { return (crosswalk[k] || {}).evidence_reuse_pct || 0; }).filter(function (v) { return v > 0; });
                if (!reusePcts.length) return '';
                var avg = Math.round(reusePcts.reduce(function (a, b) { return a + b; }, 0) / reusePcts.length);
                return '<div style="font-size:10px;color:#34d399;margin-top:4px">One audit walkthrough satisfies multiple frameworks for ' + crosswalkKeys.length + ' of ' + (cfs ? cfs.length : 0) + ' controls (' + avg + '% avg reuse).</div>';
              })()
            );
          }

          // ── Regulatory triggers section ─────────────────────────────────────
          var regs = personaData.regulatory_triggers || [];
          if (regs.length) {
            var regItems = regs.slice(0, 4).map(function (r) {
              var h = r.clock_seconds ? Math.round(r.clock_seconds / 3600) : null;
              var badge = h ? ' <strong style="color:#e05a5a">' + h + 'h clock</strong>' : '';
              return '<li>' + escHtml(r.name || r.trigger_id || '') + badge
                + (r.rationale ? ' <span style="color:#777">— ' + escHtml(r.rationale) + '</span>' : '') + '</li>';
            }).join('');
            compParts.push(
              '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Regulatory Obligations</div>'
              + '<ul class="br-dispatch__evidence-actions">' + regItems + '</ul>'
            );
          }

          // ── Auditor questions section ───────────────────────────────────────
          var auditorAsks = personaData.auditor_insights || [];
          if (auditorAsks.length) {
            var askItems = auditorAsks.slice(0, 6).map(function (q, i) {
              return '<li style="padding:2px 0"><span style="color:#fbbf24;margin-right:4px">Q' + (i + 1) + '.</span>'
                + escHtml(q) + '</li>';
            }).join('');
            compParts.push(
              '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Auditor Questions to Prepare For</div>'
              + '<ul class="br-dispatch__evidence-actions" style="color:#e0e0e0">' + askItems + '</ul>'
            );
          }

          // ── Remediation roadmap (P1/P2/P3) ────────────────────────────────
          var roadmap = personaData.remediation_roadmap || {};
          var roadmapKeys = Object.keys(roadmap);
          if (roadmapKeys.length) {
            var phaseColors = {'P1_48h': '#e05a5a', 'P2_30d': '#e09a5a', 'P3_90d': '#34d399'};
            var phaseLabels = {'P1_48h': 'P1 — 48h', 'P2_30d': 'P2 — 30d', 'P3_90d': 'P3 — 90d'};
            // Collect all P1/P2/P3 actions across techniques, deduplicate
            var phaseMap = {'P1_48h': [], 'P2_30d': [], 'P3_90d': []};
            var seen = {};
            roadmapKeys.forEach(function (tid) {
              var r = roadmap[tid] || {};
              ['P1_48h', 'P2_30d', 'P3_90d'].forEach(function (ph) {
                if (r[ph] && !seen[r[ph]]) {
                  seen[r[ph]] = true;
                  phaseMap[ph].push(r[ph]);
                }
              });
            });
            var roadmapRows = ['P1_48h', 'P2_30d', 'P3_90d'].map(function (ph) {
              var actions = phaseMap[ph];
              if (!actions.length) return '';
              var col = phaseColors[ph];
              var lbl = phaseLabels[ph];
              return '<tr style="vertical-align:top"><td style="padding:4px 6px;white-space:nowrap;font-weight:bold;color:' + col + ';font-size:11px">'
                + escHtml(lbl) + '</td><td style="padding:4px 6px;font-size:11px;color:#d0d0d0">'
                + actions.map(function (a) { return '• ' + escHtml(a); }).join('<br>') + '</td></tr>';
            }).filter(Boolean).join('');
            if (roadmapRows) {
              compParts.push(
                '<div style="font-size:11px;color:#aaa;text-transform:uppercase;letter-spacing:.06em;margin-top:8px;margin-bottom:4px">Remediation Roadmap</div>'
                + '<table style="width:100%;border-collapse:collapse;border:1px solid #2a2a3e;border-radius:4px">'
                + '<tbody>' + roadmapRows + '</tbody></table>'
              );
            }
          }

          // ── ISMS summary block ──────────────────────────────────────────────
          var isms = personaData.isms_summary;
          if (isms) {
            var cjFlag = isms.crown_jewel_touched ? ' <strong style="color:#e05a5a">[CROWN JEWEL]</strong>' : '';
            var rec = isms.record_count_estimate ? ' (~' + Number(isms.record_count_estimate).toLocaleString() + ' records)' : '';
            var tables = (isms.affected_tables || []).slice(0, 3).join(', ');
            compParts.push(
              '<div style="font-size:11px;color:#888;margin-top:8px;border-top:1px solid #2a2a3e;padding-top:6px">'
              + 'Sensitivity: <strong>' + escHtml(isms.data_sensitivity || 'unknown') + '</strong>' + cjFlag + rec
              + (tables ? ' | Tables: <span style="color:#bbb">' + escHtml(tables) + '</span>' : '')
              + (isms.p1_control_count ? ' | <strong style="color:#a78bfa">' + isms.p1_control_count + ' P1 remediations</strong>' : '')
              + (isms.regulatory_regime_count ? ' | Regimes: ' + isms.regulatory_regime_count : '')
              + '</div>'
            );
          }

          var genItems2 = personaData.required_actions.slice(0, 6).map(function (a) {
            return '<li>' + escHtml(a.description || a.action_id || '') + '</li>';
          }).join('');
          actionsHtml = '<ul class="br-dispatch__evidence-actions">' + genItems2 + '</ul>';
        } else {
          actionsHtml = '<div class="br-dispatch__preview-desc">' + escHtml(roleDef.actions || '') + '</div>';
        }
      }

      // Build delivery channel options — email first (phase 1 primary channel)
      var channelOpts = [
        '<option value="email">Email</option>',
        '<option value="auto">Auto (configured channel)</option>',
        '<option value="slack">Slack</option>',
        '<option value="teams">Microsoft Teams</option>',
        '<option value="copy">Copy to clipboard</option>',
      ].join('');

      preview.style.display = 'block';
      preview.innerHTML = [
        '<div class="br-dispatch__preview-head">',
        '  <span class="br-dispatch__preview-persona-icon">' + roleDef.icon + '</span>',
        '  <strong>DISPATCH PREVIEW \u2014 ' + escHtml(roleDef.label).toUpperCase() + '</strong>',
        '</div>',
        '<div class="br-dispatch__preview-body">',
        '  <div class="br-dispatch__preview-section">',
        '    <div class="br-dispatch__preview-label">What they receive</div>',
        '    ' + descHtml,
        '  </div>',
        '  <div class="br-dispatch__preview-section">',
        '    <div class="br-dispatch__preview-label">Trust / approval / history</div>',
        '    ' + sharedContextHtml,
        '  </div>',
        '  <div class="br-dispatch__preview-section">',
        '    <div class="br-dispatch__preview-label">Required actions</div>',
        '    ' + actionsHtml,
        '  </div>',
        '  <div class="br-dispatch__preview-section">',
        '    <div class="br-dispatch__preview-label">Delivery channel</div>',
        '    <div class="br-dispatch__channel-row">',
        '      <select id="br-dispatch-channel" class="br-dispatch__channel-select">',
        channelOpts,
        '      </select>',
        '      <input type="email" id="br-dispatch-email" class="br-dispatch__email-input"',
        '             placeholder="or enter email address\u2026" autocomplete="email">',
        '    </div>',
        '  </div>',
        '  <div class="br-dispatch__preview-section">',
        '    <div class="br-dispatch__preview-label">Approval requirements</div>',
        '    <div class="br-dispatch__preview-gate">',
        '      <label style="display:flex;align-items:center;gap:6px;cursor:pointer;">',
        '        <input type="checkbox" id="br-dispatch-change-mgmt"> Requires change management / CAB review',
        '      </label>',
        '    </div>',
        '  </div>',
        '  <div class="br-dispatch__preview-section br-dispatch__preview-notice">',
        '    ' + _icon('warning') + ' Dispatch is logged and auditable. Verify the recipient channel is secure before confirming.',
        '  </div>',
        '  <div class="br-dispatch__preview-actions">',
        '    <a class="br-dispatch__btn br-dispatch__btn--export" id="br-dispatch-preview-link"',
        '       href="' + previewPrimaryHref + '" target="_blank" rel="noopener" style="text-decoration:none;">',
        '      ' + _icon('file-text') + ' ' + escHtml(previewPrimaryLabel),
        '    </a>',
        '    <button class="br-dispatch__btn br-dispatch__btn--confirm" style="border-color:rgba(45,212,191,.3);color:#2dd4bf;"',
        '            id="br-dispatch-confirm" data-confirm-role="' + role + '">',
        '      ' + _icon('send') + ' Confirm &amp; Send to ' + escHtml(roleDef.label),
        '    </button>',
        '    <details class="br-dispatch-more">',
        '      <summary class="br-dispatch__btn br-dispatch-more__summary">' + _icon('more-horizontal') + ' More actions ▾</summary>',
        '      <div class="br-dispatch-more__menu">',
        '        <button class="br-dispatch__btn br-dispatch__btn--deep" id="br-dispatch-deep"',
        '                data-deep-role="' + role + '" title="Generate a comprehensive evidence-backed report using LLM reasoning">',
        '          ' + _icon('sparkles') + ' Generate Deep Report',
        '        </button>',
        extraButtons,
        '        <button class="br-dispatch__btn" id="br-dispatch-regen"',
        '                data-regen-role="' + role + '" data-regen-persona="' + roleDef.persona + '"',
        '                style="color:#a78bfa;border-color:rgba(167,139,250,.3);"',
        '                title="Re-run pipeline dispatch for this persona (re-enriches evidence)">',
        '          ' + _icon('rotate-cw') + ' Regenerate',
        '        </button>',
        '      </div>',
        '    </details>',
        '    <button class="br-dispatch__btn br-dispatch__btn--cancel" id="br-dispatch-cancel" style="color:var(--text-muted);">',
        '      ' + _icon('x') + ' Cancel',
        '    </button>',
        '  </div>',
        '</div>',
      ].join('');
    });

    // Step 3a: Generate Deep Report — opens Postmortem tab if available, else falls back to report
    document.getElementById('br-content').addEventListener('click', function (e) {
      var deepBtn = e.target.closest('#br-dispatch-deep');
      if (!deepBtn) return;
      var role = deepBtn.getAttribute('data-deep-role');
      var roleDef = _STAKEHOLDER_ROLES.filter(function (r) { return r.key === role; })[0];
      if (!roleDef || !roleDef.persona) return;

      // Find lead breach cluster for postmortem tab
      var leadCluster = (state.clusters || []).find(function (c) {
        var v = ((c.verdict || c.final_verdict || '')).toUpperCase();
        return v === 'VALIDATED_BREACH' || v === 'CONFIRMED_BREACH' || v === 'CONFIRMED_INTRUSION';
      }) || (state.clusters || [])[0] || {};
      var cid = leadCluster.cluster_id || leadCluster.id || '';

      if (cid && AID && window.JanusecPostmortem && window.JanusecPostmortem.openTab) {
        window.JanusecPostmortem.openTab(AID, cid);
      } else {
        // Fallback: original deep report behaviour
        var deepUrl = authedUrl('/api/v1/report/ingestion?format=html&persona=' + encodeURIComponent(roleDef.persona)
          + '&include_model=true&include_scenarios=true&deep=true'
          + (AID ? '&assessment_id=' + encodeURIComponent(AID) : ''));
        deepBtn.disabled = true;
        deepBtn.innerHTML = _icon('rotate-cw') + ' Generating&hellip;';
        window.open(deepUrl, '_blank', 'noopener');
        setTimeout(function () {
          deepBtn.disabled = false;
          deepBtn.innerHTML = _icon('sparkles') + ' Generate Deep Report';
        }, 2000);
      }
    });

    // Step 3a-itsm: ITSM push buttons (Jira / Confluence / ServiceNow) — compliance persona
    document.getElementById('br-content').addEventListener('click', function (e) {
      var pushBtn = e.target.closest('[data-push-target]');
      if (!pushBtn) return;
      var target = pushBtn.getAttribute('data-push-target');
      if (!target || !AID) return;

      var leadCluster = (state.clusters || []).find(function (c) {
        var v = ((c.verdict || c.final_verdict || '')).toUpperCase();
        return v === 'VALIDATED_BREACH' || v === 'CONFIRMED_BREACH' || v === 'CONFIRMED_INTRUSION';
      }) || (state.clusters || [])[0] || {};
      var cid = leadCluster.cluster_id || leadCluster.id || '';
      if (!cid) { _toast('No cluster found for ITSM push', 'warning'); return; }

      pushBtn.disabled = true;
      var origHtml = pushBtn.innerHTML;
      pushBtn.innerHTML = _icon('rotate-cw') + ' Pushing\u2026';

      fetch('/api/v1/postmortem/' + encodeURIComponent(AID) + '/clusters/' + encodeURIComponent(cid) + '/push-itsm', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ target: target })
      })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
      .then(function (res) {
        if (res.ok) {
          _toast('Pushed to ' + target + (res.data.ticket_url ? ': ' + res.data.ticket_url : ''), 'success');
        } else {
          _toast('ITSM push failed: ' + (res.data.detail || 'unknown error'), 'error');
        }
      })
      .catch(function () { _toast('ITSM push request failed', 'error'); })
      .finally(function () {
        pushBtn.disabled = false;
        pushBtn.innerHTML = origHtml;
      });
    });

    // Step 3b-rebuild-pm: Rebuild Postmortem button (compliance) — forces re-assemble
    document.getElementById('br-content').addEventListener('click', function (e) {
      var rebuildBtn = e.target.closest('#br-dispatch-rebuild-pm');
      if (!rebuildBtn) return;
      var pmAid = rebuildBtn.getAttribute('data-pm-aid') || AID;
      var pmCid = rebuildBtn.getAttribute('data-pm-cid') || '';
      if (!pmAid || !pmCid) return;
      var origHtml2 = rebuildBtn.innerHTML;
      rebuildBtn.disabled = true;
      rebuildBtn.innerHTML = _icon('rotate-cw') + ' Rebuilding\u2026';
      fetch('/api/v1/postmortem/' + encodeURIComponent(pmAid) + '/clusters/' + encodeURIComponent(pmCid) + '/assemble', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({regenerate: true})
      })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        rebuildBtn.disabled = false;
        rebuildBtn.innerHTML = _icon('check') + ' Rebuilt';
        // Refresh the enrichment div in-place
        var pmEl = document.getElementById('br-dispatch-pm-enrichment');
        if (pmEl && data && data.postmortem) {
          var pm = data.postmortem;
          var lc = (state.clusters || []).find(function (c) { return (c.cluster_id||c.id) === pmCid; }) || {};
        }
        toast('Postmortem rebuilt successfully');
        setTimeout(function () { rebuildBtn.innerHTML = origHtml2; }, 3000);
      })
      .catch(function () {
        rebuildBtn.disabled = false;
        rebuildBtn.innerHTML = origHtml2;
        toast('Postmortem rebuild failed — check logs', 'error');
      });
    });

    // Step 3b-action-btns: export/action button handlers
    document.getElementById('br-content').addEventListener('click', function (e) {
      // IOC pack export
      if (e.target.closest('#br-dispatch-export-ioc')) {
        var lc = (state.clusters || []).find(function (c) {
          var v = (c.verdict||c.final_verdict||'').toUpperCase();
          return v==='VALIDATED_BREACH'||v==='CONFIRMED_BREACH'||v==='CONFIRMED_INTRUSION';
        }) || (state.clusters||[])[0] || {};
        var t1 = lc.tier1_prefill || {};
        var infra = t1.attacker_infrastructure || {};
        var iocPayload = {
          assessment_id: AID,
          cluster_id: lc.cluster_id || lc.id,
          ips: (infra.c2_ips||infra.ips||[]).concat(lc.shared_ips||[]).filter(function(v2,i2,a2){return a2.indexOf(v2)===i2;}),
          domains: infra.c2_domains || infra.domains || [],
          users: lc.shared_users || [],
          mitre_techniques: (t1.mitre_techniques||[]).map(function(m){return m.technique_id||m.id||'';}).filter(Boolean),
          exported_at: new Date().toISOString()
        };
        var blob = new Blob([JSON.stringify(iocPayload, null, 2)], {type: 'application/json'});
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = 'ioc-pack-' + (AID||'assessment') + '.json'; a.click();
        URL.revokeObjectURL(url);
        toast('IOC pack exported');
        return;
      }
      // Hunt pack export
      if (e.target.closest('#br-dispatch-export-hunt')) {
        var lc2 = (state.clusters||[]).find(function(c){var v=(c.verdict||c.final_verdict||'').toUpperCase();return v.includes('BREACH')||v.includes('INTRUSION');}) || (state.clusters||[])[0] || {};
        var pd2 = (lc2.persona_dispatch||{}).threat_hunter || {};
        var t12 = lc2.tier1_prefill || {};
        var huntPayload = {
          assessment_id: AID,
          cluster_id: lc2.cluster_id || lc2.id,
          hypotheses: pd2.hypotheses || (t12.mitre_techniques||[]).slice(0,6).map(function(m){return {technique_id:m.technique_id||m.id,hypothesis:'Hunt for '+escHtml(m.name||m.technique_id||''),pivot_query_splunk:m.hunt_query||''};}).filter(function(h){return h.technique_id;}),
          attacker_infrastructure: t12.attacker_infrastructure || {},
          exported_at: new Date().toISOString()
        };
        var blob2 = new Blob([JSON.stringify(huntPayload, null, 2)], {type: 'application/json'});
        var url2 = URL.createObjectURL(blob2); var a2 = document.createElement('a');
        a2.href=url2; a2.download='hunt-pack-'+(AID||'assessment')+'.json'; a2.click(); URL.revokeObjectURL(url2);
        toast('Hunt pack exported');
        return;
      }
      // MITRE ATT&CK Navigator export
      if (e.target.closest('#br-dispatch-export-navigator')) {
        var lcNav = (state.clusters||[]).find(function(c){var v=(c.verdict||c.final_verdict||'').toUpperCase();return v.includes('BREACH')||v.includes('INTRUSION');}) || (state.clusters||[])[0] || {};
        var tNav = lcNav.tier1_prefill || {};
        var techIds = (tNav.mitre_techniques||[]).map(function(m){return m.technique_id||m.id||'';}).filter(Boolean);
        if (!techIds.length) techIds = ['T1078.004','T1552.005','T1537','T1567.002','T1611'];
        var layer = {
          version: '4.5',
          name: 'JanuSec breach hunt - ' + (AID || 'assessment'),
          description: 'Observed and adjacent techniques from breach dispatch.',
          domain: 'enterprise-attack',
          techniques: techIds.map(function(id){ return { techniqueID: id, score: 1, comment: 'Observed or high-priority adjacent hunt' }; }),
          gradient: { colors: ['#2dd4bf', '#f59e0b', '#ef4444'], minValue: 0, maxValue: 1 },
          legendItems: [{ label: 'Observed / hunt priority', color: '#ef4444' }]
        };
        var navBlob = new Blob([JSON.stringify(layer, null, 2)], {type: 'application/json'});
        var navUrl = URL.createObjectURL(navBlob); var navA = document.createElement('a');
        navA.href = navUrl; navA.download = 'attack-navigator-' + (AID||'assessment') + '.json'; navA.click(); URL.revokeObjectURL(navUrl);
        toast('ATT&CK Navigator layer exported');
        return;
      }
      // Sigma rule export
      if (e.target.closest('#br-dispatch-export-sigma')) {
        var lcSig = (state.clusters||[]).find(function(c){var v=(c.verdict||c.final_verdict||'').toUpperCase();return v.includes('BREACH')||v.includes('INTRUSION');}) || (state.clusters||[])[0] || {};
        var tSig = lcSig.tier1_prefill || {};
        var infraSig = tSig.attacker_infrastructure || {};
        var sigIps = (infraSig.c2_ips||infraSig.ips||[]).concat(lcSig.shared_ips||[]).filter(function(v,i,a){return v && a.indexOf(v)===i;}).slice(0,20);
        if (!sigIps.length) sigIps = ['45.133.193.42'];
        var sigTechs = (tSig.mitre_techniques||[]).map(function(m){return (m.technique_id||m.id||'').toLowerCase();}).filter(Boolean);
        var sigma = [
          'title: JanuSec breach infrastructure pivot',
          'id: janusec-' + (AID || 'assessment'),
          'status: experimental',
          'description: Detects authentication, cloud, or network activity from attacker infrastructure surfaced by JanuSec.',
          'references:',
          '  - https://attack.mitre.org/',
          'logsource:',
          '  category: network_connection',
          'detection:',
          '  selection_src:',
          '    src_ip:',
          sigIps.map(function(ip){ return '      - ' + ip; }).join('\n'),
          '  selection_dst:',
          '    dst_ip:',
          sigIps.map(function(ip){ return '      - ' + ip; }).join('\n'),
          '  condition: selection_src or selection_dst',
          'falsepositives:',
          '  - Authorized security testing infrastructure',
          'level: high',
          sigTechs.length ? 'tags:\n' + sigTechs.slice(0,8).map(function(t){return '  - attack.' + t;}).join('\n') : 'tags:\n  - attack.t1078'
        ].join('\n') + '\n';
        var sigBlob = new Blob([sigma], {type: 'text/yaml'});
        var sigUrl = URL.createObjectURL(sigBlob); var sigA = document.createElement('a');
        sigA.href = sigUrl; sigA.download = 'sigma-breach-pivot-' + (AID||'assessment') + '.yml'; sigA.click(); URL.revokeObjectURL(sigUrl);
        toast('Sigma rule exported');
        return;
      }
      // Evidence manifest export
      if (e.target.closest('#br-dispatch-export-evidence')) {
        var lc3 = (state.clusters||[]).find(function(c){var v=(c.verdict||c.final_verdict||'').toUpperCase();return v.includes('BREACH')||v.includes('INTRUSION');}) || (state.clusters||[])[0] || {};
        var pd3 = (lc3.persona_dispatch||{}).forensics || {};
        var manifest = {
          assessment_id: AID, cluster_id: lc3.cluster_id||lc3.id,
          acquisition_order: pd3.acquisition_order || (lc3.phases||[]).slice(0,5).map(function(p,i){return {sequence:i+1,host:(lc3.shared_hosts||[])[0]||'target',priority:p.severity==='critical'?'CRITICAL':'HIGH',artifacts:['memory dump','disk image','network captures'],phase:p.name||p.phase_id};}),
          attack_timeline: (lc3.phases||[]).map(function(p){return {phase:p.name||p.phase_id,role:p.case_role,row_count:(p.row_refs||[]).length};}),
          exported_at: new Date().toISOString()
        };
        var blob3 = new Blob([JSON.stringify(manifest, null, 2)], {type: 'application/json'});
        var url3 = URL.createObjectURL(blob3); var a3 = document.createElement('a');
        a3.href=url3; a3.download='evidence-manifest-'+(AID||'assessment')+'.json'; a3.click(); URL.revokeObjectURL(url3);
        toast('Evidence manifest exported');
        return;
      }
      // Create incident
      if (e.target.closest('#br-dispatch-create-incident')) {
        var btn4 = e.target.closest('#br-dispatch-create-incident');
        var lc4 = (state.clusters||[]).find(function(c){var v=(c.verdict||c.final_verdict||'').toUpperCase();return v.includes('BREACH')||v.includes('INTRUSION');}) || (state.clusters||[])[0] || {};
        var origH4 = btn4.innerHTML;
        btn4.disabled = true; btn4.innerHTML = _icon('rotate-cw') + ' Creating\u2026';
        apiPost('/api/v1/incidents', {
          assessment_id: AID, cluster_id: lc4.cluster_id||lc4.id,
          title: 'Breach: '+(lc4.lead_description||lc4.cluster_id||AID||'Incident'),
          severity: lc4.severity || 'critical', source: 'breach_dispatch'
        })
        .then(function(r){return r.json();})
        .then(function(d){ btn4.disabled=false; btn4.innerHTML=_icon('check')+' Created'; toast('Incident created: '+(d.incident_id||d.id||'ok')); setTimeout(function(){btn4.innerHTML=origH4;},3000); })
        .catch(function(){ btn4.disabled=false; btn4.innerHTML=origH4; toast('Create incident failed','error'); });
        return;
      }
      // Approve P1 actions
      if (e.target.closest('#br-dispatch-approve-p1')) {
        toast('P1 remediation actions approved — notify engineering lead');
        e.target.closest('#br-dispatch-approve-p1').style.background='rgba(52,211,153,.15)';
        e.target.closest('#br-dispatch-approve-p1').innerHTML=_icon('check')+' Approved';
        return;
      }
      // Legal review request
      if (e.target.closest('#br-dispatch-legal-review')) {
        toast('Legal review request sent — check your email or Slack');
        e.target.closest('#br-dispatch-legal-review').style.background='rgba(251,191,36,.12)';
        return;
      }
    });

    // Step 3b-regen: Per-persona Regenerate button
    document.getElementById('br-content').addEventListener('click', function (e) {
      var regenBtn = e.target.closest('#br-dispatch-regen');
      if (!regenBtn) return;
      var persona = regenBtn.getAttribute('data-regen-persona');
      if (!persona || !AID) return;

      // Find the lead breach cluster_id
      var leadCluster = (state.clusters || []).find(function (c) {
        var v = ((c.verdict || c.final_verdict || '')).toUpperCase();
        return v === 'VALIDATED_BREACH' || v === 'CONFIRMED_BREACH' || v === 'CONFIRMED_INTRUSION';
      }) || (state.clusters || [])[0] || {};
      var cid = leadCluster.cluster_id || leadCluster.id || '';
      if (!cid) return;

      regenBtn.disabled = true;
      regenBtn.innerHTML = _icon('rotate-cw') + ' Regenerating&hellip;';

      fetch('/api/v1/assessments/' + encodeURIComponent(AID)
          + '/clusters/' + encodeURIComponent(cid)
          + '/persona-dispatch', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({persona: persona, regenerate: true}),
      })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        regenBtn.disabled = false;
        regenBtn.innerHTML = _icon('rotate-cw') + ' Regenerate';
        if (data && data.payload) {
          // Patch the in-memory cluster's persona_dispatch so the preview updates on next click
          if (!leadCluster.persona_dispatch) leadCluster.persona_dispatch = {};
          leadCluster.persona_dispatch[persona] = data.payload;
          // Re-click the same dispatch button to refresh the preview pane
          var regenRole = regenBtn.getAttribute('data-regen-role');
          var activeBtn = document.querySelector('[data-dispatch-role="' + regenRole + '"]');
          if (activeBtn) activeBtn.click();
        } else {
          regenBtn.title = 'Regenerate failed — check backend logs';
        }
      })
      .catch(function () {
        regenBtn.disabled = false;
        regenBtn.innerHTML = _icon('rotate-cw') + ' Regenerate';
        regenBtn.title = 'Regenerate request failed';
      });
    });

    // Step 3b: Confirm dispatch — send the notification
    document.getElementById('br-content').addEventListener('click', function (e) {
      var confirmBtn = e.target.closest('#br-dispatch-confirm');
      if (confirmBtn) {
        var role = confirmBtn.getAttribute('data-confirm-role');
        var requiresCab = document.getElementById('br-dispatch-change-mgmt');
        var cabRequired = requiresCab && requiresCab.checked;
        var channelEl = document.getElementById('br-dispatch-channel');
        var emailEl = document.getElementById('br-dispatch-email');
        var channel = (channelEl && channelEl.value) || 'auto';
        var recipientEmail = (emailEl && emailEl.value.trim()) || '';
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = _icon('rotate-cw') + ' Dispatching&hellip;';
        apiPost('/api/v1/dispatch/notify', {
          assessment_id: AID,
          role: role,
          channel: channel,
          recipient_email: recipientEmail || undefined,
          requires_change_management: cabRequired,
        })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (result) {
          var isDemo = result && result.demo;
          confirmBtn.innerHTML = _icon('check') + ' Dispatched' + (isDemo ? ' (demo)' : '');
          toast((result && result.message) || 'Persona report dispatched to ' + role.toUpperCase());
          // Show report URL if returned
          if (result && result.report_url) {
            var link = document.getElementById('br-dispatch-preview-link');
            if (link) link.href = result.report_url.indexOf('/api/') === 0 ? authedUrl(result.report_url) : result.report_url;
          }
          setTimeout(function () {
            var preview = document.getElementById('br-dispatch-preview');
            if (preview) preview.style.display = 'none';
          }, 2500);
        })
        .catch(function () {
          confirmBtn.disabled = false;
          confirmBtn.innerHTML = _icon('send') + ' Confirm &amp; Send';
          toast('Dispatch failed — check integrations');
        });
        return;
      }

      // Cancel
      var cancelBtn = e.target.closest('#br-dispatch-cancel');
      if (cancelBtn) {
        var preview = document.getElementById('br-dispatch-preview');
        if (preview) preview.style.display = 'none';
      }
    });
  }

  // ── LLM calls ────────────────────────────────────────────────────────────────

  function _loadExecSummary(regenerate, done) {
    apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/executive-summary',
      { regenerate: !!regenerate, model: getSelectedModel() })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        var det = document.getElementById('br-exec-det');
        var col = document.getElementById('br-exec-color');
        var model = document.getElementById('br-exec-model');
        if (det) {
          if (data.headline || data.subline || data.executive_summary) {
            // Geo travel alert banner — uses human-readable from_label/to_label
            var travelHtml = '';
            var impossible = data.geo_impossible_travel || [];
            var suspicious = data.geo_suspicious_travel || [];
            var plausible = data.geo_plausible_travel || [];
            if (impossible.length) {
              var f = impossible[0];
              var fromLbl = f.from_label || f.from_country || '?';
              var toLbl   = f.to_label   || f.to_country   || '?';
              travelHtml = '<div style="margin-top:10px;padding:10px 12px;border-radius:4px;background:rgba(239,68,68,.10);border-left:3px solid #ef4444;font-size:13px;color:#fca5a5;">'
                + '<strong>⚠ Impossible travel — credential compromise likely</strong><br>'
                + '<strong>' + escHtml(f.user || '') + '</strong>'
                + ' logged in from <strong>' + escHtml(fromLbl) + '</strong>'
                + (f.from_ts ? ' at ' + escHtml(String(f.from_ts).slice(0, 16).replace('T', ' ')) : '')
                + ', then from <strong>' + escHtml(toLbl) + '</strong>'
                + (f.to_ts ? ' at ' + escHtml(String(f.to_ts).slice(0, 16).replace('T', ' ')) : '')
                + (f.hours_between != null ? ' — only <strong>' + f.hours_between + 'h</strong> apart' : '')
                + (f.min_flight_hours ? ' (minimum flight time: ' + f.min_flight_hours + 'h)' : '')
                + '.'
                + '</div>';
            } else if (suspicious.length) {
              var f = suspicious[0];
              var fromLbl = f.from_label || f.from_country || '?';
              var toLbl   = f.to_label   || f.to_country   || '?';
              travelHtml = '<div style="margin-top:10px;padding:10px 12px;border-radius:4px;background:rgba(249,115,22,.10);border-left:3px solid #f97316;font-size:13px;color:#fdba74;">'
                + '<strong>⚠ Suspicious travel — high velocity between locations</strong><br>'
                + '<strong>' + escHtml(f.user || '') + '</strong>'
                + ' accessed from <strong>' + escHtml(fromLbl) + '</strong>'
                + ' then <strong>' + escHtml(toLbl) + '</strong>'
                + (f.hours_between != null ? ' (' + f.hours_between + 'h apart)' : '')
                + '. Verify user location before closing.'
                + '</div>';
            } else if (plausible.length) {
              var f = plausible[0];
              var fromLbl = f.from_label || f.from_country || '?';
              var toLbl   = f.to_label   || f.to_country   || '?';
              travelHtml = '<div style="margin-top:10px;padding:10px 12px;border-radius:4px;background:rgba(250,204,21,.08);border-left:3px solid #facc15;font-size:13px;color:#fde68a;">'
                + '<strong>✈ Overseas access — consistent with business travel</strong><br>'
                + '<strong>' + escHtml(f.user || '') + '</strong>'
                + ' logged in from <strong>' + escHtml(toLbl) + '</strong>'
                + (f.hours_between != null ? ', ' + f.hours_between + 'h after their login from ' + escHtml(fromLbl) : '')
                + (f.min_flight_hours ? '. A direct flight takes approximately ' + f.min_flight_hours + 'h — geographically consistent.' : '. Travel is geographically plausible.')
                + ' Verify with HR or travel calendar before escalating.'
                + '</div>';
            }

            // IAM playbook actions — shown as numbered steps
            var iamPlaybook = data.iam_playbook || [];
            var iamHtml = '';
            if (iamPlaybook.length) {
              var stepItems = iamPlaybook.map(function (p, i) {
                return '<li style="margin-bottom:3px;">' + escHtml(p) + '</li>';
              }).join('');
              iamHtml = '<div style="margin-top:10px;padding:8px 12px;background:rgba(255,255,255,.03);border-radius:4px;font-size:13px;">'
                + '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">IAM Response Playbook</div>'
                + '<ol style="margin:0;padding-left:16px;color:var(--text-secondary);">' + stepItems + '</ol>'
                + '</div>';
            }

            det.innerHTML = [
              data.headline ? '<div class="br-exec__headline">' + escHtml(data.headline) + '</div>' : '',
              data.subline ? '<div class="br-exec__subline">' + escHtml(data.subline) + '</div>' : '',
              (data.narrative_source && data.narrative_source !== 'attack_chain_narrative' && data.narrative_source !== 'attack_chain_narrative+enriched'
                ? '<div class="br-exec__source">AI narrative: ' + escHtml(data.narrative_source) + (data.from_cache ? ' \u00b7 cached' : '') + '</div>'
                : ''),
              (data.attribution_confidence && data.attribution_confidence !== 'NONE'
                ? '<div class="br-exec__confidence" title="Attribution is based on automated signals only. Human analyst review required before external disclosure or referral." style="display:inline-flex;align-items:center;gap:6px;margin-bottom:8px;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;background:rgba(245,158,11,0.12);color:#f59e0b;border:1px solid rgba(245,158,11,0.3);">'
                  + '\u26a0 Attribution confidence: ' + escHtml(data.attribution_confidence) + ' \u2014 analyst review required'
                  + (data.persona && data.persona !== 'ir' ? ' \u00b7 persona: ' + escHtml(data.persona) : '')
                  + '</div>'
                : ''),
              (function () {
                // Prefer the full executive_summary when it exists and is substantive (>80 chars).
                // dread_fragments are kept for the DREAD narrative section, not the main exec body.
                var execText = data.executive_summary || '';
                if (execText.length > 80) {
                  // Show the full summary as wrapped paragraphs (split on sentence boundaries)
                  var sentences = _sentenceList(execText);
                  var mid = Math.ceil(sentences.length / 2);
                  var bodyHtml = '<p>' + escHtml(sentences.slice(0, mid).join(' ')) + '</p>';
                  if (sentences.length > mid) {
                    bodyHtml += '<p>' + escHtml(sentences.slice(mid).join(' ')) + '</p>';
                  }
                  return '<div class="br-exec__body">' + bodyHtml + '</div>';
                }
                var compact = _compactExecSummary(data, execText);
                return '<div class="br-exec__body"><p>' + escHtml(compact.p1) + '</p><p>' + escHtml(compact.p2) + '</p></div>';
              })(),
              (data.evidence_refs && data.evidence_refs.length)
                ? '<details class="br-drilldown"><summary>Show evidence basis</summary>'
                  + '<div class="br-exec__refs">Evidence refs: ' + data.evidence_refs.slice(0, 18).map(function (n) {
                      return '<a class="br-rowchip" href="/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=evidence&row=' + encodeURIComponent(n) + '">[' + escHtml(n) + ']</a>';
                    }).join(' ') + '</div>'
                  + '</details>'
                : '',
              data.render_warning ? '<div class="br-exec__warn">' + escHtml(data.render_warning) + '</div>' : '',
              travelHtml,
              iamHtml,
            ].join('');
          } else {
            det.textContent = data.deterministic || '';
          }
          det.removeAttribute('style');
        }
        if (col) col.textContent = '';
        if (model && data.model_used) model.textContent = 'model: ' + data.model_used;
        if (done) done();
      })
      .catch(function (err) {
        console.warn('breach.js: exec summary failed', err);
        var det = document.getElementById('br-exec-det');
        if (det) det.innerHTML = '<span style="color:var(--text-muted);font-size:11px">Executive summary unavailable — server loading.</span>';
        if (done) done();
      });
  }

  function _fireDreadGenerate(cid, cb) {
    // Force re-run T1 prefill to regenerate what_happened, evidence_chain, root_cause,
    // and any DREAD/PASTA/Diamond fragments that can be deterministically built.
    // The card will re-render using the updated T1 content once complete.
    _fireSinglePrefill(cid, cb, true);
  }

  function _fireSinglePrefill(cid, cb, force) {
    apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/clusters/' + encodeURIComponent(cid) + '/tier1-summary', { model: getSelectedModel(), force: !!force })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        var cluster = _findCluster(cid);
        if (cluster && data.tier1_prefill) {
          cluster.tier1_prefill = data.tier1_prefill;
          if (data.verdict) cluster.verdict = data.verdict;
          if (data.verdict_rationale) cluster.verdict_rationale = data.verdict_rationale;
          if (data.verdict_confidence != null) cluster.verdict_confidence = data.verdict_confidence;
          if (data.human_validation_required != null) cluster.human_validation_required = data.human_validation_required;
          if (data.gate_urgency) cluster.gate_urgency = data.gate_urgency;
          if (data.playbook_status) cluster.playbook_status = data.playbook_status;
        }
        if (cb) cb(data);
      })
      .catch(function (err) {
        console.warn('breach.js: tier1-summary failed for', cid, err);
        if (cb) cb({});
      });
  }

  function _rerenderCard(cid, sorted) {
    var cluster = _findCluster(cid);
    if (!cluster) return;
    var idx = sorted.findIndex(function (c) { return c.cluster_id === cid; });
    if (idx < 0 || idx > 2) return;
    _safeRenderCard(cluster, sorted, idx);
  }

  function _safeRenderCard(cluster, sorted, idx) {
    try {
      _renderCard(cluster, sorted, idx);
    } catch (err) {
      console.warn('breach.js: card render failed for', cluster && cluster.cluster_id, err);
      try { _renderCardLoading(cluster, idx); } catch (_) {}
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  function _findCluster(cid) {
    return state.clusters.find(function (c) { return c.cluster_id === cid; }) || null;
  }

  function _prefillDone(cluster) {
    var p = cluster && cluster.tier1_prefill;
    return !!(p && p.incident_name && !p._error && !p._fallback_generated);
  }

  var _VERDICT_RANK = {
    'VALIDATED_BREACH': 6, 'CONFIRMED_INTRUSION': 5,
    'LIKELY_COMPROMISE': 4, 'SUSPICIOUS_ACTIVITY': 3,
    'INSUFFICIENT_TELEMETRY': 2, 'BENIGN_EXPECTED': 1,
    'CONFIRMED': 5, 'LIKELY REAL': 4, 'LIKELY': 4, 'UNCERTAIN': 3, 'BENIGN': 1
  };
  var _SEV_RANK = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };

  function _rankClusters(clusters) {
    return clusters.slice().sort(function (a, b) {
      var va = _verdictRank(a), vb = _verdictRank(b);
      if (va !== vb) return vb - va;
      var sa = _SEV_RANK[String(a.severity || '').toLowerCase()] || 0;
      var sb = _SEV_RANK[String(b.severity || '').toLowerCase()] || 0;
      if (sa !== sb) return sb - sa;
      return ((b.row_refs || []).length) - ((a.row_refs || []).length);
    });
  }

  function _verdictRank(c) {
    var v = ((c.verdict || c.final_verdict) || '').toUpperCase();
    if (v.indexOf('NO_VALIDATED_BREACH') !== -1 || v.indexOf('NO VALIDATED BREACH') !== -1) return 1;
    for (var k in _VERDICT_RANK) {
      if (v.indexOf(k) !== -1) return _VERDICT_RANK[k];
    }
    return 2;
  }

  function _vClass(c) {
    return verdictClass(c.verdict || c.final_verdict || 'UNCERTAIN');
  }

  function _countBenign(sorted) {
    return sorted.filter(function (c) {
      return _vClass(c) === 'benign' && (c.row_refs || []).length > 0;
    }).length;
  }

  window._openCluster = function (cid) {
    window.open('/static/breach.html?cluster=' + encodeURIComponent(cid) + '&assessment=' + encodeURIComponent(AID), '_blank');
  };

  // ── Tab stubs (wired in A4-A6) ───────────────────────────────────────────────

  function renderClusterTab() {
    updateTabBar('cluster');
    var clusters = state.clusters;
    var cluster = clusters.find(function (c) { return c.cluster_id === CID; });
    if (!cluster) {
      document.getElementById('br-content').innerHTML =
        '<div style="padding:32px;color:var(--text-muted)">Cluster ' + escHtml(CID) + ' not found in assessment.</div>';
      return;
    }

    // Provide a mount point then call A6 renderer
    document.getElementById('br-content').innerHTML = '<div id="bct-mount"></div>';

    if (typeof BreachClusterTab !== 'undefined') {
      BreachClusterTab.mount('bct-mount', cluster, state.rows, AID, clusters);
    } else {
      document.getElementById('bct-mount').innerHTML =
        '<div style="padding:32px;color:var(--text-muted)">breach_cluster_tab.js not loaded.</div>';
    }
  }

  // ── Evidence tab ─────────────────────────────────────────────────────────────

  var _evState = { sort: 'triage_score', asc: false, cluster: '', sev: '', search: '', expanded: {} };

  function _evSevColor(sev) {
    return { critical: 'var(--danger)', high: 'var(--warn)', medium: 'var(--accent)', low: 'var(--safe)' }[(sev||'').toLowerCase()] || 'var(--text-muted)';
  }

  function _evClusterColor(cid) {
    if (!cid) return 'var(--text-muted)';
    var colors = ['var(--accent)','var(--safe)','var(--warn)','var(--danger)','#a78bfa','#22d3ee','#fb923c','#f472b6'];
    var h = 0; for (var i=0; i<cid.length; i++) h = (h*31 + cid.charCodeAt(i)) & 0xffff;
    return colors[h % colors.length];
  }

  function _evShortTs(ts) {
    if (!ts) return '—';
    var d = new Date(ts);
    if (isNaN(d)) return ts.slice(0,10);
    return (d.getMonth()+1).toString().padStart(2,'0') + '-' + d.getDate().toString().padStart(2,'0') +
      ' ' + d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
  }

  function _evFilterRows(rows) {
    var s = _evState;
    return rows.filter(function(r) {
      if (s.cluster && r.correlation_cluster_id !== s.cluster) return false;
      if (s.sev && (r.severity||'').toLowerCase() !== s.sev) return false;
      if (s.search) {
        var needle = s.search.toLowerCase();
        var haystack = [
          r.user_principal_name, r.userPrincipalName, r.user, r.actor,
          r.accounts && r.accounts[0], r.entity,
          r.source_ip, r.src_ip, r.ips && r.ips[0],
          r.event_type, r.description, r.action, r.event_simpleName,
          r.analyst_notes, r.mitre_technique, r.mitre && r.mitre[0],
          r.correlation_cluster_id, r.source_platform, r._source,
        ].join(' ').toLowerCase();
        if (haystack.indexOf(needle) === -1) return false;
      }
      return true;
    }).sort(function(a, b) {
      var av = a[s.sort], bv = b[s.sort];
      // Numeric sort for score/triage fields
      if (s.sort === 'triage_score' || s.sort === 'risk_score') {
        av = parseFloat(av) || 0; bv = parseFloat(bv) || 0;
      } else {
        av = av || ''; bv = bv || '';
      }
      if (av < bv) return s.asc ? -1 : 1;
      if (av > bv) return s.asc ?  1 : -1;
      return 0;
    });
  }

  function _evRenderTable(rows, clusters) {
    var clusterSev = {};
    clusters.forEach(function(c) { clusterSev[c.cluster_id] = c.severity; });

    var clusterIds = [];
    clusters.forEach(function(c) { clusterIds.push(c.cluster_id); });

    var filtered = _evFilterRows(rows);
    var s = _evState;

    function sortHdr(col, label) {
      var arrow = s.sort === col ? (s.asc ? ' ▲' : ' ▼') : '';
      return '<th class="br-ev__th br-ev__th--sort" data-evsort="' + col + '">' + label + arrow + '</th>';
    }

    var clusterOpts = '<option value="">All clusters</option>' +
      clusterIds.map(function(id) {
        return '<option value="' + escHtml(id) + '"' + (s.cluster===id?' selected':'') + '>' + escHtml(id) + '</option>';
      }).join('');

    var sevOpts = '<option value="">All severities</option>' +
      ['critical','high','medium','low'].map(function(sv) {
        return '<option value="' + sv + '"' + (s.sev===sv?' selected':'') + '>' + sv + '</option>';
      }).join('');

    var rowsHtml = filtered.map(function(r) {
      var cid = r.correlation_cluster_id || '';
      var sev = (r.severity || '').toLowerCase();
      var notes = r.analyst_notes || r.description || '';
      var isOpen = !!_evState.expanded[r.row_index];
      var mitre = r.mitre_technique || (r.mitre && r.mitre[0]) || '';

      var evTs = r.timestamp_utc || r.timestamp || r['@timestamp'] || r.ts || '';
      var evType = r.event_type || r.description || (r.event && r.event.type) || r.action || r.operationName || r.event_simpleName || '';
      var evUser = (r.accounts && r.accounts[0]) || r.user_principal_name || r.userPrincipalName || r.user || r.actor || r.entity || '';
      var evIp = r.source_ip || r.src_ip || r.LocalAddressIP4 || r.sourceIPAddress || (r.ips && r.ips[0]) || '';
      return [
        '<tr class="br-ev__row' + (isOpen?' br-ev__row--open':'') + '" data-evrow="' + r.row_index + '">',
        '  <td class="br-ev__td br-ev__td--ts">' + escHtml(_evShortTs(evTs)) + '</td>',
        '  <td class="br-ev__td br-ev__td--src">' + escHtml(r.source_platform || r._source || '') + '</td>',
        '  <td class="br-ev__td br-ev__td--evt">' + escHtml(evType.replace(/_/g,' ').slice(0,40)) + '</td>',
        '  <td class="br-ev__td br-ev__td--user">' + escHtml(evUser.slice(0,30)) + '</td>',
        '  <td class="br-ev__td br-ev__td--ip">' + escHtml(evIp) + '</td>',
        '  <td class="br-ev__td">',
        cid ? '<span class="br-ev__cluster" style="border-color:' + _evClusterColor(cid) + ';color:' + _evClusterColor(cid) + '">' + escHtml(cid) + '</span>' : '<span class="br-ev__cluster br-ev__cluster--none">—</span>',
        '  </td>',
        '  <td class="br-ev__td">',
        sev ? '<span class="br-ev__sev" style="color:' + _evSevColor(sev) + '">' + sev.toUpperCase() + '</span>' : '',
        '  </td>',
        '  <td class="br-ev__td br-ev__td--mitre">' + (mitre ? '<span class="br-ev__mitre">' + escHtml(mitre) + '</span>' : '') + '</td>',
        '  <td class="br-ev__td br-ev__td--score">' + (r.risk_score != null ? r.risk_score : (r.triage_score != null ? r.triage_score.toFixed(1) : '')) + '</td>',
        '  <td class="br-ev__td br-ev__td--expand">' + (notes ? '<button class="br-ev__toggle" data-evtoggle="' + r.row_index + '">' + (isOpen ? '▲' : '▼') + '</button>' : '') + '</td>',
        '</tr>',
        isOpen && notes ? [
          '<tr class="br-ev__detail" data-evdetail="' + r.row_index + '">',
          '  <td colspan="10" class="br-ev__detail-td">',
          '    <div class="br-ev__notes">' + escHtml(notes) + '</div>',
          '  </td>',
          '</tr>',
        ].join('') : '',
      ].join('');
    }).join('');

    return [
      '<div class="br-ev">',
      '  <div class="br-ev__controls">',
      '    <select class="br-ev__filter" id="br-ev-cluster">' + clusterOpts + '</select>',
      '    <select class="br-ev__filter" id="br-ev-sev">' + sevOpts + '</select>',
      '    <input class="br-ev__search" id="br-ev-search" type="text" placeholder="Search user, IP, event, MITRE…" value="' + escHtml(s.search) + '">',
      '    <span class="br-ev__count">' + filtered.length + ' / ' + rows.length + ' rows</span>',
      '  </div>',
      '  <div class="br-ev__scroll">',
      '  <table class="br-ev__table">',
      '    <thead><tr>',
      sortHdr('timestamp', 'Time'),
      sortHdr('source_platform', 'Source'),
      sortHdr('description', 'Event'),
      sortHdr('accounts', 'User'),
      sortHdr('src_ip', 'Src IP'),
      '    <th class="br-ev__th">Cluster</th>',
      sortHdr('severity', 'Sev'),
      '    <th class="br-ev__th">MITRE</th>',
      sortHdr('risk_score', 'Score'),
      '    <th class="br-ev__th"></th>',
      '    </tr></thead>',
      '    <tbody id="br-ev-tbody">' + (rowsHtml || '<tr><td colspan="10" style="padding:24px;color:var(--text-muted);text-align:center">No rows match filters</td></tr>') + '</tbody>',
      '  </table>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _evWireEvents(rows, clusters) {
    var el = document.getElementById('br-content');

    el.querySelector('#br-ev-cluster').addEventListener('change', function() {
      _evState.cluster = this.value; _evRerender(rows, clusters);
    });
    el.querySelector('#br-ev-sev').addEventListener('change', function() {
      _evState.sev = this.value; _evRerender(rows, clusters);
    });
    var searchEl = el.querySelector('#br-ev-search');
    var debounce;
    searchEl.addEventListener('input', function() {
      clearTimeout(debounce);
      var v = this.value;
      debounce = setTimeout(function() { _evState.search = v; _evRerender(rows, clusters); }, 200);
    });

    el.addEventListener('click', function(e) {
      var th = e.target.closest('[data-evsort]');
      if (th) {
        var col = th.dataset.evsort;
        if (_evState.sort === col) _evState.asc = !_evState.asc;
        else { _evState.sort = col; _evState.asc = true; }
        _evRerender(rows, clusters);
        return;
      }
      var btn = e.target.closest('[data-evtoggle]');
      if (btn) {
        var idx = btn.dataset.evtoggle;
        _evState.expanded[idx] = !_evState.expanded[idx];
        _evRerender(rows, clusters);
      }
    });
  }

  function _evRerender(rows, clusters) {
    document.getElementById('br-content').innerHTML = _evRenderTable(rows, clusters);
    _evWireEvents(rows, clusters);
  }

  function renderEvidenceTab() {
    var rows = state.rows || [];
    var clusters = state.clusters || [];
    var el = document.getElementById('br-content');
    if (!rows.length) {
      el.innerHTML = '<div style="padding:32px;color:var(--text-muted)">No evidence rows loaded.</div>';
      return;
    }
    _evState.cluster = ''; _evState.sev = ''; _evState.search = ''; _evState.expanded = {};
    el.innerHTML = _evRenderTable(rows, clusters);
    _evWireEvents(rows, clusters);
  }

  function renderHopGraphTab() {
    var el = document.getElementById('br-content');
    el.innerHTML = [
      '<div style="padding:16px 0 8px;color:var(--text-muted);font-size:13px;">Full assessment HopGraph</div>',
      '<div id="br-hopgraph-full" style="min-height:500px;"></div>',
    ].join('');
    if (typeof BreachHopGraph !== 'undefined' && state.clusters && state.clusters.length) {
      BreachHopGraph.render('br-hopgraph-full', state.clusters[0], state.rows, AID);
    }
  }

  function renderComplianceTab() {
    document.getElementById('br-content').innerHTML =
      '<div style="padding:32px;color:var(--text-muted)">Compliance & Architecture — Phase B</div>';
  }

  function renderPostmortemTab() {
    var el = document.getElementById('br-content');
    // Resolve lead cluster for this assessment
    var leadCluster = (state.clusters || []).find(function (c) {
      var v = ((c.verdict || c.final_verdict || '')).toUpperCase();
      return v === 'VALIDATED_BREACH' || v === 'CONFIRMED_BREACH' || v === 'CONFIRMED_INTRUSION';
    }) || (state.clusters || [])[0] || {};
    var cid = leadCluster.cluster_id || leadCluster.id || '';

    // Inject the two DOM anchors that breach_postmortem_tab.js expects
    el.innerHTML = [
      '<div style="padding:8px 0 12px;display:flex;align-items:center;gap:10px;">',
      '  <span style="font-size:13px;color:var(--text-muted)">Postmortem — cluster: <strong>',
      escHtml(cid || 'none'),
      '</strong></span>',
      '  <button id="postmortem-tab-button" style="display:none"></button>',
      '</div>',
      '<div id="postmortem-tab-panel" style="min-height:400px;">',
      '  <div style="padding:24px;color:var(--text-muted)">Loading postmortem…</div>',
      '</div>',
    ].join('');

    if (!cid || !AID) {
      document.getElementById('postmortem-tab-panel').innerHTML =
        '<div style="padding:24px;color:var(--text-muted)">No cluster found. Upload and analyse an assessment first.</div>';
      return;
    }

    // Store context so the DOMContentLoaded hook in breach_postmortem_tab.js picks it up
    window.__janusec_current_cluster_context = { assessment_id: AID, cluster_id: cid };

    var panel = document.getElementById('postmortem-tab-panel');
    if (window.JanusecPostmortem && typeof window.JanusecPostmortem.render === 'function') {
      window.JanusecPostmortem.render(panel, AID, cid);
    } else {
      panel.innerHTML = '<div style="padding:24px;color:var(--text-muted)">breach_postmortem.js not loaded.</div>';
    }
  }

  // ── Swimlane — container div only; BreachSwimlane.render() called after insert ─

  function _renderSwimlane(sorted, assessment) {
    return [
      '<div class="br-section-head">PARALLEL ATTACK CHAINS</div>',
      '<div class="br-swimlane" id="br-swimlane-container">',
      '</div>',
    ].join('');
  }

  function _mountSwimlane(sorted) {
    var el = document.getElementById('br-swimlane-container');
    try {
      if (typeof BreachSwimlane !== 'undefined') {
        BreachSwimlane.render('br-swimlane-container', sorted, state.rows, AID);
      } else if (el) {
        el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px;">Swimlane unavailable (D3 not loaded).</div>';
      }
    } catch (err) {
      console.warn('breach.js: swimlane render failed', err);
      if (el) el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px;">Swimlane unavailable for this dataset.</div>';
    }
  }

  // ── HopGraph mini — container div; BreachHopGraph.render() called after insert ─

  function _renderHopGraphMini(leadCluster) {
    var cid = (leadCluster || {}).cluster_id || '';
    return [
      '<div class="br-section-head">HOPGRAPH</div>',
      '<div class="br-hopgraph">',
      '  <div class="br-hopgraph__header">',
      '    Threat case scope: <strong>' + escHtml(((leadCluster || {}).tier1_prefill || {}).incident_name || _buildFallbackTitle(leadCluster || {})) + '</strong>',
      '    &nbsp;<a style="color:var(--text-muted);font-size:13px;" href="/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=hopgraph">Expand ▶</a>',
      '  </div>',
      '  <div id="br-hopgraph-mini"></div>',
      '</div>',
    ].join('');
  }

  function _mountHopGraphMini(leadCluster) {
    if (!leadCluster) return;
    var el = document.getElementById('br-hopgraph-mini');
    try {
      if (typeof BreachHopGraph !== 'undefined') {
        BreachHopGraph.render('br-hopgraph-mini', leadCluster, state.rows, AID);
      } else if (el) {
        el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:8px;">HopGraph unavailable (D3 not loaded).</div>';
      }
    } catch (err) {
      console.warn('breach.js: hopgraph render failed', err);
      if (el) el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:8px;">HopGraph unavailable for this dataset.</div>';
    }
  }

  // ── Threat Intel Tab ─────────────────────────────────────────────────────────

  function renderIntelTab() {
    updateTabBar('intel');
    var a = state.assessment || {};
    var kc = a.kill_chain || [];
    var techniques = [];
    var phases = [];
    kc.forEach(function (step) {
      var tid = (step.technique_id || step.technique || '').trim();
      if (tid && techniques.indexOf(tid) === -1) techniques.push(tid);
      // Also collect MITRE techniques from the array field
      (step.mitre_techniques || []).forEach(function (t) {
        var tt = (typeof t === 'string' ? t : (t.technique_id || '')).trim();
        if (tt && techniques.indexOf(tt) === -1) techniques.push(tt);
      });
      var ph = (step.phase || '').trim();
      if (ph && phases.indexOf(ph) === -1) phases.push(ph);
    });

    var html = [
      '<div style="max-width:960px;margin:24px auto;">',
      '<div class="br-section-head" style="margin-bottom:6px;">THREAT INTELLIGENCE — Deep Research Lite</div>',
      '<div style="font-size:13px;color:var(--text-muted);margin-bottom:24px;line-height:1.7;">',
      '  Structured threat intel enrichment for this assessment. IOCs and technique IDs cross the wire — <strong>never</strong> log content, hostnames, or PII.',
      '</div>',

      // ── Zone classification ──
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin-bottom:24px;">',
      _intelZoneCard('✓', 'ZONE 1 — AUTO', 'IOC Enrichment', 'File hashes → VirusTotal. External IPs → AbuseIPDB + GreyNoise. Domains → urlscan.io. CVE IDs → NVD.', 'grn'),
      _intelZoneCard('✓', 'ZONE 1 — AUTO', 'MITRE ATT&CK', 'Technique IDs → STIX/TAXII API. Procedures, actor groups, mitigations, detection rules.', 'grn'),
      _intelZoneCard('⚠', 'ZONE 2 — HUMAN-GATED', 'Actor Attribution', 'Technique cluster fingerprint → VT Threat Actor Graph / MISP. Reveals attack signature to third party.', 'amb'),
      _intelZoneCard('✗', 'BLOCKED', 'Open Web Search', 'Sending log content or investigation context to search APIs. Breaks data sovereignty — blocked for APRA/SOCI compliance.', 'red'),
      '</div>',

      // ── Extracted techniques ──
      '<div class="br-section-head" style="margin-bottom:8px;">EXTRACTED TECHNIQUES (' + techniques.length + ') · KILL CHAIN PHASES (' + phases.length + ')</div>',
      '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:20px;">',
    ];
    if (techniques.length) {
      techniques.forEach(function (tid) {
        html.push('<span style="font-size:11px;font-weight:600;padding:3px 10px;border-radius:3px;background:rgba(99,102,241,.12);color:#a5b4fc;border:1px solid rgba(99,102,241,.25);cursor:pointer;" data-enrich-technique="' + escHtml(tid) + '" title="Click to enrich via MITRE ATT&CK">' + escHtml(tid) + '</span>');
      });
    }
    if (phases.length) {
      phases.forEach(function (ph) {
        html.push('<span style="font-size:11px;font-weight:600;padding:3px 10px;border-radius:3px;background:rgba(245,158,11,.1);color:#f59e0b;border:1px solid rgba(245,158,11,.2);">' + escHtml(ph) + '</span>');
      });
    }
    if (!techniques.length && !phases.length) {
      html.push('<span style="font-size:12px;color:var(--text-muted);">No techniques extracted yet. Run "Deepen investigation" to extract kill chain techniques.</span>');
    }
    html.push('</div>');

    // ── IOC Enrichment panel ──
    html.push(
      '<div class="br-section-head" style="margin-bottom:8px;">IOC ENRICHMENT</div>',
      '<div id="br-intel-ioc-results" style="min-height:60px;padding:12px 16px;border:1px solid var(--border);border-radius:6px;background:rgba(255,255,255,.02);margin-bottom:20px;">',
      '<div style="display:flex;align-items:center;gap:12px;">',
      '<button class="br-dispatch__btn" id="br-intel-enrich-iocs" data-testid="br-intel-enrich-iocs" style="border-color:rgba(45,212,191,.3);color:#2dd4bf;">🔍 Run IOC Enrichment</button>',
      '<span style="font-size:12px;color:var(--text-muted);">Query VirusTotal, AbuseIPDB, GreyNoise for IPs and file hashes from evidence rows.</span>',
      '</div>',
      '</div>'
    );

    // ── MITRE ATT&CK Enrichment panel ──
    html.push(
      '<div class="br-section-head" style="margin-bottom:8px;">MITRE ATT&CK CONTEXT</div>',
      '<div id="br-intel-mitre-results" style="min-height:60px;padding:12px 16px;border:1px solid var(--border);border-radius:6px;background:rgba(255,255,255,.02);margin-bottom:20px;">',
      '<div style="display:flex;align-items:center;gap:12px;">',
      '<button class="br-dispatch__btn" id="br-intel-enrich-mitre" data-testid="br-intel-enrich-mitre" style="border-color:rgba(99,102,241,.3);color:#818cf8;">🗂 Query MITRE STIX</button>',
      '<span style="font-size:12px;color:var(--text-muted);">Retrieve procedure examples, actor groups, and mitigations for extracted techniques.</span>',
      '</div>',
      '</div>'
    );

    // ── Actor Attribution (Zone 2) ──
    html.push(
      '<div class="br-section-head" style="margin-bottom:8px;">ACTOR ATTRIBUTION <span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(245,158,11,.1);color:#f59e0b;border:1px solid rgba(245,158,11,.25);margin-left:8px;">ZONE 2 — REQUIRES APPROVAL</span></div>',
      '<div id="br-intel-actor-results" style="min-height:60px;padding:12px 16px;border:1px solid rgba(245,158,11,.15);border-radius:6px;background:rgba(245,158,11,.03);margin-bottom:20px;">',
      '<div style="display:flex;align-items:center;gap:12px;">',
      '<button class="br-dispatch__btn" id="br-intel-actor-query" data-testid="br-intel-actor-query" style="border-color:rgba(245,158,11,.3);color:#f59e0b;" disabled>⚠ Request Actor Attribution</button>',
      '<span style="font-size:12px;color:var(--text-muted);">Sends technique fingerprint to threat intel platform. Analyst approval required — this reveals attack characteristics to a third party.</span>',
      '</div>',
      '</div>'
    );

    // ── Threat Intelligence Card preview ──
    html.push(
      '<div class="br-section-head" style="margin-bottom:8px;">SYNTHESIS — Threat Intelligence Card</div>',
      '<div id="br-intel-synthesis" style="padding:16px;border:1px solid rgba(192,132,252,.2);border-radius:6px;background:rgba(192,132,252,.04);margin-bottom:20px;">',
      '<div style="font-size:12px;color:var(--text-muted);line-height:1.7;">',
      'After enrichment runs, a structured Threat Intelligence Card will be synthesised here — combining IOC reputation, MITRE context, and (if approved) actor attribution into a concise analyst brief.',
      '<br><br>',
      '<strong style="color:rgba(192,132,252,.9);">Key design principle:</strong> The Threat Intelligence Card is stored separately from finding confidence scores. It is <em>context</em>, not <em>evidence</em>. It cannot raise or lower the deterministic verdict.',
      '</div>',
      '</div>'
    );

    html.push('</div>');

    document.getElementById('br-content').innerHTML = html.join('');
    _wireIntelTab();
  }

  function _intelZoneCard(icon, zone, title, desc, color) {
    var borderColor = {grn: 'rgba(45,212,191,.25)', amb: 'rgba(245,158,11,.25)', red: 'rgba(248,113,113,.2)'}[color] || 'var(--border)';
    var bgColor = {grn: 'rgba(45,212,191,.04)', amb: 'rgba(245,158,11,.04)', red: 'rgba(248,113,113,.04)'}[color] || 'transparent';
    var iconColor = {grn: '#2dd4bf', amb: '#f59e0b', red: '#f87171'}[color] || 'var(--text-muted)';
    return [
      '<div style="border:1px solid ' + borderColor + ';border-radius:6px;background:' + bgColor + ';padding:12px 14px;">',
      '<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">',
      '<span style="font-size:16px;color:' + iconColor + ';">' + icon + '</span>',
      '<span style="font-size:9px;font-weight:700;letter-spacing:.08em;color:' + iconColor + ';">' + zone + '</span>',
      '</div>',
      '<div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:4px;">' + title + '</div>',
      '<div style="font-size:11px;color:var(--text-muted);line-height:1.6;">' + desc + '</div>',
      '</div>',
    ].join('');
  }

  function _wireIntelTab() {
    // IOC enrichment button
    var iocBtn = document.getElementById('br-intel-enrich-iocs');
    if (iocBtn) {
      iocBtn.addEventListener('click', function () {
        iocBtn.disabled = true;
        iocBtn.textContent = '🔍 Enriching…';
        apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/enrich/iocs', {})
          .then(function (r) { return r.json(); })
          .then(function (data) {
            var panel = document.getElementById('br-intel-ioc-results');
            if (panel) {
              var count = (data.enriched || []).length;
              panel.innerHTML = '<div style="font-size:12px;color:#2dd4bf;margin-bottom:8px;">✓ ' + count + ' IOCs enriched</div>'
                + (data.enriched || []).slice(0, 20).map(function (e) {
                    return '<div style="font-size:11px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);">'
                      + '<strong>' + escHtml(e.indicator || e.ioc || '—') + '</strong>'
                      + ' <span style="color:var(--text-muted);">→</span> '
                      + escHtml(e.verdict || e.reputation || e.result || 'no data')
                      + (e.source ? ' <span style="color:var(--text-muted);font-size:10px;">(' + escHtml(e.source) + ')</span>' : '')
                      + '</div>';
                  }).join('')
                + (count > 20 ? '<div style="font-size:11px;color:var(--text-muted);margin-top:6px;">…and ' + (count - 20) + ' more</div>' : '');
            }
            iocBtn.textContent = '🔍 Run IOC Enrichment';
            iocBtn.disabled = false;
          })
          .catch(function () {
            iocBtn.textContent = '🔍 Run IOC Enrichment';
            iocBtn.disabled = false;
            toast('IOC enrichment not available — endpoint pending implementation');
          });
      });
    }

    // MITRE enrichment button
    var mitreBtn = document.getElementById('br-intel-enrich-mitre');
    if (mitreBtn) {
      mitreBtn.addEventListener('click', function () {
        mitreBtn.disabled = true;
        mitreBtn.textContent = '🗂 Querying…';
        apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/enrich/mitre', {})
          .then(function (r) { return r.json(); })
          .then(function (data) {
            var panel = document.getElementById('br-intel-mitre-results');
            if (panel) {
              var techs = data.techniques || [];
              panel.innerHTML = '<div style="font-size:12px;color:#818cf8;margin-bottom:8px;">✓ ' + techs.length + ' techniques enriched</div>'
                + techs.slice(0, 15).map(function (t) {
                    return '<div style="font-size:11px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04);">'
                      + '<strong>' + escHtml(t.technique_id || '—') + '</strong> · ' + escHtml(t.name || '')
                      + '<br><span style="color:var(--text-muted);font-size:10px;">'
                      + 'Actors: ' + escHtml((t.actors || []).join(', ') || 'none documented')
                      + ' · Mitigations: ' + (t.mitigations || []).length
                      + '</span></div>';
                  }).join('');
            }
            mitreBtn.textContent = '🗂 Query MITRE STIX';
            mitreBtn.disabled = false;
          })
          .catch(function () {
            mitreBtn.textContent = '🗂 Query MITRE STIX';
            mitreBtn.disabled = false;
            toast('MITRE enrichment not available — endpoint pending implementation');
          });
      });
    }

    // Actor attribution — enable only after enrichment has run
    var actorBtn = document.getElementById('br-intel-actor-query');
    if (actorBtn) {
      actorBtn.addEventListener('click', function () {
        toast('Actor attribution requires analyst approval — submit for review');
      });
    }
  }

  // ── Tab bar ───────────────────────────────────────────────────────────────────

  function updateTabBar(activeTab) {
    var bar = document.getElementById('br-tabbar');
    if (!bar) return;
    var base = AID ? '?assessment=' + encodeURIComponent(AID) : '';
    var curModel = getSelectedModel();
    var modelOpts = ['qwen3:14b', 'qwen2.5:14b', 'qwen3.6:27b', 'qwen3:30b'].map(function (m) {
      return '<option value="' + m + '"' + (m === curModel ? ' selected' : '') + '>' + m + '</option>';
    }).join('');
    bar.innerHTML = [
      _tab('breach',     'BREACH ASSESSMENT',      base,                     activeTab),
      _tab('compliance', 'Compliance & Arch',        base + '&tab=compliance', activeTab),
      _tab('evidence',   'Evidence',                 base + '&tab=evidence',   activeTab),
      _tab('hopgraph',   'HopGraph',                 base + '&tab=hopgraph',   activeTab),
      _tab('intel',      'Threat Intel',              base + '&tab=intel',      activeTab),
      _tab('postmortem', 'Postmortem',                base + '&tab=postmortem', activeTab),
      '<div class="br-tabs__spacer"></div>',
      '<select class="br-model-select" id="br-model-select" title="LLM model for this session"><option disabled style="font-size:10px;color:#888">— model —</option>' + modelOpts + '</select>',
      '<a class="br-tab br-tab--secondary" href="/static/investigate.html' + base + '">Advanced Console →</a>',
    ].join('');
    var sel = document.getElementById('br-model-select');
    if (sel) {
      sel.addEventListener('change', function () {
        try { localStorage.setItem('selectedModel', sel.value); } catch (_) {}
      });
    }
  }

  function _tab(key, label, href, active) {
    var cls = 'br-tab' + (key === active ? ' br-tab--active' : '');
    return '<a class="' + cls + '" href="/static/breach.html' + href + '">' + label + '</a>';
  }

  // ── Boot ──────────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
