(function () {
  'use strict';

  if (!localStorage.getItem('apiKey') && /localhost|127\.0\.0\.1/.test(window.location.hostname)) {
    try { localStorage.setItem('apiKey', 'devkey123'); } catch (_) {}
  }

  function apiBase() { return window.JANUSEC_API_BASE || ''; }

  function authHeaders() {
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
    try { return localStorage.getItem('selectedModel') || 'qwen3:14b'; } catch (_) { return 'qwen3:14b'; }
  }

  function apiFetch(path, opts) {
    return fetch(apiBase() + path, Object.assign({ headers: authHeaders() }, opts || {}));
  }

  function apiPost(path, body) {
    return apiFetch(path, {
      method: 'POST',
      body: JSON.stringify(body || {}),
    });
  }

  function authQuery() {
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
    var sep = path.indexOf('?') === -1 ? '?' : '&';
    return apiBase() + path + sep + authQuery();
  }

  function openAuthed(path) {
    window.open(authedUrl(path), '_blank', 'noopener');
  }

  window.JanuSecBreachAPI = {
    apiBase: apiBase,
    authHeaders: authHeaders,
    getSelectedModel: getSelectedModel,
    apiFetch: apiFetch,
    apiPost: apiPost,
    authQuery: authQuery,
    authedUrl: authedUrl,
    openAuthed: openAuthed
  };
})();
