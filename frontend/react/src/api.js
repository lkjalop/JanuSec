// Canonical API base: prefer VITE_API_BASE (Vite) else current origin
export const apiBase = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE)
  ? import.meta.env.VITE_API_BASE
  : (window.location && window.location.origin ? window.location.origin : '');

function authHeaders() {
  const key = localStorage.getItem('apiKey');
  return key ? { 'x-api-key': key } : {};
}

export async function getJSON(path, options = {}) {
  const extraHeaders = options.headers || {};
  const base = apiBase.replace(/\/$/, '');
  const url = base + (path.startsWith('/') ? path : `/${path}`);
  const r = await fetch(url, { headers: { ...authHeaders(), ...extraHeaders } });
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}

export async function postJSON(path, body, options = {}) {
  const extraHeaders = options.headers || {};
  const base = apiBase.replace(/\/$/, '');
  const url = base + (path.startsWith('/') ? path : `/${path}`);
  const r = await fetch(url, { method:'POST', headers: { 'Content-Type': 'application/json', ...authHeaders(), ...extraHeaders }, body: JSON.stringify(body)});
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}

export function tenantHeaders(tenant) {
  return tenant ? { 'X-Tenant-ID': tenant } : {};
}

// Build absolute URL for SSE or WS using apiBase
export function sseUrl(path) {
  const base = apiBase.replace(/\/$/, '');
  const url = base + (path.startsWith('/') ? path : `/${path}`);
  return url;
}

export function wsUrl(path) {
  const abs = sseUrl(path);
  try {
    const u = new URL(abs);
    u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return u.toString();
  } catch {
    return abs;
  }
}
