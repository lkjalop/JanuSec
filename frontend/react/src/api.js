// Point frontend to backend FastAPI server during dev
export const apiBase = 'http://127.0.0.1:8080';

function authHeaders() {
  const key = localStorage.getItem('apiKey');
  return key ? { 'x-api-key': key } : {};
}

export async function getJSON(path, options = {}) {
  const extraHeaders = options.headers || {};
  const r = await fetch(apiBase + path, { headers: { ...authHeaders(), ...extraHeaders } });
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}

export async function postJSON(path, body, options = {}) {
  const extraHeaders = options.headers || {};
  const r = await fetch(apiBase + path, { method:'POST', headers: { 'Content-Type': 'application/json', ...authHeaders(), ...extraHeaders }, body: JSON.stringify(body)});
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}

export function tenantHeaders(tenant) {
  return tenant ? { 'X-Tenant-ID': tenant } : {};
}
