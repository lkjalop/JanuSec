export const apiBase = '';

function authHeaders() {
  const key = localStorage.getItem('apiKey');
  return key ? { 'x-api-key': key } : {};
}

export async function getJSON(path) {
  const r = await fetch(apiBase + path, { headers: authHeaders() });
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}

export async function postJSON(path, body) {
  const r = await fetch(apiBase + path, { method:'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(body)});
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}
