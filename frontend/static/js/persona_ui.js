// Minimal persona UI helpers for LIVE console
// Functions: fetchPersonaView, previewAndSend, sendFeedback, fetchAttention

async function fetchPersonaView(reportId, persona='executive', disclosure_level=2, top_n=10) {
  const url = `/api/v1/reports/${reportId}/persona_view?persona=${encodeURIComponent(persona)}&disclosure_level=${disclosure_level}&top_n=${top_n}`;
  const headers = {};
  if (localStorage.apiKey) headers['x-api-key'] = localStorage.apiKey;
  const resp = await fetch(url, {headers});
  if (!resp.ok) throw new Error('Failed to load persona view');
  return await resp.json();
}

async function previewAndSend(reportId, recipients, format='html', include_model=false, disclosure_level=2, top_n=10) {
  // preview: fetch persona view then POST to send endpoint
  const personaView = await fetchPersonaView(reportId, 'executive', disclosure_level, top_n);
  // call send
  const resp = await fetch(`/api/v1/reports/${reportId}/send`, {
    method: 'POST',
    headers: Object.assign({'Content-Type': 'application/json'}, localStorage.apiKey ? {'x-api-key': localStorage.apiKey} : {}),
    body: JSON.stringify({recipients, format, include_model})
  });
  return await resp.json();
}

async function sendFeedback(reportId, feedback) {
  const resp = await fetch(`/api/v1/reports/${reportId}/feedback`, {
    method: 'POST',
    headers: Object.assign({'Content-Type': 'application/json'}, localStorage.apiKey ? {'x-api-key': localStorage.apiKey} : {}),
    body: JSON.stringify(feedback)
  });
  return await resp.json();
}

async function fetchAttention() {
  const headers = {};
  if (localStorage.apiKey) headers['x-api-key'] = localStorage.apiKey;
  const resp = await fetch('/api/v1/reports/attention', {headers});
  return await resp.json();
}

window.PersonaUI = {fetchPersonaView, previewAndSend, sendFeedback, fetchAttention};
