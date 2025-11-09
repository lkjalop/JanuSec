// Fetch demo hunt overview and inject into the DOM. Non-blocking and resilient.
(async function(){
  try{
    const resp = await fetch('/api/v1/hunt/overview');
    if(!resp.ok) return;
    const j = await resp.json();
    const ov = j.overview || {};
    const wrap = document.querySelector('.wrap');
    if(!wrap) return;
    const card = document.createElement('div'); card.className='card';
    card.innerHTML = `
      <h3>Hunt Overview</h3>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <div class="muted">Decisions: <strong>${ov.recent_decisions||0}</strong></div>
        <div class="muted">Incidents: <strong>${ov.active_incidents||0}</strong></div>
        <div class="muted">Open Triage: <strong>${ov.open_triage_rows||0}</strong></div>
      </div>
      <div style="margin-top:8px" class="muted">Seeded snapshot (demo)</div>
    `;
    // place at top after nav
    const first = wrap.firstElementChild; if(first) wrap.insertBefore(card, first.nextSibling);
  }catch(_err){ /* best-effort */ }
})();
