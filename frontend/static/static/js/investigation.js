// Duplicate for production path: /static/js/investigation.js
(function(){
    async function openInvestigationDetails(eventId){
        try{
            const overlay = document.getElementById('investigationModal');
            const content = document.getElementById('invDetailsContent');
            const badge = document.getElementById('invVerdictPill');
            const eid = document.getElementById('invEventId');
            if (eid) eid.textContent = eventId;
            if (overlay) overlay.style.display = 'flex';
            if (content) content.innerHTML = '<div class="evidence-item">Loading investigation details…</div>';
            const exR = await fetch(`/api/v1/decisions/${encodeURIComponent(eventId)}/explain`, { headers: authHeaders() });
            const explain = exR && exR.ok ? await exR.json() : null;
            if (badge) badge.textContent = `Verdict: ${explain && explain.verdict ? explain.verdict : 'UNKNOWN'}`;
            if (content) content.innerHTML = `<div class="evidence-item">Explain: <pre style="white-space:pre-wrap">${JSON.stringify(explain, null, 2)}</pre></div>`;
        }catch(e){
            console.error('openInvestigationDetails failed', e);
            const content = document.getElementById('invDetailsContent');
            if (content) content.innerHTML = `<div class="evidence-item">Failed to load details: ${e && e.message}</div>`;
        }
    }
    window.openInvestigationDetails = openInvestigationDetails;
})();
