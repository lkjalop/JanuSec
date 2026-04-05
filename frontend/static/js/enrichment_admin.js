/* Small helpers to fetch enrichment jobs and CRQ observations for admin UI */
(function(window){
    'use strict';
    async function getEnrichJobs(){
        try{
            const r = await fetch('/api/v1/admin/enrichment/jobs', { headers: window.authHeaders ? window.authHeaders() : {}});
            if(!r.ok) return {source: 'error', jobs: []};
            return await r.json();
        }catch(e){ return {source:'error', jobs: []}; }
    }

    async function getRecentCrqObservations(limit=20, tenant=null){
        try{
            let url = '/api/v1/crq/recent?limit='+encodeURIComponent(String(limit));
            if(tenant) url += '&tenant='+encodeURIComponent(tenant);
            const r = await fetch(url, { headers: window.authHeaders ? window.authHeaders() : {} });
            if(!r.ok) return [];
            const j = await r.json();
            return j.observations || [];
        }catch(e){ return []; }
    }

    // small render helper for a container element: shows job key and next_run
    function renderEnrichJobs(containerId, data){
        const el = document.getElementById(containerId);
        if(!el) return;
        const jobs = data.jobs || [];
        el.innerHTML = jobs.map(j=>{
            const key = j.key || j.payload || 'unknown';
            const next = (j.data && j.data.next_run) ? new Date(Number(j.data.next_run)*1000).toLocaleString() : (j.next_run? new Date(Number(j.next_run)*1000).toLocaleString() : 'n/a');
            const backoff = (j.data && j.data.backoff) ? j.data.backoff : j.backoff || 0;
            return `<div class='enrich-job'><strong>${key}</strong> — next: ${next} backoff:${backoff}</div>`;
        }).join('');
    }

    window.enrichmentAdmin = { getEnrichJobs, getRecentCrqObservations, renderEnrichJobs };
})(window);
