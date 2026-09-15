// Duplicate for production path: /static/js/metrics.js
// Proxy to the main /js/metrics.js content (kept inline for simplicity)
(function(){
    async function updateMetrics(){
        try{
            const r = await fetch('/api/v1/dashboard/metrics', { headers: authHeaders() });
            if (!r.ok) throw new Error('metrics_fetch_failed');
            const j = await r.json();
            const elC = document.getElementById('criticalCount'); if (elC) elC.textContent = j.critical_count ?? j.critical ?? 0;
            const elH = document.getElementById('highCount'); if (elH) elH.textContent = j.high_count ?? j.high ?? 0;
            const elM = document.getElementById('mediumCount'); if (elM) elM.textContent = j.medium_count ?? j.medium ?? 0;
            const elL = document.getElementById('lastUpdate'); if (elL) elL.textContent = j.last_update || new Date().toISOString();
        }catch(e){ console.warn('updateMetrics fallback', e && e.message); }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => { try{ updateMetrics(); }catch(e){}; setInterval(() => { try{ updateMetrics(); }catch(e){} }, 30000); });
    } else { try{ updateMetrics(); }catch(e){}; setInterval(() => { try{ updateMetrics(); }catch(e){} }, 30000); }
    window.updateMetrics = updateMetrics;
})();
