// Extracted metrics logic (Phase 1)
(function(){
    async function updateMetrics(){
        try{
            // Minimal safe implementation: call dashboard/metrics and update header counts
            const r = await fetch('/api/v1/dashboard/metrics', { headers: authHeaders() });
            if (!r.ok) throw new Error('metrics_fetch_failed');
            const j = await r.json();
            const critical = j.critical_count ?? j.critical ?? 0;
            const high = j.high_count ?? j.high ?? 0;
            const medium = j.medium_count ?? j.medium ?? 0;
            const last = j.last_update || new Date().toISOString();
            const elC = document.getElementById('criticalCount'); if (elC) elC.textContent = critical;
            const elH = document.getElementById('highCount'); if (elH) elH.textContent = high;
            const elM = document.getElementById('mediumCount'); if (elM) elM.textContent = medium;
            const elL = document.getElementById('lastUpdate'); if (elL) elL.textContent = last;

            // Derive artifact & threat counts if available
            const artifacts = j.artifacts_total ?? j.artifacts ?? j.total_artifacts ?? null;
            if (artifacts !== null) {
                const aEl = document.getElementById('artifactsCount'); if (aEl) aEl.textContent = artifacts;
            }
            // Threat count could be sum of critical+high+medium if not explicit
            const threatsRaw = j.active_threats ?? j.threats ?? j.active ?? null;
            let threatsVal = threatsRaw;
            if (threatsVal === null || threatsVal === undefined) {
                const maybe = critical + high + medium;
                if (maybe > 0) threatsVal = maybe; else threatsVal = 0;
            }
            const tEl = document.getElementById('threatCount'); if (tEl) tEl.textContent = threatsVal;

            // Temporal EWMA sparkline: track a short history of temporal_avg_score for visualization
            try{
                const temporalAvg = (j.temporal_avg_score ?? j.temporal_avg ?? j.temporal) || 0;
                window._temporalSpark = window._temporalSpark || { data: [], maxLen: 40 };
                const s = window._temporalSpark;
                s.data.push(Number(temporalAvg) || 0);
                if(s.data.length > s.maxLen) s.data.splice(0, s.data.length - s.maxLen);
                drawTemporalSparkline(s.data);
            }catch(_err){ /* ignore spark errors */ }

            // Secondary status call for reconciliation (optional)
            try {
                const sr = await fetch('/api/v1/dashboard/status', { headers: authHeaders() });
                if (sr.ok) {
                    const sj = await sr.json();
                    // Prefer explicit totals if present
                    if (sj.artifacts_total && document.getElementById('artifactsCount')) {
                        document.getElementById('artifactsCount').textContent = sj.artifacts_total;
                    }
                    if (sj.active_threats && document.getElementById('threatCount')) {
                        document.getElementById('threatCount').textContent = sj.active_threats;
                    }
                    // Update severity counts if different
                    if (typeof sj.critical === 'number' && sj.critical !== critical) { const el = document.getElementById('criticalCount'); if (el) el.textContent = sj.critical; }
                    if (typeof sj.high === 'number' && sj.high !== high) { const el = document.getElementById('highCount'); if (el) el.textContent = sj.high; }
                    if (typeof sj.medium === 'number' && sj.medium !== medium) { const el = document.getElementById('mediumCount'); if (el) el.textContent = sj.medium; }
                }
            } catch (_err) { /* ignore reconciliation errors */ }
        }catch(_err){
            // noop fallback
            console.warn('updateMetrics fallback', _err && _err.message);
        }
    }

    // Simple canvas sparkline renderer (temporal avg)
    function drawTemporalSparkline(values){
        try{
            // Always create canvas element so tests can observe it even if values are empty
            if(!values) values = [];
            let card = document.getElementById('temporalMetricCard');
            if(!card) return;
            let canvas = card.querySelector('canvas.temporal-spark');
            if(!canvas){
                canvas = document.createElement('canvas');
                canvas.className = 'temporal-spark';
                canvas.width = 220; canvas.height = 28;
                canvas.style.width = '220px'; canvas.style.height = '28px';
                canvas.style.display = 'block'; canvas.style.marginTop = '6px';
                const label = document.createElement('div'); label.style.fontSize='11px'; label.style.color='var(--text-muted)'; label.textContent='Temporal EWMA';
                card.appendChild(label);
                card.appendChild(canvas);
            }
            const ctx = canvas.getContext('2d');
            const w = canvas.width; const h = canvas.height; ctx.clearRect(0,0,w,h);
            const maxv = Math.max(...values, 0.001); const minv = Math.min(...values, 0);
            const range = Math.max(0.0001, maxv - minv);
            ctx.lineWidth = 2; ctx.strokeStyle = 'rgba(74,99,231,0.9)'; ctx.beginPath();
            for(let i=0;i<values.length;i++){
                const x = Math.floor((i/(values.length-1||1))*(w-2))+1;
                const norm = (values[i]-minv)/range;
                const y = Math.floor(h - 2 - (norm*(h-4)));
                if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
            }
            ctx.stroke();
            // draw current dot
            const last = values[values.length-1]; const lx = Math.floor(((values.length-1)/(values.length-1||1))*(w-2))+1; const lnorm = (last-minv)/range; const ly = Math.floor(h - 2 - (lnorm*(h-4)));
            ctx.fillStyle = 'rgba(74,99,231,1)'; ctx.beginPath(); ctx.arc(lx, ly, 3, 0, Math.PI*2); ctx.fill();
            // mark canvas as drawn for deterministic tests
            try{ canvas.dataset.drawn = '1'; canvas.setAttribute('data-drawn','1'); window.__temporalDrawn = true; window.dispatchEvent(new Event('temporal-drawn')); }catch(_err){}
        }catch(_err){ console.warn('spark draw failed', _err); }
    }

    // Single scheduler: call once on DOMContentLoaded and every 30s
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => { try{ updateMetrics(); }catch(_err){}; setInterval(() => { try{ updateMetrics(); }catch(_err){} }, 30000); });
    } else {
        try{ updateMetrics(); }catch(_err){}; setInterval(() => { try{ updateMetrics(); }catch(_err){} }, 30000);
    }

    window.updateMetrics = updateMetrics;
})();
