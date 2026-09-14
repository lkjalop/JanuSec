// Extracted live console logic previously inlined in janusec-platform-complete-LIVE.html
// This file intentionally mirrors the original runtime behavior but is now external to avoid
// large inline blocks and to make Playwright waits deterministic via emitted events/markers.

(function(){
    // Minimal guards to avoid double-loading when the script is included multiple times
    if(window.__liveConsoleBundleLoaded) return; window.__liveConsoleBundleLoaded = true;

    // Re-export or define helpers used by the original inline code path
    // ensureNotifications and ensureParseHelpers were inline; rely on shared files being loaded

    // AttachActionHandlers stub (some handlers are extracted to other files)
    window.attachActionHandlers = function(){
        try {
            const btnRpt = document.getElementById('btnExportReport');
            if (btnRpt) btnRpt.addEventListener('click', exportInvestigationReport);
            const feed = document.getElementById('alertFeed');
            if (feed) feed.addEventListener('click', async (ev) => {
                const item = ev.target.closest('.alert-item');
                if (!item) return;
                const id = item.getAttribute('data-event-id');
                if (!id) return;
                openInvestigationDetails(id);
            });
            const invPanel = document.getElementById('investigationPanel');
            if (invPanel) invPanel.addEventListener('click', async () => {
                try {
                    const r = await (window.safeFetch || fetch)('/api/v1/decisions/recent?limit=1', { headers: authHeaders() });
                    let j = {};
                    try{ j = await r.json().catch(()=>({})); }catch(_){ }
                    if (!r.ok) {
                        const det = (j && (j.detail || j.error)) ? (j.detail || j.error) : ('HTTP ' + r.status);
                        showNotification('Failed to fetch recent decisions: ' + det, 'error');
                        return;
                    }
                    const row = j && (j.rows && j.rows[0] || j.events && j.events[0]);
                    const id = row ? (row.event_id || row.id) : null;
                    if (id) openInvestigationDetails(id); else showNotification('No recent decision available', 'error');
                } catch (e) {
                    showNotification('Failed to open investigation details', 'error');
                }
            });
            const loopIncident = document.getElementById('btnLoopIncident');
            const loopSbom = document.getElementById('btnLoopSbom');
            if(loopIncident) loopIncident.addEventListener('click', pushIncidentFromInvestigation);
            if(loopSbom) loopSbom.addEventListener('click', pushSbomFromInvestigation);
        } catch (e) { console.warn('attachActionHandlers failed', e); }
    };

    // Recreate small helper functions and event markers used by Playwright tests
    function _emitAdminReady(){ try{ let m = document.getElementById('admin_rules_ready'); if(!m){ m = document.createElement('div'); m.id = 'admin_rules_ready'; m.style.display='none'; document.body.appendChild(m); } m.setAttribute('data-ts', String(Date.now())); window.__adminRulesReady = true; window.dispatchEvent(new Event('admin-rules-ready')); }catch(_){ } }

    // Expose refreshData used by header buttons
    window.refreshData = function(){ showNotification('Refreshing data...'); setTimeout(()=>{ try{ if(window.updateMetrics) updateMetrics(); }catch(_){ } showNotification('Data refreshed successfully'); }, 1000); };

    function loopStatus(message, tone){
        const el = document.getElementById('loopClosureStatus');
        if(!el) return;
        el.style.color = tone === 'error' ? 'var(--critical)' : 'var(--text-muted)';
        el.textContent = message;
    }

    function renderLoopCoverage(ctx){
        const el = document.getElementById('loopCoverageHint');
        if(!el) return;
        if(!ctx || !ctx.evidence_summary){
            el.textContent = 'Evidence coverage target pending.';
            el.style.color = 'var(--text-muted)';
            return;
        }
        const summary = ctx.evidence_summary;
        const pct = Math.round((summary.coverage || summary.coverage_percent/100 || 0) * 100) / 1;
        const target = Math.round(((summary.policy && summary.policy.target) || summary.target || 0) * 100);
        el.textContent = `Evidence coverage ${pct}% (target ${target}%)`;
        const status = summary.status || (summary.meets_target ? 'ok' : 'gap');
        if(status === 'critical'){
            el.style.color = 'var(--critical)';
        } else if(status === 'warn' || status === 'gap'){
            el.style.color = 'var(--high)';
        } else {
            el.style.color = 'var(--text-muted)';
        }
    }

    function renderLoopPlaybook(ctx){
        const el = document.getElementById('loopPlaybookPreview');
        if(!el) return;
        if(!ctx || !ctx.playbook_preview){
            el.innerHTML = '<div class="small">Open an investigation to preview SOAR steps.</div>';
            return;
        }
        const pb = ctx.playbook_preview;
        const esc = window._htmlEsc || function(v){ return v; };
        const steps = (pb.steps || []).slice(0,3).map(step=>`<div style="margin-bottom:4px">• ${esc(step)}</div>`).join('') || '<div style="color:var(--text-muted)">Steps not provided.</div>';
        const domain = pb.domain ? `Domain: ${pb.domain.toUpperCase()}` : '';
        el.innerHTML = `
            <div style="font-weight:600;margin-bottom:4px">${esc(pb.summary || 'Playbook preview')}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">${esc(domain)}</div>
            ${steps}
        `;
    }

    window.addEventListener('investigation-context', function(ev){
        const ctx = ev && ev.detail ? ev.detail.context : null;
        renderLoopPlaybook(ctx);
        renderLoopCoverage(ctx);
    });
    if(window.__activeInvestigationContext){
        renderLoopPlaybook(window.__activeInvestigationContext);
        renderLoopCoverage(window.__activeInvestigationContext);
    }

    async function pushIncidentFromInvestigation(){
        const ctx = window.__activeInvestigationContext;
        if(!ctx || !ctx.eventId){
            loopStatus('Open an investigation first.', 'error');
            showNotification('Select an investigation before pushing incident','warn');
            return;
        }
        loopStatus('Sending incident...', 'info');
        const payload = {
            artifact_id: ctx.eventId,
            title: `Investigation ${ctx.eventId}`,
            severity: ctx.verdict && ctx.verdict !== 'unknown' ? ctx.verdict.toLowerCase() : 'medium',
            description: (ctx.summary || '').slice(0, 2000) || 'Investigation summary unavailable.',
            attack_subgraph: ctx.graph || ctx.explain?.graph_summary || null
        };
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/incidents', {
                method: 'POST',
                headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
                body: JSON.stringify(payload)
            });
            if(!resp.ok){
                const detail = await resp.json().catch(()=>({}));
                loopStatus(`Incident failed: ${detail.detail || resp.status}`, 'error');
                showNotification('Incident push failed','error');
                return;
            }
            loopStatus('Incident created.', 'success');
            showNotification('Incident pushed to /api/v1/incidents','success');
        }catch(err){
            console.error(err);
            loopStatus('Incident error: '+(err.message||err), 'error');
            showNotification('Incident push exception','error');
        }
    }

    async function pushSbomFromInvestigation(){
        const ctx = window.__activeInvestigationContext;
        if(!ctx || !ctx.eventId){
            loopStatus('Open an investigation first.', 'error');
            showNotification('Select an investigation before publishing SBOM delta','warn');
            return;
        }
        loopStatus('Publishing SBOM delta...', 'info');
        const component = {
            name: ctx.binary?.name || ctx.eventId,
            version: ctx.binary?.version || ctx.explain?.artifact_version || 'latest',
            hash: ctx.binary?.sha256 || ctx.explain?.sha256 || ctx.explain?.file_hash || '',
            verdict: ctx.verdict || 'unknown',
            tags: ctx.explain?.mapping_tags || undefined
        };
        const payload = { components: [component] };
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/sbom/upload', {
                method: 'POST',
                headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
                body: JSON.stringify(payload)
            });
            if(!resp.ok){
                const detail = await resp.json().catch(()=>({}));
                loopStatus(`SBOM push failed: ${detail.detail || resp.status}`, 'error');
                showNotification('SBOM delta failed','error');
                return;
            }
            loopStatus('SBOM delta published.', 'success');
            showNotification('SBOM delta submitted','success');
        }catch(err){
            console.error(err);
            loopStatus('SBOM error: '+(err.message||err), 'error');
            showNotification('SBOM delta exception','error');
        }
    }

    window.pushIncidentFromInvestigation = pushIncidentFromInvestigation;
    window.pushSbomFromInvestigation = pushSbomFromInvestigation;

    // Initialize platform - similar to original but tolerant of demo mode
    window.initializePlatform = async function(){
        try{
            showNotification('JanuSec Platform connecting to backend...', 'info');
            const healthResponse = await (window.safeFetch || fetch)('/health', { headers: { ...authHeaders() } });
            if (!healthResponse.ok) {
                if (healthResponse.status === 401 || healthResponse.status === 403) {
                    showAuthBanner({ message: 'Unauthorized (401/403) — your API key is missing or invalid.' });
                    throw new Error('Unauthorized');
                }
                throw new Error('Backend not available');
            }
            await updateMetrics();
            setInterval(updateMetrics, 30000);
            showNotification('JanuSec Platform initialized successfully - all systems connected!', 'success');
        } catch (error) {
            console.error('Backend connection failed:', error);
            showAuthBanner({ message: (error && String(error)) || 'Backend connection failed - running in demo mode' });
            showNotification('Backend connection failed - running in demo mode', 'error');
            try{ updateMetrics(); }catch(_){ }
        }
    };

    // Boot sequence - used by original document ready wiring
    window._boot = function(){ try{ renderNlpPanel && renderNlpPanel(); initializePlatform && initializePlatform(); attachActionHandlers && attachActionHandlers(); }catch(e){ console.error('boot failed', e); } };

    // Expose admin ready emitter for test hooks
    window._emitAdminReady = _emitAdminReady;

    // When loaded, if DOM is already ready, run _boot, else wait for DOMContentLoaded
    if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', window._boot); } else { window._boot(); }

    // Mark bundle loaded for Playwright deterministic waits
    try{ window.__liveConsoleReady = true; window.dispatchEvent(new Event('live-console-ready')); }catch(_){ }

})();
