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
                    const r = await fetch('/api/v1/decisions/recent?limit=1', { headers: authHeaders() });
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
        } catch (e) { console.warn('attachActionHandlers failed', e); }
    };

    // Recreate small helper functions and event markers used by Playwright tests
    function _emitAdminReady(){ try{ let m = document.getElementById('admin_rules_ready'); if(!m){ m = document.createElement('div'); m.id = 'admin_rules_ready'; m.style.display='none'; document.body.appendChild(m); } m.setAttribute('data-ts', String(Date.now())); window.__adminRulesReady = true; window.dispatchEvent(new Event('admin-rules-ready')); }catch(_){ } }

    // Expose refreshData used by header buttons
    window.refreshData = function(){ showNotification('Refreshing data...'); setTimeout(()=>{ try{ if(window.updateMetrics) updateMetrics(); }catch(_){ } showNotification('Data refreshed successfully'); }, 1000); };

    // Initialize platform - similar to original but tolerant of demo mode
    window.initializePlatform = async function(){
        try{
            showNotification('JanuSec Platform connecting to backend...', 'info');
            const healthResponse = await fetch('/health', { headers: { ...authHeaders() } });
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
