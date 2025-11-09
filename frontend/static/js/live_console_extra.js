/* Extra Live Console helpers extracted from inline HTML for linting and maintainability */
(function(window, document){
    'use strict';

    function _htmlEsc(s){ try{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }catch(_err){ return '';} }

    // Render factors helper used by multiple panels
    function renderFactors(list, containerId){
        const container = document.getElementById(containerId || 'endpointMalwareFactors');
        if(!container) return;
        container.innerHTML = (list||[]).map(function(f){
            try{
                if(typeof f === 'string'){
                    const label = (f.split(':')[1]||f);
                    return "<span class='pill' title='"+_htmlEsc(f)+"'>"+_htmlEsc(label)+"</span>";
                } else if(typeof f === 'object' && f !== null){
                    const name = f.factor || f.name || 'factor';
                    const label = (String(name).split(':')[1]||name);
                    const meta = [];
                    if(f.score !== undefined) meta.push('score:'+f.score);
                    if(f.reason) meta.push('reason:'+f.reason);
                    if(f.mitre) meta.push('mitre:'+f.mitre);
                    if(f.tags) meta.push('tags:'+JSON.stringify(f.tags));
                    const title = meta.length ? meta.join(' | ') : JSON.stringify(f);
                    return "<span class='pill' title='"+_htmlEsc(title)+"'>"+_htmlEsc(label)+"</span>";
                } else { return ''; }
            }catch(_err){ return ''; }
        }).join('');
    }

    async function toggleIntegration(service, el){
        // prefer explicit element; avoid implicit global `event`
        const btn = el || (typeof window !== 'undefined' && window._lastEvent && window._lastEvent.target && window._lastEvent.target.closest ? window._lastEvent.target.closest('.integration-btn') : null);
        if(!btn) return;
        const shouldEnable = !btn.classList.contains('connected');
        try{
            const r = await fetch('/api/v1/integrations/'+encodeURIComponent(service)+'/toggle?enabled='+String(shouldEnable), { method: 'POST', headers: Object.assign({'Content-Type':'application/json'}, (window.authHeaders?window.authHeaders():{})) });
            let data = {};
            try{ data = await r.json(); }catch(_err){ data = {}; }
            if(!r.ok || data.error) throw new Error(data.error || 'toggle_failed');
            btn.classList.toggle('connected', shouldEnable);
            if(window.showNotification) window.showNotification(service.toUpperCase()+' '+(shouldEnable? 'connected':'disconnected'));
            if(shouldEnable && (service === 'slack' || service === 'teams' || service === 'whatsapp')){
                try{
                    const wr = await fetch('/api/v1/webhooks/test', { method:'POST', headers: Object.assign({'Content-Type':'application/json'}, (window.authHeaders?window.authHeaders():{})), body: JSON.stringify({service:service}) });
                    let wj = {};
                    try{ wj = await wr.json(); }catch(_err){ wj = {}; }
                    if(!wr.ok){ const det = (wj && (wj.detail||wj.error)) ? (wj.detail||wj.error) : ('HTTP '+wr.status); if(window.showNotification) window.showNotification('Webhook test failed: '+det,'error'); }
                }catch(_err){ console.error(_err); if(window.showNotification) window.showNotification('Webhook test failed: '+(_err.message||_err),'error'); }
            }
        }catch(e){ console.error(e); if(window.showNotification) window.showNotification('Failed to toggle '+service+': '+(e.message||e)); }
    }

    // Expose helpers
    window.liveConsoleExtra = window.liveConsoleExtra || {};
    window.liveConsoleExtra.renderFactors = renderFactors;
    window.toggleIntegration = toggleIntegration;
    // small escape util (used by some inline handlers)
    window._htmlEsc = _htmlEsc;

})(window, document);
