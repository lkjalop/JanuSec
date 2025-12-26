// Extracted investigation modal logic (Phase 1 + threat_model/controls/graph)
(function(){
    async function openInvestigationDetails(eventId, options){
        try{
            const overlay = document.getElementById('investigationModal');
            const content = document.getElementById('invDetailsContent');
            const factorPanel = document.getElementById('invFactorPanel');
            const badge = document.getElementById('invVerdictPill');
            const eid = document.getElementById('invEventId');
            if (eid) eid.textContent = eventId;
            if (overlay) overlay.style.display = 'flex';
            if (content) content.innerHTML = '<div class="evidence-item">Loading investigation details…</div>';
            const triggeredInsights = (options && options.correlation_insights) || null;

            const fetcher = window.safeFetch || fetch;
            const exR = await fetcher(`/api/v1/decisions/${encodeURIComponent(eventId)}/explain`, { headers: authHeaders() });
            const explain = exR && exR.ok ? await exR.json() : null;
            if (badge) badge.textContent = `Verdict: ${explain && explain.verdict ? explain.verdict : 'UNKNOWN'}`;
            try{
                const summary = explain?.narrative || explain?.narrative_text || explain?.summary || '';
                const graph = explain?.graph_summary || explain?.hopgraph_summary || null;
                const binaryMeta = (explain?.binary || explain?.artifact || {});
                const liveInsights = triggeredInsights || explain?.correlation_insights || null;
                window.__activeInvestigationContext = {
                    eventId,
                    verdict: explain?.verdict || 'unknown',
                    summary: typeof summary === 'string' && summary.trim() ? summary : JSON.stringify({ verdict: explain?.verdict, mitre: explain?.mitre, factors: explain?.factors?.slice?.(0,5) }, null, 2),
                    explain,
                    graph,
                    binary: binaryMeta,
                    playbook_preview: explain?.playbook_preview || null,
                    evidence_summary: explain?.evidence_summary || null,
                    correlation_insights: liveInsights || [],
                };
                try{
                    if(window.renderCorrelationInsightPanel){
                        window.renderCorrelationInsightPanel(liveInsights);
                    }
                }catch(_err){ }
            }catch(_err){
                window.__activeInvestigationContext = {
                    eventId,
                    explain,
                    playbook_preview: explain?.playbook_preview || null,
                    evidence_summary: explain?.evidence_summary || null,
                    correlation_insights: triggeredInsights || [],
                };
                try{
                    if(window.renderCorrelationInsightPanel){
                        window.renderCorrelationInsightPanel(triggeredInsights);
                    }
                }catch(_inner){}
            }
            try{
                window.dispatchEvent(new CustomEvent('investigation-context', { detail: { context: window.__activeInvestigationContext } }));
            }catch(_){}
            // Populate factor selection panel
            try {
                if (factorPanel) {
                    const factorsRaw = [];
                    if (Array.isArray(explain?.factors)) {
                        for (const f of explain.factors) {
                            if (typeof f === 'string') factorsRaw.push(f);
                            else if (f && typeof f === 'object') factorsRaw.push(f.name || f.type || f.id || JSON.stringify(f));
                        }
                    }
                    if (!factorsRaw.length && Array.isArray(explain?.correlation_factors)) {
                        for (const f of explain.correlation_factors) {
                            if (typeof f === 'string') factorsRaw.push(f);
                        }
                    }
                    const allUnique = Array.from(new Set(factorsRaw));
                    // Build meta map from explain.factors objects if available
                    const metaMap = {};
                    if (Array.isArray(explain?.factors)) {
                        for (const f of explain.factors) {
                            if (f && typeof f === 'object') {
                                const nm = f.name || f.type || f.id;
                                if (nm) metaMap[nm] = { domain: f.domain || null, precedence: f.precedence || null };
                            }
                        }
                    }
                    window._factorMetaMap = metaMap;
                    window._allInvestigationFactors = allUnique; // cache for search filtering
                    const display = allUnique.slice(0,40);
                    if (display.length) {
                        factorPanel.innerHTML = display.map(f=>{
                            const meta = metaMap[f] || {};
                            const domAttr = meta.domain ? ` data-domain="${meta.domain}"` : '';
                            const precAttr = meta.precedence != null ? ` data-precedence="${meta.precedence}"` : '';
                            return `<button type="button" class="factor-pill" data-factor="${f}"${domAttr}${precAttr}>${f}</button>`;
                        }).join('');
                        const drawer = document.getElementById('factorDetailsDrawer');
                        factorPanel.querySelectorAll('.factor-pill').forEach(btn=>{
                            btn.addEventListener('click', ()=>{ 
                                btn.classList.toggle('selected');
                                const fname = btn.getAttribute('data-factor');
                                // Fetch weight history sparkline (best-effort)
                                (window.safeFetch || fetch)(`/api/v1/factors/history/${encodeURIComponent(fname)}`, {headers: authHeaders()})
                                    .then(r=>r.ok? r.json():null)
                                    .then(j=>{
                                        if(!j||!Array.isArray(j.history)||!j.history.length) return;
                                        const vals = j.history.map(x=>x[1]);
                                        const min = Math.min(...vals), max = Math.max(...vals);
                                        const blocks = ['▁','▂','▃','▄','▅','▆','▇'];
                                        const spark = vals.slice(-20).map(v=>{
                                            const norm = max>min? (v-min)/(max-min):0;
                                            return blocks[Math.min(blocks.length-1, Math.floor(norm*(blocks.length)))];
                                        }).join('');
                                        btn.setAttribute('title', `history: ${spark}`);
                                        if(drawer){
                                            const meta = metaMap[fname] || {};
                                            drawer.style.display='block';
                                            drawer.innerHTML = `<div style="font-weight:600;margin-bottom:4px;">Factor: ${fname}</div>`
                                                + `<div style="font-size:11px;opacity:.8;">Domain: ${meta.domain||'n/a'} | Precedence: ${meta.precedence!=null?meta.precedence:'n/a'}</div>`
                                                + `<div style="font-size:11px;margin-top:4px;">Recent weights: ${spark}</div>`;
                                        }
                                    }).catch(()=>{});
                            });
                        });
                        // If more than 40 factors, show subtle note
                        if (allUnique.length > 40) {
                            const note = document.createElement('div');
                            note.style.cssText = 'width:100%;font-size:10px;opacity:.5;margin-top:4px;';
                            note.textContent = `Showing first 40 of ${allUnique.length} factors – use filter to narrow.`;
                            factorPanel.appendChild(note);
                        }
                    } else {
                        factorPanel.innerHTML = '<div style="font-size:11px;opacity:.6;">No factors surfaced</div>';
                    }
                    // Wire factor search filtering
                    const searchEl = document.getElementById('factorSearchInput');
                    const domainFilterEl = document.getElementById('factorDomainFilter');
                    // Populate domain filter options
                    if(domainFilterEl){
                        try {
                            const doms = Array.from(new Set(Object.values(metaMap).map(m=>m.domain).filter(Boolean))).sort();
                            doms.forEach(d=>{ const o=document.createElement('option'); o.value=d; o.textContent=d; domainFilterEl.appendChild(o); });
                        } catch(_err){ }
                    }
                    if (searchEl) {
                        searchEl.oninput = () => {
                            const term = (searchEl.value||'').trim().toLowerCase();
                            const domVal = domainFilterEl ? domainFilterEl.value : '';
                            const selectedBefore = new Set(Array.from(factorPanel.querySelectorAll('.factor-pill.selected')).map(el=>el.getAttribute('data-factor')));
                            const source = window._allInvestigationFactors || [];
                            let filtered = source.filter(f=>{
                                const textOk = !term || f.toLowerCase().includes(term);
                                const domOk = !domVal || (metaMap[f] && metaMap[f].domain === domVal);
                                return textOk && domOk;
                            });
                            // Limit render size to 120 to avoid huge DOM churn
                            const render = filtered.slice(0,120);
                            factorPanel.innerHTML = render.map(f=>`<button type="button" class="factor-pill" data-factor="${f}">${f}</button>`).join('');
                            factorPanel.querySelectorAll('.factor-pill').forEach(btn=>{
                                btn.addEventListener('click', ()=>{ btn.classList.toggle('selected'); });
                                const fv = btn.getAttribute('data-factor');
                                if (selectedBefore.has(fv)) btn.classList.add('selected');
                            });
                            if (filtered.length > render.length) {
                                const more = document.createElement('div');
                                more.style.cssText = 'width:100%;font-size:10px;opacity:.5;margin-top:4px;';
                                more.textContent = `Filtered ${filtered.length} factors – showing first ${render.length}. Refine search to narrow.`;
                                factorPanel.appendChild(more);
                            } else if (!render.length) {
                                const none = document.createElement('div');
                                none.style.cssText = 'width:100%;font-size:11px;opacity:.6;';
                                none.textContent = 'No matching factors';
                                factorPanel.appendChild(none);
                            }
                        };
                    }
                    if(domainFilterEl){ domainFilterEl.onchange = ()=>{ if(searchEl && searchEl.oninput) searchEl.oninput(); }; }
                }
            } catch(_err){ if(factorPanel) factorPanel.innerHTML = '<div style="font-size:11px;opacity:.6;">Factor load failed</div>'; }
            // Build quick badges for spikes/residuals and mapped techniques/tags
            let badgesHtml = '';
            try{
                const fx = Array.isArray(explain?.factors) ? explain.factors.map(f=>f.name||f) : [];
                const corr = Array.isArray(explain?.correlation_factors) ? explain.correlation_factors : [];
                const all = [...fx, ...corr].filter(Boolean).map(String);
                const spikes = all.filter(f=>f.startsWith('an:')||f.startsWith('chg:')||f.startsWith('z:'));
                if (spikes.length){
                    badgesHtml += `<div class="badge-row">${spikes.slice(0,12).map(s=>`<span class="pill pill-warn">${s}</span>`).join('')}</div>`;
                }
                const mitre = Array.isArray(explain?.mitre) ? explain.mitre.map(m=>m.id||m).filter(Boolean) : [];
                if (mitre.length){
                    badgesHtml += `<div class="badge-row">${mitre.slice(0,8).map(t=>`<span class="pill pill-info">${t}</span>`).join('')}</div>`;
                }
                // New: render mapping tags (ATLAS / OWASP LLM) when present
                const tags = (explain && explain.mapping_tags) ? explain.mapping_tags : {};
                const atlas = Array.isArray(tags?.atlas) ? tags.atlas : (Array.isArray(explain?.atlas) ? explain.atlas : []);
                const owasp = Array.isArray(tags?.owasp_llm) ? tags.owasp_llm : (Array.isArray(explain?.owasp_llm) ? explain.owasp_llm : []);
                if (atlas && atlas.length) {
                    badgesHtml += `<div class="badge-row">${atlas.slice(0,10).map(a=>`<span class="pill pill-info">${a}</span>`).join('')}</div>`;
                }
                if (owasp && owasp.length) {
                    badgesHtml += `<div class="badge-row">${owasp.slice(0,10).map(o=>`<span class="pill pill-info">${o}</span>`).join('')}</div>`;
                }
            }catch(_e){/*noop*/}

            // Risk ablation (optional)
            let risk = null;
            try {
                const rR = await (window.safeFetch || fetch)(`/api/v1/risk/${encodeURIComponent(eventId)}/explain?include_ablation=1`, { headers: authHeaders() });
                risk = rR && rR.ok ? await rR.json() : null;
            } catch(_err) { risk = null; }
            let abTbl = '';
            try{
                const abl = Array.isArray(risk?.ablation) ? risk.ablation : [];
                if (abl.length){
                    const rows = abl.slice(0,6).map(a=>`<tr><td>${a.factor}</td><td>${(a.delta??0).toFixed(3)}</td><td>${(a.new_score??0).toFixed(3)}</td></tr>`).join('');
                    abTbl = `<div class=\"evidence-item\"><div class=\"section-title\">Risk Factor Ablation</div><table class=\"simple-table\"><thead><tr><th>Factor</th><th>Delta</th><th>New Score</th></tr></thead><tbody>${rows}</tbody></table></div>`;
                }
            }catch(_err){}

            // Unified threat model + controls (compact cards)
            let tmHtml = '';
            try{
                const tm = explain?.threat_model || null;
                if (tm) {
                    const stride = (tm.stride?.categories||[]).slice(0,6).join(', ');
                    const dread = tm.dread?.average || {};
                    const dreadStr = ['damage','reproducibility','exploitability','affected_users','discoverability']
                      .map(k=>`${k.slice(0,4)}:${(dread[k]??0).toFixed(1)}`).join(' ');
                    const maestro = (tm.maestro?.primary||'unknown');
                    tmHtml += `<div class=\"evidence-item\">`
                           + `<div class=\"section-title\">Unified Threat Model</div>`
                           + `<div class=\"tm-row\"><strong>STRIDE:</strong> ${stride||'n/a'}</div>`
                           + `<div class=\"tm-row\"><strong>DREAD:</strong> ${dreadStr||'n/a'}</div>`
                           + `<div class=\"tm-row\"><strong>Primary Phase:</strong> ${maestro}</div>`
                           + `</div>`;
                }
                const ctrls = Array.isArray(explain?.controls) ? explain.controls : [];
                if (ctrls.length){
                    tmHtml += `<div class=\"evidence-item\"><div class=\"section-title\">Controls</div>`
                           + `<div class=\"badge-row\">${ctrls.slice(0,12).map(c=>`<span class=\"pill pill-info\">${c}</span>`).join('')}</div>`
                           + `</div>`;
                }
            }catch(_e){}

            // Graph context timeline (lite/light), if provided
            let graphHtml = '';
            try{
                const gc = explain?.graph_context || null;
                if (gc && (gc.lite || gc.light)){
                    function summarizeCtx(ctx){
                        try{
                            const nodes = Array.isArray(ctx.nodes)?ctx.nodes:[];
                            const edges = Array.isArray(ctx.edges)?ctx.edges:[];
                            const seeds = Array.isArray(ctx.seeds)?ctx.seeds:[];
                            const head = `<div><strong>Seeds:</strong> ${seeds.map(s=>`${s.type}:${s.id}`).slice(0,3).join(', ')||'n/a'}</div>`
                                       + `<div><strong>Nodes:</strong> ${nodes.length}, <strong>Edges:</strong> ${edges.length}</div>`;
                            const list = edges.slice(0,5).map(e=>`<li>${e.src_type}:${e.src_id} → ${e.dst_type}:${e.dst_id} <em>[${e.phase||'unknown'}]</em></li>`).join('');
                            return head + (list? `<ul>${list}</ul>` : '');
                        }catch(_err){ return ''; }
                    }
                    graphHtml += `<div class=\"evidence-item\"><div class=\"section-title\">Graph Context</div>`
                              + (gc.lite? `<div><strong>Lite</strong>${summarizeCtx(gc.lite)}</div>`: '')
                              + (gc.light? `<div style=\"margin-top:8px\"><strong>Light</strong>${summarizeCtx(gc.light)}</div>`: '')
                              + `</div>`;
                }
            }catch(_e){}

            if (content) content.innerHTML = `${badgesHtml}${tmHtml}${graphHtml}${abTbl}<div class=\"evidence-item\">Explain: <pre style=\"white-space:pre-wrap\">${JSON.stringify(explain, null, 2)}</pre></div>`;
        }catch(e){
            console.error('openInvestigationDetails failed', e);
            const content = document.getElementById('invDetailsContent');
            if (content) content.innerHTML = `<div class="evidence-item">Failed to load details: ${e && e.message}</div>`;
        }
    }

    window.openInvestigationDetails = openInvestigationDetails;
})();



    // Batch feedback queue management
    (function(){
        const queue = []; // { id, factors:[...], label }
        let perItemFactors = {}; // decision_id -> [factors]
        try{ perItemFactors = JSON.parse(localStorage.getItem('batchPerItemFactors')||'{}'); }catch(_){ perItemFactors = {}; }
        function renderQueue(){
            const el = document.getElementById('batchQueueList');
            if(!el) return;
            if(!queue.length){ el.innerHTML = '<div style="font-size:12px;opacity:.6;">Queue empty</div>'; return; }
            el.innerHTML = queue.map(item=>{
                const fcount = (perItemFactors[item.id]||[]).length;
                const badge = fcount ? `<span style="background:#2b7a2b;color:#fff;padding:2px 6px;border-radius:10px;font-size:11px;margin-left:6px;">${fcount}</span>` : '';
                return `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px;border-bottom:1px solid rgba(255,255,255,0.02);">
                            <div style="flex:1; word-break:break-all; font-size:13px;">${item.id} ${badge}<div style="font-size:11px;opacity:.6;">label: ${item.label} • factors: ${fcount}</div></div>
                            <div style="display:flex;flex-direction:column;gap:6px;margin-left:8px;">
                                <button class="btn small" data-act="attach" data-id="${item.id}">Attach</button>
                                <button class="btn small" data-act="remove" data-id="${item.id}">Remove</button>
                            </div>
                        </div>`;
            }).join('');
            // show recent failure indicator
            try{
                const failures = (window._batchFeedbackLastFailed || []).length || 0;
                const hdr = document.createElement('div');
                hdr.style.cssText = 'font-size:11px;opacity:.8;padding:4px 6px;';
                hdr.textContent = failures ? `Recent failures: ${failures} (use Retry)` : '';
                if(failures) el.insertBefore(hdr, el.firstChild);
            }catch(_){ }
            // wire actions
            el.querySelectorAll('button[data-act]').forEach(b=>{
                b.addEventListener('click', ()=>{
                    const act = b.getAttribute('data-act'); const id = b.getAttribute('data-id');
                    if(act==='remove'){ removeFromQueue(id); }
                    else if(act==='attach'){ attachFactorsToItem(id); }
                });
            });
        }
        function addToQueue(ids){
            const parts = Array.isArray(ids) ? ids : String(ids||'').split(',').map(s=>s.trim()).filter(Boolean);
            for(const id of parts){
                if(!queue.find(q=>q.id===id)) queue.push({ id, label: (document.getElementById('batchLabelSelect') && document.getElementById('batchLabelSelect').value) || 'false_positive' });
            }
            renderQueue();
        }
        function removeFromQueue(id){
            const idx = queue.findIndex(q=>q.id===id); if(idx>=0) queue.splice(idx,1);
            delete perItemFactors[id]; renderQueue();
        }
        function attachFactorsToItem(id){
            // copy current selected factors from invFactorPanel into perItemFactors mapping
            try{
                const selected = Array.from(document.querySelectorAll('#invFactorPanel .factor-pill.selected')).map(el=>el.getAttribute('data-factor')).filter(Boolean);
                perItemFactors[id] = selected;
                try{ localStorage.setItem('batchPerItemFactors', JSON.stringify(perItemFactors)); }catch(_){ }
                showNotification(`Attached ${selected.length} factors to ${id}`);
                renderQueue();
            }catch(e){ showNotification('Attach factors failed: '+(e.message||e),'error'); }
        }
        async function submitBatch(){
            if(!queue.length){ showNotification('Queue empty','error'); return; }
            const label = (document.getElementById('batchLabelSelect') && document.getElementById('batchLabelSelect').value) || 'false_positive';
            const results = { success:[], failed:[] };
            // Attempt batch endpoint first
            try{
                const batchItems = queue.map(it=>({ decision_id: it.id, label: it.label || label, apply_calibration: true, factors: perItemFactors[it.id] && perItemFactors[it.id].length ? perItemFactors[it.id] : undefined }));
                        const r = await (window.safeFetch || fetch)('/api/v1/feedback/decisions/batch', { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ items: batchItems }) });
                if(r.ok){
                    const j = await r.json().catch(()=>({}));
                    const resArr = j && j.results || [];
                    for(const rr of resArr){ if(rr.status === 'ok') results.success.push(rr.decision_id || rr.decision_id); else results.failed.push({ id: rr.decision_id || rr.decision_id, detail: rr.error || 'failed' }); }
                } else {
                    // fallback to sequential
                    throw new Error('batch_endpoint_failed');
                }
            }catch(e){
                // fallback: sequential submit
                for(const item of queue.slice()){
                    const payload = { decision_id: item.id, label: item.label || label, apply_calibration:true, factors: perItemFactors[item.id] && perItemFactors[item.id].length ? perItemFactors[item.id] : undefined };
                    try{
                        const r = await (window.safeFetch || fetch)('/api/v1/feedback/decision', { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
                        let j={}; try{ j = await r.json().catch(()=>({})); }catch(_){ }
                        if(!r.ok){ results.failed.push({ id: item.id, detail: j && (j.detail||j.error) || ('HTTP '+r.status) }); }
                        else { results.success.push(item.id); }
                    }catch(err){ results.failed.push({ id: item.id, detail: err.message||err }); }
                }
            }
            // Report and keep failed items in queue for retry
            if(results.success.length) showNotification(`Batch success: ${results.success.length}`,'success');
            if(results.failed.length) {
                showNotification(`Batch failed: ${results.failed.length}. Open failures for details`,'error');
                console.warn('Batch submit failures', results.failed);
                // store last failures for retry helper
                window._batchFeedbackLastFailed = results.failed;
                showFailureModal(results.failed);
            }
            // Remove successful items from queue
            for(const id of results.success){ removeFromQueue(id); }
            // Persist perItemFactors (cleanup removed entries)
            try{ sessionStorage.setItem('batchPerItemFactors', JSON.stringify(perItemFactors)); }catch(_){ }
            renderQueue();
        }
        // wire UI
        function initBatchUI(){
            try{
                const addBtn = document.getElementById('btnBatchAdd');
                const input = document.getElementById('batchAddInput');
                const submit = document.getElementById('btnBatchSubmit');
                const retryBtn = document.getElementById('btnBatchRetry');
                const toggle = document.getElementById('btnToggleBatch');
                const panel = document.getElementById('batchFeedbackPanel');
                if(addBtn && input){ addBtn.addEventListener('click', ()=>{ addToQueue(input.value); input.value=''; }); }
                if(input){ input.addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ addToQueue(input.value); input.value=''; } }); }
                if(submit){ submit.addEventListener('click', submitBatch); }
                if(retryBtn){ retryBtn.addEventListener('click', ()=>{ const lf = window._batchFeedbackLastFailed || []; if(!lf.length){ showNotification('No recent failures to retry','error'); return; } const ids = lf.map(x=>x.id); addToQueue(ids); submitBatch(); }); }
                if(toggle && panel){ toggle.addEventListener('click', ()=>{ if(panel.style.display==='none'){ panel.style.display='block'; toggle.textContent='Hide'; } else { panel.style.display='none'; toggle.textContent='Show'; } }); }
                // wire failure modal retry all
                try{
                    const retryAll = document.getElementById('btnBatchRetryAll');
                    if(retryAll){ retryAll.addEventListener('click', ()=>{ const lf = window._batchFeedbackLastFailed || []; if(!lf.length){ showNotification('No failures to retry','error'); return; } const ids = lf.map(x=>x.id); addToQueue(ids); document.getElementById('batchFailureModal').style.display='none'; submitBatch(); }); }
                }catch(_){ }
                renderQueue();
            }catch(e){ console.error('initBatchUI failed',e); }
        }
        // expose for manual use/tests
        window._batchFeedback = { addToQueue, removeFromQueue, submitBatch, attachFactorsToItem, initBatchUI, _queue: queue, _perItemFactors: perItemFactors };
        // init on DOM ready
        try{ document.addEventListener('DOMContentLoaded', ()=>{ setTimeout(()=>{ initBatchUI(); }, 50); }); }catch(_){ initBatchUI(); }
    })();

        // Failure modal renderer
        function showFailureModal(failures){
            try{
                const modal = document.getElementById('batchFailureModal');
                const body = document.getElementById('batchFailureBody');
                if(!modal || !body) return;
                body.innerHTML = failures.map(f=>{
                    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);">
                                <div style="flex:1;word-break:break-all;"><div style="font-weight:600">${f.id}</div><div style="font-size:12px;opacity:.7">${f.detail}</div></div>
                                <div style="display:flex;flex-direction:column;gap:6px;margin-left:8px;">
                                    <button class="btn small" data-fail-id="${f.id}" data-act="retry">Retry</button>
                                    <button class="btn small" data-fail-id="${f.id}" data-act="queue">Re-queue</button>
                                </div>
                            </div>`;
                }).join('');
                // wire buttons
                body.querySelectorAll('button[data-act]').forEach(b=>{
                    b.addEventListener('click', ()=>{
                        const act = b.getAttribute('data-act'); const id = b.getAttribute('data-fail-id');
                        if(act==='retry'){
                            // attempt single retry immediately
                            (async ()=>{
                                const payload = { decision_id: id, label: (document.getElementById('batchLabelSelect') && document.getElementById('batchLabelSelect').value) || 'false_positive', apply_calibration:true, factors: perItemFactors[id] };
                                try{
                                    const r = await (window.safeFetch || fetch)('/api/v1/feedback/decision', { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
                                    if(!r.ok){ const j = await r.json().catch(()=>({})); showNotification('Retry failed: '+(j && (j.detail||j.error) || r.status),'error'); }
                                    else { showNotification('Retry success: '+id,'success'); removeFromQueue(id); }
                                }catch(e){ showNotification('Retry error: '+(e.message||e),'error'); }
                            })();
                        } else if(act==='queue'){
                            addToQueue([id]);
                            showNotification('Re-queued '+id);
                        }
                    });
                });
                modal.style.display = 'flex';
            }catch(e){ console.error('showFailureModal failed', e); }
        }
