(function(){
                const panel = document.getElementById('llmSummariesPanel'); if(!panel) return;
                const out = document.getElementById('llmOutput');
                const status = document.getElementById('llmStatus');
                const btnTriage = document.getElementById('btnTriage');
                const btnExplain = document.getElementById('btnExplain');
                const btnCopy = document.getElementById('btnCopyLlm');
                const btnExport = document.getElementById('btnExportLlm');
                const tier1El = document.getElementById('llmTier1');
                const tier2El = document.getElementById('llmTier2');
                const boostsEl = document.getElementById('llmPipelineBoosts');
                // Accessibility roles
                btnTriage && btnTriage.setAttribute('role','button'); btnTriage && btnTriage.setAttribute('aria-label','Generate Triage');
                btnExplain && btnExplain.setAttribute('role','button'); btnExplain && btnExplain.setAttribute('aria-label','Generate Explain');
                btnCopy && btnCopy.setAttribute('role','button'); btnCopy && btnCopy.setAttribute('aria-label','Copy Summary');
                btnExport && btnExport.setAttribute('role','button'); btnExport && btnExport.setAttribute('aria-label','Export Summary');

                async function getRecentDecision(){
                    try{
                        const r = await (window.safeFetch || fetch)('/api/v1/decisions/recent?limit=1', { headers: authHeaders() });
                        const j = await r.json().catch(()=>({}));
                        const d = (j.decisions || j.rows || [])[0] || {};
                        return d;
                    }catch(_){ return {}; }
                }
                function renderJSON(obj){ out.textContent = JSON.stringify(obj, null, 2); }
                function chip(text){ return `<span class="pill">${_htmlEsc(text)}</span>`; }
                function renderTier1FromDecision(d){
                    try{
                        if(!tier1El) return;
                        const cb = d && d.confidence_breakdown || {};
                        const tags = Array.isArray(d && d.factors) ? d.factors.slice(0,10).map(f=> (typeof f==='string'? f : (f.name||f.factor||'factor'))) : [];
                        const parts = [];
                        if(d && d.verdict) parts.push(chip('Verdict: '+d.verdict));
                        if(d && d.confidence!=null) parts.push(chip('Conf: '+Number(d.confidence).toFixed(2)));
                        if(cb.base!=null) parts.push(chip('Base: '+Number(cb.base).toFixed(2)));
                        if(cb.chain_bonus!=null) parts.push(chip('Chain: '+Number(cb.chain_bonus).toFixed(2)));
                        if(cb.mapping_bonus!=null) parts.push(chip('MapB: '+Number(cb.mapping_bonus).toFixed(2)));
                        if(cb.co_occurrence_adjustment!=null) parts.push(chip('CoOcc: '+Number(cb.co_occurrence_adjustment).toFixed(2)));
                        const md = d && d.domain_diversity; const ms = d && d.mapping_semantics;
                        const dd = (d && (d.domain_diversity_score!=null? d.domain_diversity_score : (md && md.score)))
                        if(dd!=null) parts.push(chip('Diversity: '+Number(dd).toFixed(2)));
                        const mss = (d && (d.mapping_semantics_score!=null? d.mapping_semantics_score : (ms && ms.score)));
                        if(mss!=null) parts.push(chip('Mapping: '+Number(mss).toFixed(2)));
                        const pathLen = d && (d.path_length!=null? d.path_length : undefined);
                        if(pathLen!=null) parts.push(chip('Path: '+pathLen));
                        const phaseCnt = d && (d.distinct_phase_count!=null? d.distinct_phase_count : undefined);
                        if(phaseCnt!=null) parts.push(chip('Phases: '+phaseCnt));
                        if(tags.length){ parts.push('<span class="small" style="opacity:.8">Factors:</span> '+tags.map(t=>chip(t)).join(' ')); }
                        tier1El.innerHTML = parts.join(' ');
                        tier1El.style.display = 'block';
                    }catch(_){ }
                }
                function renderTier2Structured(resp, d){
                    try{
                        if(!tier2El) return;
                        const ds = (d && d.dependency_status) || {};
                        const degraded = !!(ds && ds.degraded);
                        const sec = [];
                        const narrative = resp.narrative || resp.summary || resp.overview || null;
                        const evidence = resp.evidence || resp.context || null;
                        const factors = resp.factors || resp.key_factors || null;
                        const actions = resp.actions || resp.recommendations || null;
                        if(degraded){ sec.push(`<div class="warning-banner" style="display:block;margin:0 0 8px 0;"><strong>Degraded mode</strong> Tier 2 may rely on cached HopGraph snapshots.</div>`); }
                        if(narrative){ sec.push(`<div style="margin-bottom:6px;"><strong>Narrative</strong><div class="small" style="margin-top:4px;">${_htmlEsc(typeof narrative==='string'? narrative : JSON.stringify(narrative))}</div></div>`); }
                        if(evidence){ sec.push(`<div style="margin-bottom:6px;"><strong>Evidence</strong><div class="small" style="margin-top:4px;">${_htmlEsc(typeof evidence==='string'? evidence : JSON.stringify(evidence))}</div></div>`); }
                        if(factors){
                            const list = Array.isArray(factors)? factors : Object.keys(factors).map(k=>`${k}: ${JSON.stringify(factors[k])}`);
                            sec.push(`<div style="margin-bottom:6px;"><strong>Factors</strong><div class="small" style="margin-top:4px;">${list.slice(0,10).map(x=>_htmlEsc(typeof x==='string'? x : JSON.stringify(x))).map(t=>`<span class=\"pill\">${t}</span>`).join(' ')}</div></div>`);
                        }
                                (function(){
                                    (function(){
                                        try{
                                            // If another element with id=fileInput already present (above), nothing to do.
                                            if(!document.getElementById('fileInput')){
                                                const inp = document.createElement('input'); inp.type='file'; inp.id='fileInput'; inp.multiple=true;
                                                inp.accept = '.pcap,.evtx,.json,.csv,.log,.xls,.xlsx,.xlsm,.ods,.zip,.gz'; inp.style.display='none'; document.body.appendChild(inp);
                                            } else {
                                                // make sure it's attached to body (tests use state:attached)
                                                const el = document.getElementById('fileInput'); if(el && !el.closest('body')) document.body.appendChild(el);
                                            }
                                            // Test-mode: make file input visible for Playwright if requested via localStorage
                                            try{
                                                const mode = localStorage.getItem('testMode');
                                                const force = localStorage.getItem('forceFileInputVisible');
                                                if(mode === 'playwright' || force === '1'){
                                                    const el = document.getElementById('fileInput');
                                                    if(el){ el.style.display = 'block'; el.style.visibility = 'visible'; el.style.position = 'static'; el.style.zIndex = 9999; el.setAttribute('data-test','csv-file-input'); }
                                                }
                                            }catch(_){ }
                                        }catch(e){ console.warn('fileInput shim failed', e); }
                                    })();