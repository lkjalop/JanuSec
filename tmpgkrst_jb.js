// csv_analyzer.js - Production CSV Analyzer logic
// Single, cleaned implementation with severity sort, inline details, persistence and simple resizing
(function(){
  try { window.__csvReady = true; } catch(_){ }
  window.parseTabular = window.parseTabular || { ensureXlsxLib: function(){} };
  var FILTER_MODE = localStorage.getItem('csv_filter_mode') || 'all';
  var SELECTED_ROWS = new Set();
  var VERDICT_VIEW_MODE = localStorage.getItem('csv_verdict_view') || 'initial';
  
  function getInitialVerdict(rec){
    if(!rec) return '';
    if(rec._initial_verdict){
      return rec._initial_verdict;
    }
    if(rec.verdict){
      return String(rec.verdict).toUpperCase();
    }
    return '';
  }
  
  function getPipelineVerdict(rec){
    if(!rec) return '';
    if(rec._pipeline_verdict){
      return rec._pipeline_verdict;
    }
    return '';
  }
  
  function getVerdictForView(rec){
    if(!rec) return '';
    if(VERDICT_VIEW_MODE === 'pipeline'){
      return getPipelineVerdict(rec) || getInitialVerdict(rec) || '';
    }
    return getInitialVerdict(rec) || getPipelineVerdict(rec) || '';
  }

  function formatConfidenceValue(input){
    try{
      if(input === null || typeof input === 'undefined'){
        return '';
      }
      var value = typeof input === 'number' ? input : parseFloat(input);
      if(isNaN(value)){
        return '';
      }
      if(value <= 1 && value >= 0){
        return Math.round(value * 100) + '%';
      }
      if(value >= 0 && value <= 100){
        return Math.round(value) + '%';
      }
      return Number(value).toFixed(2);
    }catch(_){
      return '';
    }
  }

  function setVerdictViewMode(mode){
    if(mode !== 'pipeline') mode = 'initial';
    VERDICT_VIEW_MODE = mode;
    try{ localStorage.setItem('csv_verdict_view', mode); }catch(_){}
    updateVerdictViewButtons();
    renderTableFromResults();
  }

  function updateVerdictViewButtons(){
    try{
      var initBtn = document.getElementById('btnVerdictViewInitial');
      var pipeBtn = document.getElementById('btnVerdictViewPipeline');
      if(initBtn){
        var initActive = VERDICT_VIEW_MODE === 'initial';
        initBtn.classList.toggle('active-view', initActive);
        initBtn.setAttribute('aria-pressed', initActive ? 'true' : 'false');
      }
      if(pipeBtn){
        var pipeActive = VERDICT_VIEW_MODE === 'pipeline';
        pipeBtn.classList.toggle('active-view', pipeActive);
        pipeBtn.setAttribute('aria-pressed', pipeActive ? 'true' : 'false');
      }
      var info = document.getElementById('verdictViewInfo');
      if(info){
        info.textContent = VERDICT_VIEW_MODE === 'pipeline' ? 'Post-pipeline verdicts' : 'Initial heuristics';
      }
    }catch(_){ }
  }
  
  // Expose a safe accessor for selected row indexes so other modules (e.g. Deep Analyze
  // attachment IIFE) can read them without direct scope access. This prevents ReferenceError
  // when window.initiateDeepAnalyze() runs before this closure's local bindings are visible.
  try { window.__getSelectedRowIndexes = function(){ return Array.from(SELECTED_ROWS); }; } catch(_){ }
  // Expose selected rows for external actions (e.g., Send to Identity Graph)
  Object.defineProperty(window, 'csvSelectedRows', {
    get: function(){ try{ var list = window.LAST_RESULTS||[]; return Array.from(SELECTED_ROWS).map(function(idx){ return list[idx]; }); }catch(_){ return []; } },
    configurable: true
  });

  // Wrapper functions exposed on window so header dropdown can call handlers directly
  try {
    window.csvActions = window.csvActions || {};
    // Start a deep analyze for selected rows (or all if none selected)
    window.csvActions.startDeepAnalyze = function(opts){ try{ if(typeof initiateDeepAnalyze === 'function'){ initiateDeepAnalyze(opts); return true; } if(typeof window.initiateDeepAnalyze === 'function'){ window.initiateDeepAnalyze(opts); return true; } }catch(_){ } return false; };
    // Start batch analyze using current view / selection
    window.csvActions.startBatchAnalyze = function(opts){ try{ if(typeof startBatchAnalyze === 'function'){ startBatchAnalyze(opts); return true; } if(typeof window.startBatchAnalyze === 'function'){ window.startBatchAnalyze(opts); return true; } }catch(_){ } return false; };
    // Aggregate latest parent assessment into drawer
    window.csvActions.aggregateLatestParent = async function(parentId){ try{ if(typeof aggregateBatchesToDrawer === 'function'){ await aggregateBatchesToDrawer(parentId); return true; } if(typeof window.aggregateBatchesToDrawer === 'function'){ await window.aggregateBatchesToDrawer(parentId); return true; } }catch(e){ console.warn('aggregateLatestParent error', e); } return false; };
    // Send selected rows to identity graph endpoint
    window.csvActions.sendSelectedToIdentity = async function(){ try{ var rows = window.csvSelectedRows || []; if(!rows.length) return false; if(typeof postSelectedToIdentityGraph === 'function'){ await postSelectedToIdentityGraph(rows); return true; } if(typeof window._postIdentityEvent === 'function'){ await window._postIdentityEvent(rows); return true; } // fallback: use integrations endpoint
        try{ await fetch('/api/v1/integrations/identity/batch', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ rows: rows }) }); return true; }catch(_){ return false; } }catch(e){ console.warn('sendSelectedToIdentity', e); return false; } };
    // Send selected rows to cloud inventory endpoint
    window.csvActions.sendSelectedToCloud = async function(){ try{ var rows = window.csvSelectedRows || []; if(!rows.length) return false; if(typeof postSelectedToCloudInventory === 'function'){ await postSelectedToCloudInventory(rows); return true; } try{ await fetch('/api/v1/integrations/cloud/batch', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ rows: rows }) }); return true; }catch(_){ return false; } }catch(e){ console.warn('sendSelectedToCloud', e); return false; } };
    // Send selected rows to network flows endpoint
    window.csvActions.sendSelectedToNetwork = async function(){ try{ var rows = window.csvSelectedRows || []; if(!rows.length) return false; if(typeof postSelectedToNetworkFlows === 'function'){ await postSelectedToNetworkFlows(rows); return true; } try{ await fetch('/api/v1/integrations/network/batch', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ rows: rows }) }); return true; }catch(_){ return false; } }catch(e){ console.warn('sendSelectedToNetwork', e); return false; } };
    // Correlate selected rows (start multi-source correlator)
    window.csvActions.correlateSelectedRows = async function(){ try{ var rows = window.csvSelectedRows || []; if(!rows.length) return false; if(typeof startCorrelationSession === 'function'){ await startCorrelationSession(rows); return true; } try{ await fetch('/api/v1/graph/session/build', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ session_ids: [], correlate: true, mapping: {} , rows: rows }) }); return true; }catch(_){ return false; } }catch(e){ console.warn('correlateSelectedRows', e); return false; } };
  }catch(_){ }

  function verdictPassFail(v, rec){
    try{
      var s = String(v || '').toUpperCase().trim();
      if((!s || !s.length) && rec){
        s = getVerdictForView(rec) || '';
      }
      if(!s) return 'NEUTRAL';
      if(s.includes('GOOD')||s.includes('BENIGN')||s.includes('CONTROLLED')) return 'PASS';
      if(s.includes('MALICIOUS')||s.includes('SUSPICIOUS')||s.includes('THREAT')) return 'FAIL';
      return 'NEUTRAL';
    }catch(_){
      return 'NEUTRAL';
    }
  }

  function computeDreadBreakdown(factors){
    // DREAD demo scoring now includes numeric signals: avPositives and threatWeight
    try{
      var base = 0;
      (factors||[]).forEach(function(f){ if(!f) return; var s=String(f).toLowerCase(); if(s.includes('lolbin')) base += 2; if(s.includes('unsigned')||s.includes('sensitive')) base += 1; if(s.includes('novel')||s.includes('global')) base += 1; if(s.includes('repeat')||s.includes('multi')) base += 1; });
      // clamp base
      base = Math.max(0, base);
      // If caller provided raw numeric signals as second arg, use them
      var av = 0, tw = 0;
      if(arguments && arguments.length>1){ var raw = arguments[1]||{}; try{ av = parseInt(String(raw.avPositives||raw.av_positives||raw.avPos||0).replace(/[^0-9]/g,''),10)||0; }catch(_){ av=0; } try{ tw = parseFloat(String(raw.threatWeight||raw.threatweight||raw.ThreatWeight||0).replace(/[^0-9\.\-]/g,''))||0; }catch(_){ tw=0; } }
      // Map av to 0-5, threatWeight to 0-5
      var avScore = Math.min(5, av);
      var twScore = Math.min(5, Math.round(tw/2));
      var score = base + avScore + twScore; // potential range 0..~15
      var norm = Math.min(10, Math.round(score));
      var level = norm<=3?'low':(norm<=6?'medium':'high');
      return { score: norm, level: level, details: { base: base, av: av, avScore: avScore, threatWeight: tw, twScore: twScore } };
    }catch(_){ return { score:0, level:'low', details:{} }; }
  }

  function openTier2ForRow(index){
    try{
      localStorage.setItem('csv_deep_row', String(index));
      localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS||[]));
      window.open('/static/csv_deep_analysis.html','_blank');
    }catch(_){ }
  }

  let LLM_SIDEBAR, LLM_SIDEBAR_BODY, LLM_SIDEBAR_META, LLM_SIDEBAR_COST, LLM_SIDEBAR_CURRENT;

  function ensureTier1SidebarRefs(){
    if(LLM_SIDEBAR) return;
    LLM_SIDEBAR = document.getElementById('llmSidebar');
    LLM_SIDEBAR_BODY = document.getElementById('llmSidebarBody');
    LLM_SIDEBAR_META = document.getElementById('llmSidebarMeta');
    LLM_SIDEBAR_COST = document.getElementById('llmSidebarCost');
    const closeBtn = document.getElementById('llmSidebarClose');
    const t2Btn = document.getElementById('llmSidebarT2');
    if(closeBtn){ closeBtn.addEventListener('click', hideTier1Sidebar); }
    if(t2Btn){ t2Btn.addEventListener('click', function(){ if(typeof LLM_SIDEBAR_CURRENT === 'number'){ openTier2ForRow(LLM_SIDEBAR_CURRENT); } }); }
  }

  // Properly hide Tier 1 sidebar (previous implementation was a mistaken copy of a fetch routine and broke parsing)
  function hideTier1Sidebar(){
    try {
      ensureTier1SidebarRefs();
      if(LLM_SIDEBAR){
        LLM_SIDEBAR.classList.remove('visible');
        LLM_SIDEBAR.style.display='none';
      }
      LLM_SIDEBAR_CURRENT = null;
    }catch(_){ }
  }

  // Helper to show loading while requesting Tier 1 summary
  function setTier1SidebarLoading(row){
    try{ ensureTier1SidebarRefs(); if(!LLM_SIDEBAR) return; LLM_SIDEBAR.style.display='block'; LLM_SIDEBAR.classList.add('visible'); LLM_SIDEBAR_CURRENT = (row && (typeof row.row_index==='number'? row.row_index : null)); if(LLM_SIDEBAR_BODY) LLM_SIDEBAR_BODY.innerHTML='<div style="padding:12px">Loading Tier 1 summary…</div>'; if(LLM_SIDEBAR_COST) LLM_SIDEBAR_COST.textContent='--'; if(LLM_SIDEBAR_META) LLM_SIDEBAR_META.textContent = 'Row '+ (LLM_SIDEBAR_CURRENT!=null? LLM_SIDEBAR_CURRENT:'?'); }catch(_){ }
  }

  // Render Tier 1 summary content
  function showTier1Sidebar(row, summaryText, cost){
    try{
      ensureTier1SidebarRefs();
      if(!LLM_SIDEBAR) return;
      LLM_SIDEBAR.style.display='block';
      LLM_SIDEBAR.classList.add('visible');
      LLM_SIDEBAR_CURRENT = (row && (typeof row.row_index==='number'? row.row_index : null));
      if(LLM_SIDEBAR_META) LLM_SIDEBAR_META.textContent = 'Row '+ (LLM_SIDEBAR_CURRENT!=null? LLM_SIDEBAR_CURRENT:'?');
      var resolvedRow = resolveSidebarRow(row);
      if(LLM_SIDEBAR_BODY){
        var content = formatTier1Summary(summaryText || '');
        var actions = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">'
          + '<button class="btn" id="llmActionPass">Pass</button>'
          + '<button class="btn" id="llmActionEscalate">Escalate</button>'
          + '<button class="btn" id="llmActionComment">Comment</button>'
          + '<button class="btn" id="llmActionReqLogs">Request Logs</button>'
          + '<button class="btn" id="llmActionTier2">Tier 2</button>'
          + '<button class="btn" id="llmActionDetach">Detach</button>'
          + '</div>';
        var helper = '<div class="tier1-action-hint"><strong>Decision flow</strong><ul><li><strong>Pass</strong> records a benign verdict via /api/v1/telemetry/dispositions.</li><li><strong>Escalate</strong> marks the row for Tier 2 follow-up.</li><li><strong>Request Logs</strong> calls /api/v1/integrations/request_sensitive_logs so host telemetry is ready before deeper investigation.</li></ul></div>';
        var status = '<div id="llmActionStatus" class="tier1-action-status">Use these controls to record your next move.</div>';
        var confidenceHtml = resolvedRow ? buildTier1ConfidenceBlock(resolvedRow) : '';
        LLM_SIDEBAR_BODY.innerHTML = actions + helper + status + '<div id="llmSidebarContent">'+content+'</div>' + confidenceHtml;
        LLM_SIDEBAR_BODY.style.maxHeight='calc(100vh - 180px)';
        LLM_SIDEBAR_BODY.style.overflow='auto';
        try{
          var passBtn = document.getElementById('llmActionPass');
          if(passBtn){
            passBtn.addEventListener('click', function(){
              try{
                updateTier1ActionStatus('Submitting PASS to /api/v1/telemetry/dispositions...');
                handleTier1ActionPromise(postDisposition(LLM_SIDEBAR_CURRENT, 'pass'), 'Row recorded as PASS. Move to the next alert when ready.', 'PASS action failed. Verify API access or network.');
              }catch(_){ }
            });
          }
          var escBtn = document.getElementById('llmActionEscalate');
          if(escBtn){
            escBtn.addEventListener('click', function(){
              try{
                updateTier1ActionStatus('Flagging this row for Tier 2 review...');
                handleTier1ActionPromise(postDisposition(LLM_SIDEBAR_CURRENT, 'escalate'), 'Escalation saved. Open Tier 2 or hand off to an analyst.', 'Escalate action failed. Check backend connectivity.');
              }catch(_){ }
            });
          }
          var comBtn = document.getElementById('llmActionComment');
          if(comBtn){
            comBtn.addEventListener('click', function(){
              try{
                var note = prompt('Add comment for row '+LLM_SIDEBAR_CURRENT);
                if(note){
                  var rec = (window.LAST_RESULTS||[])[LLM_SIDEBAR_CURRENT]||{};
                  var payload = { event_id: (rec.raw && (rec.raw.event_id||rec.raw.EventID)) || null, note: note };
                  updateTier1ActionStatus('Sending analyst note to /api/v1/feedback/human_review...');
                  handleTier1ActionPromise(fetch('/api/v1/feedback/human_review', { method: 'POST', headers: Object.assign({'Content-Type':'application/json'}, authHeaders()), body: JSON.stringify(payload) }).then(function(resp){ return resp.ok; }), 'Comment saved for audit trail.', 'Comment failed to save.');
                }
              }catch(_){ }
            });
          }
          var rlBtn = document.getElementById('llmActionReqLogs');
          if(rlBtn){
            rlBtn.addEventListener('click', function(){
              try{
                var rec = (window.LAST_RESULTS||[])[LLM_SIDEBAR_CURRENT]||{};
                var payload = { reason: 'Analyst requested sensitive logs from Tier1', record: rec };
                updateTier1ActionStatus('Requesting supporting logs before deep dive...');
                handleTier1ActionPromise(fetch('/api/v1/integrations/request_sensitive_logs', { method: 'POST', headers: Object.assign({'Content-Type':'application/json'}, authHeaders()), body: JSON.stringify(payload) }).then(function(resp){ return resp.ok; }), 'Log request queued. Wait for confirmation before Tier 2.', 'Log request failed. Ensure integrations endpoint is reachable.');
              }catch(_){ }
            });
          }
          var t2Btn2 = document.getElementById('llmActionTier2');
          if(t2Btn2){
            t2Btn2.addEventListener('click', function(){
              try{
                updateTier1ActionStatus('Opening Tier 2 deep dive for row '+LLM_SIDEBAR_CURRENT+'...');
                openTier2ForRow(LLM_SIDEBAR_CURRENT);
              }catch(_){ }
            });
          }
          var detBtn = document.getElementById('llmActionDetach');
          if(detBtn){
            detBtn.addEventListener('click', function(){
              try{
                updateTier1ActionStatus('Detaching Tier 1 summary to a new window...');
                detachSummary();
              }catch(_){ }
            });
          }
        }catch(_){ }
      }
      if(LLM_SIDEBAR_COST) LLM_SIDEBAR_COST.textContent = '$'+Number(cost||0).toFixed(4);
    }catch(_){ }
  }

  function mergeAssessmentRowsIntoResults(payload){
    try{
      var list = Array.isArray(payload && payload.rows) ? payload.rows : (Array.isArray(payload) ? payload : []);
      if(!Array.isArray(window.LAST_RESULTS) || !list.length){
        return;
      }
      var indexMap = {};
      list.forEach(function(entry){
        if(entry && typeof entry.row_index === 'number'){
          indexMap[entry.row_index] = entry;
        }
      });
      var refreshed = 0;
      window.LAST_RESULTS = window.LAST_RESULTS.map(function(rec, idx){
        var match = indexMap.hasOwnProperty(idx) ? indexMap[idx] : null;
        if(!match){
          return rec;
        }
        var updated = Object.assign({}, rec);
        var pipelineVerdict = '';
        if(match.verdict){
          pipelineVerdict = String(match.verdict).toUpperCase();
        } else if(match.decision && match.decision.verdict){
          pipelineVerdict = String(match.decision.verdict).toUpperCase();
        }
        if(pipelineVerdict){
          updated._pipeline_verdict = pipelineVerdict;
        }
        if(typeof match.confidence === 'number'){
          updated._pipeline_confidence = match.confidence;
        } else if(match.decision && typeof match.decision.confidence === 'number'){
          updated._pipeline_confidence = match.decision.confidence;
        }
        if(Array.isArray(match.factors)){
          updated.factors = match.factors.slice();
        }
        if(match.summary){
          updated.llm_summary = match.summary;
        } else if(match.llm && match.llm.summary){
          updated.llm_summary = match.llm.summary;
        }
        if(match.payload || match.tier2_payload){
          updated._tier2_payload = match.tier2_payload || match.payload;
        }
        if(match.evidence || match.supporting_evidence){
          updated._pipeline_evidence = match.evidence || match.supporting_evidence;
        }
        if(match.tasks || match.investigation_tasks){
          updated._pipeline_tasks = match.tasks || match.investigation_tasks;
        }
        if(match.uncertainty_flags){
          updated._uncertaintyFlags = match.uncertainty_flags;
        }
        if(match.tier){
          updated._tier = match.tier;
        }
        updated._pipeline_row = match;
        updated.verdict = getVerdictForView(updated);
        refreshed++;
        return updated;
      });
      if(refreshed){
        try{
          localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS));
          localStorage.setItem('csv_last_results_ts', String(Date.now()/1000));
        }catch(_){}
      }
    }catch(err){
      console.warn('mergeAssessmentRowsIntoResults error', err);
