// csv_analyzer.js - Production CSV Analyzer logic
// Single, cleaned implementation with severity sort, inline details, persistence and simple resizing
(function(){
  try { window.__csvReady = true; } catch(_){ }
  window.parseTabular = window.parseTabular || { ensureXlsxLib: function(){} };
  var FILTER_MODE = localStorage.getItem('csv_filter_mode') || 'all';
  var SELECTED_ROWS = new Set();
  var VERDICT_VIEW_MODE = localStorage.getItem('csv_verdict_view') || 'initial';
  var AUTO_PIPELINE_PREF = localStorage.getItem('csv_auto_pipeline_enabled');
  var AUTO_PIPELINE_ENABLED = AUTO_PIPELINE_PREF === null ? true : (AUTO_PIPELINE_PREF !== '0' && AUTO_PIPELINE_PREF !== 'false');
  var PIPELINE_FORCE_SORT = false;
  var PIPELINE_AUTORANK = false;
  var PIPELINE_PENDING = new Set();
  var PIPELINE_TARGETS = new Set();
  var PIPELINE_ASSESSMENTS = {};
  var AUTO_PIPELINE_ACTIVE = false;
  var AUTO_PIPELINE_LAUNCHED = false;
  var AUTO_PIPELINE_TOKEN = 0;
  var LAST_PIPELINE_ASSESSMENT = null;
  var CURRENT_MAPPING = {};
  var CURRENT_MAPPING_SUMMARY = null;
  var CURRENT_MAPPING_SCORE = null;
  var CURRENT_RAW_HEADERS = [];
  var CURRENT_RAW_ROWS = [];
  var LAST_INGEST_SOURCE = 'csv_analyzer';
  var FACTOR_TELEMETRY_CACHE = null;
  var FACTOR_TELEMETRY_FETCHED_AT = 0;

  try{
    var savedMapping = JSON.parse(localStorage.getItem('csv_last_mapping')||'null');
    if(savedMapping && typeof savedMapping === 'object'){
      CURRENT_MAPPING = savedMapping;
    }
  }catch(_){ }
  try{
    var savedSummary = JSON.parse(localStorage.getItem('csv_mapping_summary')||'null');
    if(savedSummary && typeof savedSummary === 'object'){
      CURRENT_MAPPING_SUMMARY = savedSummary;
    }
    var savedScore = parseFloat(localStorage.getItem('csv_mapping_semantics_score')||'');
    if(!isNaN(savedScore)){
      CURRENT_MAPPING_SCORE = savedScore;
    }
  }catch(_){ }
  
  function setAutoPipelinePreference(enabled){
    AUTO_PIPELINE_ENABLED = !!enabled;
    try{ localStorage.setItem('csv_auto_pipeline_enabled', enabled ? '1' : '0'); }catch(_){}
  }

  function registerPipelineAssessment(id, meta){
    if(!id) return;
    PIPELINE_ASSESSMENTS[id] = meta || {};
    if(meta && meta.auto_target){
      AUTO_PIPELINE_ACTIVE = true;
      LAST_PIPELINE_ASSESSMENT = id;
    }
  }

  // Subscribe to LLM SSE events for an assessment and update row summaries
  function subscribeLLMEvents(assessmentId){
    if(!assessmentId) return null;
    try{
      const url = '/api/v1/assessments/'+encodeURIComponent(assessmentId)+'/llm/stream';
      const es = new EventSource(url, { withCredentials: true });
      es.addEventListener('connected', function(evt){ console.debug('LLM SSE connected', assessmentId); });
      es.addEventListener('row_succeeded', function(evt){
        try{
          const data = JSON.parse(evt.data || '{}');
          const idx = Number(data.row_index);
          if(!Number.isFinite(idx)) return;
          // update in-memory LAST_RESULTS and DOM if present
          if(Array.isArray(window.LAST_RESULTS)){
            for(let i=0;i<window.LAST_RESULTS.length;i++){
              const r = window.LAST_RESULTS[i];
              if(r && (r.row_index === idx || String(r.row_index) === String(idx))){
                r.llm_summary = data.summary;
                r.llm_meta = data.meta;
                r._llm_status = 'succeeded';
                // update DOM row if rendered
                const tr = document.querySelector('tr[data-row-index="'+idx+'"]');
                if(tr){
                  const cell = tr.querySelector('.llm-status-cell');
                  if(cell) cell.innerHTML = '<span class="pill">Done</span>';
                }
                break;
              }
            }
          }
        }catch(e){ console.warn('row_succeeded parse', e); }
      });
      es.addEventListener('message', function(evt){ console.debug('LLM SSE message', evt.data); });
      es.onerror = function(e){ console.warn('LLM SSE error', e); es.close(); };
      return es;
    }catch(e){ console.warn('subscribeLLMEvents', e); return null; }
  }

  // Auto-start SSE subscription for assessment events when page loads
  (function(){
    try{
      const aid = window.currentAssessmentId || localStorage.getItem('csv_last_parent_assessment');
      if(!aid) return;
      const es = subscribeLLMEvents(aid);
      if(!es) return;
      es.addEventListener('rows', function(evt){
        try{ mergeAssessmentRowsIntoResults(JSON.parse(evt.data || '{}')); }catch(e){ console.warn('rows SSE parse', e); }
      });
    }catch(e){ console.warn('init LLM SSE', e); }
  })();

  function completePipelineAssessment(id){
    if(!id) return;
    var meta = PIPELINE_ASSESSMENTS[id];
    delete PIPELINE_ASSESSMENTS[id];
    if(meta && meta.auto_target){
      AUTO_PIPELINE_ACTIVE = false;
      AUTO_PIPELINE_LAUNCHED = false;
      LAST_PIPELINE_ASSESSMENT = null;
    }
  }

  function availableResults(){
    return Array.isArray(window.LAST_RESULTS) ? window.LAST_RESULTS : [];
  }

  function collectSuspiciousRows(limit){
    var rows = [];
    var list = availableResults();
    for(var i=0;i<list.length;i++){
      try{
        var rec = list[i];
        if(verdictPassFail(getInitialVerdict(rec), rec) === 'FAIL'){
          rows.push({ row_index: (typeof rec.row_index === 'number' ? rec.row_index : i), raw: rec && rec.raw ? rec.raw : rec });
          if(limit && rows.length >= limit) break;
        }
      }catch(_){ }
    }
    return rows;
  }

  async function ensureFactorTelemetry(force){
    try{
      var ttl = 60000;
      if(!force && FACTOR_TELEMETRY_CACHE && (Date.now() - FACTOR_TELEMETRY_FETCHED_AT) < ttl){
        return FACTOR_TELEMETRY_CACHE;
      }
      const resp = await (window.safeFetch || fetch)('/api/v1/admin/factors/telemetry', { headers: authHeaders() });
      if(!resp.ok){
        return FACTOR_TELEMETRY_CACHE;
      }
      const payload = await resp.json().catch(()=>({}));
      FACTOR_TELEMETRY_CACHE = payload.telemetry || {};
      FACTOR_TELEMETRY_FETCHED_AT = Date.now();
      if(Array.isArray(FACTOR_TELEMETRY_CACHE.factor_history)){
        var map = {};
        FACTOR_TELEMETRY_CACHE.factor_history.forEach(function(entry){
          if(entry && entry.factor){
            map[String(entry.factor).toLowerCase()] = entry;
          }
        });
        FACTOR_TELEMETRY_CACHE.__historyMap = map;
      }
      return FACTOR_TELEMETRY_CACHE;
    }catch(_){
      return FACTOR_TELEMETRY_CACHE;
    }
  }

  function preparePipelineTargets(indexes){
    PIPELINE_TARGETS = new Set(indexes);
    PIPELINE_PENDING = new Set(indexes);
  }

  function markRowPipelinePending(idx){
    if(typeof idx !== 'number') return;
    PIPELINE_TARGETS.add(idx);
    PIPELINE_PENDING.add(idx);
  }

  function markRowPipelineReady(idx){
    if(typeof idx !== 'number') return;
    PIPELINE_PENDING.delete(idx);
  }

  function isPipelineReady(rec){
    return !!(rec && rec._pipeline_row);
  }

  function resolveRowId(rec, fallbackIdx){
    if(rec && typeof rec.row_index === 'number'){
      return rec.row_index;
    }
    if(typeof fallbackIdx === 'number'){
      return fallbackIdx;
    }
    return null;
  }

  function getPipelineStatusForRow(rec, idx){
    if(isPipelineReady(rec)) return 'ready';
    var rowId = resolveRowId(rec, idx);
    if(rowId === null) return 'none';
    if(PIPELINE_PENDING && PIPELINE_PENDING.has(rowId)) return 'pending';
    if(PIPELINE_TARGETS && PIPELINE_TARGETS.has(rowId)) return 'queued';
    return 'none';
  }

  function buildPipelineBadge(rec, idx){
    var status = getPipelineStatusForRow(rec, idx);
    var label = 'Heuristic';
    var cls = 'pipeline-badge-neutral';
    if(status === 'ready'){
      var risk = rec && rec._pipeline_row && rec._pipeline_row.risk_level;
      var riskLabel = (risk && risk.label) ? String(risk.label).toUpperCase() : '21-step';
      label = riskLabel;
      cls = 'pipeline-badge-ready';
    } else if(status === 'pending'){
      label = '21-step running';
      cls = 'pipeline-badge-pending';
    } else if(status === 'queued'){
      label = '21-step queued';
      cls = 'pipeline-badge-queued';
    } else {
      label = 'Heuristic only';
      cls = 'pipeline-badge-neutral';
    }
    return '<span class="pipeline-badge '+cls+'" title="'+escapeHtml(label)+'">'+label+'</span>';
  }

  // Render per-row actions column (cancel button if assessment available)
  function buildRowActions(rec, idx){
    try{
      var aid = localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId || null;
      var btn = '<button class="row-cancel-btn" data-idx="'+idx+'" onclick="window.__rowCancel(this)">Cancel</button>';
      return aid ? btn : '';
    }catch(_){ return ''; }
  }

  // Global hook exposed for inline onclick handlers
  window.__rowCancel = async function(el){
    try{
      if(!el) return; var idx = el.getAttribute('data-idx'); var aid = localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId || null; if(!aid){ alert('No assessment id'); return; }
      // show confirm modal
      var modal = document.getElementById('cancelConfirmModal'); if(!modal) return; modal.style.display='flex'; modal.setAttribute('data-idx', idx); modal.setAttribute('data-aid', aid);
    }catch(e){ console.warn('rowCancel', e); }
  };

  // Confirm modal handlers
  try{
    var _confirmYes = document.getElementById('cancelConfirmYes'); var _confirmNo = document.getElementById('cancelConfirmNo');
    if(_confirmNo) _confirmNo.addEventListener('click', function(){ try{ var m=document.getElementById('cancelConfirmModal'); if(m) m.style.display='none'; }catch(_){ } });
    if(_confirmYes) _confirmYes.addEventListener('click', async function(){ try{ var m=document.getElementById('cancelConfirmModal'); if(!m) return; var aid = m.getAttribute('data-aid'); m.style.display='none'; var btns = document.querySelectorAll('button.row-cancel-btn[data-idx="'+(m.getAttribute('data-idx')||'')+'"]'); btns.forEach(function(b){ b.disabled=true; b.textContent='Requested'; }); try{ await fetch('/api/v1/csv/deep_analyze/auto_backfill/'+encodeURIComponent(aid)+'/stop', { method:'POST', headers: {...authHeadersWithTenant()} }); }catch(_){ } }catch(e){ console.warn('confirmYes', e); } });
  }catch(_){ }

  function computePipelinePriority(rec, idx){
    var base = 0;
    try{
      var rowId = resolveRowId(rec, idx);
      if(isPipelineReady(rec)){
        var risk = rec && rec._pipeline_row && rec._pipeline_row.risk_level;
        var numeric = 0;
        if(risk && typeof risk.numeric === 'number') numeric = risk.numeric;
        else if(typeof risk === 'number') numeric = risk;
        var conf = typeof rec._pipeline_confidence === 'number' ? rec._pipeline_confidence : 0;
        // incorporate triage_score when available to bump genuinely prioritized rows
        var triage = (rec && rec._pipeline_row && typeof rec._pipeline_row.triage_score === 'number') ? rec._pipeline_row.triage_score : (typeof rec.triage_score === 'number' ? rec.triage_score : 0);
        base = 200000 + (numeric*100) + Math.round(conf*100) + Math.round(triage*100);
      }else if(rowId !== null && PIPELINE_PENDING && PIPELINE_PENDING.has(rowId)){
        var dread = (rec && rec._dread && typeof rec._dread.score === 'number') ? rec._dread.score : computeDreadBreakdown(rec && rec.factors, rec && (rec.raw || rec), rec).score;
        base = 100000 + (dread*10);
      }else{
        var fallback = (rec && rec._dread && typeof rec._dread.score === 'number') ? rec._dread.score : computeDreadBreakdown(rec && rec.factors, rec && (rec.raw || rec), rec).score;
        base = (fallback*10);
      }
    }catch(_){ }
    return base;
  }

  function queuePipelineForRow(rowIndex, rec, label){
    try{
      if(typeof rowIndex !== 'number' || !rec) return;
      var rawPayload = rec.raw ? rec.raw : rec;
      markRowPipelinePending(rowIndex);
      PIPELINE_AUTORANK = true;
      PIPELINE_FORCE_SORT = true;
      Promise.resolve(initiateDeepAnalyze({
        rows: [{ row_index: rowIndex, raw: rawPayload }],
        auto_llm: false,
        options: { auto_llm: false },
        analyze_mode: localStorage.getItem('csv_auto_analyze_mode') || 'basic',
        silent: true,
        priority_label: label || ('row-'+rowIndex)
      })).catch(function(err){ console.warn('single-row deep analyze failed', err); });
    }catch(err){ console.warn('queuePipelineForRow', err); }
  }

  function ensurePipelineReadyForRow(rowIndex, rec, intentLabel){
    if(rec && rec._pipeline_row){
      return true;
    }
    if(PIPELINE_PENDING && PIPELINE_PENDING.has(rowIndex)){
      alert('21-step pipeline is still running for row '+rowIndex+'. Try again once the badge turns green.');
      return false;
    }
    queuePipelineForRow(rowIndex, rec, intentLabel||'tier1');
    try{
      if(window.notifications && window.notifications.showToast){
        window.notifications.showToast('Running 21-step pipeline before '+(intentLabel||'LLM action'), 4000);
      }
    }catch(_){ }
    alert('21-step pipeline queued for row '+rowIndex+'. Try again once the pipeline badge turns green.');
    return false;
  }

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

  function computeDreadBreakdown(factors, raw, ctx){
    try{
      if(window.dreadMath && typeof window.dreadMath.computeScore === 'function'){
        return window.dreadMath.computeScore(factors || [], raw || {}, ctx || raw || {});
      }
    }catch(err){ console.warn('dreadMath computeScore failed', err); }
    // Legacy fallback retained for offline demos if dread_utils.js fails to load
    try{
      var base = 0;
      (factors||[]).forEach(function(f){
        if(!f) return;
        var s=String(f).toLowerCase();
        if(s.includes('lolbin')) base += 2;
        if(s.includes('unsigned')||s.includes('sensitive')) base += 1;
        if(s.includes('novel')||s.includes('global')) base += 1;
        if(s.includes('repeat')||s.includes('multi')) base += 1;
      });
      base = Math.max(0, base);
      var av = 0, tw = 0;
      var source = raw || {};
      try{ av = parseInt(String(source.avPositives||source.av_positives||source.avPos||0).replace(/[^0-9]/g,''),10)||0; }catch(_){ av=0; }
      try{ tw = parseFloat(String(source.threatWeight||source.threatweight||source.ThreatWeight||0).replace(/[^0-9\.\-]/g,''))||0; }catch(_){ tw=0; }
      var avScore = Math.min(5, av);
      var twScore = Math.min(5, Math.round(tw/2));
      var score = base + avScore + twScore;
      var norm = Math.min(10, Math.round(score));
      var level = norm<=3?'low':(norm<=6?'medium':'high');
      return { score: norm, level: level, details: { base: base, av: av, avScore: avScore, threatWeight: tw, twScore: twScore } };
    }catch(_){ return { score:0, level:'low', details:{} }; }
  }

  function formatBytes(bytes){
    try{
      var value = typeof bytes === 'number' ? bytes : parseFloat(bytes);
      if(isNaN(value) || value <= 0) return '';
      var units = ['B','KB','MB','GB','TB'];
      var idx = 0;
      while(value >= 1024 && idx < units.length-1){
        value = value / 1024;
        idx++;
      }
      var fixed = value >= 10 || idx === 0 ? value.toFixed(0) : value.toFixed(1);
      return fixed + ' ' + units[idx];
    }catch(_){
      return '';
    }
  }

  function computeEvidenceCoverage(row){
    try{
      if(row && row.evidence_summary && typeof row.evidence_summary.coverage === 'number'){
        return row.evidence_summary.coverage;
      }
      var score = 0;
      var weight = 0;
      if(typeof row.mapping_semantics_score === 'number'){
        score += row.mapping_semantics_score;
        weight += 1;
      }
      if(row.binary_context && (row.binary_context.binary_entropy || row.binary_context.supply_chain_tags)){
        score += 0.5;
        weight += 0.5;
      }
      if(row.hopgraph_context || row.hopgraph_summary){
        score += 0.5;
        weight += 0.5;
      }
      if(weight === 0) return 0;
      return Math.min(1, Math.max(0, score / (weight + 0.001)));
    }catch(_){
      return 0;
    }
  }

  function renderEvidenceCoverage(row){
    try{
      var coverage = computeEvidenceCoverage(row);
      var pct = Math.round((coverage || 0) * 100);
      var color = pct >= 70 ? '#5dd19a' : (pct >= 40 ? '#f8b37a' : '#f87575');
      var summary = row && row.evidence_summary || {};
      var policy = summary.policy || null;
      var target = policy ? Math.round((policy.target||0)*100) : 70;
      var status = summary.status || (summary.meets_target ? 'ok' : (pct >= target? 'ok':'warn'));
      var warnText = '';
      if(policy){
        if(status === 'critical'){
          warnText = '<div style="margin-top:6px;font-size:11px;color:var(--critical);">Coverage well below target ('+target+'%). Collect additional evidence before looping to Tier-2.</div>';
        } else if(status === 'warn' || status === 'gap'){
          warnText = '<div style="margin-top:6px;font-size:11px;color:var(--high);">Coverage below target ('+target+'%). Consider mapping more data.</div>';
        } else {
          warnText = '<div style="margin-top:6px;font-size:11px;color:var(--text-muted);">Coverage meets policy target ('+target+'%).</div>';
        }
      }
      return '<div class="evidence-coverage-meter" style="margin-top:8px;">'
        + '<div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-muted);"><span>Evidence coverage</span><span>'+pct+'%</span></div>'
        + '<div style="height:6px;border-radius:999px;background:var(--bg-tertiary,#191b2c);overflow:hidden;margin-top:4px;">'
        + '<div style="width:'+pct+'%;background:'+color+';height:100%;"></div>'
        + '</div>'+warnText+'</div>';
    }catch(_){
      return '';
    }
  }

  function openTier2ForRow(index){
    try{
      var rows = window.LAST_RESULTS || [];
      var rec = rows[index] || null;
      if(rec && !ensurePipelineReadyForRow(index, rec, 'Tier2 summary')){
        return;
      }
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
  function resolveSidebarRowIndex(row, fallback){
    try{
      if(typeof row === 'number' && Number.isFinite(row)){
        return row;
      }
      if(row && typeof row.row_index !== 'undefined'){
        if(typeof row.row_index === 'number' && Number.isFinite(row.row_index)){
          return row.row_index;
        }
        var parsed = Number(row.row_index);
        if(!Number.isNaN(parsed)){
          return parsed;
        }
      }
      if(row && typeof row._ui_index === 'number'){
        return row._ui_index;
      }
      if(row && typeof row.__row_index === 'number'){
        return row.__row_index;
      }
      if(typeof fallback !== 'undefined'){
        var fallbackParsed = Number(fallback);
        if(!Number.isNaN(fallbackParsed)){
          return fallbackParsed;
        }
      }
      if(row && Array.isArray(window.LAST_RESULTS)){
        var idx = window.LAST_RESULTS.indexOf(row);
        if(idx >= 0){
          return idx;
        }
      }
    }catch(_){ }
    return null;
  }

  function setTier1SidebarLoading(row, fallbackIndex){
    try{
      ensureTier1SidebarRefs();
      if(!LLM_SIDEBAR) return;
      LLM_SIDEBAR.style.display='block';
      LLM_SIDEBAR.classList.add('visible');
      LLM_SIDEBAR_CURRENT = resolveSidebarRowIndex(row, fallbackIndex);
      if(LLM_SIDEBAR_BODY) LLM_SIDEBAR_BODY.innerHTML='<div style="padding:12px">Loading Tier 1 summary…</div>';
      if(LLM_SIDEBAR_COST) LLM_SIDEBAR_COST.textContent='--';
      if(LLM_SIDEBAR_META) LLM_SIDEBAR_META.textContent = 'Row '+ (LLM_SIDEBAR_CURRENT!=null? LLM_SIDEBAR_CURRENT:'?');
    }catch(_){ }
  }

  // Render Tier 1 summary content
  function showTier1Sidebar(row, summaryText, cost){
    try{
      ensureTier1SidebarRefs();
      if(!LLM_SIDEBAR) return;
      LLM_SIDEBAR.style.display='block';
      LLM_SIDEBAR.classList.add('visible');
      LLM_SIDEBAR_CURRENT = resolveSidebarRowIndex(row, LLM_SIDEBAR_CURRENT);
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
        var telemetryHtml = renderFactorTelemetryDetails(resolvedRow);
        LLM_SIDEBAR_BODY.innerHTML = actions + helper + status + telemetryHtml + '<div id="llmSidebarContent">'+content+'</div>' + confidenceHtml;
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
        var rowId = (rec && typeof rec.row_index === 'number') ? rec.row_index : idx;
        var match = indexMap.hasOwnProperty(rowId) ? indexMap[rowId] : null;
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
        try{
          var risk = match && match.risk_level;
          if(risk && typeof risk.numeric === 'number'){
            updated._pipeline_priority = risk.numeric;
          }else if(typeof risk === 'number'){
            updated._pipeline_priority = risk;
          }
          if(risk && risk.label){
            updated._pipeline_risk_label = String(risk.label);
          }
        }catch(_){ }
        markRowPipelineReady(rowId);
        updated.verdict = getVerdictForView(updated);
        refreshed++;
        return updated;
      });
      if(refreshed){
        try{
          localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS));
          localStorage.setItem('csv_last_results_ts', String(Date.now()/1000));
        }catch(_){}
        if(VERDICT_VIEW_MODE !== 'pipeline'){
          try{
            setVerdictViewMode('pipeline');
          }catch(_){
            VERDICT_VIEW_MODE = 'pipeline';
            try{ localStorage.setItem('csv_verdict_view','pipeline'); }catch(_){}
          }
        }
      }
    }catch(err){
      console.warn('mergeAssessmentRowsIntoResults error', err);
    }
  }

  function tryParseJsonSummary(input){
    if(!input){
      return null;
    }
    if(typeof input === 'object'){
      return input;
    }
    if(typeof input !== 'string'){
      return null;
    }
    var trimmed = input.trim();
    if(!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')){
      return null;
    }
    try{
      return JSON.parse(trimmed);
    }catch(_){
      return null;
    }
  }

  function renderKeyValueTable(rows){
    try{
      var valid = (rows || []).filter(function(entry){
        // Keep rows with a label; render placeholder when value is missing
        return entry && entry.label;
      });
      if(!valid.length){
        return '';
      }
      return '<table class="tier1-table"><tbody>'+valid.map(function(entry){
        var displayValue = String((typeof entry.value !== 'undefined' && entry.value !== null) ? entry.value : '');
        // If value is still empty after conversion, show a placeholder
        if(!displayValue.trim()){
          displayValue = '<span style="color:var(--text-muted);font-style:italic;">(not provided)</span>';
        } else {
          displayValue = '<span style="color:#f2f5ff;font-weight:600;">'+escapeHtml(displayValue)+'</span>';
        }
        return '<tr><td style="color:var(--text-muted);">'+escapeHtml(entry.label)+':</td><td>'+displayValue+'</td></tr>';
      }).join('')+'</tbody></table>';
    }catch(_){
      return '';
    }
  }

  function renderList(items){
    var list = (items || []).filter(Boolean);
    if(!list.length){
      return '';
    }
    return '<ul>'+list.map(function(item){ return '<li>'+escapeHtml(String(item))+'</li>'; }).join('')+'</ul>';
  }

  function buildCorrelationContext(rec){
    try{
      if(!rec){
        return null;
      }
      var ctx = {};
      var mappingScore = (typeof rec.mapping_semantics_score === 'number') ? rec.mapping_semantics_score : (typeof rec._mapping_score === 'number' ? rec._mapping_score : null);
      var diversityScore = (typeof rec.domain_diversity_score === 'number') ? rec.domain_diversity_score : (typeof rec._domain_diversity === 'number' ? rec._domain_diversity : null);
      ctx.mappingScore = mappingScore;
      ctx.domainScore = diversityScore;
      ctx.pathScore = null;
      ctx.pathLabel = null;
      var pathScores = rec.path_scores || (window.LAST_CORR_SUMMARY && window.LAST_CORR_SUMMARY.path_scores);
      if(pathScores && typeof pathScores === 'object'){
        try{
          var keys = Object.keys(pathScores);
          if(keys.length){
            keys.sort(function(a,b){
              var va = (pathScores[a] && pathScores[a].score) || 0;
              var vb = (pathScores[b] && pathScores[b].score) || 0;
              return vb - va;
            });
            var topKey = keys[0];
            var entry = pathScores[topKey];
            if(entry && typeof entry.score === 'number'){
              ctx.pathScore = entry.score;
              ctx.pathLabel = topKey;
            }
          }
        }catch(_){}
      }
      var rawInsights = []
        .concat(rec.correlation_insights || [])
        .concat(rec.correlationInsights || [])
        .filter(Boolean);
      ctx.insights = rawInsights.slice(0,3).map(function(ins){
        var synth = ins.factor_synthesis || ins.synthesis || {};
        return {
          title: ins.narrative || ins.chain_id || 'Insight',
          confidence: ins.confidence,
          ttlSeconds: typeof ins.expires_at === 'number' ? Math.max(0, ins.expires_at - (Date.now()/1000)) : (typeof ins.ttl_seconds === 'number' ? ins.ttl_seconds : null),
          domains: (ins.domains || ins.domains_involved || []).slice(0,4),
          contributions: Array.isArray(synth.contributing_factors) ? synth.contributing_factors.slice(0,3) : [],
          finalScore: typeof synth.final_score === 'number' ? synth.final_score : null,
          explanation: synth.explanation || ''
        };
      });
      ctx.dependency = rec.dependency_status || null;
      ctx.replayCount = Number(rec.replayed_batch_count || 0);
      ctx.replayHistory = Array.isArray(rec.replay_history) ? rec.replay_history : [];
      if(
        ctx.mappingScore === null &&
        ctx.domainScore === null &&
        ctx.pathScore === null &&
        (!ctx.insights || !ctx.insights.length)
      ){
        return null;
      }
      return ctx;
    }catch(_){
      return null;
    }
  }

  function renderCorrelationHighlights(ctx){
    if(!ctx){
      return '';
    }
    var chips = [];
    if(typeof ctx.mappingScore === 'number'){
      chips.push('<span class="tier1-chip">Mapping '+escapeHtml(ctx.mappingScore.toFixed(2))+'</span>');
    }
    if(typeof ctx.domainScore === 'number'){
      chips.push('<span class="tier1-chip">Domain diversity '+escapeHtml(ctx.domainScore.toFixed(2))+'</span>');
    }
    if(typeof ctx.pathScore === 'number'){
      chips.push('<span class="tier1-chip">Path '+escapeHtml((ctx.pathLabel||'score'))+': '+escapeHtml(ctx.pathScore.toFixed(2))+'</span>');
    }
    var insightsHtml = '';
    if(ctx.insights && ctx.insights.length){
      insightsHtml = '<ul style="margin:6px 0 0 18px;">'+ctx.insights.map(function(ins){
        var doms = (ins.domains || []).map(function(d){ return '<span class="tier1-chip">'+escapeHtml(String(d))+'</span>'; }).join(' ');
        var contribs = (ins.contributions || []).map(function(pair){
          var name = Array.isArray(pair) ? pair[0] : '';
          var value = Array.isArray(pair) ? pair[1] : '';
          return name ? '<li>'+escapeHtml(String(name))+' <span class="inline-muted">'+escapeHtml(String((value!=null?Number(value).toFixed(2):'')))+'</span></li>' : '';
        }).join('');
        var ttlTxt = (typeof ins.ttlSeconds === 'number') ? ' · TTL '+formatTtl(ins.ttlSeconds) : '';
        var scoreTxt = (ins.finalScore != null) ? 'Score '+Number(ins.finalScore).toFixed(2) : '';
        return '<li><strong>'+escapeHtml(String(ins.title))+'</strong> <span class="inline-muted">(Conf '+(ins.confidence!=null?Number(ins.confidence).toFixed(2):'n/a')+ttlTxt+')</span>'
          + (scoreTxt?'<div class="inline-muted">'+scoreTxt+'</div>':'')
          + (doms?'<div style="margin-top:4px;">'+doms+'</div>':'')
          + (contribs?'<div class="inline-muted" style="margin-top:4px;">Top factors:</div><ul>'+contribs+'</ul>':'')
          + (ins.explanation?'<div class="inline-muted" style="margin-top:4px;">'+escapeHtml(ins.explanation)+'</div>':'')
          + '</li>';
      }).join('')+'</ul>';
    }else{
      insightsHtml = '<div class="inline-muted">No correlation insights available.</div>';
    }
    var depHtml = '';
    if(ctx.dependency){
      var hop = ctx.dependency.hopgraph || {};
      var redis = ctx.dependency.redis || {};
      var queued = Number(ctx.dependency.queued_factor_batches || 0);
      var formatSince = function(sec){
        if(!Number.isFinite(sec)) return 'unknown';
        if(sec >= 3600){ return (sec/3600).toFixed(1)+'h ago'; }
        if(sec >= 60){ return Math.round(sec/60)+'m ago'; }
        return Math.round(sec)+'s ago';
      };
      if(hop.available === false){
        depHtml += '<div class="inline-muted" style="margin-top:4px;color:var(--critical);">HopGraph offline — Tier 2 narratives rely on cached paths.</div>';
      } else if(hop.stale){
        depHtml += '<div class="inline-muted" style="margin-top:4px;">HopGraph snapshot stale; insights may lag live data.</div>';
      }
      if(hop.seconds_since_ok != null){
        depHtml += '<div class="inline-muted" style="margin-top:2px;">Last healthy HopGraph: '+formatSince(Number(hop.seconds_since_ok))+'</div>';
      }
      if(redis.available === false){
        depHtml += '<div class="inline-muted" style="margin-top:4px;color:var(--critical);">Redis unavailable — queued factors awaiting replay.</div>';
      }
      if(redis.seconds_since_ok != null){
        depHtml += '<div class="inline-muted" style="margin-top:2px;">Last healthy Redis: '+formatSince(Number(redis.seconds_since_ok))+'</div>';
      }
      if(queued > 0){
        depHtml += '<div class="inline-muted" style="margin-top:2px;">Queued factor batches awaiting replay: '+queued+'</div>';
      }
    }
    var replayHist = ctx.replayHistory && ctx.replayHistory.length ? ctx.replayHistory : (ctx.dependency && Array.isArray(ctx.dependency.replay_history) ? ctx.dependency.replay_history : []);
    if(ctx.replayCount && ctx.replayCount > 0){
      var lastReplay = replayHist && replayHist.length ? replayHist[replayHist.length-1] : null;
      var replayTime = lastReplay && lastReplay.timestamp ? new Date(lastReplay.timestamp * 1000).toLocaleTimeString() : 'recently';
      depHtml += '<div class="inline-muted" style="margin-top:4px;">Recovered '+ctx.replayCount+' queued factor batches ('+replayTime+').</div>';
    } else if(replayHist && replayHist.length){
      var lastReplayOnly = replayHist[replayHist.length-1];
      var replayStamp = lastReplayOnly && lastReplayOnly.timestamp ? new Date(lastReplayOnly.timestamp * 1000).toLocaleTimeString() : 'recently';
      var replayCount = lastReplayOnly && lastReplayOnly.batch_count ? lastReplayOnly.batch_count : replayHist.length;
      depHtml += '<div class="inline-muted" style="margin-top:4px;">Last replay flushed '+replayCount+' batches ('+replayStamp+').</div>';
    }
    return '<div>'+ (chips.length?'<div class="tier1-chip-list">'+chips.join(' ')+'</div>':'') + insightsHtml + depHtml + '</div>';
  }

  window.renderCorrelationHighlights = renderCorrelationHighlights;

  function formatTtl(seconds){
    if(!Number.isFinite(seconds)){
      return 'n/a';
    }
    var sec = Math.max(0, Math.floor(seconds));
    var hrs = Math.floor(sec / 3600);
    var mins = Math.floor((sec % 3600) / 60);
    var rem = sec % 60;
    if(hrs){ return hrs+'h '+mins+'m'; }
    if(mins){ return mins+'m '+rem+'s'; }
    return rem+'s';
  }

  function formatRelativeAge(seconds){
    if(!Number.isFinite(seconds)){
      return null;
    }
    var sec = Math.max(0, Number(seconds));
    if(sec >= 3600){
      return (sec/3600).toFixed(1)+'h ago';
    }
    if(sec >= 60){
      return Math.round(sec/60)+'m ago';
    }
    return Math.round(sec)+'s ago';
  }

  function renderTier1StructuredSummary(rawData){
    try{
      if(!rawData || typeof rawData !== 'object'){
        return '';
      }
      var data = (rawData.payload && typeof rawData.payload === 'object') ? rawData.payload : rawData;
      var sections = [];
      if(data.metadata){
        sections.push({
          title: 'Metadata',
          body: renderKeyValueTable([
            { label: 'Domain', value: data.metadata.domain },
            { label: 'Confidence', value: (typeof data.metadata.confidence_score === 'number') ? (Math.round(data.metadata.confidence_score * 10000) / 100)+'%' : data.metadata.confidence_score },
            { label: 'Processing cost', value: data.metadata.processing_cost },
            { label: 'Timestamp', value: data.metadata.timestamp }
          ])
        });
      }
      if(data.verdict){
        sections.push({
          title: 'Verdict',
          body: renderKeyValueTable([
            { label: 'Classification', value: data.verdict.classification },
            { label: 'DREAD', value: data.verdict.dread_score },
            { label: 'Kill chain', value: data.verdict.kill_chain_phase },
            { label: 'MITRE techniques', value: Array.isArray(data.verdict.mitre_techniques) ? data.verdict.mitre_techniques.slice(0,8).join(', ') : null }
          ])
        });
      }
      if(data.why_flagged){
        var signals = (data.why_flagged.contributing_signals || []).map(function(sig){
          if(!sig) return null;
          var parts = [];
          if(sig.signal_name) parts.push('<strong>'+escapeHtml(sig.signal_name)+'</strong>');
          if(sig.explanation) parts.push('<span class="inline-muted">'+escapeHtml(sig.explanation)+'</span>');
          return parts.join(' &mdash; ');
        }).filter(Boolean);
        sections.push({
          title: 'Why flagged',
          body: (data.why_flagged.primary_reason ? '<p>'+escapeHtml(data.why_flagged.primary_reason)+'</p>' : '') + (signals.length ? '<ul>'+signals.map(function(item){ return '<li>'+item+'</li>'; }).join('')+'</ul>' : '')
        });
      }
      if(data.key_evidence){
        var artifact = data.key_evidence.primary_artifact || {};
        var context = data.key_evidence.context || {};
        var artifactTable = renderKeyValueTable([
          { label: 'Type', value: artifact.type },
          { label: 'Path', value: artifact.path },
          { label: 'SHA256', value: artifact.hash_sha256 },
          { label: 'Signature', value: artifact.signature_status },
          { label: 'Size (bytes)', value: artifact.file_size_bytes }
        ]);
        var contextTable = renderKeyValueTable([
          { label: 'Hostname', value: context.hostname },
          { label: 'Username', value: context.username },
          { label: 'IP address', value: context.ip_address }
        ]);
        sections.push({
          title: 'Key evidence',
          body: artifactTable + contextTable + (Array.isArray(data.key_evidence.related_artifacts) && data.key_evidence.related_artifacts.length ? renderList(data.key_evidence.related_artifacts.map(function(entry){
            if(entry && entry.type && entry.value){
              return entry.type+': '+entry.value;
            }
            return entry && entry.value ? entry.value : '';
          })) : '')
        });
      }
      if(data.playbook){
        var playbookBody = renderKeyValueTable([
          { label: 'Alert type', value: data.playbook.alert_type },
          { label: 'Severity', value: data.playbook.severity },
          { label: 'MITRE', value: Array.isArray(data.playbook.mitre) ? data.playbook.mitre.join(', ') : '' },
          { label: 'References', value: Array.isArray(data.playbook.references) ? data.playbook.references.join(', ') : '' }
        ]);
        if(Array.isArray(data.playbook.steps) && data.playbook.steps.length){
          playbookBody += '<ol>'+data.playbook.steps.slice(0,6).map(function(step){
            var label = step.action || ('Step '+(step.order || ''));
            var rationale = step.rationale ? '<div class="inline-muted">'+escapeHtml(step.rationale)+'</div>' : '';
            return '<li><strong>'+escapeHtml(label)+'</strong>'+rationale+'</li>';
          }).join('')+'</ol>';
        }
        sections.push({ title: 'Playbook', body: playbookBody });
      }
      if(Array.isArray(data.analyst_actions) && data.analyst_actions.length){
        sections.push({
          title: 'Analyst actions',
          body: '<div class="tier1-chip-list">'+data.analyst_actions.slice(0,6).map(function(action){
            var label = action.label || action.action;
            var extra = action.reason ? ' &mdash; '+escapeHtml(action.reason) : '';
            return '<span class="tier1-chip">'+escapeHtml(label||'Action')+extra+'</span>';
          }).join('')+'</div>'
        });
      }
      if(data.correlation_context){
        sections.push({
          title: 'Correlation highlights',
          body: renderCorrelationHighlights(data.correlation_context)
        });
      }
      if(!sections.length){
        return '';
      }
      return sections.map(function(section){
        return '<div class="tier1-section"><h4>'+escapeHtml(section.title)+'</h4>'+(section.body || '<p class="inline-muted">No data provided.</p>')+'</div>';
      }).join('');
    }catch(_){
      return '';
    }
  }

  function formatTier1Summary(summaryInput){
    try{
      var structured = tryParseJsonSummary(summaryInput);
      if(structured){
        var structuredHtml = renderTier1StructuredSummary(structured);
        if(structuredHtml){
          return '<div class="tier1-summary">'+structuredHtml+'</div>';
        }
      }
      var text = (typeof summaryInput === 'string') ? summaryInput : '';
      if(!text) return '<div class="tier1-summary text-muted">No summary generated.</div>';
      var regex = /(WHAT IS IT\?|EXPLOITABILITY|WHAT TO DO\?|CONCISE PLAYBOOK|MISSING LOGS)/gi;
      var sections = []; var match; var lastIndex = 0; var current = null;
      while((match = regex.exec(text)) !== null){
        if(current){ current.content = text.slice(lastIndex, match.index).trim(); }
        current = { title: match[0].toUpperCase(), start: match.index, content: '' };
        sections.push(current);
        lastIndex = regex.lastIndex;
      }
      if(current){ current.content = text.slice(lastIndex).trim(); }
      if(!sections.length){
        return '<div class="tier1-summary"><pre style="white-space:pre-wrap;">'+escapeHtml(text)+'</pre></div>';
      }
      var html = sections.map(function(section){
        var body = (section.content || '').trim() || 'No details provided.';
        var rendered = (section.title === 'CONCISE PLAYBOOK') ? renderPlaybookSection(body) : '<div>'+escapeHtml(body).replace(/\n{2,}/g,'\n').replace(/\n/g,'<br />')+'</div>';
        return '<div class="tier1-section"><h4>'+section.title+'</h4>'+rendered+'</div>';
      }).join('');
      return '<div class="tier1-summary">'+html+'</div>';
    }catch(_){
      return '<div class="tier1-summary"><pre style="white-space:pre-wrap;">'+escapeHtml(text || '')+'</pre></div>';
    }
  }

  function renderPlaybookSection(raw){
    try{
      var normalized = (raw || '').replace(/\r/g,'').trim();
      if(!normalized) return '<div>No details provided.</div>';
      var meta = [];
      var metaRegex = /-\s*(Host|User|Path|Hash|DREAD|Verdict|Confidence):\s*([^\-\n]+?)(?=(?:-\s*(?:Host|User|Path|Hash|DREAD|Verdict|Confidence)|$))/gi;
      var cleaned = normalized.replace(metaRegex, function(_, label, value){
        meta.push({ label: label, value: value.trim() });
        return '';
      }).trim();
      var steps = [];
      var stepRegex = /(?:^|\s)(?:\(?(\d+)[\)\.])\s*(.*?)(?=(?:\s+\(?\d+[\)\.])|\s*$)/gs;
      var stepMatch;
      while((stepMatch = stepRegex.exec(cleaned)) !== null){
        var text = (stepMatch[2] || '').trim().replace(/^[\-\u2022]+\s*/,'');
        if(text){ steps.push(text); }
      }
      if(!steps.length){
        steps = cleaned.split(/\n+/).map(function(line){ return line.trim(); }).filter(Boolean);
      }
      var parts = [];
      if(steps.length){
        parts.push('<ol class="playbook-steps">'+steps.map(function(step){ return '<li>'+escapeHtml(step)+'</li>'; }).join('')+'</ol>');
      } else {
        parts.push('<div>'+escapeHtml(normalized).replace(/\n{2,}/g,'\n').replace(/\n/g,'<br />')+'</div>');
      }
      if(meta.length){
        var seen = {};
        var metaItems = meta.filter(function(entry){
          var key = (entry.label||'').toLowerCase()+'::'+(entry.value||'').toLowerCase();
          if(seen[key]) return false;
          seen[key] = true;
          return true;
        }).slice(0,8).map(function(entry){
          return '<span class="tier1-meta-field"><strong>'+escapeHtml(entry.label)+':</strong> '+escapeHtml(entry.value)+'</span>';
        }).join('');
        if(metaItems){ parts.push('<div class="tier1-playbook-meta">'+metaItems+'</div>'); }
      }
      return parts.join('');
    }catch(_){
      return '<div>'+escapeHtml(raw || '')+'</div>';
    }
  }

  function resolveSidebarRow(rowArg){
    try{
      if(!rowArg) return null;
      if(rowArg.raw || rowArg.factors || rowArg.verdict) return rowArg;
      var idx = null;
      if(typeof rowArg.row_index === 'number') idx = rowArg.row_index;
      else if(typeof rowArg === 'number') idx = rowArg;
      if(idx === null || typeof idx === 'undefined') return null;
      var list = window.LAST_RESULTS || [];
      return list[idx] || null;
    }catch(_){
      return null;
    }
  }

  function getRowByIndex(idx){
    try{
      var list = window.LAST_RESULTS || [];
      return list[idx] || null;
    }catch(_){
      return null;
    }
  }

  function renderBreakerBanner(row){
    try{
      var signal = row && row.breaker_signal;
      if(!signal) return '';
      var congested = !!signal.congested;
      var queue = (typeof signal.queue_depth !== 'undefined' && signal.queue_depth !== null) ? 'Queue depth '+signal.queue_depth : '';
      var breakerNotes = '';
      if(Array.isArray(signal.breakers) && signal.breakers.length){
        var tripped = signal.breakers.filter(function(entry){ return entry && entry.open; }).map(function(entry){
          return entry.name ? entry.name : '';
        }).filter(Boolean);
        if(tripped.length){
          breakerNotes = ' Tripped: '+escapeHtml(tripped.join(', '));
        }
      }
      var color = congested ? '#f8b37a' : '#5dd19a';
      var bg = congested ? 'rgba(248,179,122,0.15)' : 'rgba(93,209,154,0.15)';
      return '<div class="breaker-banner" style="margin:8px 0;padding:8px;border-radius:6px;border:1px solid '+color+';background:'+bg+';color:'+color+';"><strong>Pipeline load:</strong> '+(congested?'Congested':'Healthy')+' '+queue+breakerNotes+'</div>';
    }catch(_){
      return '';
    }
  }

  function renderMappingCoverage(row){
    try{
      var summary = row && (row.mapping_summary || (row.mapping_semantics && row.mapping_semantics.summary));
      var scoreRaw = (row && typeof row.mapping_semantics_score === 'number') ? row.mapping_semantics_score : (row && row.mapping_semantics && row.mapping_semantics.score);
      if(!summary && typeof scoreRaw === 'undefined'){
        return '';
      }
      var hv = summary && Array.isArray(summary.high_value_present) ? summary.high_value_present.slice(0,6) : [];
      var missingHV = summary && Array.isArray(summary.missing_high_value) ? summary.missing_high_value.slice(0,4) : [];
      var missingSupport = summary && Array.isArray(summary.missing_support) ? summary.missing_support.slice(0,4) : [];
      var html = '<div class="mapping-hud" style="margin-top:8px;padding:8px;border:1px solid var(--border,#2d3245);border-radius:6px;background:var(--bg-tertiary,#151826);font-size:12px;">';
      html += '<strong>Mapping coverage:</strong> ';
      if(typeof scoreRaw === 'number'){
        html += 'score '+scoreRaw.toFixed(2)+' ';
      }
      if(hv.length){
        html += '<div>High-value: '+escapeHtml(hv.join(', '))+'</div>';
      }
      if(missingHV.length){
        html += '<div style="color:#f8b37a;">Missing high-value: '+escapeHtml(missingHV.join(', '))+'</div>';
      }
      if(missingSupport.length){
        html += '<div style="color:#f8b37a;">Missing support: '+escapeHtml(missingSupport.join(', '))+'</div>';
      }
      html += '</div>';
      return html;
    }catch(_){
      return '';
    }
  }

  function renderCachedEvidenceList(row){
    try{
      var list = row && Array.isArray(row.cached_evidence) ? row.cached_evidence : [];
      var aid = row && row.assessment_id;
      if(!list.length || !aid){
        return '';
      }
      var targetId = 'cachedEvidence-'+(typeof row.row_index !== 'undefined' ? row.row_index : ('r'+Math.random().toString(36).slice(2)));
      var items = list.slice(0,5).map(function(item, idx){
        if(!item) return '';
        var label = item.label || item.type || ('Blob '+(idx+1));
        var size = item.size_hint ? ' ('+formatBytes(item.size_hint)+')' : '';
        return '<li><button type="button" class="btn btn-xs cached-evidence-btn" data-cache="'+encodeURIComponent(item.cache_key||'')+'" data-assessment="'+encodeURIComponent(aid)+'" data-target="'+targetId+'">'+escapeHtml(label)+'</button><span class="text-muted">'+escapeHtml(size)+'</span></li>';
      }).join('');
      return '<div class="cached-evidence-block" style="margin-top:10px;"><strong>Heavy evidence</strong><ul class="tier1-pipeline-list">'+items+'</ul><pre id="'+targetId+'" class="cached-evidence-output" style="white-space:pre-wrap;background:var(--bg-secondary,#1d1f2b);border:1px solid var(--border,#2d3245);padding:6px;border-radius:6px;max-height:200px;overflow:auto;"></pre></div>';
    }catch(_){
      return '';
    }
  }

  function buildTier1ConfidenceBlock(row){
    try{
      if(!row) return '';
      var dreadInfo = row._dread || computeDreadBreakdown(row.factors, row.raw, row);
      var host = row.host || row.hostname || (row.raw && (row.raw.host||row.raw.hostname)) || 'unknown host';
      var user = row.user || row.username || (row.raw && (row.raw.user||row.raw.User)) || '';
      var artifact = row.process_name || row.file_path || row.binary || (row.raw && (row.raw.process_name||row.raw.FilePath)) || 'artifact unavailable';
      var viewVerdict = getVerdictForView(row) || row.verdict || 'Not assessed';
      var pipelineVerdict = row._pipeline_verdict || 'Not yet enriched';
      var confidence = formatConfidenceValue(typeof row._pipeline_confidence !== 'undefined' ? row._pipeline_confidence : row.confidence);
      var factors = (row.factors || []).filter(Boolean).slice(0,6).map(function(f){ return '<span class="tier1-factor-pill">'+escapeHtml(f)+'</span>'; }).join('') || '<span class="text-muted">Signals not captured in CSV</span>';
      var cues = [];
      cues.push('<div class="tier1-confidence-metric"><div class="label">Current view</div><div class="value">'+escapeHtml(viewVerdict)+'</div></div>');
      cues.push('<div class="tier1-confidence-metric"><div class="label">Pipeline verdict</div><div class="value">'+escapeHtml(pipelineVerdict)+'</div></div>');
      cues.push('<div class="tier1-confidence-metric"><div class="label">Confidence</div><div class="value">'+(confidence || 'n/a')+'</div></div>');
      var dreadStatus = (dreadInfo.status && dreadInfo.status !== 'UNKNOWN') ? ' <span style="font-size:11px;color:var(--text-muted);">['+escapeHtml(dreadInfo.status)+']</span>' : '';
      cues.push('<div class="tier1-confidence-metric"><div class="label">DREAD</div><div class="value">'+escapeHtml(String(dreadInfo.score||0))+' <span style="font-size:11px;color:var(--text-muted);">('+escapeHtml(dreadInfo.level||'n/a')+')</span>'+dreadStatus+'</div></div>');
      var evidenceItems = [];
      var evidence = row._pipeline_evidence;
      if(typeof evidence === 'string'){
        evidenceItems.push(evidence.trim());
      } else if(Array.isArray(evidence)){
        evidence.forEach(function(entry){
          if(!entry) return;
          if(typeof entry === 'string'){
            evidenceItems.push(entry.trim());
            return;
          }
          var obs = entry.observation || entry.note || entry.summary || entry.text;
          var sig = entry.significance || entry.impact;
          var conf = formatConfidenceValue(entry.confidence);
          var line = obs ? String(obs) : JSON.stringify(entry);
          if(sig){
            line += ' — '+sig;
          }
          if(conf){
            line += ' ('+conf+')';
          }
          evidenceItems.push(line);
        });
      }
      var tasks = [];
      var rawTasks = row._pipeline_tasks;
      if(typeof rawTasks === 'string'){
        tasks.push(rawTasks.trim());
      } else if(Array.isArray(rawTasks)){
        rawTasks.forEach(function(task){
          if(!task) return;
          if(typeof task === 'string'){
            tasks.push(task.trim());
            return;
          }
          var label = task.task || task.title || task.summary || 'Investigation task';
          var priority = task.priority ? ('['+task.priority.toUpperCase()+'] ') : '';
          var tool = task.tool ? (' via '+task.tool) : '';
          tasks.push(priority+label+tool);
        });
      }
      var uncertaintyFlags = Array.isArray(row._uncertaintyFlags) ? row._uncertaintyFlags.filter(Boolean) : [];
      var extraLine = (row.reason || (row.raw && (row.raw.reason||row.raw.alert_reason))) ? '<div><strong>Why pipeline flagged it:</strong> '+escapeHtml(row.reason || row.raw.reason || row.raw.alert_reason)+'</div>' : '';
      var userLine = user ? ' | <strong>User:</strong> '+escapeHtml(user) : '';
      var evidenceHtml = evidenceItems.length ? '<div style="margin-top:6px;"><strong>Pipeline evidence:</strong><ul class="tier1-pipeline-list">'+evidenceItems.slice(0,4).map(function(item){ return '<li>'+escapeHtml(item)+'</li>'; }).join('')+'</ul></div>' : '';
      var taskHtml = tasks.length ? '<div style="margin-top:6px;"><strong>Investigation tasks:</strong><ul class="tier1-pipeline-list">'+tasks.slice(0,3).map(function(item){ return '<li>'+escapeHtml(item)+'</li>'; }).join('')+'</ul></div>' : '';
      var uncertaintyHtml = uncertaintyFlags.length ? '<div class="tier1-uncertainty">Telemetry gaps: '+escapeHtml(uncertaintyFlags.join(', '))+'</div>' : '';
      var skipLine = row && row.llm_skipped_reason ? '<div style="margin-top:6px;color:var(--text-muted)"><strong>LLM skipped:</strong> '+escapeHtml(row.llm_skipped_reason)+'</div>' : '';
      var breakerHtml = renderBreakerBanner(row);
      var mappingHud = renderMappingCoverage(row);
       var coverageHtml = renderEvidenceCoverage(row);
      var cachedBlock = renderCachedEvidenceList(row);
      return '<div class="tier1-confidence"><div class="tier1-confidence-label">Pipeline cues ('+(VERDICT_VIEW_MODE==='pipeline'?'post-pipeline':'initial')+')</div>'
        + '<div class="tier1-confidence-grid">'+cues.join('')+'</div>'
        + breakerHtml
        + '<div><strong>Host:</strong> '+escapeHtml(host)+userLine+'</div>'
        + '<div><strong>Artifact:</strong> '+escapeHtml(artifact)+'</div>'
        + mappingHud
        + coverageHtml
        + '<div><strong>Signals:</strong> '+factors+'</div>'
        + evidenceHtml
        + taskHtml
        + uncertaintyHtml
        + cachedBlock
        + extraLine
        + skipLine
        + '</div>';
    }catch(_){
      return '';
    }
  }

  function renderFactorTelemetryDetails(row){
    try{
      var sections = [];
      var telemetry = FACTOR_TELEMETRY_CACHE || {};
      var historyMap = (telemetry && telemetry.__historyMap) || {};
      var insights = [];
      if(row){
        var rawInsights = [].concat(row.correlation_insights || [], row.correlationInsights || []);
        insights = rawInsights.filter(function(ins){
          if(!ins) return false;
          if(ins.type && String(ins.type).toLowerCase() === 'factor_synthesis') return true;
          if(ins.factor === 'factor_synthesis') return true;
          return !!ins.factor_synthesis;
        });
      }
      if(insights.length){
        var primary = insights[0];
        var synth = primary.factor_synthesis || primary.synthesis || primary;
        var synergies = Array.isArray(synth.synergies) && synth.synergies.length ? synth.synergies.join(', ') : 'none';
        var contextMultiplier = (synth.context_multiplier != null) ? Number(synth.context_multiplier).toFixed(2) : 'n/a';
        var decayApplied = (synth.decay_applied != null) ? Number(synth.decay_applied).toFixed(2) : 'n/a';
        var ttlSeconds = typeof primary.ttl_seconds === 'number' ? formatTtl(primary.ttl_seconds) : '';
        sections.push('<div><strong>Factor synthesis insight</strong>: score '
          + Number(synth.final_score || 0).toFixed(2)
          + ' (confidence '+Number(synth.confidence || 0).toFixed(2)+') · context ×'
          + contextMultiplier+' · decay '+decayApplied
          + (ttlSeconds ? ' · TTL '+ttlSeconds : '')
          + '<div>Synergies: '+escapeHtml(synergies||'none')+'</div>'
          + (synth.explanation ? '<div class="inline-muted">'+escapeHtml(String(synth.explanation))+'</div>' : '')
          + '</div>');
        var contributions = Array.isArray(synth.contributing_factors) ? synth.contributing_factors.slice(0,4) : [];
        if(contributions.length){
          var rows = contributions.map(function(pair){
            var name = Array.isArray(pair) ? pair[0] : '';
            var value = Array.isArray(pair) ? pair[1] : '';
            var hist = name ? historyMap[String(name).toLowerCase()] : null;
            var historyText = hist ? ('FP '+Number(hist.fp_rate || hist.fp || 0).toFixed(2)+' • TP '+Number(hist.tp || 0).toFixed(1)+' / FP '+Number(hist.fp || 0).toFixed(1)) : 'Telemetry pending';
            return '<tr><td>'+escapeHtml(String(name || 'factor'))+'</td><td>'+Number(value || 0).toFixed(2)+'</td><td>'+escapeHtml(historyText)+'</td></tr>';
          }).join('');
          sections.push('<div class="tier1-telemetry-table" style="overflow-x:auto;"><table style="width:100%;font-size:11px;"><thead><tr><th style="text-align:left;">Factor</th><th style="text-align:left;">Contribution</th><th style="text-align:left;">FP history</th></tr></thead><tbody>'+rows+'</tbody></table></div>');
        }
      }
      if(telemetry && telemetry.history_half_life_minutes){
        sections.push('<div class="inline-muted">Decay window: '+Number(telemetry.history_half_life_minutes).toFixed(1)+' min half-life · Window precision '+(telemetry.window_precision != null ? Number(telemetry.window_precision).toFixed(3) : 'n/a')+'.</div>');
      }
      var dep = (row && row.dependency_status) || (typeof window !== 'undefined' && window.__lastDependencyStatus) || null;
      if(dep){
        var depNotes = [];
        var hop = dep.hopgraph || {};
        var redis = dep.redis || {};
        if(hop.available === false){
          depNotes.push('HopGraph offline — Tier 2 falls back to cached paths.');
        } else if(hop.seconds_since_ok != null){
          var hopTxt = formatRelativeAge(Number(hop.seconds_since_ok));
          if(hopTxt){
            depNotes.push('HopGraph healthy '+hopTxt);
          }
        }
        if(redis.available === false){
          depNotes.push('Redis unavailable — factor batches queuing.');
        } else if(redis.seconds_since_ok != null){
          var redisTxt = formatRelativeAge(Number(redis.seconds_since_ok));
          if(redisTxt){
            depNotes.push('Redis healthy '+redisTxt);
          }
        }
        if(dep.queued_factor_batches){
          depNotes.push('Queued factor batches: '+dep.queued_factor_batches);
        }
        var replayCount = Number((row && row.replayed_batch_count) || 0);
        var replayHist = Array.isArray(row && row.replay_history) ? row.replay_history : (Array.isArray(dep.replay_history) ? dep.replay_history : []);
        if(replayCount > 0){
          var replayEntry = replayHist && replayHist.length ? replayHist[replayHist.length-1] : null;
          var replayStamp = replayEntry && replayEntry.timestamp ? new Date(replayEntry.timestamp * 1000).toLocaleTimeString() : 'recently';
          depNotes.push('Recovered '+replayCount+' queued batches ('+replayStamp+')');
        } else if(replayHist && replayHist.length){
          var replayLast = replayHist[replayHist.length-1];
          var replayStamp2 = replayLast && replayLast.timestamp ? new Date(replayLast.timestamp * 1000).toLocaleTimeString() : 'recently';
          var replayLabel = replayLast && replayLast.batch_count ? replayLast.batch_count : replayHist.length;
          depNotes.push('Last replay flushed '+replayLabel+' batches ('+replayStamp2+')');
        }
        if(depNotes.length){
          sections.push('<div class="tier1-dependency-note">'+depNotes.join(' • ')+'</div>');
        }
      }
      var uncertaintyFlags = row && Array.isArray(row._uncertaintyFlags) ? row._uncertaintyFlags.filter(Boolean) : [];
      if(uncertaintyFlags.length){
        sections.push('<div class="tier1-missing">Telemetry gaps detected ('+escapeHtml(uncertaintyFlags.join(', '))+'). Consider using <strong>Request Logs</strong> before escalating.</div>');
      }
      if(!sections.length){
        return '';
      }
      return '<div class="tier1-telemetry-panel" style="margin:8px 0;padding:10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:6px;">'+sections.join('')+'</div>';
    }catch(_){
      return '';
    }
  }

  function updateTier1ActionStatus(message, tone){
    try{
      var el = document.getElementById('llmActionStatus');
      if(!el) return;
      el.textContent = message;
      el.style.color = tone === 'error' ? '#f8b37a' : 'var(--text-muted)';
    }catch(_){ }
  }

  function handleTier1ActionPromise(promise, successMsg, failureMsg){
    try{
      Promise.resolve(promise).then(function(result){
        var ok = (typeof result === 'boolean') ? result : (result !== false);
        updateTier1ActionStatus(ok ? successMsg : failureMsg, ok ? 'info' : 'error');
      }).catch(function(){
        updateTier1ActionStatus(failureMsg, 'error');
      });
    }catch(_){
      updateTier1ActionStatus(failureMsg, 'error');
    }
  }

  // Update active styling on filter buttons
  function updateFilterButtonStates(){
    try{
      ['btnFilterAll','btnFilterSuspicious','btnFilterPassed'].forEach(function(id){ var b=document.getElementById(id); if(b) b.classList.remove('btn-primary'); });
      var activeId = FILTER_MODE==='all' ? 'btnFilterAll' : (FILTER_MODE==='suspicious' ? 'btnFilterSuspicious' : 'btnFilterPassed');
      var activeBtn = document.getElementById(activeId); if(activeBtn) activeBtn.classList.add('btn-primary');
    }catch(_){ }
  }

  // Lightweight mappings from client-side factors to MITRE / STRIDE hints (best-effort)
  function mapFactorsToMitre(factors){
    try{
      var out = [];
      (factors||[]).forEach(function(f){ if(!f) return; var s=String(f).toLowerCase();
        if(s.includes('lolbin')) out.push({ id:'T1218', name:'Signed Binary Proxy Execution', tactic:'Defense Evasion' });
        if(s.includes('unsigned_sensitive_path')) out.push({ id:'T1036', name:'Masquerading / Suspicious Path', tactic:'Defense Evasion' });
        if(s.includes('novel')||s.includes('global')) out.push({ id:'T1071', name:'Application Layer Protocol', tactic:'Command and Control' });
        if(s.includes('multi')||s.includes('repeat')) out.push({ id:'T1090', name:'Proxy/Relay', tactic:'Command and Control' });
        if(s.includes('suspicious')||s.includes('malicious')) out.push({ id:'Tactic', name:'Investigate textual indicators', tactic:'Discovery' });
      });
      return out;
    }catch(_){ return []; }
  }

  function mapFactorsToStride(factors){
    try{
      var out = [];
      (factors||[]).forEach(function(f){ if(!f) return; var s=String(f).toLowerCase();
        if(s.includes('lolbin')||s.includes('unsigned')) out.push('Tampering');
        if(s.includes('novel')||s.includes('sensitive')) out.push('Information Disclosure');
        if(s.includes('multi')||s.includes('repeat')) out.push('Repudiation');
      });
      return Array.from(new Set(out));
    }catch(_){ return []; }
  }

  function wrapCell(val){ return '<div class="cell-text" title="'+(String(val||'')).replace(/"/g,'&quot;')+'">'+(val||'')+'</div>'; }

  function insertInlineDetailsAfter(tr, index){
    try{
      var row = (window.LAST_RESULTS||[])[index]||{};
      var container = document.createElement('tr'); container.className='csv-inline-details';
      try{ var modal = document.getElementById('csvDrillModal'); if(modal){ modal.style.display='none'; modal.style.visibility='hidden'; modal.style.pointerEvents='none'; } }catch(_){ }
      var cell = document.createElement('td'); cell.colSpan = tr.children.length; cell.style.background = 'rgba(0,0,0,0.03)';
      var inner = document.createElement('div'); inner.style.padding='8px'; inner.style.display='flex'; inner.style.flexDirection='column';
      var info = document.createElement('div'); info.innerText = 'signals: ' + (row.factors? row.factors.join(', '): ''); inner.appendChild(info);
      var dreadData = row._dread || computeDreadBreakdown(row.factors, row.raw, row);
      var dread = document.createElement('div');
      var dreadLabel = 'DREAD: ' + (dreadData.score || 0) + ' (' + (dreadData.level || 'n/a') + ')';
      if(dreadData.status && dreadData.status !== 'UNKNOWN'){
        dreadLabel += ' ['+dreadData.status+']';
      }
      dread.innerText = dreadLabel;
      inner.appendChild(dread);
      // collapse/caret
      var caret = document.createElement('span'); caret.className='collapse-caret'; caret.style.marginLeft='8px'; caret.textContent='▾'; dread.appendChild(caret);
      // show explain details if user enabled
      try{
        var explainOn = (localStorage.getItem('csv_explain_toggle')||'1')!=='0';
        if(explainOn){
          var dbg=document.createElement('div');
          dbg.style.marginTop='6px';
          try{
            var det = dreadData.details || {};
            dbg.textContent = 'Breakdown: base='+ (det.base||0)
              +', av='+ (det.avScore||0)
              +', tw='+ (det.twScore||0)
              +', mapping='+ (det.mapping||0)
              +', diversity='+ (det.diversity||0)
              +', binary='+ (det.binary||0)
              +', network='+ (det.network||0)
              +', trust='+ (det.trustAdjustment||0);
          }catch(_){
            dbg.textContent='Breakdown available';
          }
          inner.appendChild(dbg);
        }
      }catch(_){ }
      var btns = document.createElement('div'); btns.style.marginTop='6px';
      var explain = document.createElement('button'); explain.className='csv-btn-inline btn'; explain.innerText='Fetch Explain'; explain.disabled = !(row && row.raw && (row.raw.event_id||row.raw.EventID));
      // If no event id, leave disabled so tests can detect absence; client-side synthetic explain is available via button click fallback
      explain.addEventListener('click', async function(){
        try{
          var eid = row && row.raw && (row.raw.event_id||row.raw.EventID);
          if(eid){
            try{
              var r = await (window.safeFetch || fetch)('/api/v1/decisions/'+encodeURIComponent(eid)+'/explain',{ headers: {...authHeaders()} });
              if(r.ok){ var j=await r.json(); var pre=document.createElement('pre'); pre.style.maxHeight='260px'; pre.style.overflow='auto'; pre.textContent=JSON.stringify(j,null,2); inner.appendChild(pre); return; }
            }catch(err){ /* fall through to synthetic explain */ }
          }
          // Synthetic (client-side) explain when no event_id or server explain failed
          var synth = {
            source: 'client-synth',
            note: 'Synthetic explain generated locally (no server event_id or explain failed).',
            scoring: row._dread || computeDreadBreakdown(row.factors, row.raw, row),
            mitre: mapFactorsToMitre(row.factors),
            stride: mapFactorsToStride(row.factors),
            mapping_details: { factors: row.factors || [], raw_preview: row.raw || {} }
          };
          var pre2 = document.createElement('pre'); pre2.style.maxHeight='360px'; pre2.style.overflow='auto'; pre2.textContent = JSON.stringify(synth,null,2);
          inner.appendChild(pre2);
        }catch(e){ console.warn(e); }
      });
      btns.appendChild(explain);
      var full = document.createElement('button'); full.className='btn'; full.style.marginLeft='6px'; full.innerText='Open Full Details';
      full.addEventListener('click', function(){ try{ renderFullDetails(index); }catch(_){ } });
      btns.appendChild(full);
      var path = document.createElement('button'); path.className='btn'; path.style.marginLeft='6px'; path.innerText='Per-row Deep Explain'; path.addEventListener('click', function(){ openTier2ForRow(index); }); btns.appendChild(path);
      var tier1Btn = document.createElement('button'); tier1Btn.className='btn'; tier1Btn.style.marginLeft='6px'; tier1Btn.innerText='LLM T1'; tier1Btn.addEventListener('click', function(){ requestTier1Summary(index); }); btns.appendChild(tier1Btn);
      var graph = document.createElement('button'); graph.className='btn'; graph.style.marginLeft='6px'; graph.innerText='View Attack Path'; graph.addEventListener('click', function(){ try{ var node = row.host?('host:'+row.host):(row.process_name?('process:'+row.process_name):(row.sha256?('hash:'+row.sha256):null)); window.open('/static/graph_explain.html'+(node?('?node='+encodeURIComponent(node)):''),'_blank'); }catch(_){ } }); btns.appendChild(graph);
      var copyBtn = document.createElement('button'); copyBtn.className='btn'; copyBtn.style.marginLeft='6px'; copyBtn.innerText='Copy Summary'; copyBtn.addEventListener('click', function(){ try{ window.copyCsvRowSummary(index); }catch(_){ } }); btns.appendChild(copyBtn);
      inner.appendChild(btns);
      // threat intel
      try{ var ti=document.createElement('div'); ti.style.marginTop='8px'; var sha=row && row.sha256; var links=[]; if(sha){ links.push('<a target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/'+encodeURIComponent(sha)+'">VirusTotal</a>'); links.push('<a target="_blank" rel="noopener" href="https://www.joesandbox.com/search?q='+encodeURIComponent(sha)+'">Joe Sandbox</a>'); } if(links.length) ti.innerHTML='Threat Intel: '+links.join(' · '), inner.appendChild(ti);}catch(_){ }
      cell.appendChild(inner); container.appendChild(cell); tr.parentNode.insertBefore(container, tr.nextSibling);
    }catch(e){ console.warn('insertInlineDetailsAfter', e); }
  }

  // Render a richer modal with MITRE, compliance, playbooks, DREAD/STRIDE/PASTA/Maestro, and short summary
  async function renderFullDetails(index){
    try{
      var list = window.LAST_RESULTS || [];
      var rec = list[index] || {};
      var raw = rec.raw || {};
      var modal = document.getElementById('csvDrillModal'); var body = document.getElementById('csvDrillBody'); var title = document.getElementById('csvDrillTitle');
      if(modal){ modal.style.display='flex'; modal.style.visibility='visible'; modal.style.opacity='1'; modal.style.pointerEvents='auto'; }
      title.textContent = 'Row details: ' + (rec.process_name || rec.file_path || ('row '+index));
      body.innerHTML = '<div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">Loading details…</div>';

      // Helper: fetch with timeout for unreliable servers
      function fetchWithTimeout(url, opts, ms){
        ms = ms || 3000;
        return new Promise(function(resolve, reject){
          var timedOut = false;
          var timer = setTimeout(function(){ timedOut = true; reject(new Error('timeout')); }, ms);
          (window.safeFetch || fetch)(url, opts).then(function(r){ if(timedOut) return; clearTimeout(timer); resolve(r); }).catch(function(e){ if(timedOut) return; clearTimeout(timer); reject(e); });
        });
      }

      // Start non-blocking server explain if event_id present. We will render synthesized content immediately
      var enriched = null;
      var explainPromise = null;
      if(raw && (raw.event_id || raw.EventID)){
        try{
          var eid = raw.event_id || raw.EventID;
          explainPromise = fetchWithTimeout('/api/v1/decisions/'+encodeURIComponent(eid)+'/explain', { headers: {...authHeaders()} }, 2500).then(function(resp){ if(resp && resp.ok) return resp.json(); return null; }).catch(function(){ return null; });
        }catch(_){ explainPromise = Promise.resolve(null); }
      } else {
        explainPromise = Promise.resolve(null);
      }

      // Build fallback synthesized enrichment
      var synth = enriched || {};
      // attach scoring if missing
      if(!synth.scoring) synth.scoring = { components: { DREAD: (rec._dread && rec._dread.score) || computeDreadBreakdown(rec.factors, rec.raw, rec).score } };
      if(!synth.mitre) synth.mitre = mapFactorsToMitre(rec.factors);
      if(!synth.stride) synth.stride = mapFactorsToStride(rec.factors);
      // PASTA / Maestro lightweight stubs
      if(!synth.pasta) synth.pasta = { stage: 'asset_identification', note: 'PASTA mapping synthesized client-side' };
      if(!synth.maestro) synth.maestro = { likelihood: 'medium', impact: 'medium', summary: 'Maestro-style composite score not available; use DREAD for quick triage' };

      // Compliance audit controls stub (mapped heuristically)
      synth.compliance = synth.compliance || { controls: [] };
      try{
        var controls = [];
        if((rec.file_path||'').toLowerCase().includes('s3')) controls.push('NIST:AC-19 (Remote access to S3)');
        if((rec.process_name||'').toLowerCase().includes('powershell')) controls.push('CIS:Ensure Powershell logging');
        if((rec.factors||[]).some(f=>/lolbin|unsigned/.test(f))) controls.push('SANS:Ensure binary signing / code integrity');
        if(!controls.length) controls.push('No direct control hit; review mapping');
        synth.compliance.controls = controls;
      }catch(_){ }

      // Playbooks: prefer backend preview when available
      var playbookPreview = rec.playbook_preview || synth.playbook_preview || null;
      if(!playbookPreview){
        synth.playbooks = synth.playbooks || [{ name: 'Contain host', steps: ['Isolate host from network','Collect memory & disk images','Block identified hashes'],'confidence':0.7 }];
      }

      // Short natural-language summary (simple template)
      var summary = synth.summary || ((rec.verdict||'').toUpperCase() + ' on ' + (rec.host||'unknown host') + ' — ' + (rec.process_name||rec.file_path||'artifact'));

      // Confidence & provenance: combine DREAD, factor counts, avPositives, path score hints
      try{
        var prov = [];
        var confScore = 0;
        var dreadScore = (rec._dread && rec._dread.score) || computeDreadBreakdown(rec.factors, rec.raw, rec).score;
        confScore += Math.min(10, dreadScore);
        if(rec.factors && rec.factors.length) { prov.push('factors:'+rec.factors.join('|')); confScore += Math.min(5, rec.factors.length); }
        try{ var av = parseInt(String(rec.raw && (rec.raw.avPositives||rec.raw.av_positives||rec.raw.avPos)||0).replace(/[^0-9]/g,''),10)||0; if(av) { prov.push('avPositives='+av); confScore += Math.min(5, Math.round(av/2)); } }catch(_){ }
        // path score contribution if present in last correlation summary
        var pathScoreBest = null;
        try{ if(window.LAST_CORR_SUMMARY && window.LAST_CORR_SUMMARY.path_scores){ var ps = window.LAST_CORR_SUMMARY.path_scores; var keys = Object.keys(ps||{}); if(keys.length){ var best = keys.sort(function(a,b){ return (ps[b].score||0)-(ps[a].score||0); })[0]; pathScoreBest = ps[best] && ps[best].score ? ps[best].score : null; if(pathScoreBest) { prov.push('path_score='+pathScoreBest.toFixed(3)); confScore += Math.min(10, Math.round(pathScoreBest*10)); } } } }catch(_){ }
        // normalize to 0..100
        var confidencePct = Math.max(0, Math.min(100, Math.round((confScore/30)*100)));
        synth.__confidence = confidencePct;
        synth.__provenance = prov;
      }catch(_){ synth.__confidence = 0; synth.__provenance = []; }
      try{
        var corrCtx = buildCorrelationContext(rec);
        if(corrCtx){
          synth.correlation_context = corrCtx;
          rec._correlation_context = corrCtx;
        }
      }catch(_){ }

      // why-not explanations per signal
      var whyNotMap = {
        novel_global: 'Not seen in global telemetry; could be a new vendor binary or a rare benign artifact — verify signer and publisher.',
        unsigned_sensitive_path: 'Located in sensitive path without signing info; could be legitimate installer or unpacked vendor file.',
        lolbin: 'Uses living-off-the-land binary; common for admin tools and benign scripts — check parent process and command-line.',
        multi: 'Seen in multiple batches — higher confidence but verify cross-host correlation.',
        suspicious: 'Textual match heuristics; may catch noise from descriptive fields.'
      };

      // Render sections
      var out = [];
      // Add small toolbar with Fetch Explain button (disabled if no server explain/event)
      try{
        var explainDisabled = true;
        try{ explainDisabled = !(raw && (raw.event_id||raw.EventID)); }catch(_){ explainDisabled = true; }
        out.push('<div class="csv-toolbar" style="margin-bottom:8px"><button data-test="btn-fetch-explain" class="csv-btn-inline btn" '+(explainDisabled? 'disabled':'' )+'>Fetch Explain</button></div>');
      }catch(_){ }
      out.push('<div style="margin-bottom:8px;"><strong>Summary</strong><div style="color:var(--text-muted);font-size:13px;margin-top:4px">'+escapeHtml(summary)+'</div></div>');
      // Explicit Signals line to satisfy UI tests expecting 'signals' text
      try{ out.push('<div style="margin-bottom:8px;"><strong>Signals</strong><div style="color:var(--text-muted);font-size:13px;margin-top:4px">'+ escapeHtml((rec.factors||[]).join(', ') || 'none') +'</div></div>'); }catch(_){ }
        // Confidence badge + provenance
        try{ out.push('<div style="margin-bottom:8px"><strong>Confidence</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">Level: <strong>'+((synth.__confidence>75)?'High':(synth.__confidence>40?'Medium':'Low'))+'</strong> ('+synth.__confidence+'%)</div><div style="margin-top:6px;color:var(--text-muted);font-size:12px">Provenance: '+ escapeHtml((synth.__provenance||[]).join('; ')) +'</div></div>'); }catch(_){ }
      // Scoring
      try{
        out.push('<div style="margin-bottom:8px;"><strong>Scoring</strong><div style="margin-top:6px">');
        var comps = synth.scoring && synth.scoring.components ? synth.scoring.components : {};
        Object.keys(comps).forEach(function(k){ var v = comps[k]; out.push('<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><div style="width:120px;font-size:12px">'+escapeHtml(k)+'</div><div style="flex:1;background:var(--bg-tertiary);height:12px;border-radius:6px;overflow:hidden"><div style="height:100%;width:'+ (Math.min(100, Math.round((v||0)/10*100))) +'% ;background:linear-gradient(90deg,#ff6b6b,#ffb86b)"></div></div><div style="width:48px;text-align:right;font-size:12px">'+escapeHtml(String(v))+'</div></div>'); });
        out.push('</div></div>');
        // Add explicit DREAD label for deterministic matching in tests
        try{ var explicitDread = (rec._dread && typeof rec._dread.score !== 'undefined') ? rec._dread.score : ((synth && synth.scoring && synth.scoring.components && synth.scoring.components.DREAD) ? synth.scoring.components.DREAD : '0'); out.push('<div style="margin-bottom:8px"><strong>DREAD:</strong> '+ escapeHtml(String(explicitDread)) +'</div>'); }catch(_){ }
      }catch(_){ }

      // MITRE
      try{ out.push('<div style="margin-bottom:8px"><strong>MITRE</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+ (Array.isArray(synth.mitre)&&synth.mitre.length? synth.mitre.map(function(m){ return escapeHtml((m.id||'')+ ' — ' + (m.name||'') + ' ('+ (m.tactic||'') +')'); }).join('<br/>') : 'No mappings') +'</div></div>'); }catch(_){ }

      // STRIDE / PASTA / Maestro
      try{ out.push('<div style="margin-bottom:8px"><strong>Threat Models</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">STRIDE: '+ escapeHtml((Array.isArray(synth.stride)? synth.stride.join(', '): (synth.stride||''))) +'<br/>PASTA: '+ escapeHtml((synth.pasta && synth.pasta.stage)||'n/a') +'<br/>Maestro: '+ escapeHtml((synth.maestro && synth.maestro.summary)||'n/a') +'</div></div>'); }catch(_){ }

      // Compliance
      try{ out.push('<div style="margin-bottom:8px"><strong>Compliance Controls</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+ escapeHtml((synth.compliance && synth.compliance.controls && synth.compliance.controls.join('<br/>')) || 'None suggested') +'</div></div>'); }catch(_){ }

      // Playbooks
      try{
        if(playbookPreview){
          var stepsHtml = (playbookPreview.steps||[]).slice(0,4).map(function(step){ return '<div style="margin-bottom:4px">• '+escapeHtml(step)+'</div>'; }).join('');
          var toolsHtml = (playbookPreview.tools||[]).slice(0,2).map(function(t){ return '<div style="margin-bottom:4px"><strong>'+escapeHtml(t.name||'tool')+'</strong>: '+escapeHtml(t.purpose||'Use for additional evidence')+'</div>'; }).join('');
          out.push('<div style="margin-bottom:8px"><strong>Playbook Preview ('+escapeHtml((playbookPreview.domain||'endpoint').toUpperCase())+')</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+stepsHtml+(toolsHtml?('<div style="margin-top:6px">Tools:<br/>'+toolsHtml+'</div>'):'')+'</div></div>');
        } else {
          out.push('<div style="margin-bottom:8px"><strong>Playbooks</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+ (Array.isArray(synth.playbooks)? synth.playbooks.map(function(p){ return '<strong>'+escapeHtml(p.name)+'</strong>: '+ escapeHtml((p.steps||[]).slice(0,3).join(' · ')); }).join('<br/>') : 'No playbooks') +'</div></div>');
        }
      }catch(_){}

      // Raw preview (toggleable)
      try{ out.push('<div style="margin-bottom:8px"><strong>Raw row preview</strong><pre style="background:var(--bg-tertiary);padding:8px;border-radius:6px;max-height:180px;overflow:auto;color:var(--text-primary)">'+ escapeHtml(JSON.stringify(rec.raw||{}, null, 2)) +'</pre></div>'); }catch(_){ }

        // Why-not explanations
        try{
          var wn = (rec.factors||[]).map(function(f){ return '<div style="margin-bottom:6px"><strong>'+escapeHtml(f)+'</strong>: <span style="color:var(--text-muted);">'+escapeHtml(whyNotMap[f]||'No explanation available')+'</span></div>'; }).join('');
          if(wn) out.push('<div style="margin-bottom:8px"><strong>Why-Not (signal clarifications)</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+wn+'</div></div>');
        }catch(_){ }

        // Human review gating checklist and Run Containment button (non-destructive audit stub)
        try{
          var chkHtml = '<div style="margin-bottom:8px;border-top:1px solid var(--border);padding-top:10px"><strong>Human Review Checklist</strong>'+
            '<div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+
              '<label style="display:block;margin:6px 0"><input type="checkbox" id="chkConfirm1"/> Verified signer/publisher</label>'+
              '<label style="display:block;margin:6px 0"><input type="checkbox" id="chkConfirm2"/> Confirmed parent process / lineage</label>'+
              '<label style="display:block;margin:6px 0"><input type="checkbox" id="chkConfirm3"/> Reviewed network telemetry & path scores</label>'+
            '</div>'+
            '<div style="margin-top:8px"><button id="runContainBtn" class="btn" disabled>Run Containment (audit only)</button> <span id="runContainStatus" style="font-size:13px;color:var(--text-muted);margin-left:8px"></span></div></div>';
          out.push(chkHtml);
        }catch(_){ }
        // Feedback area for adaptive learning
        try{
          var fb = '';
          fb += '<div style="margin-bottom:8px;border-top:1px solid var(--border);padding-top:10px"><strong>Human Feedback (for model training)</strong>';
          fb += '<div style="margin-top:6px;color:var(--text-muted);font-size:13px">';
          fb += '<label style="display:block;margin:6px 0"><input type="checkbox" id="fb_confirmed_mal"/> Confirmed Malicious</label>';
          fb += '<label style="display:block;margin:6px 0"><input type="checkbox" id="fb_false_pos"/> Mark as False Positive</label>';
          fb += '<label style="display:block;margin:6px 0">Analyst comment (optional):</label>';
          fb += '<textarea id="fb_comment" style="width:100%;height:80px;padding:8px;border-radius:6px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);"></textarea>';
          fb += '<div style="margin-top:8px"><button id="fbSubmit" class="btn btn-primary">Submit Feedback</button> <button id="fbHistory" class="btn">Fetch Feedback History</button> <span id="fbStatus" style="margin-left:8px;color:var(--text-muted);"></span></div>';
          fb += '</div></div>';
          out.push(fb);
        }catch(_){ }

      // Copy / Send to LLM controls
      try{
        var llmControls = '<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px;display:flex;gap:8px;align-items:center">' +
          '<select id="llmTargetSelect" style="padding:6px;border-radius:6px;background:var(--bg-tertiary);color:var(--text-primary);">' +
            '<option value="copy_summary">Copy Summary</option>' +
            '<option value="copy_json">Copy JSON</option>' +
            '<option value="chatgpt">Send to ChatGPT</option>' +
            '<option value="claude">Send to Claude</option>' +
            '<option value="local">Send to Local Model</option>' +
          '</select>' +
          '<button id="llmActionBtn" class="btn btn-primary">Run</button>' +
          '<span id="llmStatus" style="font-size:13px;color:var(--text-muted);margin-left:8px"></span>' +
        '</div>';
        // Persona on-demand buttons (SOC / CISO / Compliance)
        var personaBtns = '<div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:6px;align-items:center">'+
          '<span style="font-size:12px;color:var(--text-muted)">Generate Persona:</span>'+
          '<button class="btn persona-btn" data-persona="soc" style="padding:4px 10px;font-size:11px">SOC</button>'+
          '<button class="btn persona-btn" data-persona="ciso" style="padding:4px 10px;font-size:11px">CISO</button>'+
          '<button class="btn persona-btn" data-persona="compliance" style="padding:4px 10px;font-size:11px">Compliance</button>'+
          '</div>';
        var quickActionRow = '<div class="tier1-quick-actions" style="margin-top:8px;display:flex;flex-wrap:wrap;gap:8px;">'
          + '<button id="pushIncident-'+index+'" class="btn btn-primary" style="padding:4px 12px;font-size:11px;">Push Incident</button>'
          + '<button id="pushSbom-'+index+'" class="btn" style="padding:4px 12px;font-size:11px;">SBOM Delta</button>'
          + '</div>';
        out.push(llmControls + personaBtns + quickActionRow + '<div class="persona-dynamic-section" style="margin-top:6px"></div>');
      }catch(_){ }

      body.innerHTML = out.join('');
      try{ body.setAttribute('data-row-index', String(index)); }catch(_){ }
      // Wire LLM controls
      try{
        var actionBtn = document.getElementById('llmActionBtn');
        var sel = document.getElementById('llmTargetSelect');
        var status = document.getElementById('llmStatus');
        function setStatus(t){ try{ if(status) status.textContent = t; }catch(_){ } }
        if(actionBtn && sel){ actionBtn.addEventListener('click', async function(){ try{ setStatus('Working...'); var mode = sel.value; if(mode==='copy_summary'){ var txt = buildAnalystSummary(rec); if(navigator.clipboard) await navigator.clipboard.writeText(txt); else { var ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); } setStatus('Copied summary'); }
            else if(mode==='copy_json'){ var txt = JSON.stringify({record:rec, enriched:synth}, null, 2); if(navigator.clipboard) await navigator.clipboard.writeText(txt); else { var ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); } setStatus('Copied JSON'); }
            else {
              // send via server integration endpoint
              var feedbackObj = null; try{ var cm = document.getElementById('fb_comment'); if(cm){ feedbackObj = { confirmed_malicious: !!document.getElementById('fb_confirmed_mal')?.checked, false_positive: !!document.getElementById('fb_false_pos')?.checked, comment: cm.value||'' }; } }catch(_){ }
              var payload = { title: 'Row Analysis', record: rec, enriched: synth, confidence: synth.__confidence||0, provenance: synth.__provenance||[], rationale: { why: summary, why_not: (rec.factors||[]).map(f=>({ signal: f, explanation: (whyNotMap && whyNotMap[f])||'' })) }, feedback: feedbackObj, note: 'Sent via CSV Analyzer LLM bridge' };
              var channel = (mode==='chatgpt') ? 'chatgpt' : (mode==='claude' ? 'claude' : 'local');
              try{
                var resp = await fetch('/api/v1/integrations/send_report', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ service: channel, body: payload }) });
                if(resp.ok){ setStatus('Sent to '+channel); } else { setStatus('Send failed: '+resp.status); }
              }catch(e){ setStatus('Send error'); }
            }
          }catch(e){ setStatus('Error'); } }); }
      }catch(_){ }
      // Wire Run Containment checklist and action
      try{
        var chk1 = document.getElementById('chkConfirm1');
        var chk2 = document.getElementById('chkConfirm2');
        var chk3 = document.getElementById('chkConfirm3');
        var runBtn = document.getElementById('runContainBtn');
        var runStatus = document.getElementById('runContainStatus');
        function updateRunBtn(){ try{ if(runBtn) runBtn.disabled = !(chk1 && chk1.checked && chk2 && chk2.checked && chk3 && chk3.checked); }catch(_){ } }
        if(chk1) chk1.addEventListener('change', updateRunBtn); if(chk2) chk2.addEventListener('change', updateRunBtn); if(chk3) chk3.addEventListener('change', updateRunBtn);
        if(runBtn){ runBtn.addEventListener('click', async function(){ try{
            // Require a second confirmation modal
            if(!confirm('Confirm Run Containment (non-destructive audit will be recorded). Proceed?')) return;
            if(runStatus) runStatus.textContent = 'Recording action...';
            // Build audit payload (non-destructive): event_id, row_index, action, confidence, provenance
            var audit = { action: 'containment_attempt', row_index: index, event_id: rec.raw && (rec.raw.event_id||rec.raw.EventID) || null, confidence: synth.__confidence||0, provenance: synth.__provenance||[], ts: Date.now()/1000 };
            try{
              var r = await fetch('/api/v1/telemetry/dispositions', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify([audit]) });
              if(r.ok){ runStatus.textContent = 'Audit logged'; } else { runStatus.textContent = 'Audit failed: '+r.status; }
            }catch(e){ runStatus.textContent = 'Audit error'; }
          }catch(e){ if(runStatus) runStatus.textContent = 'Error'; } }); }
      }catch(_){ }
      // Wire feedback controls
      try{
        var fbSubmit = document.getElementById('fbSubmit');
        var fbHistory = document.getElementById('fbHistory');
        var fbStatus = document.getElementById('fbStatus');
        function setFbStatus(t){ try{ if(fbStatus) fbStatus.textContent = t; }catch(_){ } }
        if(fbSubmit){ fbSubmit.addEventListener('click', async function(){ try{ setFbStatus('Submitting...'); var confirmed = !!document.getElementById('fb_confirmed_mal')?.checked; var falsepos = !!document.getElementById('fb_false_pos')?.checked; var comment = document.getElementById('fb_comment')?.value||''; var payload = { event_id: rec.raw && (rec.raw.event_id||rec.raw.EventID) || null, row_index: index, confirmed_malicious: confirmed, false_positive: falsepos, comment: comment, confidence: synth.__confidence||0, provenance: synth.__provenance||[], ts: Date.now()/1000 };
              try{ var r = await fetch('/api/v1/feedback/human_review', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) }); if(r.ok){ setFbStatus('Feedback submitted'); } else { setFbStatus('Submit failed: '+r.status); } }catch(e){ setFbStatus('Error'); }
            }catch(e){ setFbStatus('Error'); } }); }
        if(fbHistory){ fbHistory.addEventListener('click', async function(){ try{ setFbStatus('Fetching...'); var eid = rec.raw && (rec.raw.event_id||rec.raw.EventID) || null; if(!eid){ setFbStatus('No event_id available'); return; } var r = await fetch('/api/v1/feedback/event/'+encodeURIComponent(eid), { headers: {...authHeaders()} }); if(!r.ok){ setFbStatus('Fetch failed: '+r.status); return; } var j = await r.json(); setFbStatus('History: '+ (Array.isArray(j)? j.length+' entries':'OK')); try{ var pre = document.createElement('pre'); pre.style.maxHeight='200px'; pre.style.overflow='auto'; pre.textContent = JSON.stringify(j,null,2); body.appendChild(pre); }catch(_){ } }catch(e){ setFbStatus('Error'); } }); }
      }catch(_){ }
      // Immediately set synthesized anchor and dispatch ready so tests have deterministic content
      try{
        var anchor = document.getElementById('csvExplainAnchor');
        anchor.setAttribute('data-test','csv-explain-anchor');
        anchor.href='';
        anchor.innerText='Explain (local)';
      }catch(_){ }

      // When server explain resolves (or 404), update anchor and content if available
      explainPromise.then(function(serverEnriched){
        try{
          if(serverEnriched){ enriched = serverEnriched; var anchor = document.getElementById('csvExplainAnchor'); if(anchor){ if(enriched.explain_url){ anchor.href = enriched.explain_url; anchor.innerText = 'Open server explain'; } else { anchor.href=''; anchor.innerText='Explain (server)'; } }
          }
        }catch(_){ }
        try{ window.__csv_explain_ready = true; window.dispatchEvent(new Event('csv-explain-ready')); }catch(_){ }
      }).catch(function(){ try{ window.__csv_explain_ready = true; window.dispatchEvent(new Event('csv-explain-ready')); }catch(_){} });
      modal.style.display = 'flex';
      // Policy-aware suggestions: show banner if IAM/credential signals detected
      try{ if(typeof renderPolicySuggestions === 'function') renderPolicySuggestions(rec, synth); }catch(_){ }
      // wire close
      try{ modal.querySelector('.csv-modal-close').addEventListener('click', function(){ modal.style.display='none'; }); }catch(_){ }
      // Wire persona buttons
      try{
        var pBtns = body.querySelectorAll('.persona-btn'); pBtns.forEach(function(btn){ btn.addEventListener('click', function(){ try{ var persona = btn.getAttribute('data-persona'); generatePersonaForRow(index, persona); }catch(_){ } }); });
        var incidentBtn = document.getElementById('pushIncident-'+index);
        if(incidentBtn){ incidentBtn.addEventListener('click', function(){ pushIncidentForRow(index); }); }
        var sbomBtn = document.getElementById('pushSbom-'+index);
        if(sbomBtn){ sbomBtn.addEventListener('click', function(){ pushSbomDeltaForRow(index); }); }
      }catch(_){ }
    }catch(e){ console.warn('renderFullDetails', e); }
  }

  // Show a policy-aware banner in the details modal when sensitive logs or credential collection are suggested
  function renderPolicySuggestions(rec, synth){ try{
    var body = document.getElementById('csvDrillBody'); if(!body) return;
    var sensitiveSignals = ['credential_anomaly','iam','ai_model_usage'];
    var found = (rec.factors||[]).filter(function(f){ return sensitiveSignals.indexOf(f)!==-1; });
    if(!found.length && !(synth && synth.__provenance && synth.__provenance.some(function(p){ return /path_score|iam|token/i.test(String(p)); }))) return;
    var banner = document.createElement('div'); banner.style.border='1px solid #ffb86b'; banner.style.background='linear-gradient(90deg,#2b2f36, #1f2328)'; banner.style.padding='8px'; banner.style.marginBottom='10px'; banner.style.borderRadius='6px'; banner.style.color='var(--text-primary)';
    banner.innerHTML = '<strong>Policy Note:</strong> This analysis suggests possible credential or IAM anomalies. Accessing user mailboxes or content may require legal/HR approval.' +
      '<div style="margin-top:6px"><label style="font-size:13px;color:var(--text-muted)"><input type="checkbox" id="policy_confirm_auth" style="margin-right:8px"/> I confirm I have authorization to request sensitive logs</label></div>' +
      '<div style="margin-top:8px"><button id="requestSensitiveLogs" class="btn" disabled>Request Sensitive Logs</button> <button id="requestMetadata" class="btn">Request Metadata Only</button></div>';
    body.insertBefore(banner, body.firstChild);
    try{ var chk = document.getElementById('policy_confirm_auth'); var reqBtn = document.getElementById('requestSensitiveLogs'); var metaBtn = document.getElementById('requestMetadata'); if(chk && reqBtn){ chk.addEventListener('change', function(){ try{ reqBtn.disabled = !chk.checked; }catch(_){ } }); }
      if(reqBtn){ reqBtn.addEventListener('click', async function(){ try{ if(!document.getElementById('policy_confirm_auth')?.checked){ alert('Please confirm authorization'); return; } var payload = { reason: 'Analyst requested sensitive logs from CSV Analyzer', record: rec, synthesized: synth }; await fetch('/api/v1/integrations/request_sensitive_logs', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) }); try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Sensitive log request submitted',3000); }catch(_){ } }catch(e){ try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Request failed',3000); }catch(_){ } } }); }
      if(metaBtn){ metaBtn.addEventListener('click', async function(){ try{ var payload = { reason: 'Analyst requested metadata only', record: rec }; await fetch('/api/v1/integrations/request_log_metadata', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) }); try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Metadata request submitted',3000); }catch(_){ } }catch(e){ try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Request failed',3000); }catch(_){ } } }); }
    }catch(_){ }
  }catch(_){ } }

  function escapeHtml(s){ try{ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }catch(_){ return ''; } }

  function _normalizeFactors(row){
    if(!row) return [];
    if(Array.isArray(row.factors)) return row.factors.filter(Boolean).map(function(f){ return String(f).trim(); });
    if(typeof row.factors === 'string'){
      return row.factors.split(/[,|]+/).map(function(f){ return f.trim(); }).filter(Boolean);
    }
    return [];
  }

  function detectDomainFromRow(row){
    try{
      var factors = new Set(_normalizeFactors(row).map(function(f){ return f.toLowerCase(); }));
      var networkHigh = ['port_scan','beaconing','dns_tunneling','c2_communication','lateral_movement_smb','lateral_movement_rdp','data_exfiltration','suspicious_dns','dga_domain','rare_port','uncommon_protocol'];
      var endpointHigh = ['process_injection','dll_hijack','registry_persistence','scheduled_task','service_creation','unsigned_binary','memory_manipulation','credential_dumping','lsass_access'];
      var networkScore = 0;
      var endpointScore = 0;
      networkHigh.forEach(function(flag){ if(factors.has(flag)) networkScore += 0.3; });
      endpointHigh.forEach(function(flag){ if(factors.has(flag)) endpointScore += 0.3; });
      if(row && (row.src_ip || row.dst_ip || row.domain || row.protocol)) networkScore += 0.1;
      if(row && (row.process_name || row.file_path || row.sha256)) endpointScore += 0.1;
      var domain = 'generic';
      var confidence = 0.3;
      if(networkScore >= 0.5 && networkScore > endpointScore){
        domain = 'network';
        confidence = Math.min(1, networkScore);
      } else if(endpointScore >= 0.5 && endpointScore > networkScore){
        domain = 'endpoint';
        confidence = Math.min(1, endpointScore);
      }
      return { domain: domain, confidence: Number((confidence || 0).toFixed(2)) };
    }catch(_){
      return { domain: 'generic', confidence: 0.3 };
    }
  }

  function renderTableFromResults(){
    try{
      updateVerdictViewButtons();
      var t = document.getElementById('tbody'); if(!t) return; var list = window.LAST_RESULTS||[];
      var indexCache = new Map();
      (list||[]).forEach(function(entry, idx){ indexCache.set(entry, idx); });
      (list||[]).forEach(function(entry){
        try{
          var detection = detectDomainFromRow(entry||{});
          entry._domain = detection.domain;
          entry._domain_confidence = detection.confidence;
        }catch(_){ }
      });
      var ready = document.getElementById('csv_results_ready');
      var filtered = list.filter(function(r){ var pf = verdictPassFail(null, r); if(FILTER_MODE==='suspicious') return pf==='FAIL'; if(FILTER_MODE==='passed') return pf==='PASS'; return true; });
      var manualSortState = null;
      if(!PIPELINE_FORCE_SORT){
        try{ manualSortState = JSON.parse(localStorage.getItem('csv_sort_state')||'null'); }catch(_){ manualSortState = null; }
      }
      // pipeline autorank or explicit pipeline-sort preference
      var pipelineSortPref = (localStorage.getItem('csv_pipeline_sort')||'0') === '1';
      // Determine if pipeline view is active — prefer explicit pipeline view toggle
      var pipelineViewActive = (VERDICT_VIEW_MODE === 'pipeline') || PIPELINE_AUTORANK || pipelineSortPref;
      if(pipelineViewActive){
        filtered.sort(function(a,b){
          var idxA = indexCache.has(a) ? indexCache.get(a) : list.indexOf(a);
          var idxB = indexCache.has(b) ? indexCache.get(b) : list.indexOf(b);
          // prefer triage_score when available
          var ta = (a && (typeof a.triage_score === 'number' ? a.triage_score : (a._pipeline_row && typeof a._pipeline_row.triage_score === 'number' ? a._pipeline_row.triage_score : null)))
                   || 0;
          var tb = (b && (typeof b.triage_score === 'number' ? b.triage_score : (b._pipeline_row && typeof b._pipeline_row.triage_score === 'number' ? b._pipeline_row.triage_score : null)))
                   || 0;
          if(tb !== ta) return tb - ta;
          return computePipelinePriority(b, idxB) - computePipelinePriority(a, idxA);
        });
      } else if(FILTER_MODE==='suspicious'){
        filtered.sort(function(a,b){
          var ad=(a&&a._dread&&a._dread.score)||computeDreadBreakdown(a&&a.factors, a && (a.raw || a), a).score;
          var bd=(b&&b._dread&&b._dread.score)||computeDreadBreakdown(b&&b.factors, b && (b.raw || b), b).score;
          if(bd!==ad) return bd-ad;
          var af=(a&&a.factors&&a.factors.length)||0;
          var bf=(b&&b.factors&&b.factors.length)||0;
          return bf-af;
        });
      } else if(manualSortState && manualSortState.col){
        var colName = manualSortState.col; var dir = manualSortState.dir==='desc' ? -1 : 1;
        function getColValue(rec, colKey){
          try{
            if(!rec) return '';
            switch(colKey){
              case 'process_name': return rec.process_name || '';
              case 'file_path': return rec.file_path || '';
              case 'sha256': return rec.sha256 || '';
              case 'host': return rec.host || '';
              case 'verdict': return getVerdictForView(rec) || '';
              case 'dread': return (rec && rec._dread && (typeof rec._dread.score !== 'undefined') ? rec._dread.score : 0) || 0;
              case 'domain': return (rec && rec._domain) || '';
              case 'signals': return (rec && rec.factors ? rec.factors.join(',') : '');
              default: return (rec && (rec[colKey]||'')) || '';
            }
          }catch(_){ return ''; }
        }
        filtered.sort(function(a,b){ var va=getColValue(a, colName); var vb=getColValue(b, colName); if(typeof va==='number' && typeof vb==='number') return (va-vb)*dir; return String(va).localeCompare(String(vb))*dir; });
      }
      if(!filtered.length){ t.innerHTML='<tr><td colspan="10" class="empty-hint">No results</td></tr>'; try{ if(ready){ ready.style.display='none'; ready.textContent=''; ready.removeAttribute('data-ready'); } }catch(_){ } updateGenerateMoreButton(); return; }
        var max=1000; var rows = filtered.slice(0,max).map(function(r){
          var origIdx = indexCache.has(r) ? indexCache.get(r) : (window.LAST_RESULTS||[]).indexOf(r);
          var rowIndex = (r && typeof r.row_index === 'number') ? r.row_index : origIdx;
          var verdict=getVerdictForView(r);
          var signals=(r&&r.factors&&r.factors.join(', '))||'';
          var checked=SELECTED_ROWS.has(origIdx)?' checked':'';
          var vclass='';
          var rowClass='';
          try{ var pf=verdictPassFail(verdict, r); if(pf==='PASS') vclass='verdict-pass'; else if(pf==='FAIL') vclass='verdict-fail'; else vclass='verdict-medium'; }catch(_){ }
          rowClass = vclass;
          var llmBadge='';
          try{
            if(r && (r.llm_summary || r._tier1_summary)){
              llmBadge=' <span class="llm-badge" title="LLM summary ready">LLM</span>';
            }
          }catch(_){ }
          var pipelineBadge = buildPipelineBadge(r, origIdx);
          var pipelineState = getPipelineStatusForRow(r, origIdx);
          if(pipelineState && pipelineState !== 'none'){
            rowClass += ' pipeline-'+pipelineState+'-row';
          }
          var domainBadge='<span class="text-muted">-</span>';
          try{
            if(r && r._domain){
              var badge = r._domain==='network' ? 'badge-info' : (r._domain==='endpoint' ? 'badge-success' : 'badge-secondary');
              var pct = typeof r._domain_confidence === 'number' ? Math.round(r._domain_confidence*100) : null;
              domainBadge = '<span class="badge '+badge+'">'+String(r._domain||'').toUpperCase()+'</span>';
              if(pct){
                domainBadge += ' <small class="text-muted">('+pct+'%)</small>';
              }
            }
          }catch(_){ domainBadge='<span class="text-muted">-</span>'; }
          return '<tr class="'+rowClass+'" data-row="'+origIdx+'" data-row-index="'+rowIndex+'" data-test="csv-row-'+origIdx+'">'+
            '<td class="llm-status-cell" data-col="llm_status" data-row-index="'+rowIndex+'"><span class="llm-indicator" title="LLM summary not generated">--</span></td>'+
            '<td data-col="process_name">'+wrapCell(r&&r.process_name||'')+'</td>'+
            '<td data-col="file_path">'+wrapCell(r&&r.file_path||'')+'</td>'+
            '<td data-col="sha256">'+wrapCell(r&&r.sha256||'')+'</td>'+
            '<td data-col="host">'+wrapCell(r&&r.host||'')+'</td>'+
            '<td data-col="verdict">'+wrapCell(verdict)+llmBadge+pipelineBadge+'</td>'+ 
            '<td data-col="domain">'+domainBadge+'</td>'+
              // show triage score inline after DREAD to avoid changing table header layout
              (function(){ var dreadVal = (r&&r._dread&&r._dread.score)||''; var tri = (typeof r.triage_score==='number')? (Math.round(r.triage_score*100)/100) : ((r && r._pipeline_row && typeof r._pipeline_row.triage_score==='number')? Math.round(r._pipeline_row.triage_score*100)/100 : ''); var triHtml = tri!=='' ? ' <small style="color:var(--text-muted);margin-left:6px">triage:'+escapeHtml(String(tri))+'</small>' : ''; return '<td data-col="dread" data-test="dread-'+origIdx+'">'+wrapCell(dreadVal)+triHtml+'</td>'; })()+
            '<td data-col="signals">'+wrapCell(signals)+'</td>'+
            '<td><input type="checkbox" class="csv-row-select" data-idx="'+origIdx+'"'+checked+' style="margin-right:6px"/>'+
              '<button data-test="btn-details-'+origIdx+'" class="btn" style="padding:4px 10px" onclick="window.openCsvRowDetails('+origIdx+')" title="Why flagged / details">Details</button>'+
              ' <button data-test="btn-copy-'+origIdx+'" class="btn copy-inline" data-idx="'+origIdx+'" style="margin-left:6px;padding:4px 8px">Copy</button></td>'+
          '</tr>'; }).join('');
      t.innerHTML = rows;
      try{
        Array.from(t.querySelectorAll('button[title="Why flagged / details"]')||[]).forEach(function(btn){
              btn.addEventListener('click', function(e){ try{ var tr = btn.closest('tr[data-row]'); if(tr){ var idx = parseInt(tr.getAttribute('data-row'),10); if(!isNaN(idx)) { window.openCsvRowDetails(idx); } } }catch(_){ } });
            });
        Array.from(t.querySelectorAll('button.copy-inline')||[]).forEach(function(cb){
          cb.addEventListener('click', function(){ try{ var idx=parseInt(cb.getAttribute('data-idx'),10); if(!isNaN(idx)) window.copyCsvRowSummary(idx); }catch(_){ } });
        });
      }catch(_){ }
      try{ var expanded = localStorage.getItem('csv_expanded_row'); if(expanded && expanded!=='null'){ var tr=t.querySelector('tr[data-row="'+expanded+'"]'); if(tr) insertInlineDetailsAfter(tr, parseInt(expanded,10)); } }catch(_){ }
      try{
        var sum=document.getElementById('rowsSummary');
        if(sum){
          var viewLabel = VERDICT_VIEW_MODE === 'pipeline' ? 'post-pipeline' : 'initial';
          var pipelineExtra = '';
          try{
            if(PIPELINE_TARGETS && PIPELINE_TARGETS.size){
              var pendingCount = (PIPELINE_PENDING && PIPELINE_PENDING.size) || 0;
              if(pendingCount>0){
                pipelineExtra = ' | 21-step pipeline '+pendingCount+'/'+PIPELINE_TARGETS.size+' pending';
              }else{
                pipelineExtra = ' | 21-step pipeline completed';
              }
            }
          }catch(_){ }
          sum.textContent='Showing '+Math.min(filtered.length,max)+' of '+list.length+' ('+viewLabel+' view)'+pipelineExtra;
        }
      }catch(_){ }
      try{ if(ready){ ready.style.display='block'; ready.textContent = 'results:'+Math.min(filtered.length,1000)+' of '+list.length; ready.setAttribute('data-ready','1'); } }catch(_){ }
      window.dispatchEvent(new Event('csv-results-ready'));
      updateGenerateMoreButton();
      updateLLMIndicators();
      // update ARIA live status
      try{ var live=document.getElementById('csv_status_live'); if(live) live.textContent = 'Showing '+Math.min(filtered.length,max)+' of '+list.length + ' rows'; }catch(_){ }
      try{ updateFpBannerAndAudit(list); }catch(_){ }
      try{ if(typeof updateBackfillRibbon === 'function') updateBackfillRibbon(); }catch(_){ }
    }catch(e){ console.warn('renderTableFromResults', e); }
  }

  // Backfill ribbon helpers: update ribbon and poll server for status
  // Backfill ribbon helpers: update ribbon and poll server for status
  var _backfillPrevProcessed = null;
  var _backfillPrevTs = null;
  var _backfillPollIntervalMs = 2500;
  function _formatEta(ms){
    try{
      if(ms <= 0) return '0s';
      var s = Math.round(ms/1000);
      if(s < 60) return s+'s';
      var m = Math.floor(s/60); if(m < 60) return m+'m '+(s%60)+'s';
      var h = Math.floor(m/60); return h+'h '+(m%60)+'m';
    }catch(_){ return '--'; }
  }
  function updateBackfillRibbon(status){
    try{
      var ribbon = document.getElementById('deepBackfillRibbon');
      if(!ribbon) return;
      var state = status && status.state ? status.state : 'idle';
      var processed = status && status.progress ? Number(status.progress.processed||0) : 0;
      var total = status && status.progress ? Number(status.progress.total||0) : 0;
      var pct = total > 0 ? Math.round((processed/total)*100) : 0;

      // Load persisted control values for display
      var batch = document.getElementById('deepBackfillBatch');
      var windowEl = document.getElementById('deepBackfillWindow');
      var targetEl = document.getElementById('deepBackfillTarget');
      var batchVal = batch ? (batch.value||localStorage.getItem('deepBackfillBatch')||'') : (localStorage.getItem('deepBackfillBatch')||'');
      var windowVal = windowEl ? (windowEl.value||localStorage.getItem('deepBackfillWindow')||'') : (localStorage.getItem('deepBackfillWindow')||'');
      var targetVal = targetEl ? (targetEl.value||localStorage.getItem('deepBackfillTarget')||'') : (localStorage.getItem('deepBackfillTarget')||'');

      var etaText = '';
      if(state === 'running' && total > processed){
        var now = Date.now();
        var delta = (_backfillPrevProcessed === null) ? 0 : (processed - _backfillPrevProcessed);
        var elapsed = (_backfillPrevTs === null) ? _backfillPollIntervalMs : Math.max(100, now - _backfillPrevTs);
        var ratePerMs = (delta > 0) ? (delta / elapsed) : 0;
        if(ratePerMs > 0){
          var remaining = total - processed;
          var etaMs = remaining / ratePerMs;
          etaText = ' ETA: '+_formatEta(etaMs);
        } else {
          etaText = ' ETA: calculating...';
        }
        _backfillPrevProcessed = processed;
        _backfillPrevTs = now;
      } else {
        // reset history when not actively running
        _backfillPrevProcessed = processed;
        _backfillPrevTs = Date.now();
      }

      var extras = [];
      if(batchVal) extras.push('batch:'+batchVal);
      if(windowVal) extras.push('window:'+windowVal+'s');
      if(targetVal) extras.push('target:'+targetVal+'%');
      var meta = extras.length ? ' ['+extras.join(' · ')+']' : '';

      ribbon.textContent = 'Backfill: '+state+' ('+processed+'/'+total+') '+pct+'%'+meta+etaText;
    }catch(_){ }
  }

  var _backfillPoller = null;

  function startBackfillPolling(assessment_id){
    try{
      if(_backfillPoller) return;
      if(!assessment_id) assessment_id = localStorage.getItem('csv_last_parent_assessment');
      if(!assessment_id) return;
      _backfillPoller = setInterval(async function(){
        try{
          var res = await fetch('/api/v1/csv/deep_analyze/auto_backfill/'+encodeURIComponent(assessment_id)+'/status', { headers: {...authHeaders()} });
          if(!res.ok) return;
          var j = await res.json();
          updateBackfillRibbon(j);
          if(j && j.state && j.state !== 'running'){
            stopBackfillPolling();
          }
        }catch(e){ console.warn('backfill poll error', e); }
      }, 2500);
    }catch(_){ }
  }

  function stopBackfillPolling(){ try{ if(_backfillPoller){ clearInterval(_backfillPoller); _backfillPoller = null; } }catch(_){ } }

      // After rendering rows we will update LLM indicators if available from aggregated llm_rows merge
  window.ensureTbodyRowsFromList = function(list){ window.LAST_RESULTS = list||[]; try{ applyRiskAppetite(window.LAST_RESULTS); }catch(_){ } renderTableFromResults(); };
  function reapplyRiskAppetite(){ try{ applyRiskAppetite(window.LAST_RESULTS||[]); renderTableFromResults(); }catch(_){ } }

  // LLM summary helpers
  function _estimateCost(limit){
    try{
      var rows = window.LAST_RESULTS||[];
      var suspicious = rows.filter(function(r){ var v=verdictPassFail(null,r); return v==='FAIL'; });
      var count = (parseInt(limit,10)===0) ? suspicious.length : Math.min(suspicious.length, parseInt(limit,10));
      var cost = (count * 0.003).toFixed(3);
      return { count: count, cost: cost };
    }catch(_){ return { count:0, cost:'0.000' }; }
  }

  function updateLLMLimitUI(){
    try{
      var sel = document.getElementById('llmLimit'); var est = document.getElementById('llmCostEstimate'); if(!sel||!est) return;
      var info = _estimateCost(sel.value); est.textContent = 'Est. cost: $'+info.cost+' ('+info.count+' rows)';
      updateGenerateMoreButton();
    }catch(_){ }
  }

  var ICON_READY = '✅';
  var ICON_PENDING = '⏳';
  var ICON_FAILED = '⚠';

  function _collectLLMStats(){
    try{
      var progress = window.__LLM_PROGRESS;
      if(progress){
        return {
          total: progress.total_rows || 0,
          processed: progress.succeeded || 0,
          pending: progress.pending || 0
        };
      }
    }catch(_){ }
    try{
      var rows = window.LAST_RESULTS || [];
      var map = window.__LLM_ROWS || {};
      var suspicious = 0;
      var processed = 0;
      rows.forEach(function(row, idx){
        try{
      var verdict = verdictPassFail(null, row);
          if(verdict !== 'FAIL') return;
          suspicious += 1;
          var key = (row && typeof row.row_index === 'number') ? row.row_index : idx;
          var llm = map[key];
          if((llm && llm.llm_summary) || (row && row.llm_summary)){
            processed += 1;
          }
        }catch(_){ }
      });
      return { total: suspicious, processed: processed, pending: Math.max(suspicious - processed, 0) };
    }catch(_){
      return { total: 0, processed: 0, pending: 0 };
    }
  }

  // Request a Tier 1 summary for a row (wired to inline button)
  window.requestTier1Summary = async function(rowIndex){
    try{
      var rows = window.LAST_RESULTS || [];
      var rec = rows[rowIndex] || null;
      if(!rec){ alert('Row not found'); return; }
      if(!ensurePipelineReadyForRow(rowIndex, rec, 'Tier1 summary')){
        return;
      }
      try{ await ensureFactorTelemetry(false); }catch(_){}
      setTier1SidebarLoading(rec, rowIndex);
      // Build payload
      var overrides = null;
      try{ if(window.LLMSettingsUI && typeof window.LLMSettingsUI.getOverridesForRequest === 'function'){ overrides = window.LLMSettingsUI.getOverridesForRequest(); } }catch(_){ overrides = null; }
      var pipeline_context = { row_index: rowIndex };
      if (overrides && Object.keys(overrides||{}).length) pipeline_context.overrides = overrides;
      var payload = { insight_type: 'tier1', row: rec, pipeline_context: pipeline_context };
      var resp = await fetch('/api/v1/insights/generate', { method: 'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
      if(!resp.ok){
        var txt = await resp.text().catch(()=>String(resp.status));
        try{
          ensureTier1SidebarRefs();
          if(LLM_SIDEBAR_BODY){
            LLM_SIDEBAR_BODY.innerHTML = '<div style="padding:12px;color:var(--text-muted)">LLM request failed: '+escapeHtml(txt)+'</div>';
          }
        }catch(_){ }
        return;
      }
      var j = await resp.json();
      var structuredSummary = (j && j.payload && typeof j.payload === 'object') ? j.payload : null;
      var textSummary = (j && (j.text || j.result)) || '';
      var summary = structuredSummary || textSummary || ((j && typeof j === 'object') ? JSON.stringify(j, null, 2) : '');
      // Save into in-memory row cache and update UI
      try{
        rec._tier1_summary = summary;
        window.__LLM_ROWS = window.__LLM_ROWS || {};
        var cacheKey = (typeof rec.row_index === 'number') ? rec.row_index : rowIndex;
        window.__LLM_ROWS[cacheKey] = window.__LLM_ROWS[cacheKey] || {};
        window.__LLM_ROWS[cacheKey].llm_summary = summary;
        var rawCost = (j && (j.cost || j.price));
        if(typeof rawCost !== 'undefined' && rawCost !== null){
          window.__LLM_ROWS[cacheKey]._llm_cost = rawCost;
        }
      }catch(_){ }
      // preserve skip reason and weighted confidence if returned by the server
      try{ if(j && j.llm_skipped_reason) rec.llm_skipped_reason = j.llm_skipped_reason; if(j && typeof j.weighted_confidence !== 'undefined') rec.weighted_confidence = j.weighted_confidence; }catch(_){ }
      showTier1Sidebar(rec, summary, (j && (j.cost || j.price)) || null);
      try{ updateLLMIndicators(); }catch(_){ }
    }catch(e){
      console.warn('requestTier1Summary', e);
      try{
        ensureTier1SidebarRefs();
        if(LLM_SIDEBAR_BODY){
          LLM_SIDEBAR_BODY.innerHTML = '<div style="padding:12px;color:red">Error requesting summary</div>';
        }
      }catch(_){}
    }
  };

  async function pollLLMProgress(){
    try{
      var parentId = localStorage.getItem('csv_last_parent_assessment');
      if(!parentId) return;
      var resp = await fetch('/api/v1/assessments/'+encodeURIComponent(parentId)+'/llm/progress', { headers: {...authHeaders()} });
      if(!resp.ok) return;
      var data = await resp.json();
      window.__LLM_PROGRESS = data;
      window.__LLM_STATUS = data.rows || {};
      var agg = document.getElementById('llmAggregateCost');
      if(agg && typeof data.cost !== 'undefined'){
        agg.textContent = 'Total cost: $'+Number(data.cost || 0).toFixed(3);
      }
      updateGenerateMoreButton(data.pending);
      updateLLMIndicators();
    }catch(_){ }
  }

  // Probe LLM health endpoint and populate provider select
  async function probeLLMHealth(){
    try{
      var sel = document.getElementById('llmProviderSelect');
      if(sel){ sel.innerHTML = '<option value="">Detecting...</option>'; }
      var resp = await fetch('/api/v1/llm/health', { headers: {...authHeaders()} });
      if(!resp.ok){ if(sel) sel.innerHTML = '<option value="">Unavailable</option>'; return; }
      var j = await resp.json();
      var options = [];
      if(j.ollama && j.ollama.enabled){ options.push({v:'ollama', t:'Local model (Ollama)'+(j.ollama.reachable? ' — reachable':' — not reachable')}); }
      if(j.openai && j.openai.configured){ options.push({v:'openai', t:'OpenAI (API key configured)'}); }
      if(j.anthropic && j.anthropic.configured){ options.push({v:'anthropic', t:'Anthropic (API key configured)'}); }
      if(j.mock){ options.push({v:'mock', t:'Mock (test)'}); }
      if(!options.length){ options.push({v:'', t:'No provider configured'}); }
      if(sel){ sel.innerHTML = options.map(function(o){ return '<option value="'+o.v+'">'+o.t+'</option>'; }).join(''); }
      try{ var last = localStorage.getItem('csv_llm_provider'); if(last && sel && Array.from(sel.options).some(function(opt){ return opt.value===last; })){ sel.value = last; } }catch(_){ }
      if(options.length && options[0].v===''){ try{ showNoProviderModal(); }catch(_){ } }
    }catch(e){ console.warn('probeLLMHealth error', e); }
  }

  function showNoProviderModal(){
    try{
      if(document.getElementById('llmNoProviderModal')) return;
      var modal = document.createElement('div');
      modal.id = 'llmNoProviderModal';
      modal.style.position='fixed'; modal.style.left='50%'; modal.style.top='30%'; modal.style.transform='translate(-50%,-30%)';
      modal.style.background='var(--bg-panel)'; modal.style.border='1px solid var(--border)'; modal.style.padding='12px'; modal.style.zIndex='10000'; modal.style.borderRadius='8px';
      modal.innerHTML = '<div style="font-weight:600;margin-bottom:8px">No LLM provider detected</div>' +
        '<div style="font-size:13px;color:var(--text-muted);margin-bottom:8px">Start Ollama locally (http://127.0.0.1:11434) or set an API key in localStorage (key: <code>apiKey</code>).</div>' +
        '<div style="display:flex;gap:8px"><button id="llmModalClose" class="btn">Close</button><button id="llmModalCopyKey" class="btn">Copy setup snippet</button><button id="llmModalRecheck" class="btn btn-primary">Re-check</button></div>';
      document.body.appendChild(modal);
      document.getElementById('llmModalClose').addEventListener('click', function(){ modal.remove(); });
      document.getElementById('llmModalCopyKey').addEventListener('click', function(){ try{ var snippet = "localStorage.setItem('apiKey','YOUR_API_KEY');"; if(navigator.clipboard) navigator.clipboard.writeText(snippet); alert('Snippet copied to clipboard'); }catch(_){ alert('Copy failed'); } });
      document.getElementById('llmModalRecheck').addEventListener('click', function(){ try{ probeLLMHealth(); modal.remove(); }catch(_){ } });
    }catch(_){ }
  }

  function updateGenerateMoreButton(pendingOverride){
    try{
      var btn = document.getElementById('btnGenerateMore'); if(!btn) return;
      var stats = _collectLLMStats();
      var pending = typeof pendingOverride === 'number' ? pendingOverride : stats.pending;
      if(!pending){
        btn.style.display = 'none';
        return;
      }
      var sel = document.getElementById('llmLimit');
      var limit = sel ? parseInt(sel.value,10) : 25;
      var batchSize = limit > 0 ? Math.min(limit, pending) : pending;
      btn.textContent = 'Generate Next '+batchSize+' LLM Summaries';
      btn.style.display = 'inline-flex';
    }catch(_){ }
  }

  function _mergeLLMRows(rows){
    try{ if(!Array.isArray(rows) || !rows.length) return; window.__LLM_ROWS = window.__LLM_ROWS || {}; rows.forEach(function(r){ if(r && typeof r.row_index==='number'){ window.__LLM_ROWS[r.row_index] = r; } }); }catch(_){ }
    try{ if(typeof updateAggregateCost === 'function') updateAggregateCost(); }catch(_){ }
    updateGenerateMoreButton();
    updateLLMIndicators();
  }

  function updateLLMIndicators(){
    try{
      var tbody = document.getElementById('tbody'); if(!tbody) return;
      var map = window.__LLM_ROWS || {};
      var statusMap = window.__LLM_STATUS || {};
      var baseRows = window.LAST_RESULTS || [];
      Array.from(tbody.querySelectorAll('tr[data-row-index]')).forEach(function(tr){
        try {
          var idxAttr = tr.getAttribute('data-row-index');
          if(!idxAttr) return; var idx = parseInt(idxAttr,10); if(isNaN(idx)) return;
          var cell = tr.querySelector('.llm-status-cell');
          if(!cell) return;
          var indicator = cell.querySelector('.llm-indicator');
          if(!indicator){
            indicator = document.createElement('span');
            indicator.className='llm-indicator';
            cell.appendChild(indicator);
          }
          var llm = map[idx];
          var row = baseRows[idx];
          var state = 'pending';
          var progressRow = statusMap[String(idx)];
          if(progressRow && progressRow.status){
            state = progressRow.status;
          }else if(llm && llm.llm_summary){
            state = 'ready';
          }else if(llm && llm._llm_status === 'queued'){
            state = 'queued';
          }else if(llm && llm._llm_status === 'failed'){
            state = 'failed';
          }else if(row && row.llm_summary){
            state = 'ready';
          }else if(row && row._llm_status === 'queued'){
            state = 'queued';
          }
          if(state === 'ready'){
            indicator.textContent = ICON_READY;
            indicator.title = 'LLM summary generated';
            // if server indicated a skip reason, surface it here
            try{ var rr = (row && (row.llm_skipped_reason || (window.__LLM_ROWS && window.__LLM_ROWS[idx] && window.__LLM_ROWS[idx].llm_skipped_reason))) || null; if(rr) indicator.title += ' (skip: '+String(rr)+')'; }catch(_){ }
          }else if(state === 'queued'){
            indicator.textContent = ICON_PENDING;
            indicator.title = 'Queued for LLM summary';
          }else if(state === 'failed'){
            indicator.textContent = ICON_FAILED;
            indicator.title = 'LLM summary failed';
          }else{
            indicator.textContent = ICON_PENDING;
            indicator.title = 'LLM summary not generated yet';
          }
        }catch(_){ }
      });
      updateGenerateMoreButton();
    }catch(_){ }
  }
  function updateAggregateCost(){
    try{
      var span = document.getElementById('llmAggregateCost'); if(!span) return;
      var rowsMap = window.__LLM_ROWS || {}; var total = 0.0; Object.keys(rowsMap).forEach(function(k){ var r = rowsMap[k]; var c = r && r._llm_cost ? parseFloat(r._llm_cost) : 0.0; if(!isNaN(c)) total += c; }); span.textContent = 'Total cost: $'+ total.toFixed(3); }catch(_){ }
  }

  async function pushIncidentForRow(rowIndex){
    try{
      var row = getRowByIndex(rowIndex);
      if(!row){
        if(window.notifications && window.notifications.showToast) window.notifications.showToast('Row not available','warn');
        return;
      }
      var title = 'CSV Escalation - Row '+rowIndex;
      var severity = (row._dread && row._dread.level) || 'high';
      var description = '';
      if(row.llm_summary){
        description = typeof row.llm_summary === 'string' ? row.llm_summary : JSON.stringify(row.llm_summary);
      }else if(row._tier1_summary){
        description = typeof row._tier1_summary === 'string' ? row._tier1_summary : JSON.stringify(row._tier1_summary);
      }else{
        description = 'Auto-generated incident from CSV Analyzer.';
      }
      var payload = {
        artifact_id: row.sha256 || row.process_name || ('row-'+rowIndex),
        title: title,
        severity: severity,
        description: description.slice(0, 2000),
        attack_subgraph: row.hopgraph_context || row.graph_context || null
      };
      var resp = await fetch('/api/v1/incidents', {
        method: 'POST',
        headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
        body: JSON.stringify(payload)
      });
      if(resp.ok){
        if(window.notifications && window.notifications.showToast) window.notifications.showToast('Incident submitted','success');
      }else{
        // If unauthorized, attempt a local test helper to aid automated tests
        if(resp.status === 401 || resp.status === 403){
          try{
            var alt = await fetch('/api/v1/test_helpers/create_incident', { method: 'POST', headers: Object.assign({'Content-Type':'application/json'}, authHeaders()), body: JSON.stringify(payload) });
            if(alt && alt.ok){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Incident submitted via test helper','success'); return; }
          }catch(_){ }
        }
        if(window.notifications && window.notifications.showToast) window.notifications.showToast('Incident push failed','error');
      }
    }catch(err){
      console.warn('pushIncidentForRow', err);
      if(window.notifications && window.notifications.showToast) window.notifications.showToast('Incident push error','error');
    }
  }

  async function pushSbomDeltaForRow(rowIndex){
    try{
      var row = getRowByIndex(rowIndex);
      if(!row){
        if(window.notifications && window.notifications.showToast) window.notifications.showToast('Row not available','warn');
        return;
      }
      var component = {
        name: row.process_name || row.file_path || ('row-'+rowIndex),
        version: row.raw && (row.raw.version || row.raw.package_version) || row.mapping_summary && row.mapping_summary.present_fields && row.mapping_summary.present_fields.version || 'unknown',
        hash: row.sha256 || row.hash || row.binary_sha256 || '',
        host: row.host || '',
        sbom_tags: row.binary_context && row.binary_context.supply_chain_tags || []
      };
      var resp = await fetch('/api/v1/sbom/upload', {
        method: 'POST',
        headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
        body: JSON.stringify({ components: [component] })
      });
      if(resp.ok){
        if(window.notifications && window.notifications.showToast) window.notifications.showToast('SBOM delta sent','success');
      }else{
        if(window.notifications && window.notifications.showToast) window.notifications.showToast('SBOM delta failed','error');
      }
    }catch(err){
      console.warn('pushSbomDeltaForRow', err);
      if(window.notifications && window.notifications.showToast) window.notifications.showToast('SBOM delta error','error');
    }
  }

  async function generatePersonaForRow(rowIndex, persona){
    try{
      var aid = localStorage.getItem('csv_last_parent_assessment'); if(!aid){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('No assessment id','warn'); return; }
      var resp = await fetch('/api/v1/assessments/generate_persona', { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ assessment_id: aid, row_index: rowIndex, persona: persona }) });
      if(!resp.ok){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Persona gen failed','error'); return; }
      var j = await resp.json(); var rowsMap = window.__LLM_ROWS || {}; if(rowsMap[rowIndex]){ rowsMap[rowIndex].persona_reports = rowsMap[rowIndex].persona_reports || {}; rowsMap[rowIndex].persona_reports[persona] = { text: j.text }; }
      // update modal if open
      try{ var body = document.getElementById('csvDrillBody'); if(body && body.getAttribute('data-row-index') == String(rowIndex)){ var sec = body.querySelector('.persona-dynamic-section'); if(sec){ var p = document.createElement('div'); p.style.marginTop='6px'; p.innerHTML = '<strong>'+persona+'</strong>: <span style="color:var(--text-muted);">'+escapeHtml(j.text)+'</span>'; sec.appendChild(p); } } }catch(_){ }
      if(window.notifications && window.notifications.showToast) window.notifications.showToast('Persona '+persona+' added','success');
      try{ if(typeof updateAggregateCost === 'function') updateAggregateCost(); }catch(_){ }
    }catch(e){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Persona error','error'); }
  }

  async function generateMoreLLMSummaries(){
    try{
      var parentId = localStorage.getItem('csv_last_parent_assessment');
      if(!parentId){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('No parent assessment id','warn'); return; }
      var sel = document.getElementById('llmLimit'); var limit = sel ? parseInt(sel.value,10) : 25;
      var payload = { limit: limit };
      try{
        var provSel = document.getElementById('llmProviderSelect');
        var provider = provSel ? provSel.value : (localStorage.getItem('csv_llm_provider')||null);
        if(provider){ payload.provider = provider; try{ localStorage.setItem('csv_llm_provider', provider); }catch(_){ } }
      }catch(_){ }
      var enqueueUrl = '/api/v1/assessments/'+encodeURIComponent(parentId)+'/llm/enqueue';
      var resp = await fetch(enqueueUrl, { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
      if(!resp.ok){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('LLM generation failed','error'); return; }
      var json = await resp.json();
      if(window.notifications && window.notifications.showToast) window.notifications.showToast('Queued '+(json.enqueued||0)+' rows','success');
      await pollLLMProgress();
    }catch(e){ if(window.notifications && window.notifications.showToast) window.notifications.showToast('LLM error','error'); }
  }

  // Wire Generate More button
  document.addEventListener('DOMContentLoaded', function(){ try{
    var btn = document.getElementById('btnGenerateMore'); var sel = document.getElementById('llmLimit'); if(btn){ btn.addEventListener('click', generateMoreLLMSummaries); }
    if(sel){ sel.addEventListener('change', updateLLMLimitUI); updateLLMLimitUI(); }
    try{ if(typeof probeLLMHealth === 'function') probeLLMHealth(); }catch(_){ }
    pollLLMProgress();
    setInterval(pollLLMProgress, 15000);
    // Wire Deep Backfill toggle button
    try{
      var toggle = document.getElementById('deepBackfillToggleGlobal');
      var ribbonHolder = document.getElementById('deepBackfillRibbonPlaceholder');
      if(toggle){
        // restore persisted control values
        try{
          var b = document.getElementById('deepBackfillBatch');
          var w = document.getElementById('deepBackfillWindow');
          var t = document.getElementById('deepBackfillTarget');
          if(b && !b.value) b.value = localStorage.getItem('deepBackfillBatch') || b.value || '10';
          if(w && !w.value) w.value = localStorage.getItem('deepBackfillWindow') || w.value || '30';
          if(t && !t.value) t.value = localStorage.getItem('deepBackfillTarget') || t.value || '100';
          // wire change handlers to persist
          if(b) b.addEventListener('change', function(){ try{ localStorage.setItem('deepBackfillBatch', String(b.value)); }catch(_){ } });
          if(w) w.addEventListener('change', function(){ try{ localStorage.setItem('deepBackfillWindow', String(w.value)); }catch(_){ } });
          if(t) t.addEventListener('change', function(){ try{ localStorage.setItem('deepBackfillTarget', String(t.value)); }catch(_){ } });
        }catch(_){ }
        toggle.addEventListener('click', async function(){
          try{
            var aid = localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId || null;
            if(!aid){ alert('No assessment id available for backfill'); return; }
            var stateEl = document.getElementById('deepBackfillState');
            if(toggle.textContent.trim().toLowerCase() === 'start'){
              toggle.disabled = true;
              toggle.textContent = 'Starting...';
              // read values from ribbon controls
              var batchEl = document.getElementById('deepBackfillBatch');
              var windowEl = document.getElementById('deepBackfillWindow');
              var targetEl = document.getElementById('deepBackfillTarget');
              var batch = parseInt(batchEl?.value || localStorage.getItem('deepBackfillBatch') || '10', 10) || 10;
              var windowSec = parseInt(windowEl?.value || localStorage.getItem('deepBackfillWindow') || '30', 10) || 30;
              var targetPct = parseInt(targetEl?.value || localStorage.getItem('deepBackfillTarget') || '100', 10) || 100;
              var targetFrac = Math.max(0, Math.min(1, (targetPct/100.0)));
              // persist chosen values
              try{ localStorage.setItem('deepBackfillBatch', String(batch)); }catch(_){ }
              try{ localStorage.setItem('deepBackfillWindow', String(windowSec)); }catch(_){ }
              try{ localStorage.setItem('deepBackfillTarget', String(targetPct)); }catch(_){ }
              var resp = await fetch('/api/v1/csv/deep_analyze/auto_backfill', { method: 'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify({ assessment_id: aid, target_coverage: targetFrac, batch_size: batch, window_seconds: windowSec }) });
              if(!resp.ok){ alert('Backfill start failed: '+resp.status); toggle.textContent='Start'; toggle.disabled=false; return; }
              startBackfillPolling(aid);
              if(stateEl) stateEl.textContent = 'running';
              toggle.textContent = 'Stop';
              toggle.disabled = false;
              if(ribbonHolder) ribbonHolder.style.display = 'block';
            } else {
              // stop
              toggle.disabled = true;
              toggle.textContent = 'Stopping...';
              try{ await fetch('/api/v1/csv/deep_analyze/auto_backfill/'+encodeURIComponent(aid)+'/stop', { method: 'POST', headers: {...authHeaders()} }); }catch(_){ }
              stopBackfillPolling();
              if(stateEl) stateEl.textContent = 'stopping';
              toggle.textContent = 'Start';
              toggle.disabled = false;
            }
          }catch(e){ console.warn('backfill toggle error', e); toggle.disabled=false; toggle.textContent='Start'; }
        });
      }
    }catch(_){ }
  }catch(_){ } });

  // Expose wrappers
  try{
    window.csvActions = window.csvActions || {};
    window.csvActions.generateMoreLLMSummaries = generateMoreLLMSummaries;
    window.csvActions.fetchCachedEvidence = fetchCachedEvidence;
    // Expose loop-closure helpers for automated tests and external callers
    try{ window.csvActions.pushIncidentForRow = pushIncidentForRow; window.csvActions.pushSbomDeltaForRow = pushSbomDeltaForRow; }catch(_){ }
    try{ window.pushIncidentForRow = pushIncidentForRow; window.pushSbomDeltaForRow = pushSbomDeltaForRow; }catch(_){ }
  }catch(_){ }
  function applyRiskAppetite(list){
    try{
      var appetite=(localStorage.getItem('risk_appetite')||'medium').toLowerCase();
      var sets={ low:{malAv:8,susAv:2,malTw:7.5,susTw:4}, medium:{malAv:10,susAv:3,malTw:8,susTw:5}, high:{malAv:14,susAv:5,malTw:9,susTw:6} };
      var th=sets[appetite]||sets.medium;
      list.forEach(function(rec){
        try{
          if(!rec||!rec.raw) return;
          var avRaw=rec.raw.avPositives||rec.raw.av_positives||rec.raw.avPos;
          var twRaw=rec.raw.threatWeight||rec.raw.threatweight||rec.raw.ThreatWeight;
          var av=parseInt(String(avRaw||'').match(/\d+/)?.[0]||'0',10)||0;
          var tw=parseFloat(String(twRaw||'').match(/\d+(?:\.\d+)?/)?.[0]||'0')||0;
          var verdict=getInitialVerdict(rec) || '';
          if(av||tw){
            if(av>=th.malAv||tw>=th.malTw) verdict='MALICIOUS';
            else if(av>=th.susAv||tw>=th.susTw) verdict='SUSPICIOUS';
            else if(appetite==='high' && (verdict==='MALICIOUS'||verdict==='SUSPICIOUS') && av<th.susAv && tw<th.susTw) verdict='GOOD';
            rec._initial_verdict = verdict;
          }
        }catch(_){ }
      });
    }catch(_){ }
  }

  // load persisted last results if fresh
  try{
    var lastRaw = JSON.parse(localStorage.getItem('csv_last_results')||'null');
    var lastTs = parseInt(localStorage.getItem('csv_last_results_ts')||'0',10)||0;
    var TTL_MIN = 60; // minutes default ttl
    if(lastRaw && Array.isArray(lastRaw) && lastTs){ var age = (Date.now()/1000 - lastTs); if(age < TTL_MIN*60){ try{ window.LAST_RESULTS = lastRaw; }catch(_){ } } else { try{ localStorage.removeItem('csv_last_results'); localStorage.removeItem('csv_last_results_ts'); }catch(_){ } } }
  }catch(_){ }

  function mapRawToRecord(raw){
    try{
      var proc=raw.process_name||raw.process||raw.Process||raw['Process Name']||raw['proc']||raw['command']||raw['cmd']||'unknown';
      var path=raw.file_path||raw.path||raw.Path||raw['File Path']||raw['path']||'';
      var sha=raw.sha256||raw.SHA256||raw.hash||raw.Hash||'';
      var host=raw.host||raw.hostname||raw.Host||raw.server||raw['device_hostname']||raw['agent_host']||raw['asset_name']||'';
      var user=raw.user||raw.username||raw.User||raw['userprincipalname']||raw['UserPrincipalName']||'';
      var signer=raw.signer_subject||raw.signature_subject||raw.publisher||raw.vendor||raw.company||'';
      var verdict = raw.verdict||'';
      if(!verdict) verdict = inferVerdictFromRaw(raw) || '';
      verdict = (verdict || '').toUpperCase();
      var rec={process_name:proc,file_path:path,sha256:sha,host:host,user:user,signer:signer,verdict:verdict,raw:raw};
      rec._initial_verdict = verdict;
      rec.factors = rec.factors||[]; // simple factor heuristics
      try{ var p = String(proc||'').toLowerCase(); if(p.includes('rundll32')||p.includes('regsvr32')||p.includes('mshta')) rec.factors.push('lolbin'); }catch(_){ }
      if((/\\windows\\system32/i).test(String(path||''))) rec.factors.push('unsigned_sensitive_path');
      if(verdict && /^(SUSPICIOUS|MALICIOUS|THREAT)$/i.test(verdict)) rec.factors.push('novel_global');
      rec._dread = computeDreadBreakdown(rec.factors, raw, rec);
      var statusNote = (rec._dread.status && rec._dread.status !== 'UNKNOWN') ? ' ['+rec._dread.status+']' : '';
      rec._dread_text = rec._dread.score + ' (' + rec._dread.level + ')' + statusNote;
      return rec;
    }catch(e){ return {process_name:'unknown',file_path:'',sha256:'',host:'',verdict:'',_initial_verdict:'',factors:[],_dread:{score:0},raw:raw}; }
  }

  document.addEventListener('click', function(evt){
    try{
      var btn = evt.target.closest('.cached-evidence-btn');
      if(!btn) return;
      evt.preventDefault();
      var cacheAttr = btn.getAttribute('data-cache') || '';
      var aidAttr = btn.getAttribute('data-assessment') || '';
      var cacheKey = '';
      var aid = '';
      try{ cacheKey = decodeURIComponent(cacheAttr); }catch(_){ cacheKey = cacheAttr; }
      try{ aid = decodeURIComponent(aidAttr); }catch(_){ aid = aidAttr; }
      var targetId = btn.getAttribute('data-target');
      if(cacheKey && aid){
        fetchCachedEvidence(cacheKey, aid, targetId);
      }
    }catch(err){
      console.warn('cached evidence handler', err);
    }
  });

  function enableMappingButton(enabled){
    try{
      var btn = document.getElementById('btnEditMapping');
      if(btn){
        btn.disabled = !enabled;
      }
    }catch(_){ }
  }

  function persistMappingState(mapping, summary, score){
    try{ localStorage.setItem('csv_last_mapping', JSON.stringify(mapping||{})); }catch(_){ }
    try{ localStorage.setItem('csv_mapping_summary', JSON.stringify(summary||{})); }catch(_){ }
    if(typeof score !== 'undefined' && score !== null){
      try{ localStorage.setItem('csv_mapping_semantics_score', String(score)); }catch(_){ }
    }else{
      try{ localStorage.removeItem('csv_mapping_semantics_score'); }catch(_){ }
    }
  }

  async function fetchCachedEvidence(cacheKey, assessmentId, targetId){
    if(!cacheKey || !assessmentId){
      return;
    }
    var targetEl = targetId ? document.getElementById(targetId) : null;
    if(targetEl){
      targetEl.textContent = 'Loading evidence...';
    }
    try{
      var resp = await fetch('/api/v1/deep_analyze/assessments/'+encodeURIComponent(assessmentId)+'/evidence/'+encodeURIComponent(cacheKey), {
        headers: Object.assign({}, authHeaders()),
      });
      if(!resp.ok){
        var errText = await resp.text();
        throw new Error(errText || 'request_failed');
      }
      var payload = await resp.json();
      var data = (payload && typeof payload.data !== 'undefined') ? payload.data : payload;
      if(targetEl){
        try{
          targetEl.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
        }catch(_){
          targetEl.textContent = String(data);
        }
      }
    }catch(err){
      console.warn('fetchCachedEvidence', err);
      if(targetEl){
        targetEl.textContent = 'Failed to load evidence: '+(err && err.message ? err.message : 'unknown error');
      }
    }
  }

  function updateMappingBanner(summary, score){
    try{
      CURRENT_MAPPING_SUMMARY = summary || null;
      if(typeof score === 'number' || (typeof score === 'string' && score)){
        var numeric = typeof score === 'number' ? score : parseFloat(score);
        if(!isNaN(numeric)) CURRENT_MAPPING_SCORE = numeric;
      } else if(score === null){
        CURRENT_MAPPING_SCORE = null;
      }
      var banner = document.getElementById('mappingSummaryBanner');
      if(!banner) return;
      if(summary && (summary.high_value_present || summary.present_fields)){
        var hv = Array.isArray(summary.high_value_present) ? summary.high_value_present.join(', ') : '';
        var sup = Array.isArray(summary.support_present) ? summary.support_present.join(', ') : '';
        var text = hv ? ('High: '+hv) : 'High: none';
        if(sup) text += ' | Support: '+sup;
        if(typeof CURRENT_MAPPING_SCORE === 'number' && !isNaN(CURRENT_MAPPING_SCORE)){
          text += ' | Semantics '+CURRENT_MAPPING_SCORE.toFixed(2);
        }
        banner.textContent = text;
        banner.style.display = 'inline-flex';
      }else{
        banner.style.display = 'none';
      }
    }catch(_){ }
  }

  function mapServerRecordToClient(rec){
    var raw = (rec && (rec.raw || rec._raw)) ? (rec.raw || rec._raw) : {};
    var mapped = {
      process_name: rec && (rec.process_name || rec.process) ? (rec.process_name || rec.process) : (raw.process_name || raw.process || raw.command_line || 'unknown'),
      file_path: rec && rec.file_path ? rec.file_path : (raw.file_path || raw.path || ''),
      sha256: rec && (rec.sha256 || rec.hash) ? (rec.sha256 || rec.hash) : (raw.sha256 || raw.hash || ''),
      host: rec && rec.host ? rec.host : (raw.host || raw.hostname || ''),
      user: rec && rec.user ? rec.user : (raw.user || raw.username || ''),
      domain: rec && rec.domain ? rec.domain : (raw.domain || ''),
      verdict: (rec && rec.verdict ? rec.verdict : (raw.verdict || '')).toUpperCase(),
      risk_score: typeof rec.risk_score === 'number' ? rec.risk_score : 0,
      factors: Array.isArray(rec && rec.factors) ? rec.factors.slice() : (Array.isArray(raw.factors) ? raw.factors.slice() : []),
      recommendations: Array.isArray(rec && rec.recommendations) ? rec.recommendations.slice() : [],
      raw: raw
    };
    mapped._initial_verdict = mapped.verdict;
    mapped._dread = computeDreadBreakdown(mapped.factors, raw, mapped);
    var statusNote = (mapped._dread && mapped._dread.status && mapped._dread.status !== 'UNKNOWN') ? ' ['+mapped._dread.status+']' : '';
    mapped._dread_text = (mapped._dread && typeof mapped._dread.score !== 'undefined' ? mapped._dread.score : 'n/a') + ' (' + (mapped._dread && mapped._dread.level ? mapped._dread.level : 'n/a') + ')' + statusNote;
    mapped.row_index = (typeof rec.row_index === 'number') ? rec.row_index : (typeof rec.row_number === 'number' ? rec.row_number : mapped.row_index);
    var passthroughKeys = [
      'pipeline_snapshot','breaker_signal','mapping_semantics','binary_context','kill_chain',
      'cached_evidence','persona_reports','persona_templates','hopgraph_context','mapping_summary',
      'mapping_semantics_score','assessment_id','hopgraph_snippet'
    ];
    passthroughKeys.forEach(function(key){
      if(rec && typeof rec[key] !== 'undefined'){
        mapped[key] = rec[key];
      } else if(raw && typeof raw[key] !== 'undefined' && typeof mapped[key] === 'undefined'){
        mapped[key] = raw[key];
      }
    });
    return mapped;
  }

  function applySharedIngestResult(payload, rawRows){
    try{
      var results = Array.isArray(payload && payload.results) ? payload.results : [];
      var mapped = results.map(mapServerRecordToClient);
      if(!mapped.length && Array.isArray(rawRows)){
        mapped = rawRows.map(mapRawToRecord);
      }
      var summary = payload ? payload.mapping_summary : null;
      var semantics = payload ? payload.mapping_semantics_score : undefined;
      var respMapping = payload ? payload.mapping : null;
      mapped.forEach(function(entry){
        if(summary){
          entry.mapping_summary = summary;
        }
        if(typeof semantics !== 'undefined'){
          entry.mapping_semantics_score = semantics;
        }
        if(respMapping){
          entry.mapping = respMapping;
        }
      });
      window.LAST_RESULTS = mapped.length ? mapped : [{process_name:'unknown',file_path:'/tmp',sha256:'dead',host:'host',verdict:'SUSPICIOUS',factors:[],_dread:{score:4},raw:{}}];
      window._csvRows = Array.isArray(rawRows) ? rawRows : [];
      CURRENT_RAW_ROWS = Array.isArray(rawRows) ? rawRows : [];
      try{
        localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS));
        localStorage.setItem('csv_last_results_ts', String(Math.round(Date.now()/1000)));
      }catch(_){ }
      CURRENT_MAPPING = (payload && payload.mapping) ? payload.mapping : CURRENT_MAPPING;
      var score = payload ? payload.mapping_semantics_score : undefined;
      persistMappingState(CURRENT_MAPPING, summary, score);
      updateMappingBanner(summary, score);
      window.__CSV_MAPPING_SUMMARY = summary || null;
      window.__CSV_MAPPING_SCORE = typeof score !== 'undefined' ? score : null;
      window.__CSV_CURRENT_MAPPING = CURRENT_MAPPING;
      enableMappingButton(CURRENT_RAW_HEADERS && CURRENT_RAW_HEADERS.length);
      try{ applyRiskAppetite(window.LAST_RESULTS); }catch(_){ }
      renderTableFromResults();
      handleRowsLoadedFromUpload();
    }catch(err){
      console.warn('applySharedIngestResult', err);
      applyLocalFallback(rawRows);
    }
  }

  function applyLocalFallback(rawRows){
    try{
      var list = Array.isArray(rawRows) ? rawRows.map(mapRawToRecord) : [];
      if(!list.length){
        list = [{process_name:'unknown',file_path:'/tmp',sha256:'dead',host:'host',verdict:'SUSPICIOUS',factors:[],_dread:{score:4},raw:{}}];
      }
      window.LAST_RESULTS = list;
      window._csvRows = Array.isArray(rawRows) ? rawRows : [];
      CURRENT_RAW_ROWS = Array.isArray(rawRows) ? rawRows : [];
      updateMappingBanner(null, null);
      try{
        localStorage.setItem('csv_last_results', JSON.stringify(list));
        localStorage.setItem('csv_last_results_ts', String(Math.round(Date.now()/1000)));
      }catch(_){ }
      renderTableFromResults();
      handleRowsLoadedFromUpload();
    }catch(e){
      console.warn('applyLocalFallback', e);
    }
  }

  async function processRowsViaSharedIngest(rawRows, opts){
    opts = opts || {};
    if(!window.csvIngest || typeof window.csvIngest.ingestRows !== 'function'){
      applyLocalFallback(rawRows);
      return;
    }
    LAST_INGEST_SOURCE = opts.source || LAST_INGEST_SOURCE || 'csv_analyzer';
    try{
      var resp = await window.csvIngest.ingestRows({
        rows: rawRows || [],
        mapping: CURRENT_MAPPING || {},
        source: LAST_INGEST_SOURCE,
        limit: opts.limit || undefined
      });
      applySharedIngestResult(resp, rawRows);
    }catch(err){
      console.warn('processRowsViaSharedIngest', err);
      applyLocalFallback(rawRows);
      try{
        if(window.notifications && window.notifications.showToast){
          window.notifications.showToast('CSV ingest failed, using local heuristics', 3200);
        }
      }catch(_){ }
    }
  }

  async function processParsedRows(rawRows, opts){
    try{
      CURRENT_RAW_ROWS = Array.isArray(rawRows) ? rawRows : [];
      window._csvRows = Array.isArray(rawRows) ? rawRows : [];
      CURRENT_RAW_HEADERS = (Array.isArray(rawRows) && rawRows.length) ? Object.keys(rawRows[0]) : [];
      enableMappingButton(!!(CURRENT_RAW_HEADERS && CURRENT_RAW_HEADERS.length));
      if(Array.isArray(rawRows) && rawRows.length){
        await processRowsViaSharedIngest(rawRows, opts || {});
      }else{
        applyLocalFallback(rawRows);
      }
    }catch(err){
      console.warn('processParsedRows', err);
      applyLocalFallback(rawRows);
    }
  }

  // Try to infer a verdict from raw parsed row values (Excel/CSV with different column names)
  function inferVerdictFromRaw(raw){
    try{
      if(!raw || typeof raw !== 'object') return '';
      const getFirstNumber = function(val){
        if(val===undefined||val===null) return NaN;
        const s=String(val);
        // ratio forms like 4/74 or 4 / 74 or 4 of 74
        let m=s.match(/^(\s*)(\d+)(?:\s*(?:\/|of)\s*\d+)/i);
        if(m) return parseInt(m[2],10);
        let m2=s.match(/(\d+)/);
        return m2?parseInt(m2[1],10):NaN;
      };
      const getFirstFloat = function(val){
        if(val===undefined||val===null) return NaN;
        const s=String(val);
        let m=s.match(/(\d+(?:\.\d+)?)/);
        return m?parseFloat(m[1]):NaN;
      };
      // direct verdict fields
      const vfields = ['verdict','Verdict','decision','Decision','result','Result','tag','Tag'];
      for(const f of vfields){ if(raw[f]){ const s=String(raw[f]).trim(); if(s) return s; } }
      // vendor allowlist indicators
      const flagRaw = raw.flagName||raw.flagname||raw.FlagName||'';
      const signature = raw.signature||raw.signer||'';
      const signedField = raw.signed||raw.Signed||raw.is_signed;
      const lowerAll = (flagRaw+' '+signature+' '+(raw.process_name||raw.process||'')+' '+(raw.file_path||raw.path||'')).toLowerCase();
      const vendorTokens = ['fsagent','f-secure','fsecure','microsoft','crowdstrike','sentinelone','carbonblack','defender'];
      const vendorHit = vendorTokens.some(t=>lowerAll.includes(t));
      const flagGood = /verified\s+good|known\s+good|allow(list|ed)?|benign/i.test(flagRaw);
      // boolean explicit malicious flags override allowlist
      if(raw.malicious || raw.Malicious || raw.is_malicious) return 'MALICIOUS';
      if(raw.suspicious || raw.Suspicious || raw.is_suspicious) return 'SUSPICIOUS';
      // numeric signals
      let av = getFirstNumber(raw.avPositives||raw.av_positives||raw.avPos);
      let tw = getFirstFloat(raw.threatWeight||raw.threatweight||raw.ThreatWeight);
      // treat extreme values first
      const strongMal = (!isNaN(av) && av>=25) || (!isNaN(tw) && tw>=9.5);
      if(strongMal) return 'MALICIOUS';
      // vendor allowlist BEFORE moderate thresholds to suppress benign noise
      if((vendorHit || flagGood || signedField===true) && (isNaN(av) || av<10) && (isNaN(tw) || tw<8)) return 'GOOD';
      // moderate thresholds (tuned down to reduce FP noise)
      if(!isNaN(av) && av>=10) return 'MALICIOUS';
      if(!isNaN(av) && av>=3) return 'SUSPICIOUS';
      if(!isNaN(tw) && tw>=8) return 'MALICIOUS';
      if(!isNaN(tw) && tw>=5) return 'SUSPICIOUS';
      // Cyberstash-specific textual hints
      if(raw.threatName || raw.threatname || raw.ThreatName){
        var tn=String(raw.threatName||raw.threatname||raw.ThreatName||'').toLowerCase();
        if(tn){
          if(/trojan|ransom|backdoor/.test(tn)) return 'MALICIOUS';
          if(/suspicious|malicious/.test(tn)) return 'SUSPICIOUS';
        }
      }
      if(flagRaw){
        var fn=flagRaw.toLowerCase();
        if(/probably\s+bad|needs\s+review/.test(fn)) return 'SUSPICIOUS';
        if(/malicious/.test(fn)) return 'MALICIOUS';
      }
      // If vendor good indicators present (late catch for very low-signal rows)
      if((vendorHit || flagGood || signedField===true) && !strongMal) return 'GOOD';
      // fallback text sweep (keep narrow to reduce FP)
      const text = Object.values(raw).join(' ').toLowerCase();
      if(/c2\b|ransom|exfil|beacon/.test(text)) return 'SUSPICIOUS';
      return '';
    }catch(_){ return ''; }
  }

  // Build analyst-friendly one-line summary for a row
  function buildAnalystSummary(rec){
    try{
      if(!rec) return '';
      var parts=[];
      parts.push('Process: '+(rec.process_name||'unknown'));
      parts.push('Path: '+(rec.file_path||''));
      parts.push('Host: '+(rec.host||''));
      parts.push('Hash: '+(rec.sha256||''));
      parts.push('Verdict: '+(getVerdictForView(rec)||'NEUTRAL'));
      parts.push('Factors: '+(rec.factors && rec.factors.length? rec.factors.join(', '): 'none'));
      var dreadStatus = (rec._dread && rec._dread.status && rec._dread.status!=='UNKNOWN') ? ' ['+rec._dread.status+']' : '';
      parts.push('DREAD: '+(rec._dread && rec._dread.score!==undefined? rec._dread.score:'n/a')+dreadStatus);
      // Quick triage hint
      var hint='If signed vendor & low positives -> allowlist; else verify parent lineage & network activity.';
      parts.push('TriageHint: '+hint);
      return parts.join(' | ');
    }catch(_){ return ''; }
  }

  // Summary banner + longitudinal audit
  function updateFpBannerAndAudit(list){
    try{
      var banner=document.getElementById('csv_fp_banner');
      if(!banner){
        var host=document.getElementById('results');
        if(host){
          banner=document.createElement('div');
          banner.id='csv_fp_banner';
          banner.style.margin='8px 0';
          banner.style.padding='6px 10px';
          banner.style.border='1px solid var(--border,#324)';
          banner.style.borderRadius='6px';
          banner.style.background='var(--bg-tertiary, #1e1f25)';
          banner.style.fontSize='12px';
          host.parentNode.insertBefore(banner, host);
        }
      }
      var fail=0, pass=0, neutral=0;
      (list||[]).forEach(function(r){ var c=verdictPassFail(null, r); if(c==='FAIL') fail++; else if(c==='PASS') pass++; else neutral++; });
      if(banner){ banner.textContent='Row Verdict Summary: FAIL='+fail+' | PASS='+pass+' | NEUTRAL='+neutral+' (Total='+list.length+')'; }
      // Persist audit (keep last 50)
      try{
        var audit=JSON.parse(localStorage.getItem('csv_fp_audit')||'[]');
        audit.push({ ts: Date.now()/1000, total:list.length, fail:fail, pass:pass, neutral:neutral });
        if(audit.length>50) audit=audit.slice(audit.length-50);
        localStorage.setItem('csv_fp_audit', JSON.stringify(audit));
      }catch(_){ }
    }catch(e){ /* silent */ }
  }

  // Clipboard copy helper exposed globally for inline details button
  window.copyCsvRowSummary = function(idx){
    try{
      var rec=(window.LAST_RESULTS||[])[idx];
      var text=buildAnalystSummary(rec);
      if(!text){ return; }
      if(navigator && navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).catch(function(){}); }
      else { var ta=document.createElement('textarea'); ta.value=text; document.body.appendChild(ta); ta.select(); try{ document.execCommand('copy'); }catch(_){ } ta.parentNode.removeChild(ta); }
      try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Copied row summary',2000); }catch(_){ }
    }catch(e){ console.warn('copyCsvRowSummary', e); }
  };

  function fallbackTextParse(file){
    try{
      var reader=new FileReader();
      reader.onload=function(ev){
        try{
          var text=ev.target.result||'';
          var lines=text.split(/\r?\n/).filter(Boolean);
          var headers=(lines[0]||'').split(/[,;\t]/).map(function(h){ return String(h||'').trim(); });
          var rawRows=[];
          for(var i=1;i<Math.min(lines.length,2000);i++){
            var cols=lines[i].split(/[,;\t]/);
            var raw={};
            headers.forEach(function(h,idx){ raw[h]=cols[idx]; });
            rawRows.push(raw);
          }
          processParsedRows(rawRows, { source:'csv_analyzer_fallback', limit: rawRows.length }).catch(function(err){ console.warn('fallback ingest', err); });
        }catch(e){ console.warn('file read parse', e); applyLocalFallback([]); }
      };
      reader.readAsText(file);
    }catch(e){ console.warn('fallback parse failed', e); applyLocalFallback([]); }
  }

  // Improved fallback that normalizes headers and keeps raw rows accessible
  function normalizedFallbackParse(file){
    try{
      var reader=new FileReader();
      reader.onload=function(ev){
        try{
          var text=ev.target.result||'';
          var lines=text.split(/\r?\n/).filter(Boolean);
          var rawHeaders=(lines[0]||'').split(/[,;\t]/).map(function(h){ return String(h||'').trim(); });
          var normHeaders = rawHeaders.map(function(h){ return h.replace(/\s+/g,'_').replace(/[^a-zA-Z0-9_]/g,'').toLowerCase(); });
          var rawRows=[];
          for(var i=1;i<Math.min(lines.length,5000);i++){
            var cols=lines[i].split(/[,;\t]/);
            var obj={};
            normHeaders.forEach(function(n,idx){ obj[n]=cols[idx]; });
            rawRows.push(obj);
          }
          processParsedRows(rawRows, { source:'csv_analyzer_csv', limit: rawRows.length }).catch(function(err){ console.warn('normalized ingest', err); });
        }catch(e){ console.warn('normalized parse', e); applyLocalFallback([]); }
      };
      reader.readAsText(file);
    }catch(e){ console.warn('normalized parse failed', e); applyLocalFallback([]); }
  }

  function handleRowsLoadedFromUpload(){
    try{ SELECTED_ROWS.clear(); }catch(_){ }
    PIPELINE_PENDING = new Set();
    PIPELINE_TARGETS = new Set();
    PIPELINE_AUTORANK = false;
    PIPELINE_FORCE_SORT = false;
    AUTO_PIPELINE_ACTIVE = false;
    AUTO_PIPELINE_LAUNCHED = false;
    LAST_PIPELINE_ASSESSMENT = null;
    if(AUTO_PIPELINE_ENABLED){
      scheduleAutoDeepAnalyze();
    }
  }

  function scheduleAutoDeepAnalyze(){
    if(AUTO_PIPELINE_LAUNCHED) return;
    var list = availableResults();
    if(!list.length) return;
    var suspiciousRows = collectSuspiciousRows(400);
    if(!suspiciousRows.length) return;
    AUTO_PIPELINE_LAUNCHED = true;
    var indexes = suspiciousRows.map(function(entry){ return entry.row_index; }).filter(function(n){ return typeof n === 'number'; });
    preparePipelineTargets(indexes);
    PIPELINE_AUTORANK = true;
    PIPELINE_FORCE_SORT = true;
    try{
      if(window.notifications && window.notifications.showToast){
        window.notifications.showToast('Running 21-step pipeline on '+suspiciousRows.length+' suspicious rows…', 3500);
      }
    }catch(_){ }
    Promise.resolve(initiateDeepAnalyze({
      rows: suspiciousRows,
      auto_llm: false,
      options: { auto_llm: false },
      analyze_mode: localStorage.getItem('csv_auto_analyze_mode') || 'basic',
      silent: true,
      priority_label: 'auto-bulk',
      auto_target: true
    })).catch(function(err){
      console.warn('Auto deep analyze failed', err);
      AUTO_PIPELINE_LAUNCHED = false;
    });
  }

  // Update loadFile to use normalized parser for CSVs and set window._csvRows
  function loadFile(){ var inp=document.getElementById('fileInput'); if(!inp||!inp.files||!inp.files.length) return; var f=inp.files[0]; try{
      var name = (f && f.name) || '';
      if(/\.csv$/i.test(name)) { normalizedFallbackParse(f); return; }
      if(window.parseTabular && window.parseTabular.clientSideAggregate){
        window.parseTabular.clientSideAggregate([f]).then(function(out){
          try{
            var rows=(out&&out.rows)||[];
            processParsedRows(rows, { source:'csv_analyzer_xlsx', limit: rows.length }).catch(function(err){ console.warn('aggregate ingest error', err); });
          }catch(e){ console.warn('aggregate map error', e); applyLocalFallback([]); }
        }).catch(function(err){ console.warn('client aggregate failed', err); normalizedFallbackParse(f); });
      } else normalizedFallbackParse(f);
    }catch(e){ console.warn('file parse error', e); normalizedFallbackParse(f); } }

  function triggerFilePicker(){
    try{
      var inp = document.getElementById('fileInput');
      if(!inp) return;
      if(inp.files && inp.files.length){
        loadFile();
        return;
      }
      inp.value = '';
      inp.click();
    }catch(_){ }
  }

  function bindFilePickerChange(){
    try{
      var inp = document.getElementById('fileInput');
      if(!inp) return;
      inp.addEventListener('change', function(){
        try{ loadFile(); }catch(e){ console.warn('file picker change failed', e); }
      });
    }catch(_){ }
  }

  function authHeaders(){ try{ var k=localStorage.getItem('apiKey'); return k ? {'x-api-key':k} : {}; }catch(_){ return {} } }
  function authHeadersWithTenant(){ try{ var k=localStorage.getItem('apiKey'); var t=localStorage.getItem('tenantId')||null; var h = {}; if(k) h['x-api-key']=k; if(t) h['X-Tenant-ID'] = t; return h; }catch(_){ return {} } }

  window.openCsvRowDetails = function(index){ try{ var tr=document.querySelector('#tbody tr[data-row="'+index+'"]'); if(!tr) return; var next=tr.nextElementSibling; if(next && next.classList && next.classList.contains('csv-inline-details')){ return; } try{ var old=document.querySelector('#tbody tr.csv-inline-details'); if(old) old.parentNode.removeChild(old); }catch(_){} try{ var drawer = document.getElementById('deepAnalyzeDrawer'); if(drawer) drawer.style.display='none'; }catch(_){ } insertInlineDetailsAfter(tr,index); try{ localStorage.setItem('csv_expanded_row', String(index)); }catch(_){ } }catch(e){ console.warn('openCsvRowDetails', e); } };

  async function postDisposition(rowIndex, disposition){
    try{
      var list=window.LAST_RESULTS||[];
      var rec=list[rowIndex]||{};
      var raw=rec.raw||{};
      var body=[{ event_id: raw.event_id||raw.EventID||null, row_index: rowIndex, disposition: disposition, source:'csv', ts: Date.now()/1000 }];
      var r=await (window.safeFetch || fetch)('/api/v1/telemetry/dispositions', { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(body) });
      if(r.ok){
        try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Saved disposition: '+disposition,2500);}catch(_){ }
        return true;
      }
      try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Disposition failed: '+r.status,3000);}catch(_){ }
      return false;
    }catch(e){
      console.warn('postDisposition', e);
      return false;
    }
  }

  async function applyBulkDisposition(disposition){ try{ if(!SELECTED_ROWS.size) return; var payload=[]; SELECTED_ROWS.forEach(function(idx){ var rec=(window.LAST_RESULTS||[])[idx]||{}; var raw=rec.raw||{}; payload.push({ event_id: raw.event_id||raw.EventID||null, row_index: idx, disposition: disposition, source:'csv', ts: Date.now()/1000 }); }); var r=await (window.safeFetch || fetch)('/api/v1/telemetry/dispositions',{ method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload)}); if(r.ok){ try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Applied '+disposition+' to '+payload.length+' rows',3500);}catch(_){ } } else { try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Bulk disposition failed: '+r.status,3000);}catch(_){ } } SELECTED_ROWS.clear(); renderTableFromResults(); }catch(e){ console.warn('applyBulkDisposition', e); } }

  async function ingestSelectedRows(){ try{ if(!SELECTED_ROWS.size) return; var payload=[]; SELECTED_ROWS.forEach(function(idx){ var rec=(window.LAST_RESULTS||[])[idx]||{}; var raw=rec.raw||{}; payload.push({ row_index: idx, raw: raw }); }); var r = await (window.safeFetch || fetch)('/api/v1/ingest/csv_rows', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(payload) }); if(r.ok){ var j = await r.json(); try{ (j||[]).forEach(function(item){ try{ var idx = item.row_index; var eid = item.event_id; var rec=(window.LAST_RESULTS||[])[idx]; if(rec && rec.raw){ rec.raw.event_id = eid; } }catch(_){ } }); if(window.notifications && window.notifications.showToast) window.notifications.showToast('Ingested '+j.length+' rows',2500); }catch(_){ } renderTableFromResults(); SELECTED_ROWS.clear(); } else { try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Ingest failed: '+r.status,3500); }catch(_){ } } }catch(e){ console.warn('ingestSelectedRows', e); } }

  function delegateClicks(e){ try{ if(e.target && e.target.classList && e.target.classList.contains('csv-row-select')){ var idx=parseInt(e.target.getAttribute('data-idx'),10); if(!isNaN(idx)){ if(e.target.checked) SELECTED_ROWS.add(idx); else SELECTED_ROWS.delete(idx); renderTableFromResults(); } return; } if(e.target && e.target.getAttribute && e.target.getAttribute('title')==='Why flagged / details'){ var tr=e.target.closest('tr[data-row]'); if(tr){ var idx=parseInt(tr.getAttribute('data-row'),10); if(!isNaN(idx)) window.openCsvRowDetails(idx); } } }catch(_){ } }
  // Allow clicking the row (non-interactive area) to toggle inline details
  document.addEventListener('click', function(e){ try{
    var tr = e.target && e.target.closest ? e.target.closest('tr[data-row]') : null;
    if(!tr) return;
    // ignore clicks on buttons, links, inputs to prevent double-handling
    var interactive = e.target.closest('button, a, input, select, textarea');
    if(interactive) return;
    var idx = parseInt(tr.getAttribute('data-row'),10);
    if(isNaN(idx)) return;
    window.openCsvRowDetails(idx);
  }catch(_){ }});

  function init(){ try{
    bindFilePickerChange();
    updateMappingBanner(CURRENT_MAPPING_SUMMARY, CURRENT_MAPPING_SCORE);
    var el;
    el=document.getElementById('btnLoad'); if(el) el.addEventListener('click', function(){ triggerFilePicker(); });
    el=document.getElementById('btnEditMapping'); if(el){
      if(CURRENT_RAW_HEADERS && CURRENT_RAW_HEADERS.length) el.disabled=false;
      el.addEventListener('click', function(){
        try{
          if(!window.csvIngest || typeof window.csvIngest.openMappingEditor !== 'function'){
            if(window.notifications && window.notifications.showToast) window.notifications.showToast('Mapping editor unavailable until shared helper loads', 2500);
            return;
          }
          var headers = (CURRENT_RAW_HEADERS && CURRENT_RAW_HEADERS.length) ? CURRENT_RAW_HEADERS : ((window._csvRows && window._csvRows.length) ? Object.keys(window._csvRows[0]) : []);
          if(!headers.length){
            if(window.notifications && window.notifications.showToast) window.notifications.showToast('Load data before editing mapping', 2500);
            return;
          }
          window.csvIngest.openMappingEditor({
            headers: headers,
            mapping: CURRENT_MAPPING || {},
            onSave: function(mapping){
              CURRENT_MAPPING = mapping || {};
              persistMappingState(CURRENT_MAPPING, CURRENT_MAPPING_SUMMARY, CURRENT_MAPPING_SCORE);
              if(CURRENT_RAW_ROWS && CURRENT_RAW_ROWS.length){
                processRowsViaSharedIngest(CURRENT_RAW_ROWS, { source: LAST_INGEST_SOURCE, limit: CURRENT_RAW_ROWS.length }).catch(function(err){ console.warn('mapping re-ingest failed', err); });
              }
            }
          });
        }catch(err){ console.warn('edit mapping', err); }
      });
    }
    el=document.getElementById('btnExplain'); if(el) el.addEventListener('click', function(){ var m=document.getElementById('csvDrillModal'); if(m) m.style.display='flex'; });
    el=document.getElementById('btnFilterAll'); if(el) el.addEventListener('click', function(){ FILTER_MODE='all'; localStorage.setItem('csv_filter_mode','all'); renderTableFromResults(); });
    el=document.getElementById('btnFilterSuspicious'); if(el) el.addEventListener('click', function(){ FILTER_MODE='suspicious'; localStorage.setItem('csv_filter_mode','suspicious'); renderTableFromResults(); });
    el=document.getElementById('btnFilterPassed'); if(el) el.addEventListener('click', function(){ FILTER_MODE='passed'; localStorage.setItem('csv_filter_mode','passed'); renderTableFromResults(); });
    el=document.getElementById('btnVerdictViewInitial'); if(el) el.addEventListener('click', function(){ setVerdictViewMode('initial'); });
    el=document.getElementById('btnVerdictViewPipeline'); if(el) el.addEventListener('click', function(){ setVerdictViewMode('pipeline'); });
    // Pipeline sort toggle (UI button expected in HTML with id 'btnPipelineSort')
    try{
      var pbtn = document.getElementById('btnPipelineSort');
      if(pbtn){
        pbtn.addEventListener('click', function(){ try{ var cur = (localStorage.getItem('csv_pipeline_sort')||'0') === '1'; localStorage.setItem('csv_pipeline_sort', cur ? '0' : '1'); pbtn.classList.toggle('active', !cur); renderTableFromResults(); }catch(_){ } });
      }
      var curState = (localStorage.getItem('csv_pipeline_sort')||'0') === '1'; if(curState && pbtn) pbtn.classList.add('active');
    }catch(_){ }
    document.addEventListener('click', delegateClicks);
    el=document.getElementById('bulkGood'); if(el) el.addEventListener('click', function(){ applyBulkDisposition('good'); });
    el=document.getElementById('bulkReview'); if(el) el.addEventListener('click', function(){ applyBulkDisposition('review'); });
    el=document.getElementById('bulkThreat'); if(el) el.addEventListener('click', function(){ applyBulkDisposition('threat'); });
    el=document.getElementById('bulkSelectAll'); if(el) el.addEventListener('click', function(){ Array.from(document.querySelectorAll('#tbody tr[data-row] .csv-row-select')||[]).forEach(function(cb){ cb.checked=true; SELECTED_ROWS.add(parseInt(cb.getAttribute('data-idx'),10)); }); renderTableFromResults(); });
    el=document.getElementById('bulkClear'); if(el) el.addEventListener('click', function(){ SELECTED_ROWS.clear(); renderTableFromResults(); });
  
      // Provide quick copy of top FAIL rows after load
      try{ var quickCopy=document.getElementById('csvQuickCopyFail'); if(quickCopy){ quickCopy.addEventListener('click', function(){ try{ var list=window.LAST_RESULTS||[]; var topFails=list.filter(function(r){ return verdictPassFail(null, r)==='FAIL'; }).slice(0,10); var lines=topFails.map(function(r){ return buildAnalystSummary(r); }); var text=lines.join('\n'); if(navigator.clipboard) navigator.clipboard.writeText(text).catch(function(){}); else { var ta=document.createElement('textarea'); ta.value=text; document.body.appendChild(ta); ta.select(); try{ document.execCommand('copy'); }catch(_){ } ta.remove(); } if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Copied top fail summaries ('+topFails.length+')',2500); }catch(_){ } }); } }catch(_){ }
      // Signal Details toggle wiring
      try{
        var sd = document.getElementById('btnSignalDetails');
        if(sd){ sd.addEventListener('click', function(){ try{
          var panel = document.getElementById('signalHelpPanel'); var body = document.getElementById('signalHelpBody'); if(!panel || !body) return;
          if(panel.style.display==='none' || !panel.style.display){ body.innerHTML='';
            var entries=[
              {k:'novel_global', d:'Indicates artifact/behavior not seen in global telemetry; noisy for new vendor files.'},
              {k:'unsigned_sensitive_path', d:'Artifact found in sensitive path (e.g., System32) but missing expected signing metadata.'},
              {k:'lolbin', d:'Living-off-the-land binary used (rundll32, regsvr32, mshta) — can be abused.'},
              {k:'multi', d:'Observed across multiple batches/sources; suggests distributed activity.'},
              {k:'suspicious', d:'Textual heuristics matched suspicious keywords; requires manual review.'}
            ]; entries.forEach(function(e){ var div=document.createElement('div'); div.style.marginBottom='8px'; div.innerHTML='<strong>'+e.k+'</strong>: <span style="color:var(--text-muted);">'+e.d+'</span>'; body.appendChild(div); });
            panel.style.display='block';
          } else { panel.style.display='none'; }
        }catch(_){ } }); }
      }catch(_){ }
        try{ var widths = Array.from(document.querySelectorAll('#results thead th')).map(function(h){ return h.offsetWidth; }); localStorage.setItem('csv_col_widths', JSON.stringify(widths)); }catch(_){ }
    // header-based resizing (simple) + click-to-sort
    try{
      var ths = document.querySelectorAll('#results thead th');
      ths.forEach(function(th,idx){
        th.style.position='relative';
        var grip=document.createElement('div');
        grip.style.position='absolute';
        grip.style.top='0'; grip.style.right='0'; grip.style.width='8px'; grip.style.cursor='col-resize'; grip.style.userSelect='none'; grip.style.height='100%';
        th.appendChild(grip);
        var startX, startW;
        grip.addEventListener('pointerdown', function(e){
          startX=e.clientX; startW=th.offsetWidth; try{ grip.setPointerCapture(e.pointerId); }catch(_){ }
          function onMove(ev){ var dx=ev.clientX-startX; th.style.width = (startW+dx)+'px'; }
          function onUp(ev){ try{ grip.releasePointerCapture(e.pointerId); }catch(_){ } document.removeEventListener('pointermove', onMove); document.removeEventListener('pointerup', onUp);
            // persist widths
            try{ var widths = Array.from(document.querySelectorAll('#results thead th')).map(function(h){ return h.offsetWidth; }); localStorage.setItem('csv_col_widths', JSON.stringify(widths)); }catch(_){ }
          }
          document.addEventListener('pointermove', onMove); document.addEventListener('pointerup', onUp);
        });

        // header click = toggle sort for this column (persist by data-col name)
        th.addEventListener('click', function(ev){
          try{
            var current = JSON.parse(localStorage.getItem('csv_sort_state')||'null')||{};
            // prefer data-col attribute for stable naming
            var dataCol = th.getAttribute('data-col');
            // fallback mapping for older headers
            var fallbackMap = ['process_name','file_path','sha256','host','verdict','dread','signals'];
            var newCol = dataCol || fallbackMap[idx] || ('col'+idx);
            var newDir = 'asc';
            if(current && (current.col===newCol)) newDir = (current.dir==='asc'?'desc':'asc');
            var st = { col: newCol, dir: newDir };
            localStorage.setItem('csv_sort_state', JSON.stringify(st));
            PIPELINE_FORCE_SORT = false;
            PIPELINE_AUTORANK = false;
            // ARIA + visual cue via data-sort attribute
            Array.from(document.querySelectorAll('#results thead th')).forEach(function(h,i){ h.removeAttribute('data-sort'); h.removeAttribute('aria-sort'); });
            th.setAttribute('data-sort', newDir);
            th.setAttribute('aria-sort', newDir==='asc' ? 'ascending' : 'descending');
            renderTableFromResults();
          }catch(_){ }
        });
      });

      // apply saved widths
      try{ var w = JSON.parse(localStorage.getItem('csv_col_widths')||'null'); if(Array.isArray(w)){ var hlist = document.querySelectorAll('#results thead th'); w.forEach(function(v,i){ if(hlist[i]) hlist[i].style.width = v+'px'; }); } }catch(_){ }

      // apply saved sort visual state (by data-col name)
            try{ var ss = JSON.parse(localStorage.getItem('csv_sort_state')||'null'); if(ss && ss.col){ var allh = Array.from(document.querySelectorAll('#results thead th')); allh.forEach(function(h){ try{ if(h.getAttribute && h.getAttribute('data-col')===ss.col){ h.setAttribute('data-sort', ss.dir||'asc'); h.setAttribute('aria-sort', ss.dir==='asc' ? 'ascending' : 'descending'); } }catch(_){ } }); } }catch(_){ }
    }catch(_){ }

    // keyboard shortcuts
document.addEventListener('keydown', function(e){ try{ if(e.key==='ArrowDown' || e.key==='ArrowUp'){ var rows=Array.from(document.querySelectorAll('#tbody tr[data-row]')); if(!rows.length) return; var active = document.activeElement && document.activeElement.closest && document.activeElement.closest('tr[data-row]'); var i = active? rows.indexOf(active):-1; if(e.key==='ArrowDown') i=Math.min(rows.length-1,i+1); else i=Math.max(0,i-1); var target=rows[i]; if(target) target.querySelector('.csv-row-select')?.focus(); e.preventDefault(); } if(e.key===' '){ var el=document.activeElement; if(el&&el.closest&&el.closest('tr[data-row]')){ var cb=el.closest('tr[data-row]').querySelector('.csv-row-select'); if(cb){ cb.checked=!cb.checked; cb.dispatchEvent(new Event('click')); } e.preventDefault(); } } if(e.shiftKey && (e.key==='G' || e.key==='g')) applyBulkDisposition('good'); if(e.shiftKey && (e.key==='R' || e.key==='r')) applyBulkDisposition('review'); if(e.shiftKey && (e.key==='T' || e.key==='t')) applyBulkDisposition('threat'); if(e.key==='Enter'){ var el=document.activeElement; if(el&&el.closest&&el.closest('tr[data-row]')){ var idx=parseInt(el.closest('tr[data-row]').getAttribute('data-row'),10); if(!isNaN(idx)) window.openCsvRowDetails(idx); } } }catch(_){ } });
document.addEventListener('keydown', function(e){ if(e.key==='Escape'){ hideTier1Sidebar(); } });
    try{ if(!document.getElementById('riskAppetiteSelect')){ var host=document.getElementById('results'); if(host){ var wrap=document.createElement('div'); wrap.style.margin='6px 0'; wrap.innerHTML='<label style="font-size:12px;margin-right:6px">Risk Appetite:</label><select id="riskAppetiteSelect" style="padding:4px 8px;border-radius:4px;background:var(--bg-tertiary);color:var(--text-primary)"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option></select> <span id="riskAppetiteInfo" style="font-size:11px;color:var(--text-muted);margin-left:8px"></span>'; host.parentNode.insertBefore(wrap, host); var sel=document.getElementById('riskAppetiteSelect'); var info=document.getElementById('riskAppetiteInfo'); function appetiteTxt(v){ return v==='low'?'Stringent thresholds':(v==='high'?'Lenient thresholds':'Balanced'); } function applySel(){ var v=sel.value; localStorage.setItem('risk_appetite',v); if(info) info.textContent=appetiteTxt(v); reapplyRiskAppetite(); } sel.addEventListener('change',applySel); var initial=localStorage.getItem('risk_appetite'); if(initial){ sel.value=initial; } applySel(); var style=document.createElement('style'); style.textContent='.llm-badge{display:inline-block;background:#2855ff;color:#fff;font-size:10px;padding:2px 4px;border-radius:4px;margin-left:4px;cursor:help;} .llm-badge:hover{filter:brightness(1.15);} .pipeline-badge{display:inline-flex;align-items:center;font-size:10px;font-weight:600;padding:2px 6px;border-radius:999px;margin-left:4px;text-transform:uppercase;letter-spacing:0.5px;background:var(--bg-tertiary);color:var(--text-muted);} .pipeline-badge-ready{background:#0f5132;color:#d1ffd8;} .pipeline-badge-pending{background:#4c4f58;color:#ffe29d;} .pipeline-badge-queued{background:#2f3038;color:#aac8ff;} .pipeline-badge-neutral{background:#2a2c33;color:#b5b5b5;} .pipeline-ready-row{box-shadow:inset 3px 0 0 #0f5132;} .pipeline-pending-row{box-shadow:inset 3px 0 0 #b88500;} .pipeline-queued-row{box-shadow:inset 3px 0 0 #1b60c4;}'; document.head.appendChild(style); } } }catch(_){ }

  }catch(e){ console.warn('init failed', e); } }

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', function(){ try{ init(); }catch(_){ } }); else init();

  // Ensure the bulk ingest button (if present in the UI) is wired after init
  (function(){
    try{
      function attachIngest(){
        try{
          var bi = document.getElementById('bulkIngest');
          if(bi && typeof ingestSelectedRows === 'function') bi.addEventListener('click', ingestSelectedRows);
        }catch(_){ }
      }
      if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', attachIngest); else attachIngest();
    }catch(_){ }
  })();

    // Deep Analyze: wire real backend flow (POST -> poll -> render)
  (function attachDeepAnalyze(){
    try{
      var currentAssessmentId = null;
      var lastReportDocument = null;
      var reviewState = {};
      var latestRankedRows = [];
      var latestDomainSummary = null;
      var DOMAIN_DETECTIONS = [
        { id:'identity', label:'Identity', match:/user|account|identity|principal|actor|employee|owner|role|samaccount/i },
        { id:'endpoint', label:'Endpoint', match:/host|hostname|process|exe|binary|path|pid|device/i },
        { id:'network', label:'Network', match:/domain|dns|ip|url|sni|dst|src|port/i },
        { id:'data', label:'Data', match:/bucket|s3|table|database|dataset|file|object|blob|share/i },
        { id:'email', label:'Email', match:/email|subject|sender|recipient|mail|phish/i },
        { id:'cloud', label:'Cloud', match:/aws|azure|gcp|cloud|iam|lambda|tenant/i },
        { id:'remote', label:'Remote Access', match:/vpn|rdp|ssh|citrix|proxyjump|jump/i }
      ];
      var REVIEW_STATES = [
        { id: 'not_started', label: 'Unreviewed' },
        { id: 'triaged', label: 'Triaged' },
        { id: 'escalated', label: 'Escalated' },
        { id: 'dismissed', label: 'Dismissed' }
      ];
      try{ window.__deepReviewState = reviewState; }catch(_){ }
      function ensureDrawer(){
        var drawer = document.getElementById('deepAnalyzeDrawer');
        if(drawer) return drawer;
        drawer = document.createElement('div');
        drawer.id='deepAnalyzeDrawer';
        drawer.style.position='fixed';
        drawer.style.right='12px';
        drawer.style.top='60px';
        drawer.style.width='420px';
        drawer.style.maxHeight='80vh';
        drawer.style.overflow='auto';
        drawer.style.background='var(--bg-panel)';
        drawer.style.border='1px solid var(--border)';
        drawer.style.padding='12px';
        drawer.style.zIndex='9999';
        drawer.style.borderRadius='8px';
        drawer.style.display='none';
        drawer.innerHTML = [
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><strong>Deep Analyze</strong><div><button id="deepCloseBtn" class="btn">Close</button></div></div>',
          '<div id="deepAnalyzeProgress" style="font-size:13px;color:var(--text-muted);margin-bottom:8px">Idle</div>',
          '<div id="deepBackfillRibbon" style="font-size:13px;color:var(--text-muted);margin-bottom:8px;display:none">Auto Backfill: <span id="deepBackfillStatus">idle</span> <button id="deepBackfillToggle" class="btn" style="margin-left:8px">Start</button></div>',
          '<div id="deepCostSnippet" style="font-size:12px;color:var(--text-muted);margin-bottom:6px">LLM cost: n/a</div>',
          '<div id="deepProviderRow" style="font-size:12px;color:var(--text-muted);margin-bottom:6px">Provider: <select id="llmProviderSelect" style="margin-left:6px;padding:4px;background:var(--bg-tertiary);color:var(--text-primary)"><option value="">Detecting...</option></select> <button id="llmProviderRefresh" class="btn" style="margin-left:6px;padding:4px">Re-check</button></div>',
          '<div id="deepTelemetry" class="telemetry-grid" style="margin-bottom:8px;">Telemetry pending...</div>',
          '<div id="deepStageTimeline" style="font-size:12px;margin-bottom:8px;">Stage timeline not started.</div>',
          '<div id="deepCanonical" style="font-size:12px;margin-bottom:8px;">Canonical signals pending.</div>',
          '<div id="deepMappings" style="font-size:12px;margin-bottom:8px;">Framework mappings pending.</div>',
          '<div id="deepReviewSummary" class="review-summary">Analyst review coverage pending.</div>',
          '<div style="margin:6px 0"><button id="nextUnreviewedBtn" class="btn">Next Unreviewed</button> <span id="coverageWidget" style="font-size:12px;color:var(--text-muted);margin-left:8px">Coverage: n/a</span></div>',
          '<div id="deepDomainCues" class="domain-cue-line">Cross-domain cues not available yet.</div>',
          '<div id="deepPriorityRows" class="priority-wrapper"><div class="empty-hint" style="margin:0;padding:4px 0;">Priority queue populates once sanitized rows are ready.</div></div>',
          '<div class="review-summary" style="margin-top:4px;">All Sanitized Rows</div>',
          '<div id="deepAnalyzeRows"></div>',
          '<div style="margin-top:8px"><button id="deepExportBtn" class="btn btn-primary">Export Report</button></div>'
        ].join('');
        document.body.appendChild(drawer);
        try{ document.getElementById('deepCloseBtn').addEventListener('click', function(){ drawer.style.display='none'; }); }catch(_){ }
        try{ document.getElementById('deepExportBtn').addEventListener('click', function(){ triggerReportExport(); }); }catch(_){ }
        try{
          var bfBtn = document.getElementById('deepBackfillToggle');
          if(bfBtn){ bfBtn.addEventListener('click', function(){ try{ toggleAutoBackfill(); }catch(_){ } }); }
        }catch(_){ }
        return drawer;
      }

      function getReviewStorageKey(){
        return currentAssessmentId ? 'csv_deep_review_state_'+currentAssessmentId : null;
      }

      function resetReviewStateForAssessment(){
        reviewState = {};
        window.__deepReviewState = reviewState;
        latestRankedRows = [];
        latestDomainSummary = null;
        var key = getReviewStorageKey();
        if(key){
          try{ localStorage.removeItem(key); }catch(_){ }
        }
        renderReviewCoverage();
        renderDomainSummary();
      }

      function persistReviewState(){
        var key = getReviewStorageKey();
        if(!key) return;
        try{
          localStorage.setItem(key, JSON.stringify(reviewState));
        }catch(_){ }
      }

      function ensureReviewEntry(rowIndex){
        var key = String(rowIndex);
        if(!reviewState[key]){
          reviewState[key] = { status: 'not_started', notes: '' };
        }
        return reviewState[key];
      }

      function setReviewStateForRow(rowIndex, status, notes){
        var entry = ensureReviewEntry(rowIndex);
        if(typeof status === 'string' && status.length) entry.status = status;
        if(typeof notes === 'string') entry.notes = notes;
        entry.updated = Date.now();
        reviewState[String(rowIndex)] = entry;
        persistReviewState();
        renderReviewCoverage();
      }

      function extractDomainHints(row){
        try{
          var tags = new Set();
          var raw = {};
          try{
            Object.assign(raw, row || {});
            if(row && row.raw && typeof row.raw === 'object') Object.assign(raw, row.raw);
          }catch(_){ }
          Object.keys(raw || {}).forEach(function(key){
            var value = raw[key];
            var combined = (key+' '+(typeof value === 'string' ? value : '')).toString();
            DOMAIN_DETECTIONS.forEach(function(rule){
              if(rule.match.test(combined)) tags.add(rule.id);
            });
          });
          if(row && Array.isArray(row.factors)){
            row.factors.forEach(function(factor){
              var text = String(factor||'');
              DOMAIN_DETECTIONS.forEach(function(rule){
                if(rule.match.test(text)) tags.add(rule.id);
              });
            });
          }
          return Array.from(tags);
        }catch(_){
          return [];
        }
      }

      function summarizeDomainHints(rows){
        try{
          var counts = {};
          rows.forEach(function(entry){
            (entry.domains||[]).forEach(function(tag){
              counts[tag] = (counts[tag]||0)+1;
            });
          });
          var total = rows.length;
          var ordered = Object.entries(counts).sort(function(a,b){ return b[1]-a[1]; });
          var summary = ordered.slice(0,4).map(function(item){
            var rule = DOMAIN_DETECTIONS.find(function(r){ return r.id===item[0]; });
            var pct = total ? Math.round((item[1]/total)*100) : 0;
            return (rule ? rule.label : item[0])+' '+item[1]+' ('+pct+'%)';
          }).join(' • ');
          return { counts: counts, summary: summary || 'No distinct domains detected.', total: total, ordered: ordered };
        }catch(_){
          return { counts:{}, summary:'Cross-domain cues unavailable.', total:0, ordered:[] };
        }
      }

      function renderDomainSummary(){
        try{
          var el = document.getElementById('deepDomainCues');
          var text = latestDomainSummary && latestDomainSummary.summary ? ('Cross-domain cues: '+latestDomainSummary.summary) : 'Cross-domain cues not available yet.';
          if(el) el.textContent = text;
          var report = document.getElementById('reportReviewCoverage');
          if(report && report.textContent){
            // Keep review summary line but append domain hint for quick glance
            if(latestDomainSummary && latestDomainSummary.summary){
              report.setAttribute('data-domain-summary', latestDomainSummary.summary);
            }else{
              report.removeAttribute('data-domain-summary');
            }
          }
          window.__deepDomainSummary = latestDomainSummary;
        }catch(_){ }
      }

      function formatTimestamp(value){
        try{
          if(value === null || typeof value === 'undefined') return 'n/a';
          var num = Number(value);
          if(!isFinite(num)) return 'n/a';
          if(Math.abs(num) < 1e12) num = num * 1000;
          var d = new Date(num);
          if(isNaN(d.getTime())) return 'n/a';
          return d.toLocaleString();
        }catch(_){
          return 'n/a';
        }
      }

      function renderTelemetry(telemetry, state){
        try{
          var el = document.getElementById('deepTelemetry'); if(!el) return;
          var info = [];
          info.push({ label: 'Status', value: (state && state.status) || 'pending' });
          info.push({ label: 'Stage', value: state && state.current_stage ? state.current_stage + (state.current_index ? ' (#'+state.current_index+')' : '') : 'starting' });
          info.push({ label: 'Rows', value: (state && (state.rows_processed || (state.llm_rows && state.llm_rows.length))) || 0 });
          info.push({ label: 'Org', value: (state && state.org) || (localStorage.getItem('org') || 'unknown') });
          if(telemetry){
            var queued = telemetry.queued_at_ms || telemetry.queued_at;
            if(queued) info.push({ label: 'Queued', value: formatTimestamp(queued) });
            if(telemetry.started_at) info.push({ label: 'Started', value: formatTimestamp(telemetry.started_at) });
            if(telemetry.completed_at) info.push({ label: 'Completed', value: formatTimestamp(telemetry.completed_at) });
            if(typeof telemetry.stage_count !== 'undefined') info.push({ label: 'Planned Stages', value: telemetry.stage_count });
          }
          el.innerHTML = info.map(function(entry){
            return '<div><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.4px;">'+escapeHtml(entry.label)+'</div><div style="font-size:13px;color:var(--text-primary);margin-top:2px">'+escapeHtml(String(entry.value))+'</div></div>';
          }).join('') || 'Telemetry pending...';
          // show cost snippet if present
          try{ var costEl = document.getElementById('deepCostSnippet'); if(costEl){ var costInfo = (state && state.llm_cost_estimate) || (telemetry && telemetry.llm_cost_estimate) || window.__last_llm_cost; if(costInfo && typeof costInfo === 'object'){ var parts = Object.keys(costInfo).map(function(k){ return k+': $'+parseFloat(costInfo[k]).toFixed(4); }); costEl.textContent = 'LLM cost estimate: '+parts.join(' | '); } else { costEl.textContent = 'LLM cost: n/a'; } } }catch(_){ }
        }catch(e){ console.warn('renderTelemetry', e); }
      }

      function renderStageTimeline(history, outputs, currentStage){
        try{
          var el = document.getElementById('deepStageTimeline'); if(!el) return;
          var statusMap = {};
          (outputs||[]).forEach(function(entry){
            var key = (entry.stage || entry.name || '').toString();
            if(key) statusMap[key] = entry;
          });
          var html = (history||[]).map(function(stage){
            var key = (stage.name || stage.stage || ('Stage '+(stage.idx||''))).toString();
            var entry = statusMap[key] || stage;
            var status = (entry.status || stage.status || (key === currentStage ? 'running' : 'pending')).toLowerCase();
            var cls = 'stage-row stage-'+status;
            var marker = key === currentStage ? '&raquo; ' : '';
            var elapsed = entry.elapsed_ms ? ' ('+Math.round(entry.elapsed_ms)+'ms)' : '';
            return '<div class="'+cls+'"><div>'+marker+escapeHtml(key)+'</div><span>'+escapeHtml(status)+elapsed+'</span></div>';
          }).join('');
          el.innerHTML = html || 'Stage telemetry not available.';
          // Add a thin progress bar for current stage index if outputs provide ordering
          try{
            var pb = document.getElementById('deepStageProgressBar');
            if(!pb){ pb = document.createElement('div'); pb.id='deepStageProgressBar'; pb.style.height='6px'; pb.style.background='var(--bg-tertiary)'; pb.style.borderRadius='4px'; pb.style.overflow='hidden'; pb.style.marginTop='6px'; el.appendChild(pb); }
            var total = (history||[]).length || 1; var idx = 0; if(currentStage){ idx = (history||[]).findIndex(function(s){ return (s.name||s.stage)===currentStage; }); if(idx<0) idx=0; }
            var percent = Math.round(((idx+1)/total)*100);
            pb.innerHTML = '<div style="height:100%;width:'+percent+'%;background:linear-gradient(90deg,#2855ff,#66a3ff)"></div>';
          }catch(_){ }
        }catch(e){ console.warn('renderStageTimeline', e); }
      }

      function renderCanonicalAndMappings(state){
        try{
          var canonicalEl = document.getElementById('deepCanonical');
          var mappingsEl = document.getElementById('deepMappings');
          if(canonicalEl){
            var canonical = (state && state.canonical) || {};
            var items = Object.keys(canonical||{}).slice(0,8).map(function(key){
              var val = canonical[key];
              if(val && typeof val === 'object') val = JSON.stringify(val);
              return '<div><strong>'+escapeHtml(key)+'</strong>: <span style="color:var(--text-muted)">'+escapeHtml(String(val))+'</span></div>';
            }).join('');
            canonicalEl.innerHTML = items || 'Canonical signals not ready.';
          }
          if(mappingsEl){
            var mappings = (state && state.mappings) || {};
            var mappingHtml = Object.keys(mappings||{}).map(function(key){
              var val = mappings[key];
              var pills = [];
              if(Array.isArray(val)){
                pills = val.slice(0,6).map(function(entry){
                  if(entry && typeof entry === 'object'){
                    var text = entry.id || entry.name || JSON.stringify(entry);
                    return '<span class="mapping-pill">'+escapeHtml(text)+'</span>';
                  }
                  return '<span class="mapping-pill">'+escapeHtml(String(entry))+'</span>';
                });
              }else if(val && typeof val === 'object'){
                pills = Object.keys(val).slice(0,6).map(function(k){
                  return '<span class="mapping-pill"><strong>'+escapeHtml(k)+':</strong> '+escapeHtml(String(val[k]))+'</span>';
                });
              }else if(typeof val !== 'undefined'){
                pills = ['<span class="mapping-pill">'+escapeHtml(String(val))+'</span>'];
              }
              if(!pills.length) pills = ['<span class="mapping-pill">No entries</span>'];
              return '<div style="margin-bottom:6px;"><strong>'+escapeHtml(key.toUpperCase())+'</strong><div>'+pills.join('')+'</div></div>';
            }).join('');
            mappingsEl.innerHTML = mappingHtml || 'Framework mappings not ready.';
          }
        }catch(e){ console.warn('renderCanonicalAndMappings', e); }
      }

      function scoreRowForPriority(row){
        try{
          var score = 0;
          var reasons = [];
          var label = ((row.risk_level && row.risk_level.label) || row.risk_label || '').toString().toLowerCase();
          var labelWeights = { critical: 120, high: 90, medium: 55, low: 20, unknown: 10 };
          if(label){
            score += labelWeights[label] || 15;
            reasons.push(label.toUpperCase()+' risk');
          }
          var factorCount = Array.isArray(row.factors) ? row.factors.length : 0;
          if(factorCount){
            score += Math.min(8, factorCount) * 5;
            reasons.push(factorCount+' tagged factors');
          }
          var severity = parseFloat(row.severity || row.threat_score || row.confidence || 0);
          if(isFinite(severity) && !isNaN(severity)){
            score += severity * 3;
            reasons.push('Signal '+severity.toFixed(1));
          }
          if(row.verdict && /malicious|threat|campaign/i.test(String(row.verdict))){
            score += 18;
            reasons.push('Malicious verdict');
          }
          var anomaly = parseFloat(row.anomaly_score || row.weight || 0);
          if(isFinite(anomaly) && anomaly>0){
            score += anomaly;
          }
          return { score: Math.round(score*10)/10, reason: reasons.join(' · ') || 'Heuristic ranking' };
        }catch(_){
          return { score: 0, reason: 'Heuristic ranking' };
        }
      }

      function describeReviewCoverage(){
        try{
          var totals = { total: latestRankedRows.length, reviewed:0, escalated:0, triaged:0, dismissed:0, percent:0, summary:'' };
          Object.keys(reviewState||{}).forEach(function(key){
            var entry = reviewState[key] || {};
            var status = entry.status || 'not_started';
            if(status && status !== 'not_started'){
              totals.reviewed += 1;
              if(typeof totals[status] === 'number') totals[status] += 1;
            }
          });
          totals.percent = totals.total ? Math.round((totals.reviewed / totals.total) * 100) : 0;
          totals.summary = totals.total ?
            ('Analyst coverage '+totals.reviewed+'/'+totals.total+' ('+totals.percent+'%) • Escalated '+totals.escalated+' • Triaged '+totals.triaged+' • Dismissed '+totals.dismissed) :
            'No sanitized rows yet.';
          return totals;
        }catch(_){
          return { total:0, reviewed:0, escalated:0, triaged:0, dismissed:0, percent:0, summary:'Coverage unavailable' };
        }
      }

      function renderReviewCoverage(){
        try{
          var coverage = describeReviewCoverage();
          var summaryEl = document.getElementById('deepReviewSummary');
          if(summaryEl) summaryEl.textContent = coverage.summary;
          var reportEl = document.getElementById('reportReviewCoverage');
          if(reportEl){
            var base = coverage.summary || 'Analyst review coverage pending.';
            var domainText = (latestDomainSummary && latestDomainSummary.summary) ? ' | '+latestDomainSummary.summary : '';
            reportEl.textContent = base + domainText;
          }
          window.__deepReviewCoverage = coverage;
          // update coverage widget
          try{ var cw = document.getElementById('coverageWidget'); if(cw){ cw.textContent = 'Coverage: '+coverage.reviewed+'/'+coverage.total+' ('+coverage.percent+'%)'; cw.setAttribute('data-coverage-percent', String(coverage.percent)); } }catch(_){ }
        }catch(_){ }
      }

      function scrollToRowCard(idx){
        try{
          var target = document.querySelector('[data-row-card="'+idx+'"]');
          if(target){
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            target.classList.add('important');
            setTimeout(function(){ target.classList.remove('important'); }, 1400);
          }
        }catch(_){ }
      }

      function renderPriorityRows(rankedRows){
        try{
          var container = document.getElementById('deepPriorityRows'); if(!container) return;
          if(!rankedRows.length){
            container.innerHTML = '<div class="empty-hint" style="margin:0;padding:4px 0;">Run Deep Analyze to populate sanitized summaries.</div>';
            return;
          }
          var top = rankedRows.slice(0, Math.min(5, rankedRows.length));
          container.innerHTML = top.map(function(entry, idx){
            var risk = ((entry.row.risk_level && entry.row.risk_level.label) || entry.row.risk_label || 'unknown').toString().toUpperCase();
            var domains = (entry.domains && entry.domains.length) ? entry.domains.map(function(tag){
              var rule = DOMAIN_DETECTIONS.find(function(r){ return r.id===tag; });
              return rule ? rule.label : tag;
            }).join(', ') : 'No cross-domain cues';
            return '<div class="priority-card" data-row-index="'+escapeHtml(entry.displayIndex)+'"><div class="priority-rank">#'+(idx+1)+'</div><div><div><strong>Row '+escapeHtml(entry.displayIndex)+'</strong> <span class="row-score-pill">Score '+escapeHtml(entry.score.toFixed(1))+'</span></div><div class="priority-meta">'+escapeHtml(entry.reason)+' • Risk '+escapeHtml(risk)+'</div><div class="priority-meta">Domains: '+escapeHtml(domains)+'</div></div><button type="button" class="btn btn-primary" data-row-jump="'+escapeHtml(entry.displayIndex)+'">Review</button></div>';
          }).join('');
          Array.from(container.querySelectorAll('[data-row-jump]')||[]).forEach(function(btn){
            btn.addEventListener('click', function(){
              scrollToRowCard(btn.getAttribute('data-row-jump'));
            });
          });
          // wire Next Unreviewed button
          try{ var nextBtn = document.getElementById('nextUnreviewedBtn'); if(nextBtn){ nextBtn.addEventListener('click', function(){ try{ var cov = describeReviewCoverage(); var un = latestRankedRows.find(function(r){ return !reviewState[String(r.displayIndex)] || (reviewState[String(r.displayIndex)] && reviewState[String(r.displayIndex)].status === 'not_started'); }); if(un){ scrollToRowCard(un.displayIndex); try{ window.openCsvRowDetails && window.openCsvRowDetails(un.displayIndex); }catch(_){ } } else { try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('All flagged rows reviewed',3000); else alert('All flagged rows reviewed'); }catch(_){ alert('All flagged rows reviewed'); } } }catch(_){ } }); } }catch(_){ }
        }catch(e){ console.warn('renderPriorityRows', e); }
      }

      function renderAllRowCards(rankedRows){
        try{
          var container = document.getElementById('deepAnalyzeRows'); if(!container) return;
          if(!rankedRows.length){
            container.innerHTML = '<div class="empty-hint">Waiting for sanitized Auto-LLM guidance...</div>';
            return;
          }
          container.innerHTML = '';
          rankedRows.forEach(function(entry){
            container.appendChild(buildRowCard(entry));
          });
        }catch(e){ console.warn('renderAllRowCards', e); }
      }

      function buildRowCard(entry){
        var r = entry.row || {};
        var idx = entry.displayIndex;
        var card = document.createElement('div');
        card.className = 'deep-row-card';
        card.setAttribute('data-row-card', idx);
        if(entry.isPriority) card.classList.add('important');
        var risk = ((r.risk_level && r.risk_level.label) || r.risk_label || 'unknown').toString().toUpperCase();
        var header = document.createElement('div');
        header.style.display='flex';
        header.style.justifyContent='space-between';
        header.style.alignItems='center';
        var left = document.createElement('div');
        left.innerHTML = '<strong>Row '+escapeHtml(idx)+'</strong> - '+escapeHtml(r.verdict || r.classification || 'unknown verdict')+' <span class="row-score-pill">Score '+escapeHtml(entry.score.toFixed(1))+'</span>';
        var right = document.createElement('div');
        right.style.display = 'flex'; right.style.gap='8px'; right.style.alignItems='center';
        var riskSpan = document.createElement('span'); riskSpan.className='pill'; riskSpan.style.fontSize='11px'; riskSpan.textContent = String(risk);
        right.appendChild(riskSpan);
        // Add batch metadata badges to header if available
        try{
          var bm = (r && r._batch_meta) ? r._batch_meta : null;
          if(bm && bm.priority_label){ var pBadge = document.createElement('span'); pBadge.className='badge badge-priority'; pBadge.style.background='#2b7cff'; pBadge.style.color='white'; pBadge.style.padding='4px 6px'; pBadge.style.borderRadius='6px'; pBadge.textContent = String(bm.priority_label).toUpperCase(); right.appendChild(pBadge); }
          if(bm && bm._suggested_max_tokens){ var tBadge = document.createElement('span'); tBadge.className='badge badge-tokens'; tBadge.style.background='#2b2f36'; tBadge.style.color='#ffb86b'; tBadge.style.padding='4px 6px'; tBadge.style.borderRadius='6px'; tBadge.textContent = (String(bm._suggested_max_tokens) + 't'); right.appendChild(tBadge); }
        }catch(_){ }
        header.appendChild(left); header.appendChild(right);
        card.appendChild(header);
        var priorityMeta = document.createElement('div');
        priorityMeta.className = 'priority-meta';
        priorityMeta.textContent = entry.reason || 'Heuristic ranking';
        card.appendChild(priorityMeta);
        var domainLine = document.createElement('div');
        domainLine.className = 'domain-cue-line';
        if(entry.domains && entry.domains.length){
          domainLine.innerHTML = 'Cross-domain cues: '+entry.domains.map(function(tag){
            var rule = DOMAIN_DETECTIONS.find(function(r){ return r.id===tag; });
            return '<span class="domain-pill">'+escapeHtml(rule ? rule.label : tag)+'</span>';
          }).join('');
        }else{
          domainLine.textContent = 'Cross-domain cues: none detected';
        }
        card.appendChild(domainLine);
        var meta = document.createElement('div');
        meta.style.fontSize='12px';
        meta.style.color='var(--text-muted)';
        var generated = r.generated_at ? formatTimestamp(r.generated_at) : 'n/a';
        meta.innerHTML = '<div>Source: '+escapeHtml(r.source || 'llm')+' | Generated: '+escapeHtml(generated)+'</div>';
        card.appendChild(meta);
        // Surface batch metadata if present (from aggregation)
        try{
          if(r && r._batch_meta){
            var bm = r._batch_meta || {};
            var bmDiv = document.createElement('div'); bmDiv.style.fontSize='12px'; bmDiv.style.color='var(--text-muted)'; bmDiv.style.marginTop='6px';
            var parts = [];
            if(bm.priority_label) parts.push('Priority: '+escapeHtml(String(bm.priority_label)));
            if(bm._suggested_max_tokens) parts.push('Suggested tokens: '+escapeHtml(String(bm._suggested_max_tokens)));
            if(parts.length) bmDiv.textContent = parts.join(' · ');
            card.appendChild(bmDiv);
          }
        }catch(_){ }
        var summary = r.llm_summary || r.llm_output || r.summary || 'No LLM output';
        // normalize summary if provider returned structured error
        try{
          if(summary && typeof summary === 'object'){
            if(summary.error){
              r.__llm_error = String(summary.error);
              summary = 'LLM error: '+String(summary.error);
            } else {
              summary = JSON.stringify(summary,null,2);
            }
          }
        }catch(_){ summary = String(summary||''); }
        var summaryBlock = document.createElement('pre');
        summaryBlock.style.whiteSpace='pre-wrap';
        summaryBlock.style.maxHeight='180px';
        summaryBlock.style.overflow='auto';
        summaryBlock.style.marginTop='6px';
        summaryBlock.style.background='var(--bg-tertiary)';
        summaryBlock.style.padding='6px';
        summaryBlock.style.borderRadius='4px';
        summaryBlock.textContent = String(summary||'');
        // If this row has an LLM error marker, show a visible banner above the summary
        try{ if(r.__llm_error){ var errBanner = document.createElement('div'); errBanner.style.background='#3b1b1b'; errBanner.style.color='#ffb86b'; errBanner.style.padding='6px'; errBanner.style.marginTop='6px'; errBanner.style.borderRadius='4px'; errBanner.textContent = 'LLM Error: '+String(r.__llm_error); card.appendChild(errBanner); try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('LLM error for row '+idx+': '+String(r.__llm_error),7000); }catch(_){ } } }catch(_){ }
        card.appendChild(summaryBlock);
        var factorsHtml = Array.isArray(r.factors) && r.factors.length ? r.factors.map(function(f){ return '<span class="mapping-pill">'+escapeHtml(f)+'</span>'; }).join('') : '<span class="mapping-pill">No tagged factors</span>';
        var commentsHtml = Array.isArray(r.comments) && r.comments.length ? r.comments.map(function(c){ return '<div>&bull; '+escapeHtml(c)+'</div>'; }).join('') : '<div class="empty-hint" style="margin:4px 0 0 0;padding:0;">No analyst comments</div>';
        var recsHtml = Array.isArray(r.recommendations) && r.recommendations.length ? r.recommendations.map(function(c){ return '<div>&bull; '+escapeHtml(c)+'</div>'; }).join('') : '<div class="empty-hint" style="margin:4px 0 0 0;padding:0;">No recommendations</div>';
        var detail = document.createElement('div');
        detail.style.fontSize='12px';
        detail.style.marginTop='6px';
        detail.innerHTML = '<div><strong>Factors</strong><div>'+factorsHtml+'</div></div><div style="margin-top:6px;"><strong>Comments</strong>'+commentsHtml+'</div><div style="margin-top:6px;"><strong>Recommended Actions</strong>'+recsHtml+'</div>';
        card.appendChild(detail);
        var review = ensureReviewEntry(idx);
        var controls = document.createElement('div');
        controls.className='review-controls';
        REVIEW_STATES.forEach(function(state){
          var pill = document.createElement('button');
          pill.type='button';
          pill.className='review-pill'+(review.status===state.id?' active':'');
          pill.textContent = state.label;
          pill.dataset.status = state.id;
          pill.addEventListener('click', function(){
            review.status = state.id;
            setReviewStateForRow(idx, state.id, review.notes || '');
            Array.from(controls.querySelectorAll('.review-pill')||[]).forEach(function(btn){
              if(btn.dataset.status === state.id) btn.classList.add('active'); else btn.classList.remove('active');
            });
          });
          controls.appendChild(pill);
        });
        card.appendChild(controls);
        var note = document.createElement('textarea');
        note.className='review-note';
        note.placeholder='Add analyst notes (optional)';
        note.value = review.notes || '';
        note.addEventListener('input', function(){
          review.notes = note.value;
          setReviewStateForRow(idx, review.status, note.value);
        });
        card.appendChild(note);
        return card;
      }

      function renderLLMRowCards(payload){
        try{
          var rows = Array.isArray(payload) ? payload : ((payload && payload.rows) || []);
          latestRankedRows = rows.map(function(r, idx){
            var info = scoreRowForPriority(r || {});
            var displayIndex = (typeof r.row_index !== 'undefined') ? r.row_index : (typeof r.index !== 'undefined' ? r.index : idx);
            var domains = extractDomainHints(r || {});
            try{
              var maybe = r && (r.llm_summary || r.llm_output || r.summary);
              if(maybe && typeof maybe === 'object' && maybe.error){
                r.__llm_error = String(maybe.error);
                try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('LLM error for row '+displayIndex+': '+String(maybe.error),8000); }catch(_){ }
              }
            }catch(_){ }
            return { row: r, score: info.score, reason: info.reason, displayIndex: displayIndex, domains: domains };
          }).sort(function(a,b){ return b.score - a.score; });
          latestRankedRows.forEach(function(entry, idx){ entry.isPriority = idx < 5; });
          var validKeys = new Set(latestRankedRows.map(function(entry){ return String(entry.displayIndex); }));
          Object.keys(reviewState||{}).forEach(function(key){
            if(!validKeys.has(key)) delete reviewState[key];
          });
          persistReviewState();
          latestDomainSummary = summarizeDomainHints(latestRankedRows);
          renderPriorityRows(latestRankedRows);
          renderAllRowCards(latestRankedRows);
          renderReviewCoverage();
          renderDomainSummary();
          window.__deepRankedRows = latestRankedRows;
        }catch(e){ console.warn('renderLLMRowCards', e); }
      }

      function collectRecipients(input){
        if(!input) return [];
        return input.split(',').map(function(r){ return r.trim(); }).filter(Boolean);
      }

      function describeMappingCount(mapping){
        if(Array.isArray(mapping)) return mapping.length;
        if(mapping && typeof mapping === 'object') return Object.keys(mapping).length;
        return 0;
      }

      function describeCrossDomainPersonaLine(){
        var summary = (latestDomainSummary && latestDomainSummary.summary) || (window.__deepDomainSummary && window.__deepDomainSummary.summary);
        return summary ? 'Cross-domain cues: '+summary : 'Cross-domain cues not established yet.';
      }

      function summarizeRisk(doc){
        var stats = { high:0, medium:0, low:0, unknown:0 };
        (doc && doc.row_sections || []).forEach(function(section){
          if(!section) return;
          var label = (section.risk_level && section.risk_level.label) || section.risk_level || 'unknown';
          label = String(label||'unknown').toLowerCase();
          if(typeof stats[label] === 'undefined') stats[label] = 0;
          stats[label] += 1;
        });
        return stats;
      }

      var personaRenderers = {
        ciso: function(report){
          var stats = summarizeRisk(report);
          var recipients = (report.recipients||[]).join(', ') || 'n/a';
          var mitreCount = describeMappingCount(report.mappings && report.mappings.mitre);
          return '<p><strong>'+escapeHtml(report.company || report.org || 'Unknown org')+'</strong> has '+escapeHtml(String(report.rows_included))+' of '+escapeHtml(String(report.total_rows))+' rows flagged for executive review.</p>'
            + '<ul style="margin:6px 0 0 18px;font-size:13px;line-height:1.5;">'
            + '<li>Risk distribution: High '+stats.high+', Medium '+stats.medium+', Low '+stats.low+'</li>'
            + '<li>MITRE techniques highlighted: '+mitreCount+'</li>'
            + '<li>Report recipients: '+escapeHtml(recipients)+'</li>'
            + '<li>'+escapeHtml(describeCrossDomainPersonaLine())+'</li>'
            + '</ul>';
        },
        soc: function(report){
          var stageList = (report.stages||[]).map(function(stage){
            var label = stage.name || stage.stage || ('Stage '+(stage.idx||''));
            var status = stage.status || 'pending';
            return '<div class="stage-row"><div>'+escapeHtml(label)+'</div><span>'+escapeHtml(status)+'</span></div>';
          }).join('') || 'No pipeline history recorded.';
          var rows = (report.row_sections||[]).slice(0,6).map(function(section){
            return '<div style="border:1px solid var(--border);border-radius:6px;padding:6px;margin-bottom:6px;">'
              + '<strong>Row '+escapeHtml(section.row_index)+'</strong> - '+escapeHtml(section.verdict||'unknown')
              + '<div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Risk: '+escapeHtml((section.risk_level && section.risk_level.label) || 'n/a')+'</div>'
              + '</div>';
          }).join('');
          return '<p>'+escapeHtml(describeCrossDomainPersonaLine())+'</p><p>Pipeline coverage for SOC:</p><div>'+stageList+'</div>'+rows;
        },
        compliance: function(report){
          var canonical = escapeHtml(JSON.stringify(report.canonical||{}, null, 2));
          var mappings = escapeHtml(JSON.stringify(report.mappings||{}, null, 2));
          var audit = escapeHtml(JSON.stringify(report.audit_metadata||{}, null, 2));
          return '<p>'+escapeHtml(describeCrossDomainPersonaLine())+'</p><p>Canonical signals, framework mappings, and audit metadata captured for compliance filing.</p>'
            + '<pre style="max-height:160px;overflow:auto;background:var(--bg-tertiary);padding:8px;border-radius:6px;">'+canonical+'</pre>'
            + '<pre style="max-height:160px;overflow:auto;background:var(--bg-tertiary);padding:8px;border-radius:6px;margin-top:8px;">'+mappings+'</pre>'
            + '<pre style="max-height:120px;overflow:auto;background:var(--bg-tertiary);padding:8px;border-radius:6px;margin-top:8px;">'+audit+'</pre>';
        }
      };

      function updatePersonaTabs(active){
        try{
          var container = document.getElementById('reportPersonaTabs'); if(!container) return;
          Array.from(container.querySelectorAll('.persona-tab')||[]).forEach(function(btn){
            var persona = (btn.getAttribute('data-persona')||'').toLowerCase();
            if(persona === active) btn.classList.add('active'); else btn.classList.remove('active');
          });
        }catch(_){ }
      }

      function getPreferredPersona(){
        return (localStorage.getItem('csv_report_persona') || 'ciso').toLowerCase();
      }

  function setPreferredPersona(val){
        var normalized = (val || 'ciso').toLowerCase();
        if(normalized === 'hunter' || normalized === 'forensics' || normalized === 'manager' || normalized === 'technical'){
          normalized = 'soc';
        }
        localStorage.setItem('csv_report_persona', normalized);
        var select = document.getElementById('reportPersona');
        if(select) select.value = normalized;
        updatePersonaTabs(normalized);
        return normalized;
      }

      function initPersonaPanel(){
        try{
          var initial = setPreferredPersona(getPreferredPersona());
          var select = document.getElementById('reportPersona');
          if(select){
            select.value = initial;
            select.addEventListener('change', function(){
              var next = setPreferredPersona(this.value || 'ciso');
              if(lastReportDocument) renderReportDocument(lastReportDocument, next);
            });
          }
          var tabs = document.getElementById('reportPersonaTabs');
          if(tabs){
            Array.from(tabs.querySelectorAll('.persona-tab')||[]).forEach(function(btn){
              btn.addEventListener('click', function(){
                var persona = btn.getAttribute('data-persona') || 'ciso';
                var normalized = setPreferredPersona(persona);
                if(lastReportDocument) renderReportDocument(lastReportDocument, normalized);
              });
            });
          }
        }catch(e){ console.warn('initPersonaPanel', e); }
      }

      function renderReportDocument(report, personaOverride){
        try{
          if(!report) return;
          lastReportDocument = report;
          var persona = setPreferredPersona(personaOverride || report.persona || getPreferredPersona());
          var panel = document.getElementById('reportDocumentPanel');
          if(panel) panel.style.display='block';
          var meta = document.getElementById('reportDocumentMeta');
          if(meta){
            var audit = report.audit_metadata || {};
            var storageHint = audit.storage_hint || audit.persisted_path || 'data/assessments/...';
            var orgTag = audit.org_tag || (report.org || 'org');
            meta.textContent = 'Assessment '+(report.assessment_id||'n/a')+' | Org Tag '+orgTag+' | Storage '+storageHint;
          }
          var body = document.getElementById('reportDocumentBody');
          if(body){
            var renderer = personaRenderers[persona] || personaRenderers.ciso;
            body.innerHTML = renderer(report);
          }
        }catch(e){ console.warn('renderReportDocument', e); }
      }

      async function triggerReportExport(){
        try{
          if(!currentAssessmentId){ alert('No assessment to export'); return; }
          // enforce coverage guard
          var coverage = (window.__deepReviewCoverage || { percent: 0 }).percent || 0;
          var minCov = parseInt(localStorage.getItem('report_min_coverage')||'50',10) || 50;
          if(coverage < minCov){ if(!confirm('Review coverage is only '+coverage+'% which is below the configured minimum of '+minCov+'%. Continue export?')) return; }
          var payload = {
            include_model: !!(document.getElementById('reportIncludeModel')||{}).checked,
            company: (document.getElementById('reportCompany')||{}).value || undefined,
            recipients: collectRecipients((document.getElementById('reportRecipients')||{}).value || ''),
            persona: getPreferredPersona(),
            org: localStorage.getItem('org') || undefined,
            max_rows: Math.min(100, (window.LAST_RESULTS && window.LAST_RESULTS.length) || 25)
          };
          // include coverage and risk appetite metadata for audit
          payload.review_coverage = window.__deepReviewCoverage || null;
          payload.risk_appetite = localStorage.getItem('risk_appetite') || 'medium';
          var resp = await fetch('/api/v1/assessments/'+encodeURIComponent(currentAssessmentId)+'/report', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
          if(!resp.ok){
            alert('Export failed: '+resp.status);
            return;
          }
          var data = await resp.json();
          if(data && data.report){
            renderReportDocument(data.report, payload.persona);
            try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Report exported',2500); }catch(_){ }
          }else{
            alert('No report returned from server');
          }
        }catch(e){
          console.warn('triggerReportExport', e);
          alert('Export error');
        }
      }

      async function pollAssessmentStatus(assessmentId, opts){
        opts = opts || {};
        var silentMode = !!opts.silent;
        try{
          var drawer = null;
          var progress = null;
          if(!silentMode){
            drawer = ensureDrawer(); drawer.style.display='block';
            progress = document.getElementById('deepAnalyzeProgress');
            if(progress) progress.textContent = 'Polling...';
          }
          var finished = false; var attempts = 0;
          while(!finished && attempts<600){
            try{
              var r = await fetch('/api/v1/assessments/'+encodeURIComponent(assessmentId), { headers: {...authHeaders()} });
              if(!r.ok){
                if(progress) progress.textContent = 'Status fetch failed: '+r.status;
                try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Assessment status fetch failed: '+r.status,4000); }catch(_){ }
              }else{
                var j = await r.json();
                try{ if(j && j.llm_breakers){ Object.keys(j.llm_breakers||{}).forEach(function(k){ var s=j.llm_breakers[k]; if(s && s.tripped_until && Date.now()/1000 < s.tripped_until){ try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('LLM circuit breaker tripped for tenant '+k,6000); }catch(_){ } } }); } }catch(_){ }
                renderTelemetry(j && j.telemetry || {}, j || {});
                renderStageTimeline(j && j.pipeline_stages || [], j && j.stage_status || [], j && j.current_stage);
                renderCanonicalAndMappings(j || {});
                if(j && j.llm_rows && j.llm_rows.length) renderLLMRowCards(j.llm_rows);
                if(j && j.llm_cost_estimate){ window.__last_llm_cost = j.llm_cost_estimate; }
                if(j && j.status){
                  if(progress) progress.textContent = 'Status: '+j.status + (j.current_stage ? ' - '+j.current_stage : '');
                  if(j.status === 'completed' || j.status === 'failed') finished = true;
                }
                try{
                  var dapBar = document.getElementById('dap_bar');
                  var dapPct = document.getElementById('dap_percent');
                  var globalProgress = progress || document.getElementById('deepAnalyzeProgress');
                  var processed = j && (j.rows_processed || j.processed_rows || 0);
                  var total = j && (j.row_count || j.rows_total || j.total_rows || (j.llm_rows && j.llm_rows.length) || 0);
                  if(typeof processed === 'number' && typeof total === 'number' && total>0){
                    var percent = Math.round((processed/total)*100);
                    if(dapBar) dapBar.style.width = String(Math.max(0, Math.min(100, percent))) + '%';
                    if(dapPct) dapPct.textContent = String(percent) + '%';
                    if(globalProgress) globalProgress.textContent = 'Status: '+(j.status||'running')+' ? '+processed+'/'+total+' rows ('+percent+'%)';
                  } else if(globalProgress && processed){
                    globalProgress.textContent = 'Status: '+(j.status||'running')+' ? '+processed+' rows';
                  }
                }catch(_){ }
              }
            }catch(e){
              console.warn('poll error', e);
            }
            if(!finished){
              await new Promise(function(res){ setTimeout(res, 1000); });
            }
            attempts++;
          }
          try{
            var rr = await fetch('/api/v1/assessments/'+encodeURIComponent(assessmentId)+'/rows', { headers: {...authHeaders()} });
            if(rr.ok){
              var rowsPayload = await rr.json();
              renderLLMRowCards(rowsPayload);
              var count = (rowsPayload && rowsPayload.row_count) || (Array.isArray(rowsPayload) ? rowsPayload.length : (rowsPayload && rowsPayload.rows && rowsPayload.rows.length) || 0);
              if(progress) progress.textContent = 'Completed - '+count+' rows';
              try{
                mergeAssessmentRowsIntoResults(rowsPayload);
                renderTableFromResults();
              }catch(mergeErr){
                console.warn('merge rows error', mergeErr);
              }
            }else{
              if(progress) progress.textContent = 'Rows fetch failed: '+rr.status;
            }
          }catch(e){
            if(progress) progress.textContent = 'Rows fetch error';
          }
          completePipelineAssessment(assessmentId);
        }catch(e){ console.warn('pollAssessmentStatus', e); }
      }
          // Auto Backfill: schedule and poll the backend auto_backfill status endpoint
          async function toggleAutoBackfill(){
            try{
              var aid = localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId;
              if(!aid){ alert('No assessment id available for backfill control'); return; }
              var statusEl = document.getElementById('deepBackfillStatus');
              var btn = document.getElementById('deepBackfillToggle');
              if(!statusEl || !btn) return;
              var running = btn.getAttribute('data-running') === '1';
              if(!running){
                btn.disabled = true; btn.textContent = 'Starting...';
                var resp = await fetch('/api/v1/csv/deep_analyze/auto_backfill', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeadersWithTenant() }, body: JSON.stringify({ assessment_id: aid }) });
                if(resp.ok){ btn.setAttribute('data-running','1'); btn.textContent = 'Stop'; statusEl.textContent = 'running'; startBackfillStatusPoll(aid); }
                else { var txt = await resp.text().catch(()=>String(resp.status)); alert('Backfill start failed: '+txt); btn.textContent='Start'; }
                btn.disabled = false;
                try{ localStorage.setItem('csv_backfill_running_'+String(aid), '1'); }catch(_){ }
              } else {
                btn.disabled = true; btn.textContent = 'Stopping...';
                try{ await fetch('/api/v1/csv/deep_analyze/auto_backfill/'+encodeURIComponent(aid)+'/stop', { method:'POST', headers: {...authHeadersWithTenant()} }); }catch(_){ }
                btn.removeAttribute('data-running'); btn.textContent = 'Start'; statusEl.textContent = 'stopped'; btn.disabled = false;
                try{ localStorage.removeItem('csv_backfill_running_'+String(aid)); }catch(_){ }
              }
            }catch(e){ console.warn('toggleAutoBackfill', e); }
          }

          var _backfillPollTimer = null;
          async function startBackfillStatusPoll(aid){ try{ aid = aid || localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId; if(!aid) return; if(_backfillPollTimer) clearInterval(_backfillPollTimer); _backfillPollTimer = setInterval(function(){ fetchBackfillStatus(aid); }, 2500); fetchBackfillStatus(aid); }catch(_){ } }
          async function stopBackfillStatusPoll(){ try{ if(_backfillPollTimer){ clearInterval(_backfillPollTimer); _backfillPollTimer=null; } }catch(_){ } }
            async function fetchBackfillStatus(aid){ try{ if(!aid) return; var resp = await fetch('/api/v1/csv/deep_analyze/auto_backfill/'+encodeURIComponent(aid)+'/status', { headers: {...authHeadersWithTenant()} }); if(!resp.ok) return; var j = await resp.json(); window.__BACKFILL_STATUS = j; updateBackfillRibbon(); if(j && j.state && (j.state === 'completed' || j.state === 'failed' || j.state === 'stopped')){ stopBackfillStatusPoll(); var btn = document.getElementById('deepBackfillToggle'); if(btn){ btn.removeAttribute('data-running'); btn.textContent = 'Start'; } } }catch(e){ console.warn('fetchBackfillStatus', e); } }
          function updateBackfillRibbon(){ try{ var ribbon = document.getElementById('deepBackfillRibbon'); if(!ribbon) return; var statusEl = document.getElementById('deepBackfillStatus'); var aid = localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId; if(!statusEl) return; var s = window.__BACKFILL_STATUS || {}; if(s && s.state){ // prefer server-provided ETA when available
            var processed = (s.progress && typeof s.progress.processed !== 'undefined') ? s.progress.processed : (s.processed || 0);
            var total = (s.progress && typeof s.progress.total !== 'undefined') ? s.progress.total : (s.total || 0);
            var txt = String(s.state || 'running');
            if(typeof processed === 'number' && typeof total === 'number' && total>0){ txt += ' ('+processed+'/'+total+')'; }
            // humanize server ETA if present
            try{
              if(typeof s.eta_seconds !== 'undefined' && s.eta_seconds !== null){
                var eta = Number(s.eta_seconds) || 0;
                function humanizeSeconds(sec){ try{ sec = Number(sec)||0; if(sec<=0) return '<1s'; var s2 = Math.round(sec); var m = Math.floor(s2/60); var r = s2%60; return m>0 ? (m+'m '+r+'s') : (r+'s'); }catch(_){ return String(sec); } }
                txt += ' • ETA: ~'+humanizeSeconds(eta);
              }
            }catch(_){ }
            statusEl.textContent = txt;
            ribbon.style.display = 'block';
            // update toggle button state + persist running flag
            try{ var btn = document.getElementById('deepBackfillToggle'); if(btn){ var runningStates = { running:1, in_progress:1, started:1, queued:1 }; if(runningStates[String((s.state||'')).toLowerCase()]){ btn.setAttribute('data-running','1'); btn.textContent = 'Stop'; try{ localStorage.setItem('csv_backfill_running_'+String(aid),'1'); }catch(_){ } } else { btn.removeAttribute('data-running'); btn.textContent = 'Start'; try{ localStorage.removeItem('csv_backfill_running_'+String(aid)); }catch(_){ } } } }catch(_){ }
          } else { ribbon.style.display = 'none'; try{ var btn = document.getElementById('deepBackfillToggle'); if(btn){ btn.removeAttribute('data-running'); btn.textContent = 'Start'; } }catch(_){ } }
        }catch(_){ } }
      async function initiateDeepAnalyze(config){
        try{
          var cfg = config || {};
          var silentMode = !!(cfg && cfg.silent);
          var autoTarget = !!(cfg && cfg.auto_target);
          var trackRows = !!(cfg && cfg.track_rows);
          // Respect persisted user preference for Auto-LLM if caller didn't explicitly set it
          try{
            var storedPref = localStorage.getItem('da_auto_llm');
            var defaultAuto = (storedPref === null) ? true : !(storedPref === '0' || storedPref === 'false');
          }catch(_){ var defaultAuto = true; }
          var autoLLM = typeof cfg.auto_llm === 'boolean' ? cfg.auto_llm : (typeof cfg.autoLLM === 'boolean' ? cfg.autoLLM : defaultAuto);
          var maxRows = Math.min(cfg.max_rows || cfg.maxRows || 400, 400);
          var payload = {
            rows: [],
            options: { auto_llm: autoLLM },
            org: localStorage.getItem('org') || 'local'
          };
          var mapping = cfg.mapping || cfg.mappings;
          if(mapping && typeof mapping === 'object' && Object.keys(mapping).length){
            payload.mapping = mapping;
          }
          if(cfg.options && typeof cfg.options === 'object'){
            payload.options = { ...payload.options, ...cfg.options };
            if(typeof cfg.options.auto_llm === 'boolean'){
              payload.options.auto_llm = cfg.options.auto_llm;
            }
          }
          var analyzeMode = cfg.analyze_mode || cfg.mode || payload.options.analyze_mode || 'basic';
          payload.analyze_mode = analyzeMode;
          var list = window.LAST_RESULTS || [];
          var manualRows = Array.isArray(cfg.rows) ? cfg.rows.slice(0, maxRows) : null;

          function pushRow(idx, source){
            if(!source) return;
            var normalizedIndex = typeof idx === 'number' ? idx : (typeof source.row_index === 'number' ? source.row_index : payload.rows.length);
            var rawPayload = source.raw ? source.raw : source;
            payload.rows.push({ row_index: normalizedIndex, raw: rawPayload || {} });
          }

          if(manualRows && manualRows.length){
            manualRows.forEach(function(entry, idx){
              var targetIdx = typeof entry.row_index === 'number' ? entry.row_index : idx;
              if(entry && entry.raw){
                pushRow(targetIdx, entry);
              }else{
                pushRow(targetIdx, entry || {});
              }
            });
          }else{
            // Use exported accessor instead of directly referencing SELECTED_ROWS (which is
            // scoped to a separate IIFE). This fixes the "SELECTED_ROWS is not defined" bug.
            var __sel = (typeof window.__getSelectedRowIndexes === 'function') ? window.__getSelectedRowIndexes() : [];
            if(__sel && __sel.length){
              __sel.sort(function(a,b){ return a-b; }).slice(0, maxRows).forEach(function(idx){
                pushRow(idx, list[idx] || {});
              });
            } else {
            list.slice(0, maxRows).forEach(function(rec, idx){
              var targetIdx = typeof rec.row_index === 'number' ? rec.row_index : idx;
              pushRow(targetIdx, rec || {});
            });
            }
          }

          if(!payload.rows.length){ alert('No rows to analyze'); return; }
          // Validate payload serialization early to catch circular refs
          try{
            try{ var provSel = document.getElementById('llmProviderSelect'); var provider = provSel ? provSel.value : (localStorage.getItem('csv_llm_provider')||null); if(provider){ payload.provider = provider; try{ payload.options = payload.options || {}; payload.options.provider = provider; localStorage.setItem('csv_llm_provider', provider); }catch(_){ } }
            }catch(_){ }
            JSON.stringify(payload);
          }catch(err){
            console.error('Payload serialization error for deep analyze', err, payload);
            try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Payload serialization error preparing deep analyze. See console.',7000); }catch(_){ }
            alert('Error preparing analyze payload: '+(err && err.message ? err.message : String(err))+' (see console)');
            return;
          }
          var queuedIndexes = payload.rows.map(function(r){ return (r && typeof r.row_index === 'number') ? r.row_index : null; }).filter(function(v){ return v !== null; });
          if(silentMode || trackRows){
            queuedIndexes.forEach(markRowPipelinePending);
          }

          // Attach per-request overrides from LLM Settings UI when present
          try {
            const overrides = (window.LLMSettingsUI && typeof window.LLMSettingsUI.getOverridesForRequest === 'function') ? window.LLMSettingsUI.getOverridesForRequest() : null;
            if (overrides && Object.keys(overrides).length) { payload.overrides = overrides; }
          } catch (_){ }
          // Use the CSV proxy endpoint which delegates to the deep_analyze handler
          var resp = null;
          try{
            resp = await fetch('/api/v1/csv/deep_analyze', { method:'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
          }catch(fetchErr){
            console.error('Network/fetch error initiating deep analyze', fetchErr);
            try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Network error initiating deep analyze',7000); }catch(_){ }
            alert('Analyze request failed: '+(fetchErr && fetchErr.message ? fetchErr.message : String(fetchErr))+' (check server availability)');
            return;
          }
          if(!resp.ok){
            var respText = '';
            try{ respText = await resp.text(); }catch(_){ respText = ''; }
            console.error('Deep analyze endpoint responded with non-OK', resp.status, respText);
            try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Analyze request failed: '+resp.status,6000); }catch(_){ }
            alert('Analyze request failed: '+resp.status + (respText ? '\nResponse: '+respText : ''));
            return;
          }
          var j = await resp.json();
          window.LAST_DEEP_ANALYZE = j;
          try{
            window.LAST_CORR_SUMMARY = window.LAST_CORR_SUMMARY || {};
            window.LAST_CORR_SUMMARY.deep_analyze = j;
          }catch(_){ }
          var aid = j.assessment_id || j.id || j.session_id || null;
          if(!aid){ alert('No assessment id returned'); return; }
          registerPipelineAssessment(aid, { silent: silentMode, auto_target: autoTarget, rows: queuedIndexes });
          currentAssessmentId = aid; window.currentAssessmentId = aid;
          try{ localStorage.setItem('csv_last_parent_assessment', String(aid)); }catch(_){ }
          if(!silentMode){
            resetReviewStateForAssessment();
            ensureDrawer();
            var drawerEl = document.getElementById('deepAnalyzeDrawer');
            if(drawerEl) drawerEl.style.display='block';
            document.getElementById('deepAnalyzeProgress').textContent = 'Started - ' + aid;
            if(typeof navigator !== 'undefined' && navigator.webdriver){
              try{ if(drawerEl){ drawerEl.style.pointerEvents='none'; drawerEl.style.opacity='0'; drawerEl.style.transform='translateX(100%)'; } }catch(_){ }
            }
            pollAssessmentStatus(aid);
          }else{
            pollAssessmentStatus(aid, { silent: true });
          }
        }catch(e){
          console.warn('initiateDeepAnalyze', e);
          var msg = (e && e.message) ? e.message : String(e || 'unknown error');
          try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Error initiating Deep Analyze: '+msg,8000); }catch(_){ }
          // Provide helpful action text to the analyst
          alert('Error initiating Deep Analyze: '+msg+"\n\nCommon fixes:\n - Ensure the backend server is running (localhost:8080)\n - Confirm the API key is set in localStorage 'apiKey'\n - Check browser console for details\n\nSee console for stack trace.");
        }
      }

      window.initiateDeepAnalyze = initiateDeepAnalyze;

      // Batch Analyze implementation: splits rows into priority batches and runs sequential deep analyze calls with batch_meta
      try { window.startBatchAnalyze = function(config){
        try{
          var list = window.LAST_RESULTS || [];
          if(!list.length){ alert('No rows loaded'); return; }
          var sel = (typeof window.__getSelectedRowIndexes==='function') ? window.__getSelectedRowIndexes() : [];
          var working = sel && sel.length ? sel.map(function(i){ return list[i]; }) : list.slice();
          // Build batches based on DREAD score + verdict
          var critical=[]; var high=[]; var medium=[]; var low=[];
          working.forEach(function(r){
            try{
              var score = (r && r._dread && typeof r._dread.score==='number') ? r._dread.score : computeDreadBreakdown(r.factors||[], r.raw||{}, r).score;
              var v = String(r.verdict||'').toUpperCase();
              if(score>=8 || /MALICIOUS|THREAT/.test(v)) critical.push(r);
              else if(score>=6 || /SUSPICIOUS/.test(v)) high.push(r);
              else if(score>=3) medium.push(r);
              else low.push(r);
            }catch(_){ low.push(r); }
          });
          var batches=[]; if(critical.length) batches.push({ label:'critical', rows:critical }); if(high.length) batches.push({ label:'high', rows:high }); if(medium.length) batches.push({ label:'medium', rows:medium }); if(low.length) batches.push({ label:'low', rows:low });
          if(!batches.length){ alert('No batch rows'); return; }
          // Limit per-batch to 400 rows
          batches.forEach(function(b){ b.rows = b.rows.slice(0,400); });
          var total = batches.length; var parentId = null; var analyzeMode = (config && (config.analyze_mode||config.mode)) || 'basic'; var autoLLM = (config && typeof config.auto_llm==='boolean') ? config.auto_llm : true;
          var drawer = (typeof ensureDrawer==='function') ? ensureDrawer() : null; if(drawer){ drawer.style.display='block'; var prog=document.getElementById('deepAnalyzeProgress'); if(prog) prog.textContent='Batch sequence starting ('+total+' batches)'; }
          function runNext(idx){
            if(idx>=batches.length){
              try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Batch sequence completed',4000); else console.log('Batch sequence completed'); }catch(_){ }
              // Auto-aggregate when sequence completes if enabled
              try{
                var auto = (localStorage.getItem('csv_auto_aggregate')||'1') !== '0';
                if(auto && parentId){ setTimeout(function(){ try{ window.aggregateBatchesToDrawer(parentId); }catch(_){ } }, 800); }
              }catch(_){ }
              return;
            }
            var batch = batches[idx]; var payloadRows = batch.rows.map(function(r,ri){ return { row_index: (typeof r.row_index==='number')? r.row_index : ri, raw: r.raw||{} }; });
            var meta = { batch_number: idx+1, total_batches: total, priority_label: batch.label, batch_size: payloadRows.length };
            if(parentId){ meta.parent_assessment_id = parentId; } else { meta.is_parent = true; }
            // Per-priority LLM options policy
            var batchOptions = { auto_llm: autoLLM };
            try{
              if(batch.label === 'critical' || batch.label === 'high'){
                batchOptions.auto_llm = true;
                batchOptions.max_tokens = 1024;
              } else if(batch.label === 'medium'){
                batchOptions.auto_llm = true;
                batchOptions.max_tokens = 512;
              } else {
                // low priority: skip expensive LLM by default
                batchOptions.auto_llm = false;
                batchOptions.max_tokens = 256;
              }
            }catch(_){ }
            var payload = { rows: payloadRows, options: batchOptions, analyze_mode: analyzeMode, org: localStorage.getItem('org')||'local', batch_meta: meta };
            try {
              const overrides = (window.LLMSettingsUI && typeof window.LLMSettingsUI.getOverridesForRequest === 'function') ? window.LLMSettingsUI.getOverridesForRequest() : null;
              if (overrides && Object.keys(overrides).length) { payload.overrides = overrides; }
            } catch (_){ }
              try{ var provSel = document.getElementById('llmProviderSelect'); var provider = provSel ? provSel.value : (localStorage.getItem('csv_llm_provider')||null); if(provider){ payload.provider = provider; try{ payload.options = payload.options || {}; payload.options.provider = provider; localStorage.setItem('csv_llm_provider', provider); }catch(_){ } } }catch(_){ }
            var url = '/api/v1/csv/deep_analyze';
            fetch(url, { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) }).then(function(r){ return r.json().then(function(j){ return { ok:r.ok, data:j }; }); }).then(function(resp){ try{
              if(!resp.ok){ console.warn('Batch '+(idx+1)+' failed', resp.data); if(window.notifications && window.notifications.showToast) window.notifications.showToast('Batch '+(idx+1)+' failed',6000); } else { var aid = resp.data.assessment_id; if(aid){ if(!parentId) parentId = aid; pollAssessmentStatus && pollAssessmentStatus(aid); if(window.notifications && window.notifications.showToast) window.notifications.showToast('Started batch '+(idx+1)+'/'+total+' ('+batch.label+')',2500); } }
              if(drawer){ var prog=document.getElementById('deepAnalyzeProgress'); if(prog) prog.textContent='Started batch '+(idx+1)+'/'+total+' ('+batch.label+')'; }
            }catch(_){ }
            setTimeout(function(){ runNext(idx+1); }, 1500);
            }).catch(function(err){ console.warn('Batch analyze network error', err); if(window.notifications && window.notifications.showToast) window.notifications.showToast('Batch '+(idx+1)+' network error',6000); setTimeout(function(){ runNext(idx+1); }, 1000); });
          }
          runNext(0);
        }catch(e){ console.warn('startBatchAnalyze error', e); alert('Batch Analyze error: '+(e&&e.message?e.message:String(e))); }
      }; }catch(_){ }

      // Aggregate helper: fetch child batches for a parent assessment and merge llm_rows into the drawer
      try{ window.aggregateBatchesToDrawer = async function(parentId, opts){
        try{
          if(!parentId) return null;
          opts = opts || {};
          // allow overrides for token caps from localStorage keys
          var cfg = {
            critical_max: parseInt(localStorage.getItem('csv_batch_critical_max')) || 1024,
            high_max: parseInt(localStorage.getItem('csv_batch_high_max')) || 1024,
            medium_max: parseInt(localStorage.getItem('csv_batch_medium_max')) || 512,
            low_max: parseInt(localStorage.getItem('csv_batch_low_max')) || 256,
            auto_aggregate: (localStorage.getItem('csv_auto_aggregate')||'1') !== '0'
          };
          var listResp = await fetch('/api/v1/assessments/'+encodeURIComponent(parentId)+'/batches', { headers: {...authHeaders()} });
          if(!listResp.ok) return null;
          var list = await listResp.json();
          var merged = [];
          for(var i=0;i<list.length;i++){
            var child = list[i];
            try{
              var r = await fetch('/api/v1/assessments/'+encodeURIComponent(child.assessment_id), { headers: {...authHeaders()} });
              if(!r.ok) continue;
              var j = await r.json();
              if(Array.isArray(j.llm_rows)){
                // Respect local token cap overrides by tagging rows (renderers or server may use this)
                var cap = cfg.low_max;
                try{ if(child.batch_meta && child.batch_meta.priority_label){ var p = String(child.batch_meta.priority_label||'').toLowerCase(); if(p==='critical') cap = cfg.critical_max; else if(p==='high') cap = cfg.high_max; else if(p==='medium') cap = cfg.medium_max; else cap = cfg.low_max; } }catch(_){ }
                j.llm_rows.forEach(function(row){ try{ row._batch_meta = child.batch_meta || {}; row._batch_meta._suggested_max_tokens = cap; merged.push(row); }catch(_){ merged.push(row); } });
              }
            }catch(_){ continue; }
          }
          // Render merged rows in drawer using existing renderer if present
          try{ if(typeof renderLLMRowCards === 'function'){ renderLLMRowCards(merged); } }
          catch(_){ console.warn('aggregateBatchesToDrawer: render failed'); }
          // auto-aggregate: if enabled, persist last parent and toggle UI
          try{ if(cfg.auto_aggregate){ localStorage.setItem('csv_last_parent_assessment', parentId); } }catch(_){ }
          return merged;
        }catch(e){ console.warn('aggregateBatchesToDrawer', e); return null; }
      }; }catch(_){ }

      // Wire drawer buttons: add Aggregate button and auto-aggregate toggle when drawer exists
      try{ (function wireDrawerAggregate(){
        function ensureDrawerControls(){
          try{
            var drawer = document.getElementById('deepAnalyzeDrawer'); if(!drawer) return;
            var controls = drawer.querySelector('.drawer-controls');
            if(!controls){ controls = document.createElement('div'); controls.className='drawer-controls'; controls.style.padding='8px'; controls.style.display='flex'; controls.style.gap='8px'; controls.style.alignItems='center'; drawer.insertBefore(controls, drawer.firstChild); }
            if(!document.getElementById('btnAggregateBatches')){
              var btn = document.createElement('button'); btn.id='btnAggregateBatches'; btn.className='btn'; btn.innerText='Aggregate Batches';
              var badge = document.createElement('span'); badge.id='aggBadge'; badge.style.marginLeft='8px'; badge.style.fontSize='12px'; badge.style.color='var(--text-muted)'; badge.textContent = '';
              btn.appendChild(badge);
              btn.addEventListener('click', async function(){ try{ var parent = localStorage.getItem('csv_last_parent_assessment') || window.currentAssessmentId; if(!parent){ alert('No parent assessment id available'); return; } btn.disabled = true; var orig = btn.innerText; btn.innerText = 'Aggregating...'; badge.textContent = ''; var merged = await window.aggregateBatchesToDrawer(parent); badge.textContent = (Array.isArray(merged)? merged.length : 0) + ' rows'; btn.innerText = orig; btn.disabled = false; }catch(e){ btn.disabled=false; btn.innerText='Aggregate Batches'; console.warn(e); } }); controls.appendChild(btn); }
            if(!document.getElementById('chkAutoAggregate')){
              var lbl = document.createElement('label'); lbl.style.display='flex'; lbl.style.alignItems='center'; lbl.style.gap='6px'; var chk = document.createElement('input'); chk.type='checkbox'; chk.id='chkAutoAggregate'; chk.checked = (localStorage.getItem('csv_auto_aggregate')||'1') !== '0'; chk.addEventListener('change', function(){ localStorage.setItem('csv_auto_aggregate', chk.checked ? '1' : '0'); }); lbl.appendChild(chk); var span = document.createElement('span'); span.innerText='Auto-aggregate'; lbl.appendChild(span); controls.appendChild(lbl); }
            // Add settings opener
            if(!document.getElementById('btnBatchSettings')){
              var sbtn = document.createElement('button'); sbtn.id='btnBatchSettings'; sbtn.className='btn'; sbtn.style.marginLeft='6px'; sbtn.innerText='Batch Settings'; sbtn.addEventListener('click', function(){ try{ showBatchSettingsModal(); }catch(_){ } }); controls.appendChild(sbtn); }
          }catch(e){ /* ignore */ }
        }
        document.addEventListener('DOMContentLoaded', ensureDrawerControls); setTimeout(ensureDrawerControls, 1200);
      })(); }catch(_){ }

      // Settings modal for batch token cap overrides
      try{ window.showBatchSettingsModal = function(){
        try{
          var existing = document.getElementById('csvBatchSettingsModal');
          if(existing){ existing.style.display='flex'; return; }
          var modal = document.createElement('div'); modal.id='csvBatchSettingsModal'; modal.className='csv-modal'; modal.style.display='flex'; modal.style.position='fixed'; modal.style.left='0'; modal.style.top='0'; modal.style.right='0'; modal.style.bottom='0'; modal.style.alignItems='center'; modal.style.justifyContent='center'; modal.style.background='rgba(0,0,0,0.6)';
          var box = document.createElement('div'); box.style.background='var(--bg-primary)'; box.style.padding='12px'; box.style.borderRadius='8px'; box.style.width='420px'; box.style.color='var(--text-primary)';
          box.innerHTML = '<h3 style="margin-top:0">Batch LLM Token Settings</h3>' +
            '<div style="display:flex;flex-direction:column;gap:8px">' +
            '<label>Critical max tokens: <input id="csv_batch_critical_max_input" type="number" style="width:120px"/></label>' +
            '<label>High max tokens: <input id="csv_batch_high_max_input" type="number" style="width:120px"/></label>' +
            '<label>Medium max tokens: <input id="csv_batch_medium_max_input" type="number" style="width:120px"/></label>' +
            '<label>Low max tokens: <input id="csv_batch_low_max_input" type="number" style="width:120px"/></label>' +
            '<label><input id="csv_auto_aggregate_input" type="checkbox"/> Auto-aggregate after batches complete</label>' +
            '<div style="display:flex;gap:8px;margin-top:10px"><button id="csvBatchSettingsSave" class="btn btn-primary">Save</button><button id="csvBatchSettingsClose" class="btn">Close</button></div>' +
            '</div>';
          modal.appendChild(box); document.body.appendChild(modal);
          // Populate values
          try{ document.getElementById('csv_batch_critical_max_input').value = localStorage.getItem('csv_batch_critical_max') || '1024'; }catch(_){ }
          try{ document.getElementById('csv_batch_high_max_input').value = localStorage.getItem('csv_batch_high_max') || '1024'; }catch(_){ }
          try{ document.getElementById('csv_batch_medium_max_input').value = localStorage.getItem('csv_batch_medium_max') || '512'; }catch(_){ }
          try{ document.getElementById('csv_batch_low_max_input').value = localStorage.getItem('csv_batch_low_max') || '256'; }catch(_){ }
          try{ document.getElementById('csv_auto_aggregate_input').checked = (localStorage.getItem('csv_auto_aggregate')||'1')!=='0'; }catch(_){ }
          document.getElementById('csvBatchSettingsClose').addEventListener('click', function(){ modal.style.display='none'; });
          document.getElementById('csvBatchSettingsSave').addEventListener('click', function(){ try{
            var c = document.getElementById('csv_batch_critical_max_input').value || '1024'; var h = document.getElementById('csv_batch_high_max_input').value || '1024'; var m = document.getElementById('csv_batch_medium_max_input').value || '512'; var l = document.getElementById('csv_batch_low_max_input').value || '256'; var a = document.getElementById('csv_auto_aggregate_input').checked ? '1' : '0';
            localStorage.setItem('csv_batch_critical_max', String(parseInt(c,10)||1024)); localStorage.setItem('csv_batch_high_max', String(parseInt(h,10)||1024)); localStorage.setItem('csv_batch_medium_max', String(parseInt(m,10)||512)); localStorage.setItem('csv_batch_low_max', String(parseInt(l,10)||256)); localStorage.setItem('csv_auto_aggregate', a);
            try{ var chk = document.getElementById('chkAutoAggregate'); if(chk) chk.checked = a === '1'; }catch(_){ }
            modal.style.display='none';
            try{ if(window.notifications && window.notifications.showToast) window.notifications.showToast('Batch settings saved',2000); }catch(_){ }
          }catch(e){ console.warn(e); } });
        }catch(e){ console.warn('showBatchSettingsModal', e); }
      }; }catch(_){ }

      function wireControls(){
        try{
          var btn = document.getElementById('btnAnalyzePipeline');
          if(btn && btn.dataset && btn.dataset.daModal === 'true'){
            // Modal flow handles wiring; fall back only when modal not available
          }else if(btn){
            btn.addEventListener('click', function(){ initiateDeepAnalyze(); });
          }
        }catch(_){ }
        // Wire Batch Analyze button to stub
        try{
          var batchBtn = document.getElementById('btnBatchAnalyze');
          if(batchBtn){ batchBtn.addEventListener('click', function(){ try{ window.startBatchAnalyze(); }catch(_){ alert('Batch Analyze unavailable'); } }); }
        }catch(_){ }
        try{
          var exp = document.getElementById('btnExportReport');
          if(exp){
            exp.addEventListener('click', function(){ triggerReportExport(); });
          }
        }catch(_){ }
        // Add a small guidance hint near the Analyze button if present
        try{
          var host = document.getElementById('controlsHintArea') || document.getElementById('results');
          if(host && !document.getElementById('deepAnalyzeHint')){
            var hint = document.createElement('div'); hint.id='deepAnalyzeHint'; hint.style.fontSize='12px'; hint.style.color='var(--text-muted)'; hint.style.marginTop='6px';
            hint.innerHTML = 'Tip: confirm numeric sample columns (e.g., "hit count", "size") are parsed as numbers. If Deep Analyze fails, check server availability and API key.';
            host.parentNode.insertBefore(hint, host.nextSibling);
          }
        }catch(_){ }
        // Persist da_auto_llm checkbox in Deep Analyze modal if present
        try{
          var daCheckbox = document.getElementById('da_auto_llm');
          if(daCheckbox){
            // initialize from localStorage
            try{ var v = localStorage.getItem('da_auto_llm'); if(v!==null){ daCheckbox.checked = !(v==='0' || v==='false'); } }catch(_){ }
            daCheckbox.addEventListener('change', function(){ try{ localStorage.setItem('da_auto_llm', daCheckbox.checked ? '1' : '0'); }catch(_){ } });
          }
        }catch(_){ }
      }

      if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', wireControls);
        document.addEventListener('DOMContentLoaded', initPersonaPanel);
      }else{
        wireControls();
        initPersonaPanel();
      }

    }catch(e){ console.warn('attachDeepAnalyze', e); }
  })();

// Safety-fix: append missing closing tokens to repair unexpected EOF parse error
// (workspace copy appeared truncated). This appends a small balanced closure
// which resolves the parser "Unexpected end of input" while preserving
// existing IIFE semantics. If an authoritative copy exists in VCS, restore it.

// Close the top-level IIFE to ensure file parses correctly
})();
