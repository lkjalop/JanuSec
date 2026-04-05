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
    }
  }

  function formatTier1Summary(text){
    try{
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

  function buildTier1ConfidenceBlock(row){
    try{
      if(!row) return '';
      var dreadInfo = row._dread || computeDreadBreakdown(row.factors, row.raw);
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
      cues.push('<div class="tier1-confidence-metric"><div class="label">DREAD</div><div class="value">'+escapeHtml(String(dreadInfo.score||0))+' <span style="font-size:11px;color:var(--text-muted);">('+escapeHtml(dreadInfo.level||'n/a')+')</span></div></div>');
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
      return '<div class="tier1-confidence"><div class="tier1-confidence-label">Pipeline cues ('+(VERDICT_VIEW_MODE==='pipeline'?'post-pipeline':'initial')+')</div>'
        + '<div class="tier1-confidence-grid">'+cues.join('')+'</div>'
        + '<div><strong>Host:</strong> '+escapeHtml(host)+userLine+'</div>'
        + '<div><strong>Artifact:</strong> '+escapeHtml(artifact)+'</div>'
        + '<div><strong>Signals:</strong> '+factors+'</div>'
        + evidenceHtml
        + taskHtml
        + uncertaintyHtml
        + extraLine
        + '</div>';
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
      var cell = document.createElement('td'); cell.colSpan = tr.children.length; cell.style.background = 'rgba(0,0,0,0.03)';
      var inner = document.createElement('div'); inner.style.padding='8px'; inner.style.display='flex'; inner.style.flexDirection='column';
      var info = document.createElement('div'); info.innerText = 'signals: ' + (row.factors? row.factors.join(', '): ''); inner.appendChild(info);
      var dread = document.createElement('div'); dread.innerText = 'DREAD: ' + ((row._dread && row._dread.score) || computeDreadBreakdown(row.factors, row.raw).score); inner.appendChild(dread);
      // collapse/caret
      var caret = document.createElement('span'); caret.className='collapse-caret'; caret.style.marginLeft='8px'; caret.textContent='▾'; dread.appendChild(caret);
      // show explain details if user enabled
      try{ var explainOn = (localStorage.getItem('csv_explain_toggle')||'1')!=='0'; if(explainOn){ var dbg=document.createElement('div'); dbg.style.marginTop='6px'; try{ var det = row._dread && row._dread.details? row._dread.details : {}; dbg.textContent = 'Breakdown: base='+ (det.base||0) +', avPos='+ (det.av||0) +', avScore='+ (det.avScore||0) +', tw='+ (det.threatWeight||det.twScore||0); }catch(_){ dbg.textContent='Breakdown available'; } inner.appendChild(dbg); } }catch(_){ }
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
            scoring: row._dread || computeDreadBreakdown(row.factors, row.raw),
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
      if(!synth.scoring) synth.scoring = { components: { DREAD: (rec._dread && rec._dread.score) || computeDreadBreakdown(rec.factors, rec.raw).score } };
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

      // Playbooks: suggest quick remediation actions
      synth.playbooks = synth.playbooks || [{ name: 'Contain host', steps: ['Isolate host from network','Collect memory & disk images','Block identified hashes'],'confidence':0.7 }];

      // Short natural-language summary (simple template)
      var summary = synth.summary || ((rec.verdict||'').toUpperCase() + ' on ' + (rec.host||'unknown host') + ' — ' + (rec.process_name||rec.file_path||'artifact'));

      // Confidence & provenance: combine DREAD, factor counts, avPositives, path score hints
      try{
        var prov = [];
        var confScore = 0;
        var dreadScore = (rec._dread && rec._dread.score) || computeDreadBreakdown(rec.factors, rec.raw).score;
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
      try{ out.push('<div style="margin-bottom:8px"><strong>Playbooks</strong><div style="margin-top:6px;color:var(--text-muted);font-size:13px">'+ (Array.isArray(synth.playbooks)? synth.playbooks.map(function(p){ return '<strong>'+escapeHtml(p.name)+'</strong>: '+ escapeHtml((p.steps||[]).slice(0,3).join(' · ')); }).join('<br/>') : 'No playbooks') +'</div></div>'); }catch(_){ }

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
        // Persona on-demand buttons (manager / technical / forensics)
        var personaBtns = '<div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:6px;align-items:center">'+
          '<span style="font-size:12px;color:var(--text-muted)">Generate Persona:</span>'+
          '<button class="btn persona-btn" data-persona="manager" style="padding:4px 10px;font-size:11px">Manager</button>'+
          '<button class="btn persona-btn" data-persona="technical" style="padding:4px 10px;font-size:11px">Technical</button>'+
          '<button class="btn persona-btn" data-persona="forensics" style="padding:4px 10px;font-size:11px">Forensics</button>'+
          '</div>';
        out.push(llmControls + personaBtns + '<div class="persona-dynamic-section" style="margin-top:6px"></div>');
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
      (list||[]).forEach(function(entry){
        try{
          var detection = detectDomainFromRow(entry||{});
          entry._domain = detection.domain;
          entry._domain_confidence = detection.confidence;
        }catch(_){ }
      });
      var ready = document.getElementById('csv_results_ready');
      var filtered = list.filter(function(r){ var pf = verdictPassFail(null, r); if(FILTER_MODE==='suspicious') return pf==='FAIL'; if(FILTER_MODE==='passed') return pf==='PASS'; return true; });
      if(FILTER_MODE==='suspicious'){
        filtered.sort(function(a,b){ var ad=(a&&a._dread&&a._dread.score)||computeDreadBreakdown(a&&a.factors).score; var bd=(b&&b._dread&&b._dread.score)||computeDreadBreakdown(b&&b.factors).score; if(bd!==ad) return bd-ad; var af=(a&&a.factors&&a.factors.length)||0; var bf=(b&&b.factors&&b.factors.length)||0; return bf-af; });
      } else {
        try{
          var sortState = JSON.parse(localStorage.getItem('csv_sort_state')||'null');
          if(sortState && sortState.col){
            var colName = sortState.col; var dir = sortState.dir==='desc' ? -1 : 1;
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
        }catch(_){ }
      }
      if(!filtered.length){ t.innerHTML='<tr><td colspan="10" class="empty-hint">No results</td></tr>'; try{ if(ready){ ready.style.display='none'; ready.textContent=''; ready.removeAttribute('data-ready'); } }catch(_){ } updateGenerateMoreButton(); return; }
        var max=1000; var rows = filtered.slice(0,max).map(function(r){
          var origIdx=(window.LAST_RESULTS||[]).indexOf(r);
          var rowIndex = (r && typeof r.row_index === 'number') ? r.row_index : origIdx;
          var verdict=getVerdictForView(r);
          var signals=(r&&r.factors&&r.factors.join(', '))||'';
          var checked=SELECTED_ROWS.has(origIdx)?' checked':'';
          var vclass='';
          try{ var pf=verdictPassFail(verdict, r); if(pf==='PASS') vclass='verdict-pass'; else if(pf==='FAIL') vclass='verdict-fail'; else vclass='verdict-medium'; }catch(_){ }
          var llmBadge='';
          try{
            if(r && (r.llm_summary || r._tier1_summary)){
              llmBadge=' <span class="llm-badge" title="LLM summary ready">LLM</span>';
            }
          }catch(_){ }
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
          return '<tr class="'+vclass+'" data-row="'+origIdx+'" data-row-index="'+rowIndex+'" data-test="csv-row-'+origIdx+'">'+
            '<td class="llm-status-cell" data-row-index="'+rowIndex+'"><span class="llm-indicator" title="LLM summary not generated">--</span></td>'+
            '<td>'+wrapCell(r&&r.process_name||'')+'</td>'+
            '<td>'+wrapCell(r&&r.file_path||'')+'</td>'+
            '<td>'+wrapCell(r&&r.sha256||'')+'</td>'+
            '<td>'+wrapCell(r&&r.host||'')+'</td>'+
            '<td>'+wrapCell(verdict)+llmBadge+'</td>'+ 
            '<td>'+domainBadge+'</td>'+
            '<td data-test="dread-'+origIdx+'">'+wrapCell((r&&r._dread&&r._dread.score)||'')+'</td>'+
            '<td>'+wrapCell(signals)+'</td>'+
            '<td><input type="checkbox" class="csv-row-select" data-idx="'+origIdx+'"'+checked+' style="margin-right:6px"/>'+
              '<button data-test="btn-details-'+origIdx+'" class="btn" style="padding:4px 10px" onclick="window.openCsvRowDetails('+origIdx+')" title="Why flagged / details">Details</button>'+
              ' <button data-test="btn-copy-'+origIdx+'" class="btn copy-inline" data-idx="'+origIdx+'" style="margin-left:6px;padding:4px 8px">Copy</button></td>'+
          '</tr>'; }).join('');
      t.innerHTML = rows;
      try{
        Array.from(t.querySelectorAll('button[title="Why flagged / details"]')||[]).forEach(function(btn){
              btn.addEventListener('click', function(e){ try{ var tr = btn.closest('tr[data-row]'); if(tr){ var idx = parseInt(tr.getAttribute('data-row'),10); if(!isNaN(idx)) { window.openCsvRowDetails(idx); try{ if(typeof renderFullDetails==='function') renderFullDetails(idx); }catch(_){ } } } }catch(_){ } });
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
          sum.textContent='Showing '+Math.min(filtered.length,max)+' of '+list.length+' ('+viewLabel+' view)';
        }
      }catch(_){ }
      try{ if(ready){ ready.style.display='block'; ready.textContent = 'results:'+Math.min(filtered.length,1000)+' of '+list.length; ready.setAttribute('data-ready','1'); } }catch(_){ }
      window.dispatchEvent(new Event('csv-results-ready'));
      updateGenerateMoreButton();
      updateLLMIndicators();
      // update ARIA live status
      try{ var live=document.getElementById('csv_status_live'); if(live) live.textContent = 'Showing '+Math.min(filtered.length,max)+' of '+list.length + ' rows'; }catch(_){ }
      try{ updateFpBannerAndAudit(list); }catch(_){ }
    }catch(e){ console.warn('renderTableFromResults', e); }
  }

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
      // Show sidebar if present
      try{ var sidebar = document.getElementById('llmSidebar'); if(sidebar) sidebar.style.display='block'; }catch(_){ }
      // Build payload
      var overrides = null;
      try{ if(window.LLMSettingsUI && typeof window.LLMSettingsUI.getOverridesForRequest === 'function'){ overrides = window.LLMSettingsUI.getOverridesForRequest(); } }catch(_){ overrides = null; }
      var pipeline_context = { row_index: rowIndex };
      if (overrides && Object.keys(overrides||{}).length) pipeline_context.overrides = overrides;
      var payload = { insight_type: 'tier1', row: rec, pipeline_context: pipeline_context };
      // Show loading state in sidebar
      try{ var sb = document.getElementById('llmSidebarBody'); if(sb) sb.innerHTML = '<div style="padding:12px">Requesting LLM summary...</div>'; }catch(_){ }
      var resp = await fetch('/api/v1/insights/generate', { method: 'POST', headers: { 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload) });
      if(!resp.ok){
        var txt = await resp.text().catch(()=>String(resp.status));
        try{ if(sb) sb.innerHTML = '<div style="padding:12px;color:var(--text-muted)">LLM request failed: '+escapeHtml(txt)+'</div>'; }catch(_){ }
        return;
      }
      var j = await resp.json();
      // API returns { text: '...' }
      var summary = (j && (j.text || j.result || JSON.stringify(j, null, 2))) || '';
      // Save into in-memory row cache and update UI
      try{ rec._tier1_summary = summary; window.__LLM_ROWS = window.__LLM_ROWS || {}; window.__LLM_ROWS[rec.row_index || rowIndex] = window.__LLM_ROWS[rec.row_index || rowIndex] || {}; window.__LLM_ROWS[rec.row_index || rowIndex].llm_summary = summary; }catch(_){ }
      try{ if(sb) sb.innerHTML = '<div style="padding:12px"><strong>Tier 1 Summary</strong><pre style="white-space:pre-wrap;margin-top:8px;color:var(--text-primary)">'+escapeHtml(summary)+'</pre></div>'; }catch(_){ }
      try{ updateLLMIndicators(); }catch(_){ }
    }catch(e){ console.warn('requestTier1Summary', e); try{ var sb=document.getElementById('llmSidebarBody'); if(sb) sb.innerHTML = '<div style="padding:12px;color:red">Error requesting summary</div>'; }catch(_){} }
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
  }catch(_){ } });

  // Expose wrappers
  try{ window.csvActions = window.csvActions || {}; window.csvActions.generateMoreLLMSummaries = generateMoreLLMSummaries; }catch(_){ }
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
      rec._dread = computeDreadBreakdown(rec.factors, raw);
      rec._dread_text = rec._dread.score + ' (' + rec._dread.level + ')';
      return rec;
    }catch(e){ return {process_name:'unknown',file_path:'',sha256:'',host:'',verdict:'',_initial_verdict:'',factors:[],_dread:{score:0},raw:raw}; }
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
