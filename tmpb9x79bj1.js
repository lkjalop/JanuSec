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
