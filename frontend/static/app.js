/* JanuSec Artifact Intelligence Enhanced UI Script (tabs, NLP history, sorting, auto-refresh) */
(function(){
  const API_BASE = window.API_BASE || '/api/v1';
  const TOKEN = window.API_TOKEN || null;
  const GRAFANA_URL = window.GRAFANA_URL || 'http://localhost:3000/d/janusec-main';

  // State
  let REPORT = null;
  let BUSINESS_MODE = false;
  let SELECTED_ID = null;
  let VIEW_MODE = localStorage.getItem('view_mode') || 'top';
  let PAGE = 1;
  let PAGE_SIZE = 100;
  let ACTIVE_SORT = null;              // { key:'risk'|'hosts', dir: 1|-1 } dir=-1 means descending
  let LAST_REFRESH_TS = null;
  const NLP_HISTORY_KEY = 'nlp_history_cache_v1';
  let NLP_HISTORY = loadNlpHistory();
  let CAP_LAST_FETCH = 0;
  const CAP_REFRESH_MS = 60000;
  let huntPollTimer = null;

  // ---------- Helpers ----------
  // Non-blocking notification shim for headless / test environments
  function safeNotify(msg, level){ try{ if(window.showNotification) return window.showNotification(msg, level); if(window.notifications && typeof window.notifications.showToast === 'function') return window.notifications.showToast(msg, 4000); console.log('[notify]', level||'info', msg); }catch(e){ console.log('notify-fail', e, msg); } }
  function qs(id){ return document.getElementById(id); }
  function authHeaders(){
    const h={'Accept':'application/json'};
    if(TOKEN) h['Authorization']=TOKEN.startsWith('Bearer')?TOKEN:`Bearer ${TOKEN}`;
    return h;
  }
  function setStatus(t){ const el=qs('status-text'); if(el) el.textContent=t; }
  function updateLastRefresh(){
    LAST_REFRESH_TS = Date.now();
    const el=qs('last-refresh');
    if(el) el.textContent = new Date(LAST_REFRESH_TS).toLocaleTimeString();
  }
  function capBadge(label,status){
    const st=(status||'unknown').toString();
    const safe=st.replace(/[^a-z0-9_-]/gi,'');
    return `<span class="cap-badge cap-${safe}" title="${label}: ${st}">${label}:${safe}</span>`;
  }
  async function refreshCapabilities(force=false){
    const now=Date.now();
    if(!force && now-CAP_LAST_FETCH < CAP_REFRESH_MS) return;
    CAP_LAST_FETCH = now;
    try {
      const r = await fetch('/health/deps'); if(!r.ok) throw 0; const j = await r.json();
      const caps = j.capabilities||{}; const fb=j.fallback_counters||{};
      const panel = qs('capability-panel'); if(!panel) return;
      const order=['bloom','tuner','drift','crypto','whatsapp'];
      panel.innerHTML = order.map(k=>capBadge(k,caps[k]||'unknown')).join('') + (fb.ml_stub_predictions? capBadge('ml_stub', fb.ml_stub_predictions):'');
    } catch(e){ /* silent */ }
  }
  function verdictClass(v){
    if (v==='MALICIOUS') return 'risk-critical';
    if (v==='HIGH') return 'risk-high';
    if (v==='SUSPICIOUS') return 'risk-medium';
    if (v==='LOW') return 'risk-low';
    return 'risk-minimal';
  }
  function applyViewModeIndicator(btn){ if(!btn) return; btn.classList.toggle('btn-primary', VIEW_MODE==='all'); }
  function escapeHtml(str){
    return (str||'').replace(/[&<>"']/g, c => ({
      '&':'&amp;',
      '<':'&lt;',
      '>':'&gt;',
      '"':'&quot;',
      "'":'&#39;'
    }[c]));
  }

  function huntsUrl(path){
    const base = API_BASE.endsWith('/') ? API_BASE.slice(0,-1) : API_BASE;
    return `${base}${path}`;
  }

  function updateHuntProgressBox(message){
    const box = qs('hunt-progress');
    if(!box) return;
    box.textContent = message;
  }

  function summariseProgress(data){
    if(!data) return 'No hunt data.';
    const partial = data.factors_partial ? Object.entries(data.factors_partial).map(([k,v])=>`${k}:${v}`).join(', ') : '—';
    const tiers = data.model_tiers_used ? Object.entries(data.model_tiers_used).map(([k,v])=>`${k}:${v}`).join(', ') : '—';
    return [`Session: ${data.session_id||'n/a'}`,
            `Status: ${data.status||'unknown'}`,
            `Elapsed (s): ${data.elapsed_seconds ?? 'n/a'}`,
            `Factors: ${partial}`,
            `Model tiers: ${tiers}`].join('\n');
  }

  function scheduleHuntPolling(sessionId){
    if(huntPollTimer) clearInterval(huntPollTimer);
    huntPollTimer = setInterval(()=>{
      fetchHuntProgress(sessionId, true).catch(()=>{});
    }, 5000);
  }

  async function fetchHuntProgress(sessionId, silent=false){
    if(!sessionId){
      if(!silent) updateHuntProgressBox('Provide a session id to fetch progress.');
      return null;
    }
    try{
      const url = huntsUrl(`/hunts/session/${encodeURIComponent(sessionId)}/progress`);
      const r = await fetch(url,{headers:authHeaders()});
      if(!r.ok) throw new Error(await r.text());
      const data = await r.json();
      updateHuntProgressBox(summariseProgress(data));
      if(data.status && data.status.toUpperCase()==='COMPLETE' && huntPollTimer){
        clearInterval(huntPollTimer);
        huntPollTimer = null;
      }
      return data;
    }catch(err){
      if(!silent) updateHuntProgressBox(`Hunt progress error: ${err.message}`);
      throw err;
    }
  }

  async function startHunt(){
    const sessionInput = qs('hunt-session-id');
    const windowInput = qs('hunt-window');
    const modelToggle = qs('hunt-model-enabled');
    if(!sessionInput || !windowInput) return;
    let sessionId = (sessionInput.value||'').trim();
    if(!sessionId){
      sessionId = `hunt-${Date.now()}`;
      sessionInput.value = sessionId;
    }
    const windowHours = parseInt(windowInput.value,10) || 24;
    const payload = {
      session_id: sessionId,
      window_hours: windowHours,
      model_enabled: !!(modelToggle && modelToggle.checked),
      async_run: false
    };
    updateHuntProgressBox('Starting hunt...');
    try{
      const r = await fetch(huntsUrl('/hunts/start'),{
        method:'POST',
        headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      if(!r.ok) throw new Error(await r.text());
      const data = await r.json();
      updateHuntProgressBox(`Hunt started. Status: ${data.status||'unknown'}\nEstimate units: ${data.estimate_units ?? 'n/a'}`);
      await fetchHuntProgress(sessionId, true);
      scheduleHuntPolling(sessionId);
    }catch(err){
      updateHuntProgressBox(`Hunt start failed: ${err.message}`);
    }
  }

  function downloadHuntReport(format='markdown'){
    const sessionInput = qs('hunt-session-id');
    if(!sessionInput){
      safeNotify('Hunt panel unavailable','error');
      return;
    }
    const sessionId = (sessionInput.value||'').trim();
    if(!sessionId){
      safeNotify('Provide a session id before downloading a report.','error');
      return;
    }
    const url = huntsUrl(`/hunts/report/${encodeURIComponent(sessionId)}?format=${encodeURIComponent(format)}`);
    window.open(url,'_blank');
  }

  // ---------- Fetch ----------
  async function fetchLatestReport(business=false){
    setStatus('Loading...');
    BUSINESS_MODE = business;
    // include server pagination params if backend pagination is active (we always send filter/search/sort for consistency)
    const params = new URLSearchParams();
    if(business) params.set('business','1');
    params.set('view', VIEW_MODE==='all'?'all':'top');
    const activeFilter = document.querySelector('.chip.active')?.dataset.filter;
    if(activeFilter && activeFilter!=='all') params.set('filter', activeFilter);
    const q = (qs('search-input')?.value||'').trim(); if(q) params.set('search', q);
    if(ACTIVE_SORT){
      params.set('sort', ACTIVE_SORT.key==='risk'?'risk':'hosts');
      params.set('dir', ACTIVE_SORT.dir===-1?'desc':'asc');
    }
    params.set('page','1');
    params.set('page_size', PAGE_SIZE);
    const url = `${API_BASE}/artifacts/latest_report?${params.toString()}`;
    try {
      const r = await fetch(url,{headers:authHeaders()});
      if(!r.ok) throw new Error(await r.text());
      REPORT = await r.json();
      populateHeaderStats();
      renderArtifacts();
      if(business && REPORT.business_impact) renderBusiness(REPORT.business_impact); else hideBusiness();
      refreshCostSummaryIfVisible();
      updateLastRefresh();
      setStatus('Ready');
    } catch(e){ console.error(e); setStatus('Error'); }
  }

  async function fetchCostSummary(){
    try { const r = await fetch(`${API_BASE}/cost/summary`, {headers:authHeaders()}); if(!r.ok) return null; return await r.json(); }
    catch(e){ return null; }
  }

  async function runNlpQuery(question){
    const r = await fetch(`${API_BASE}/artifacts/nlp_query`, {
      method:'POST',
      headers:{...authHeaders(),'Content-Type':'application/json'},
      body: JSON.stringify({ question })
    });
    if(!r.ok) throw new Error(await r.text());
    return await r.json();
  }

  // ---------- Stats / Filters ----------
  function populateHeaderStats(){
    if(!REPORT) return;
    const bm = REPORT.batch_meta || {};
    const sb = qs('stat-batch'); if(sb) sb.textContent = bm.batch_id || '—';
    const top = REPORT.top_risky || [];
    const all = REPORT.all_artifacts || [];
    const base = VIEW_MODE==='all' ? (all.length?all:top) : (top.length?top:all);
    const sa = qs('stat-artifacts'); if(sa) sa.textContent = base.length.toString();
    const highCt = base.filter(a=>['HIGH','MALICIOUS'].includes(a.verdict)).length;
    const sh = qs('stat-high'); if(sh) sh.textContent = highCt.toString();
  }

  function matchesFilters(a){
    const f = document.querySelector('.chip.active')?.dataset.filter || 'all';
    if(f==='high') return ['HIGH','MALICIOUS'].includes(a.verdict);
    if(f==='rare') return (a.rarity === 'RARE' || (typeof a.rarity === 'number' && a.rarity < 0.2));
    if(f==='multi') return (a.host_count && a.host_count > 1);
    return true;
  }
  function matchesSearch(a){
    const q = (qs('search-input')?.value||'').trim().toLowerCase();
    if(!q) return true;
    const factorIds = (a.factor_contributions||[]).map(f=>f.factor_id);
    const hay = [a.name,a.indicator,a.path,a.artifact_id,(a.factors||[]).join(' '),factorIds.join(' '),(a.mitre||[]).join(' ')].join(' ').toLowerCase();
    return hay.includes(q);
  }
  function currentArtifactSet(){
    if(!REPORT) return [];
    if(REPORT.data && REPORT.meta) return REPORT.data; // server pagination shape
    return VIEW_MODE==='all' ? (REPORT.all_artifacts || REPORT.top_risky || []) : (REPORT.top_risky || REPORT.all_artifacts || []);
  }

  // ---------- Rendering ----------
  function renderArtifacts(){
    const container = qs('artifact-rows');
    if(!container || !REPORT) return;
    container.innerHTML = '';
    let rows = currentArtifactSet().filter(a => matchesFilters(a) && matchesSearch(a));

    // Sorting
    if(ACTIVE_SORT){
      rows = rows.slice().sort((a,b)=>{
        const ra = ACTIVE_SORT.key==='risk' ? (a.risk_score!=null?a.risk_score:a.risk||0) : (a.host_count||0);
        const rb = ACTIVE_SORT.key==='risk' ? (b.risk_score!=null?b.risk_score:b.risk||0) : (b.host_count||0);
        return (rb - ra) * ACTIVE_SORT.dir; // default dir=-1 => descending
      });
    }

    const paginationEl = qs('pagination');
    const backendPaging = !!(REPORT && REPORT.data && REPORT.meta);
    if(!backendPaging && VIEW_MODE==='all' && rows.length > PAGE_SIZE){
      const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
      if(PAGE > totalPages) PAGE = totalPages;
      const start = (PAGE - 1) * PAGE_SIZE;
      drawRows(rows.slice(start, start + PAGE_SIZE), container);
      updatePaginationControls(PAGE, totalPages, rows.length);
      if(paginationEl) paginationEl.style.display='flex';
    } else {
      if(paginationEl) paginationEl.style.display = backendPaging ? 'flex' : 'none';
      drawRows(rows, container);
      if(backendPaging){
        const m = REPORT.meta || {};
        updatePaginationControls(m.page || 1, m.total_pages || 1, m.total_items || rows.length);
      }
    }

    if(!SELECTED_ID && rows.length){
      SELECTED_ID = rows[0].artifact_id;
      renderArtifacts();
      renderDetails(rows[0]);
    }
    populateHeaderStats();
  }

  function drawRows(list, container){
    list.forEach(a=>{
      const row = document.createElement('div');
      row.className = 'grid-row' + (a.artifact_id===SELECTED_ID?' selected':'');
      row.dataset.id = a.artifact_id;
      const riskScore = a.risk_score!=null ? a.risk_score : a.risk;
      const riskCls = verdictClass(a.verdict);
      const mitreTags = (a.mitre||[]).slice(0,4).map(m=>`<span class="mitre-tag">${m}</span>`).join('');
      const hostCount = a.host_count!=null ? a.host_count : '—';
      const dreadSeverity = a.dread_severity || (a.dread && a.dread_score!=null ? (a.dread_score>=0.66?'high':(a.dread_score>=0.33?'medium':'low')) : null);
      const factorIds = (a.factor_contributions||[]).map(f=>f.factor_id);
      const factorsShort = (a.factors&&a.factors.length?a.factors:factorIds).slice(0,6).join(' • ');
      const displayName = a.name || a.indicator || (a.path||'').split(/[\\/]/).pop() || a.artifact_id;
      const typeVal = a.type || a.kind || '—';
      const conf = (a.risk_confidence!=null)?a.risk_confidence:null;
      let confBadge='';
      if(conf!==null){
        let label='Low', cls='conf-low';
        if(conf>=0.85){ label='Certain'; cls='conf-certain'; }
        else if(conf>=0.60){ label='High'; cls='conf-high'; }
        else if(conf>=0.35){ label='Moderate'; cls='conf-mod'; }
        confBadge = `<span class="confidence-badge ${cls}" title="confidence ${(conf*100).toFixed(1)}% ambiguity ${((a.ambiguity||0)*100).toFixed(1)}%">${label}</span>`;
      }
      // Escalation badge
      let escBadge='';
      if(a.escalation_status){
        const st=a.escalation_status; const cls = `esc-${st}`;
        // compute cumulative gain if trace present
        let gain=null; if(Array.isArray(a.escalation_trace)){ gain = a.escalation_trace.reduce((s,t)=>s+(t.confidence_gain||0),0); }
        const titleParts=[]; if(gain!==null) titleParts.push(`gain ${(gain*100).toFixed(1)}%`); titleParts.push(`status ${st}`);
        escBadge = `<span class="escalation-badge ${cls}" title="${titleParts.join(' | ')}">ESC${gain!==null?('+'+(gain*100).toFixed(0)) : ''}</span>`;
      }
      row.innerHTML = `
        <div></div>
        <div class="artifact-name">${escapeHtml(displayName)}</div>
        <div style="color: var(--text-secondary);">${escapeHtml(typeVal)}</div>
        <div><span class="risk-score ${riskCls}">${riskScore!=null?Math.round(riskScore):'—'}</span></div>
  <div><span class="verdict-badge" style="color:inherit;">${a.verdict}</span> ${confBadge} ${escBadge}</div>
        <div class="hosts-count">${hostCount}</div>
        <div class="mitre-tags">${mitreTags || '-'}</div>
        <div style="font-size:12px;">${dreadSeverity?`<span class="dread-badge dread-${dreadSeverity}">${dreadSeverity.toUpperCase()}</span>`:'-'}</div>
        <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(factorsShort)}</div>`;
      row.addEventListener('click',()=>{
        SELECTED_ID = a.artifact_id;
        renderArtifacts();
        renderDetails(a);
      });
      container.appendChild(row);
    });
  }

  function updatePaginationControls(page,totalPages,totalItems){
    const info = qs('page-info'); if(info) info.textContent = `Page ${page} / ${totalPages} (${totalItems} items)`;
    const prev = qs('page-prev'); if(prev) prev.disabled = page <= 1;
    const next = qs('page-next'); if(next) next.disabled = page >= totalPages;
  }

  function renderDetails(a){
    const riskScore = a ? (a.risk_score!=null?a.risk_score:a.risk) : null;
    qs('detail-risk').textContent = riskScore!=null?Math.round(riskScore):'—';
    qs('detail-hosts').textContent = a && a.host_count!=null ? a.host_count : '—';
    qs('detail-cluster').textContent = a && a.cluster_id ? `#${a.cluster_id}` : '—';
    qs('detail-rarity').textContent = a && (a.rarity!=null) ? (typeof a.rarity==='number'?a.rarity.toFixed(3):a.rarity) : '—';
    qs('detail-hash').textContent = a && a.sha256 ? a.sha256 : '(not available)';
    // DREAD breakdown
    try {
      const dd = qs('detail-dread');
      if (dd) {
        dd.innerHTML = '';
        if (a && (a.dread || a.dread_score != null)) {
          const score = a.dread_score != null ? (Math.round(a.dread_score * 100) / 100) : '—';
          dd.innerHTML = `<div><strong>DREAD</strong>: ${score} <em>${a.dread_severity || ''}</em></div>`;
          if (a.dread && typeof a.dread === 'object') {
            const ul = document.createElement('ul'); ul.style.margin = '6px 0 0 0'; ul.style.paddingLeft = '18px';
            for (const k of Object.keys(a.dread)) {
              const li = document.createElement('li'); li.textContent = `${k}: ${a.dread[k]}`; ul.appendChild(li);
            }
            dd.appendChild(ul);
          }
        } else {
          dd.innerHTML = '<div style="color:var(--text-muted);">DREAD not available</div>';
        }
      }
    } catch (e) { /* ignore */ }
    const fac = qs('detail-factors');
    if(fac){
      fac.innerHTML='';
      const contribs = (a.factor_contributions||[]).slice().sort((x,y)=>Math.abs(y.weight)-Math.abs(x.weight));
      if(contribs.length){
        contribs.forEach(c=>{
          const div=document.createElement('div');
          div.className='factor-row';
          const w = c.weight!=null ? (c.weight>=0?`+${c.weight.toFixed(2)}`:c.weight.toFixed(2)) : '?';
            div.innerHTML = `<span class="factor-name" title="${escapeHtml(c.description||'')}">${escapeHtml(c.factor_id)}</span><span class="factor-score ${c.weight>=0?'positive':'negative'}">${w}</span>`;
          fac.appendChild(div);
        });
      } else if(a.factors && a.factors.length){
        a.factors.forEach(f=>{
          const div=document.createElement('div');
          div.className='factor-row';
          div.innerHTML=`<span class="factor-name">${escapeHtml(f)}</span><span class="factor-score positive">?</span>`;
          fac.appendChild(div);
        });
      } else {
        fac.innerHTML='<div style="font-size:11px;color:var(--text-muted);">No factor data</div>';
      }
      // Escalation trace collapsed view
      if(a && a.escalation_trace && Array.isArray(a.escalation_trace) && a.escalation_trace.length){
        const wrap=document.createElement('div');
        wrap.style.marginTop='12px';
        const btn=document.createElement('button');
        btn.className='btn'; btn.style.padding='4px 8px'; btn.style.fontSize='11px';
        btn.textContent='Show Escalation Details';
        let open=false;
        const panel=document.createElement('div');
        panel.style.display='none'; panel.style.marginTop='6px'; panel.style.border='1px solid #1E2531'; panel.style.borderRadius='4px';
        panel.innerHTML='<div class="esc-trace-head">Tier Trace</div>' + a.escalation_trace.map(t=>`<div class="esc-trace-row"><div style="width:36px;">T${t.tier}</div><div style="flex:1;">${escapeHtml(t.provider||'')}</div><div style="width:60px;">${(t.confidence_gain*100).toFixed(1)}%</div><div style="width:70px;">${t.latency_ms}ms</div><div style="width:70px;">${t.cost_units!=null?t.cost_units.toFixed(3):'0'}</div><div style="width:70px;">${t.accepted?'✔':'-'}</div>${t.error?`<div style="color:var(--risk-critical);">${escapeHtml(t.error)}</div>`:''}</div>`).join('');
        btn.addEventListener('click',()=>{ open=!open; panel.style.display=open?'block':'none'; btn.textContent=open?'Hide Escalation Details':'Show Escalation Details'; });
        wrap.appendChild(btn); wrap.appendChild(panel); fac.appendChild(wrap);
      }
    }
  }

  function renderBusiness(b){
    const el=qs('business-summary');
    if(!el) return;
    el.style.display='block';
    el.innerHTML = `<strong>Business Impact:</strong><br>${escapeHtml(b.summary||'(no summary)')}<br><br>` +
      (b.recommended_actions?`<em>Actions:</em><br><ul>${b.recommended_actions.map(a=>`<li>${escapeHtml(a)}</li>`).join('')}</ul>`:'');
  }
  function hideBusiness(){ const el=qs('business-summary'); if(el) el.style.display='none'; }

  // ---------- NLP History ----------
  function loadNlpHistory(){
    try { return JSON.parse(localStorage.getItem(NLP_HISTORY_KEY)||'[]'); }
    catch(e){ return []; }
  }
  function saveNlpHistory(){ localStorage.setItem(NLP_HISTORY_KEY, JSON.stringify(NLP_HISTORY.slice(0,5))); }
  function pushNlpHistory(q){
    if(!q) return;
    NLP_HISTORY = [q, ...NLP_HISTORY.filter(x=>x!==q)].slice(0,5);
    saveNlpHistory();
    renderNlpHistory();
  }
  function renderNlpHistory(){
    const sel = qs('nlp-history');
    if(!sel) return;
    sel.innerHTML = '<option value="" disabled selected>History (last 5)...</option>' +
      NLP_HISTORY.map(h=>`<option value="${escapeHtml(h)}">${escapeHtml(h.slice(0,80))}</option>`).join('');
  }

  // ---------- Tabs / Sorting / Auto Refresh ----------
  function switchTab(tab){
    ['factors','nlp'].forEach(t=>{
      const btn=qs('tab-'+t);
      const panel=qs('detail-'+t);
      if(btn){ btn.classList.toggle('btn-primary', t===tab); }
      if(panel){ panel.style.display = t===tab?'block':'none'; }
    });
    const qPanel = qs('nlp-query-panel');
    if(qPanel) qPanel.style.display = tab==='nlp'?'block':'none';
    localStorage.setItem('detail_tab', tab);
  }

  function toggleSort(key){
    if(ACTIVE_SORT && ACTIVE_SORT.key===key){
      ACTIVE_SORT.dir = -ACTIVE_SORT.dir;
    } else {
      ACTIVE_SORT = { key, dir: -1 }; // start descending
    }
    renderArtifacts();
  }

  function scheduleAuto(){
    clearTimeout(scheduleAuto._t);
    const chk = qs('auto-refresh');
    if(!chk || !chk.checked) return;
    scheduleAuto._t = setTimeout(async ()=>{
      await fetchLatestReport(BUSINESS_MODE);
      scheduleAuto();
    }, 60000);
  }

  // ---------- Actions ----------
  async function exportMarkdown(){
    try {
      const r=await fetch(`${API_BASE}/artifacts/latest_report?format=markdown`,{headers:authHeaders()});
      if(!r.ok) throw new Error(await r.text());
      const text=await r.text();
      const blob=new Blob([text],{type:'text/markdown'});
      const a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download='artifact_report.md';
      a.click();
      URL.revokeObjectURL(a.href);
    } catch(e){ console.error(e); }
  }

  async function pushReport(targets, webhookUrl){
    try {
      const r = await fetch(`${API_BASE}/artifacts/push_report`, {
        method:'POST',
        headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({ targets, webhook_url: webhookUrl||undefined })
      });
      if(!r.ok) throw new Error(await r.text());
      const data = await r.json();
      safeNotify('Pushed to: '+data.pushed.join(', '),'success');
    } catch(e){ safeNotify('Push failed: '+e.message,'error'); }
  }

  async function fetchReportHash(){
    try {
      const r = await fetch(`${API_BASE}/artifacts/latest_report?format=hash`, {headers:authHeaders()});
      if(!r.ok) throw new Error(await r.text());
      const j = await r.json();
      const el = qs('hash-display-inline');
      if(el){ el.style.display='block'; el.textContent = `Hash: ${j.hash}`; }
    } catch(e){ safeNotify('Hash fetch failed: '+e.message,'error'); }
  }

  function initSSE(){
    try {
      const es = new EventSource(`/api/v1/stream/artifacts`);
      es.addEventListener('hello', ev=>{ /* could show connected */ });
      es.addEventListener('snapshot', ev=>{ /* future incremental merge */ });
      es.addEventListener('artifact_update', ev=>{
        try {
          const d = JSON.parse(ev.data);
          if(!d || !d.added) return;
          // Merge into in-memory structures (top_risky only affects initial view; we update both arrays if exist)
          const updateList = (arr)=>{
            if(!Array.isArray(arr)) return;
            // Remove
            if(d.removed && d.removed.length){
              for(const rid of d.removed){
                const idx = arr.findIndex(x=>x.artifact_id===rid); if(idx>=0) arr.splice(idx,1);
              }
            }
            // Changed
            if(d.changed && d.changed.length){
              for(const ch of d.changed){
                const idx = arr.findIndex(x=>x.artifact_id===ch.artifact_id); if(idx>=0) arr[idx]=ch;
              }
            }
            // Added (ensure no duplicates)
            if(d.added && d.added.length){
              for(const add of d.added){
                if(!arr.find(x=>x.artifact_id===add.artifact_id)) arr.push(add);
              }
            }
          };
          if(REPORT){
            updateList(REPORT.top_risky);
            updateList(REPORT.all_artifacts);
            // If selected artifact updated, re-render details
            if(SELECTED_ID && [...(REPORT.top_risky||[]), ...(REPORT.all_artifacts||[])].some(a=>a.artifact_id===SELECTED_ID)){
              const art = [...(REPORT.top_risky||[]), ...(REPORT.all_artifacts||[])].find(a=>a.artifact_id===SELECTED_ID);
              if(art) renderDetails(art);
            }
            renderArtifacts();
          }
        } catch(e){ console.warn('artifact_update parse fail', e); }
      });
      es.addEventListener('heartbeat', ()=>{});
      es.onerror = ()=>{ es.close(); setTimeout(initSSE, 5000); };
    } catch(e){ console.warn('SSE init failed', e); }
  }

  async function applyOverride(){
    if(!SELECTED_ID){ safeNotify('Select an artifact first','error'); return; }
    const verdict = prompt('Enter new verdict (BENIGN|LOW|SUSPICIOUS|HIGH|MALICIOUS):');
    if(!verdict) return;
    const comment = prompt('Rationale (optional):')||'';
    try {
      const r = await fetch(`${API_BASE}/artifacts/feedback`, {
        method:'POST',
        headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({ artifact_id: SELECTED_ID, verdict, comment })
      });
      if(!r.ok) throw new Error(await r.text());
      if(REPORT){
        [...(REPORT.top_risky||[]), ...(REPORT.all_artifacts||[])]
          .forEach(a=>{ if(a.artifact_id===SELECTED_ID) a.verdict = verdict; });
        renderArtifacts();
      }
      safeNotify('Override submitted','success');
    } catch(e){ safeNotify('Override failed: '+e.message,'error'); }
  }

  function detachPanel(){
    if(!SELECTED_ID){ safeNotify('Select an artifact first','error'); return; }
    const art = [...(REPORT?.top_risky||[]), ...(REPORT?.all_artifacts||[])].find(a=>a.artifact_id===SELECTED_ID);
    const w = window.open('', '_blank','width=520,height=720');
    if(!w) return;
    w.document.write(`<html><head><title>Artifact Detail</title><style>body{font-family:Inter,Arial,sans-serif;background:#0B0E14;color:#E8EBF0;padding:16px;line-height:1.4;} code{background:#151922;padding:2px 4px;border-radius:4px;} .f{border-bottom:1px solid #222;padding:4px 0;font-size:13px;} .h{font-size:18px;font-weight:600;margin:0 0 8px;} .tag{display:inline-block;background:#1C2230;border:1px solid #2A3142;border-radius:4px;padding:2px 6px;font-size:11px;margin:2px 4px 2px 0;} </style></head><body>`);
    if(art){
      const rs = art.risk_score!=null?art.risk_score:art.risk;
      w.document.write(`<h1 class='h'>${escapeHtml(art.name||art.indicator||art.path||art.artifact_id)}</h1>`);
      w.document.write(`<p>Risk: <strong>${rs!=null?Math.round(rs):'—'}</strong> Verdict: <strong>${art.verdict}</strong> Type: <strong>${art.type||'—'}</strong></p>`);
      w.document.write(`<p>Cluster: ${art.cluster_id||'—'} Hosts: ${art.host_count||'—'} Rarity: ${art.rarity||'—'}</p>`);
      if(art.sha256) w.document.write(`<p>SHA256: <code>${art.sha256}</code></p>`);
      if(art.mitre && art.mitre.length) w.document.write(`<div>${art.mitre.map(m=>`<span class='tag'>${m}</span>`).join('')}</div>`);
      w.document.write(`<h3>Factors</h3>`);
      if(art.factor_contributions && art.factor_contributions.length){
        art.factor_contributions.forEach(c=>{
          w.document.write(`<div class='f'><strong>${escapeHtml(c.factor_id)}</strong> ${c.description?escapeHtml(c.description):''} (${c.weight!=null?c.weight.toFixed(2):'?'})</div>`);
        });
      } else {
        (art.factors||[]).forEach(f=> w.document.write(`<div class='f'>${escapeHtml(f)}</div>`));
      }
    }
    w.document.write('</body></html>');
    w.document.close();
  }

  async function onCsvFilesSelected(e){
    const files = Array.from(e.target.files||[]);
    if(!files.length) return;
    const items=[];
    for(const f of files){
      if(!f.name.toLowerCase().endsWith('.csv')) continue;
      try {
        const text=await f.text();
        text.split(/\r?\n/).map(l=>l.trim()).filter(Boolean).forEach(line=>{
          const parts=line.split(',');
          if(parts[0]) items.push({ indicator: parts[0] });
        });
      } catch(err){ console.warn('parse fail', f.name, err); }
    }
    if(!items.length){ safeNotify('No CSV indicators parsed','error'); return; }
    try {
      const r=await fetch(`${API_BASE}/artifacts/analyze_batch`, {
        method:'POST',
        headers:{...authHeaders(),'Content-Type':'application/json'},
        body: JSON.stringify({ items })
      });
      if(!r.ok) throw new Error(await r.text());
      const data=await r.json();
      safeNotify('Batch submitted. Batch ID: '+(data.batch_id||'n/a'),'success');
    } catch(err){ safeNotify('Batch error: '+err.message,'error'); }
  }

  async function refreshCostSummaryIfVisible(){
    const el=qs('cost-summary');
    if(!el || el.style.display==='none') return;
    const data=await fetchCostSummary();
    if(!data){ el.innerHTML='<em style="font-size:11px;">No cost data</em>'; return; }
    const t=data.totals||{};
    el.innerHTML = `<strong style="font-size:12px;">Cost Summary</strong><div style="font-size:11px;margin-top:4px;">Embeddings: ${t.embedding_calls||0} • Reputation: ${t.reputation_queries||0} • Artifacts: ${t.artifacts_processed||0}</div>`;
  }

  // ---------- Wiring ----------
  function wireEvents(){
    qs('btn-refresh')?.addEventListener('click', ()=> fetchLatestReport(false));
    qs('btn-export')?.addEventListener('click', exportMarkdown);
    qs('btn-monitoring')?.addEventListener('click', ()=> window.open(GRAFANA_URL, '_blank'));
    qs('btn-business')?.addEventListener('click', ()=> fetchLatestReport(true));
    qs('btn-upload')?.addEventListener('click', ()=> qs('file-input').click());
    qs('file-input')?.addEventListener('change', onCsvFilesSelected);
    qs('btn-override')?.addEventListener('click', applyOverride);
    qs('btn-detach')?.addEventListener('click', detachPanel);
    qs('btn-push-slack')?.addEventListener('click', ()=> pushReport(['slack']));
    qs('btn-push-teams')?.addEventListener('click', ()=> pushReport(['teams']));
    qs('btn-push-webhook')?.addEventListener('click', ()=>{
      const url = prompt('Webhook URL?'); if(url) pushReport(['webhook'], url);
    });
    qs('btn-push-whatsapp')?.addEventListener('click', ()=> pushReport(['whatsapp']));
    qs('btn-hash')?.addEventListener('click', fetchReportHash);

    const toggle = qs('btn-toggle-view');
    if(toggle){
      toggle.setAttribute('data-mode', VIEW_MODE);
      toggle.textContent = `View: ${VIEW_MODE==='top'?'Top':'All'}`;
      applyViewModeIndicator(toggle);
      toggle.addEventListener('click', ()=>{
        VIEW_MODE = toggle.getAttribute('data-mode')==='top' ? 'all' : 'top';
        localStorage.setItem('view_mode', VIEW_MODE);
        PAGE=1;
        toggle.setAttribute('data-mode', VIEW_MODE);
        toggle.textContent = `View: ${VIEW_MODE==='top'?'Top':'All'}`;
        applyViewModeIndicator(toggle);
        renderArtifacts();
      });
    }

    qs('page-prev')?.addEventListener('click', ()=>{
      if(REPORT && REPORT.meta){ const p=REPORT.meta.page||1; if(p>1) fetchPage(p-1); }
      else if(PAGE>1){ PAGE--; renderArtifacts(); }
    });
    qs('page-next')?.addEventListener('click', ()=>{
      if(REPORT && REPORT.meta){ const p=REPORT.meta.page||1; const tp=REPORT.meta.total_pages||1; if(p<tp) fetchPage(p+1); }
      else { PAGE++; renderArtifacts(); }
    });
    qs('page-size')?.addEventListener('change', ()=>{ PAGE_SIZE=parseInt(qs('page-size').value,10)||100; PAGE=1; renderArtifacts(); });

    // NLP
    const nlpBtn = qs('btn-nlp');
    if(nlpBtn){
      nlpBtn.addEventListener('click', async ()=>{
        const q = qs('nlp-input').value.trim();
        if(!q) return;
        nlpBtn.disabled=true;
        const orig=nlpBtn.textContent;
        nlpBtn.textContent='Running...';
        try {
          const res=await runNlpQuery(q);
          pushNlpHistory(q);
          const panel = qs('detail-nlp');
          if(panel) panel.innerHTML = `<pre style="font-size:11px;white-space:pre-wrap;">${escapeHtml(JSON.stringify(res,null,2))}</pre>`;
          switchTab('nlp');
        } catch(err){ safeNotify('NLP failed: '+err.message,'error'); }
        finally { nlpBtn.disabled=false; nlpBtn.textContent=orig; }
      });
      renderNlpHistory();
    }
    const hist = qs('nlp-history');
    if(hist){
      hist.addEventListener('change', ()=>{ const v=hist.value; if(v) qs('nlp-input').value=v; });
    }

    // Tabs
    const tabF = qs('tab-factors'); const tabN = qs('tab-nlp');
    if(tabF && tabN){
      tabF.addEventListener('click', ()=>switchTab('factors'));
      tabN.addEventListener('click', ()=>switchTab('nlp'));
      const saved = localStorage.getItem('detail_tab') || 'factors';
      switchTab(saved);
    }

    // Sorting
    document.querySelector('.grid-header')?.addEventListener('click',(e)=>{
      const txt = e.target.textContent.trim().toLowerCase();
      if(txt==='risk') toggleSort('risk');
      else if(txt==='hosts') toggleSort('hosts');
    });

    // Filters
    const savedFilter = localStorage.getItem('filter_chip') || 'chip-all';
    ['chip-all','chip-high','chip-rare','chip-multi'].forEach(id=>{
      const el=qs(id); if(!el) return;
      el.addEventListener('click', ()=>{
        document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
        el.classList.add('active');
        localStorage.setItem('filter_chip', id);
        renderArtifacts();
      });
    });
    if(qs(savedFilter)){
      document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
      qs(savedFilter).classList.add('active');
    }

    qs('search-input')?.addEventListener('input', ()=> renderArtifacts());

    const huntSessionInput = qs('hunt-session-id');
    if(huntSessionInput && !huntSessionInput.value){
      huntSessionInput.value = `hunt-${Date.now()}`;
    }
    qs('btn-hunt-start')?.addEventListener('click', startHunt);
    qs('btn-hunt-refresh')?.addEventListener('click', ()=>{
      const sid = (qs('hunt-session-id')?.value||'').trim();
      fetchHuntProgress(sid).catch(err=> safeNotify('Progress error: '+err.message,'error'));
    });
    qs('btn-hunt-download')?.addEventListener('click', ()=> downloadHuntReport('markdown'));

    // Auto refresh
    qs('auto-refresh')?.addEventListener('change', scheduleAuto);
  }

  // ---------- Init ----------
  setInterval(refreshCostSummaryIfVisible, 10000);
  wireEvents();
  fetchLatestReport(false);
  initSSE();
  // Capability panel auto-refresh
  refreshCapabilities(true);
  setInterval(()=>refreshCapabilities(false), 15000);

  async function fetchPage(p){
    try {
      setStatus('Loading...');
      const params = new URLSearchParams();
      params.set('page', p);
      params.set('page_size', PAGE_SIZE);
      params.set('view', VIEW_MODE==='all'?'all':'top');
      const activeFilter = document.querySelector('.chip.active')?.dataset.filter;
      if(activeFilter && activeFilter!=='all') params.set('filter', activeFilter);
      const q = (qs('search-input')?.value||'').trim(); if(q) params.set('search', q);
      if(ACTIVE_SORT){
        params.set('sort', ACTIVE_SORT.key==='risk'?'risk':'hosts');
        params.set('dir', ACTIVE_SORT.dir===-1?'desc':'asc');
      }
      const r = await fetch(`${API_BASE}/artifacts/latest_report?${params.toString()}`, {headers:authHeaders()});
      if(!r.ok) throw new Error(await r.text());
      REPORT = await r.json();
      renderArtifacts();
      updateLastRefresh();
      setStatus('Ready');
    } catch(e){ console.error(e); setStatus('Error'); }
  }

})();
