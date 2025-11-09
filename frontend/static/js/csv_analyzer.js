// csv_analyzer.js - Production CSV Analyzer logic
// Single, cleaned implementation with severity sort, inline details, persistence and simple resizing
(function(){
  try { window.__csvReady = true; } catch(_){ }
  window.parseTabular = window.parseTabular || { ensureXlsxLib: function(){} };
  var FILTER_MODE = localStorage.getItem('csv_filter_mode') || 'all';
  var SELECTED_ROWS = new Set();
  // Expose selected rows for external actions (e.g., Send to Identity Graph)
  Object.defineProperty(window, 'csvSelectedRows', {
    get: function(){ try{ var list = window.LAST_RESULTS||[]; return Array.from(SELECTED_ROWS).map(function(idx){ return list[idx]; }); }catch(_){ return []; } },
    configurable: true
  });

  function verdictPassFail(v){ try{ var s=String(v||'').toUpperCase().trim(); if(!s) return 'NEUTRAL'; if(s.includes('GOOD')||s.includes('BENIGN')||s.includes('CONTROLLED')) return 'PASS'; if(s.includes('MALICIOUS')||s.includes('SUSPICIOUS')||s.includes('THREAT')) return 'FAIL'; return 'NEUTRAL'; }catch(_){ return 'NEUTRAL'; } }

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
      var explain = document.createElement('button'); explain.className='btn'; explain.innerText='Fetch Explain'; explain.disabled = !(row && row.raw && (row.raw.event_id||row.raw.EventID));
      // Always allow a client-side explain: if event_id exists fetch server explain, otherwise synthesize a local explain
      explain.disabled = false;
      explain.addEventListener('click', async function(){
        try{
          var eid = row && row.raw && (row.raw.event_id||row.raw.EventID);
          if(eid){
            try{
              var r = await fetch('/api/v1/decisions/'+encodeURIComponent(eid)+'/explain',{ headers: {...authHeaders()} });
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
      var path = document.createElement('button'); path.className='btn'; path.style.marginLeft='6px'; path.innerText='Per-row Deep Explain'; path.addEventListener('click', function(){ try{ localStorage.setItem('csv_deep_row', String(index)); localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS||[])); window.open('/static/csv_deep_analysis.html','_blank'); }catch(_){ } }); btns.appendChild(path);
      var graph = document.createElement('button'); graph.className='btn'; graph.style.marginLeft='6px'; graph.innerText='View Attack Path'; graph.addEventListener('click', function(){ try{ var node = row.host?('host:'+row.host):(row.process_name?('process:'+row.process_name):(row.sha256?('hash:'+row.sha256):null)); window.open('/static/graph_explain.html'+(node?('?node='+encodeURIComponent(node)):''),'_blank'); }catch(_){ } }); btns.appendChild(graph);
      inner.appendChild(btns);
      // threat intel
      try{ var ti=document.createElement('div'); ti.style.marginTop='8px'; var sha=row && row.sha256; var links=[]; if(sha){ links.push('<a target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/'+encodeURIComponent(sha)+'">VirusTotal</a>'); links.push('<a target="_blank" rel="noopener" href="https://www.joesandbox.com/search?q='+encodeURIComponent(sha)+'">Joe Sandbox</a>'); } if(links.length) ti.innerHTML='Threat Intel: '+links.join(' · '), inner.appendChild(ti);}catch(_){ }
      cell.appendChild(inner); container.appendChild(cell); tr.parentNode.insertBefore(container, tr.nextSibling);
    }catch(e){ console.warn('insertInlineDetailsAfter', e); }
  }

  function renderTableFromResults(){
    try{
      var t = document.getElementById('tbody'); if(!t) return; var list = window.LAST_RESULTS||[];
      var filtered = list.filter(function(r){ var pf = verdictPassFail(r && r.verdict); if(FILTER_MODE==='suspicious') return pf==='FAIL'; if(FILTER_MODE==='passed') return pf==='PASS'; return true; });
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
                  case 'verdict': return rec.verdict || '';
                  case 'dread': return (rec && rec._dread && (typeof rec._dread.score !== 'undefined') ? rec._dread.score : 0) || 0;
                  case 'signals': return (rec && rec.factors ? rec.factors.join(',') : '');
                  default: return (rec && (rec[colKey]||'')) || '';
                }
              }catch(_){ return ''; }
            }
            filtered.sort(function(a,b){ var va=getColValue(a, colName); var vb=getColValue(b, colName); if(typeof va==='number' && typeof vb==='number') return (va-vb)*dir; return String(va).localeCompare(String(vb))*dir; });
          }
        }catch(_){ }
      }
      if(!filtered.length){ t.innerHTML='<tr><td colspan="8" class="empty-hint">No results</td></tr>'; return; }
      var max=1000; var rows = filtered.slice(0,max).map(function(r){ var origIdx=(window.LAST_RESULTS||[]).indexOf(r); var verdict=r&&r.verdict||''; var signals=(r&&r.factors&&r.factors.join(', '))||''; var checked=SELECTED_ROWS.has(origIdx)?' checked':''; var vclass=''; try{ var pf=verdictPassFail(verdict); if(pf==='PASS') vclass='verdict-pass'; else if(pf==='FAIL') vclass='verdict-fail'; else vclass='verdict-medium'; }catch(_){ }
        return '<tr class="'+vclass+'" data-row="'+origIdx+'">'+
          '<td>'+wrapCell(r&&r.process_name||'')+'</td>'+
          '<td>'+wrapCell(r&&r.file_path||'')+'</td>'+
          '<td>'+wrapCell(r&&r.sha256||'')+'</td>'+
          '<td>'+wrapCell(r&&r.host||'')+'</td>'+
          '<td>'+wrapCell(verdict)+'</td>'+
          '<td>'+wrapCell((r&&r._dread&&r._dread.score)||'')+'</td>'+
          '<td>'+wrapCell(signals)+'</td>'+
          '<td><input type="checkbox" class="csv-row-select" data-idx="'+origIdx+'"'+checked+' style="margin-right:6px"/>'+
            '<button class="btn" style="padding:4px 10px" onclick="window.openCsvRowDetails('+origIdx+')" title="Why flagged / details">Details</button></td>'+
        '</tr>'; }).join('');
      t.innerHTML = rows;
      try{ var expanded = localStorage.getItem('csv_expanded_row'); if(expanded && expanded!=='null'){ var tr=t.querySelector('tr[data-row="'+expanded+'"]'); if(tr) insertInlineDetailsAfter(tr, parseInt(expanded,10)); } }catch(_){ }
      try{ var sum=document.getElementById('rowsSummary'); if(sum) sum.textContent='Showing '+Math.min(filtered.length,max)+' of '+list.length; }catch(_){ }
      var ready=document.getElementById('csv_results_ready'); if(ready) ready.style.display='block'; window.dispatchEvent(new Event('csv-results-ready'));
      // update ARIA live status
      try{ var live=document.getElementById('csv_status_live'); if(live) live.textContent = 'Showing '+Math.min(filtered.length,max)+' of '+list.length + ' rows'; }catch(_){ }
    }catch(e){ console.warn('renderTableFromResults', e); }
  }

  window.ensureTbodyRowsFromList = function(list){ window.LAST_RESULTS = list||[]; renderTableFromResults(); };

  // load persisted last results if fresh
  try{
    var lastRaw = JSON.parse(localStorage.getItem('csv_last_results')||'null');
    var lastTs = parseInt(localStorage.getItem('csv_last_results_ts')||'0',10)||0;
    var TTL_MIN = 60; // minutes default ttl
    if(lastRaw && Array.isArray(lastRaw) && lastTs){ var age = (Date.now()/1000 - lastTs); if(age < TTL_MIN*60){ try{ window.LAST_RESULTS = lastRaw; }catch(_){ } } else { try{ localStorage.removeItem('csv_last_results'); localStorage.removeItem('csv_last_results_ts'); }catch(_){ } } }
  }catch(_){ }

  function mapRawToRecord(raw){ try{ var proc=raw.process_name||raw.process||'unknown'; var path=raw.file_path||raw.path||''; var sha=raw.sha256||raw.SHA256||''; var host=raw.host||raw.hostname||''; var verdict = raw.verdict||''; if(!verdict) verdict = inferVerdictFromRaw(raw) || ''; var rec={process_name:proc,file_path:path,sha256:sha,host:host,verdict:verdict,raw:raw}; rec.factors = rec.factors||[]; // simple factor heuristics
    try{ var p = String(proc||'').toLowerCase(); if(p.includes('rundll32')||p.includes('regsvr32')||p.includes('mshta')) rec.factors.push('lolbin'); }catch(_){ }
    if((/\\windows\\system32/i).test(String(path||''))) rec.factors.push('unsigned_sensitive_path');
    if((String(verdict||'').toUpperCase().includes('SUSPICIOUS') || String(verdict||'').toUpperCase().includes('MALICIOUS'))) rec.factors.push('novel_global');
    // compute DREAD with raw numeric hints
    rec._dread = computeDreadBreakdown(rec.factors, raw);
    rec._dread_text = rec._dread.score + ' (' + rec._dread.level + ')';
    return rec;}catch(e){ return {process_name:'unknown',file_path:'',sha256:'',host:'',verdict:'',factors:[],_dread:{score:0},raw:raw}; }
  }

  // Try to infer a verdict from raw parsed row values (Excel/CSV with different column names)
  function inferVerdictFromRaw(raw){
    try{
      if(!raw || typeof raw !== 'object') return '';
      // common columns
      const vfields = ['verdict','Verdict','decision','Decision','result','Result','tag','Tag'];
      for(const f of vfields){ if(raw[f]){ const s=String(raw[f]).trim(); if(s) return s; } }
      // boolean flags
      const trueVals = ['true','1','yes','y'];
      if(raw.malicious || raw.Malicious || raw.is_malicious){ return 'MALICIOUS'; }
      if(raw.suspicious || raw.Suspicious || raw.is_suspicious){ return 'SUSPICIOUS'; }
      // Cyberstash-specific hints
      if(raw.threatName || raw.threatname || raw.ThreatName){ var tn = String(raw.threatName||raw.threatname||raw.ThreatName||'').toLowerCase(); if(tn && (tn.includes('suspicious')||tn.includes('malicious')||tn.includes('trojan')||tn.includes('ransom'))) return tn.includes('malicious')?'MALICIOUS':'SUSPICIOUS'; }
      if(raw.flagName || raw.flagname || raw.FlagName){ var fn = String(raw.flagName||raw.flagname||raw.FlagName||'').toLowerCase(); if(fn && (fn.includes('probably bad')||fn.includes('malicious')||fn.includes('suspicious'))) return fn.includes('malicious')?'MALICIOUS':'SUSPICIOUS'; }
      if(raw.avPositives || raw.av_positives || raw.avPos){ var av = parseInt(String(raw.avPositives||raw.av_positives||raw.avPos||0).replace(/[^0-9]/g,''),10); if(!isNaN(av) && av>3) return 'MALICIOUS'; if(!isNaN(av) && av>0) return 'SUSPICIOUS'; }
      if(raw.threatWeight || raw.threatweight || raw.ThreatWeight){ var tw = parseFloat(String(raw.threatWeight||raw.threatweight||raw.ThreatWeight||0).replace(/[^0-9\.|\-]/g,'')); if(!isNaN(tw) && tw>=7) return 'MALICIOUS'; if(!isNaN(tw) && tw>=4) return 'SUSPICIOUS'; }
      // heuristic: if scores exist and high, mark suspicious
      const scoreKeys = ['score','risk_score','confidence','Confidence'];
      for(const k of scoreKeys){ if(raw[k]){ const n = parseFloat(String(raw[k]).replace(/[^0-9\.\-]/g,'')); if(!isNaN(n) && n>6) return 'SUSPICIOUS'; } }
      // fallback: strings containing suspicious tokens
      const text = Object.values(raw).join(' ').toLowerCase();
      if(text.includes('suspicious') || text.includes('malicious') || text.includes('threat') || text.includes('c2') || text.includes('ransom')) return 'SUSPICIOUS';
      return '';
    }catch(_){ return ''; }
  }

  function fallbackTextParse(file){ try{ var reader=new FileReader(); reader.onload=function(ev){ try{ var text=ev.target.result||''; var lines=text.split(/\r?\n/).filter(Boolean); var headers=(lines[0]||'').split(','); var list=[]; for(var i=1;i<Math.min(lines.length,1200);i++){ var cols=lines[i].split(','); var raw={}; headers.forEach(function(h,idx){ raw[h]=cols[idx]; }); list.push(mapRawToRecord(raw)); } window.LAST_RESULTS = list.length?list:[{process_name:'unknown',file_path:'/tmp',sha256:'dead',host:'host',verdict:'SUSPICIOUS',factors:[],_dread:{score:4}}]; try{ localStorage.setItem('csv_last_results', JSON.stringify(window.LAST_RESULTS)); }catch(_){ } renderTableFromResults(); }catch(e){ console.warn('file read parse', e); } }; reader.readAsText(file); }catch(e){ console.warn('fallback parse failed', e); } }

  function loadFile(){ var inp=document.getElementById('fileInput'); if(!inp||!inp.files||!inp.files.length) return; var f=inp.files[0]; try{ if(window.parseTabular && window.parseTabular.clientSideAggregate){ window.parseTabular.clientSideAggregate([f]).then(function(out){ try{ var rows=(out&&out.rows)||[]; var list=rows.map(mapRawToRecord); window.LAST_RESULTS=list; try{ localStorage.setItem('csv_last_results', JSON.stringify(list)); }catch(_){ } renderTableFromResults(); }catch(e){ console.warn('aggregate map error', e); } }).catch(function(err){ console.warn('client aggregate failed', err); fallbackTextParse(f); }); } else fallbackTextParse(f); }catch(e){ console.warn('file parse error', e); fallbackTextParse(f); } }

  function authHeaders(){ try{ var k=localStorage.getItem('apiKey')||'devkey123'; return {'x-api-key':k}; }catch(_){ return {'x-api-key':'devkey123'} } }

  window.openCsvRowDetails = function(index){ try{ var tr=document.querySelector('#tbody tr[data-row="'+index+'"]'); if(!tr) return; var next=tr.nextElementSibling; if(next && next.classList && next.classList.contains('csv-inline-details')){ next.parentNode.removeChild(next); try{ localStorage.removeItem('csv_expanded_row'); }catch(_){ } return; } try{ var old=document.querySelector('#tbody tr.csv-inline-details'); if(old) old.parentNode.removeChild(old); }catch(_){} insertInlineDetailsAfter(tr,index); try{ localStorage.setItem('csv_expanded_row', String(index)); }catch(_){ } }catch(e){ console.warn('openCsvRowDetails', e); } };

  async function postDisposition(rowIndex, disposition){ try{ var list=window.LAST_RESULTS||[]; var rec=list[rowIndex]||{}; var raw=rec.raw||{}; var body=[{ event_id: raw.event_id||raw.EventID||null, row_index: rowIndex, disposition: disposition, source:'csv', ts: Date.now()/1000 }]; var r=await fetch('/api/v1/telemetry/dispositions', { method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(body) }); if(r.ok){ try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Saved disposition: '+disposition,2500);}catch(_){ } }else{ try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Disposition failed: '+r.status,3000);}catch(_){ } } }catch(e){ console.warn('postDisposition', e); } }

  async function applyBulkDisposition(disposition){ try{ if(!SELECTED_ROWS.size) return; var payload=[]; SELECTED_ROWS.forEach(function(idx){ var rec=(window.LAST_RESULTS||[])[idx]||{}; var raw=rec.raw||{}; payload.push({ event_id: raw.event_id||raw.EventID||null, row_index: idx, disposition: disposition, source:'csv', ts: Date.now()/1000 }); }); var r=await fetch('/api/v1/telemetry/dispositions',{ method:'POST', headers:{ 'Content-Type':'application/json', ...authHeaders() }, body: JSON.stringify(payload)}); if(r.ok){ try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Applied '+disposition+' to '+payload.length+' rows',3500);}catch(_){ } } else { try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Bulk disposition failed: '+r.status,3000);}catch(_){ } } SELECTED_ROWS.clear(); renderTableFromResults(); }catch(e){ console.warn('applyBulkDisposition', e); } }

  async function ingestSelectedRows(){ try{ if(!SELECTED_ROWS.size) return; var payload=[]; SELECTED_ROWS.forEach(function(idx){ var rec=(window.LAST_RESULTS||[])[idx]||{}; var raw=rec.raw||{}; payload.push({ row_index: idx, raw: raw }); }); var r = await fetch('/api/v1/ingest/csv_rows', { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify(payload) }); if(r.ok){ var j = await r.json(); try{ (j||[]).forEach(function(item){ try{ var idx = item.row_index; var eid = item.event_id; var rec=(window.LAST_RESULTS||[])[idx]; if(rec && rec.raw){ rec.raw.event_id = eid; } }catch(_){ } }); if(window.notifications && window.notifications.showToast) window.notifications.showToast('Ingested '+j.length+' rows',2500); }catch(_){ } renderTableFromResults(); SELECTED_ROWS.clear(); } else { try{ if(window.notifications&&window.notifications.showToast) window.notifications.showToast('Ingest failed: '+r.status,3500); }catch(_){ } } }catch(e){ console.warn('ingestSelectedRows', e); } }

  function delegateClicks(e){ try{ if(e.target && e.target.classList && e.target.classList.contains('csv-row-select')){ var idx=parseInt(e.target.getAttribute('data-idx'),10); if(!isNaN(idx)){ if(e.target.checked) SELECTED_ROWS.add(idx); else SELECTED_ROWS.delete(idx); renderTableFromResults(); } return; } if(e.target && e.target.getAttribute && e.target.getAttribute('title')==='Why flagged / details'){ var tr=e.target.closest('tr[data-row]'); if(tr){ var idx=parseInt(tr.getAttribute('data-row'),10); if(!isNaN(idx)) window.openCsvRowDetails(idx); } } }catch(_){ } }

  function init(){ try{ document.getElementById('btnLoad').addEventListener('click', loadFile); document.getElementById('btnExplain').addEventListener('click', function(){ document.getElementById('csvDrillModal').style.display='flex'; }); document.getElementById('btnAnalyzePipeline').addEventListener('click', function(){ /*noop*/ }); document.getElementById('btnFilterAll').addEventListener('click', function(){ FILTER_MODE='all'; localStorage.setItem('csv_filter_mode','all'); renderTableFromResults(); }); document.getElementById('btnFilterSuspicious').addEventListener('click', function(){ FILTER_MODE='suspicious'; localStorage.setItem('csv_filter_mode','suspicious'); renderTableFromResults(); }); document.getElementById('btnFilterPassed').addEventListener('click', function(){ FILTER_MODE='passed'; localStorage.setItem('csv_filter_mode','passed'); renderTableFromResults(); }); document.addEventListener('click', delegateClicks); document.getElementById('bulkGood').addEventListener('click', function(){ applyBulkDisposition('good'); }); document.getElementById('bulkReview').addEventListener('click', function(){ applyBulkDisposition('review'); }); document.getElementById('bulkThreat').addEventListener('click', function(){ applyBulkDisposition('threat'); }); document.getElementById('bulkSelectAll').addEventListener('click', function(){ Array.from(document.querySelectorAll('#tbody tr[data-row] .csv-row-select')||[]).forEach(function(cb){ cb.checked=true; SELECTED_ROWS.add(parseInt(cb.getAttribute('data-idx'),10)); }); renderTableFromResults(); }); document.getElementById('bulkClear').addEventListener('click', function(){ SELECTED_ROWS.clear(); renderTableFromResults(); });
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

  })();
