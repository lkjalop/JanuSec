// Shared CSV ingestion + mapping helpers for csv_analyzer, csv_multi, csv_deep
(function(){
  const CANONICAL_FIELDS = [
    { key: 'process_name', label: 'Process' },
    { key: 'file_path', label: 'File Path' },
    { key: 'hash', label: 'Hash / SHA256' },
    { key: 'user', label: 'User' },
    { key: 'host', label: 'Host' },
    { key: 'command_line', label: 'Command Line' },
    { key: 'parent_process', label: 'Parent Process' },
    { key: 'domain', label: 'Domain' },
    { key: 'ip', label: 'IP (Any)' },
    { key: 'ip_src', label: 'IP Source' },
    { key: 'ip_dst', label: 'IP Destination' },
    { key: 'email', label: 'Email' },
    { key: 'url', label: 'URL' },
  ];

  function authHeaders(){
    try{
      const key = localStorage.getItem('apiKey') || 'devkey123';
      return { 'x-api-key': key };
    }catch(_){
      return { 'x-api-key': 'devkey123' };
    }
  }

  function detectMapping(rows){
    if(!rows || !rows.length) return {};
    const mapping = {};
    const sample = rows[0];
    const headers = Object.keys(sample || {});
    const lower = {};
    headers.forEach(function(h){ lower[h.toLowerCase()] = h; });
    CANONICAL_FIELDS.forEach(function(field){
      const aliases = [field.key, field.key.replace('_',' '), field.key.replace('_','')];
      let matched = null;
      for(const alias of aliases){
        if(lower[alias]){ matched = lower[alias]; break; }
      }
      if(!matched){
        for(const header of headers){
          const h = header.toLowerCase();
          if(h.includes(field.key)){ matched = header; break; }
          if(field.key==='hash' && (h.includes('sha') || h.includes('hash'))){ matched = header; break; }
          if(field.key==='process_name' && (h.includes('process') || h.includes('exe'))){ matched = header; break; }
          if(field.key==='file_path' && (h.includes('path') || h.includes('file'))){ matched = header; break; }
        }
      }
      if(matched) mapping[field.key] = matched;
    });
    return mapping;
  }

  function ensureModal(){
    let modal = document.getElementById('csvMappingModal');
    if(modal) return modal;
    modal = document.createElement('div');
    modal.id = 'csvMappingModal';
    modal.style.position = 'fixed';
    modal.style.top = '0';
    modal.style.left = '0';
    modal.style.right = '0';
    modal.style.bottom = '0';
    modal.style.background = 'rgba(0,0,0,0.55)';
    modal.style.display = 'none';
    modal.style.zIndex = '3000';
    modal.innerHTML = '<div style="max-width:520px;margin:40px auto;background:var(--bg-secondary,#1D1F2B);border:1px solid var(--border,#2d3245);border-radius:10px;padding:16px;color:var(--text-primary,#fff);font-family:Inter,Segoe UI,sans-serif;">'
      + '<div style="display:flex;justify-content:space-between;align-items:center;">'
      + '<h3 style="margin:0;font-size:16px;">Column Mapping</h3>'
      + '<button id="csvMappingClose" style="border:none;background:transparent;color:#fff;font-size:18px;cursor:pointer;">&times;</button>'
      + '</div>'
      + '<div id="csvMappingBody" style="max-height:420px;overflow:auto;margin-top:12px;"></div>'
      + '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:12px;">'
      + '<button id="csvMappingCancel" class="btn">Cancel</button>'
      + '<button id="csvMappingSave" class="btn btn-primary">Save Mapping</button>'
      + '</div>'
      + '</div>';
    document.body.appendChild(modal);
    document.getElementById('csvMappingClose').onclick = function(){ modal.style.display = 'none'; };
    document.getElementById('csvMappingCancel').onclick = function(){ modal.style.display = 'none'; };
    return modal;
  }

  function openMappingEditor(options){
    const modal = ensureModal();
    const headers = options.headers || [];
    const current = options.mapping || {};
    const body = document.getElementById('csvMappingBody');
    const selects = {};
    body.innerHTML = CANONICAL_FIELDS.map(function(field){
      const selectId = 'map_'+field.key;
      return '<div style="margin-bottom:10px;">'
        + '<label style="font-size:12px;color:var(--text-muted,#9ca4b0);display:block;margin-bottom:4px;">'+field.label+'</label>'
        + '<select id="'+selectId+'" style="width:100%;padding:6px;border-radius:6px;background:var(--bg-tertiary,#151826);border:1px solid var(--border,#2d3245);color:inherit;">'
        + '<option value="">-- none --</option>'
        + headers.map(function(h){
            const selected = (current[field.key] === h) ? 'selected' : '';
            return '<option value="'+h+'" '+selected+'>'+h+'</option>';
          }).join('')
        + '</select></div>';
    }).join('');
    modal.style.display = 'block';
    document.getElementById('csvMappingSave').onclick = function(){
      const mapping = {};
      CANONICAL_FIELDS.forEach(function(field){
        const el = document.getElementById('map_'+field.key);
        if(el && el.value) mapping[field.key] = el.value;
      });
      modal.style.display = 'none';
      if(typeof options.onSave === 'function'){
        options.onSave(mapping);
      }
    };
  }

  async function ingestRows(options){
    const body = {
      rows: options.rows || [],
      mapping: options.mapping || {},
      source: options.source || 'csv_ingest',
      limit: options.limit || undefined,
    };
    const resp = await fetch('/api/v1/csv/ingest_rows', {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authHeaders(), options.headers || {}),
      body: JSON.stringify(body),
    });
    if(!resp.ok){
      const text = await resp.text();
      throw new Error('ingest_rows failed: '+text);
    }
    return await resp.json();
  }

  window.csvIngest = {
    detectMapping,
    openMappingEditor,
    ingestRows,
  };
})();
