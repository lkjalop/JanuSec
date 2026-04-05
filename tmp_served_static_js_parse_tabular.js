// Shared tabular parsing helpers (CSV + optional XLSX + gzip) 
// Provides: ensureXlsxLib, parseCsvText, parseXlsxArrayBuffer, maybeDecompressFile, clientSideAggregate
/* eslint-disable no-unused-vars */
(function(global){
  function detectDelimiter(sample){
    const cand=[',','\t',';','|']; let best=',',bestScore=-1; for(const c of cand){ const score=(sample.match(new RegExp(c,'g'))||[]).length; if(score>bestScore){bestScore=score;best=c;} } return best;
  }
  function splitCsvLine(line, expected, delim=','){
    const out=[]; let cur=''; let inQ=false; const d=delim==='\t'?'\t':delim; for(let i=0;i<line.length;i++){ const ch=line[i]; if(ch==='"'){ if(inQ && line[i+1]==='"'){ cur+='"'; i++; } else inQ=!inQ; } else if(ch===d && !inQ){ out.push(cur); cur=''; } else { cur+=ch; } } out.push(cur); if(typeof expected==='number') while(out.length<expected) out.push(''); return out.map(x=>x.trim());
  }
  function parseCsvText(text){ const lines=text.split(/\r?\n/).filter(l=>l.trim().length>0); if(!lines.length) return []; const delim=detectDelimiter(lines.slice(0,50).join('\n')); const headers=splitCsvLine(lines[0], undefined, delim); const rows=[]; for(let i=1;i<lines.length;i++){ const cols=splitCsvLine(lines[i], headers.length, delim); const obj={}; headers.forEach((h,idx)=> obj[h]=cols[idx]); rows.push(obj); } return rows; }
  async function ensureXlsxLib(timeoutMs = 8000){
    if(global.XLSX && !global.XLSX.__placeholder && global.XLSX.read && global.XLSX.utils) return true;
    // Prefer a local vendor copy when present (faster and avoids CDN/CSP issues)
    const sources = [
      '/static/vendor/xlsx.full.min.js',
      'https://cdn.jsdelivr.net/npm/xlsx@0.19.3/dist/xlsx.full.min.js',
      'https://unpkg.com/xlsx@0.19.3/dist/xlsx.full.min.js'
    ];
    for(const src of sources){
      const ok = await new Promise((resolve)=>{
        if(global.XLSX && global.XLSX.read) return resolve(true);
        const script = document.createElement('script');
        let settled = false;
        script.src = src;
        script.async = true;
  script.onload = () => { if(settled) return; settled = true; const ok = !!global.XLSX && !global.XLSX.__placeholder && !!global.XLSX.read; resolve(ok); };
        script.onerror = () => { if(settled) return; settled = true; resolve(false); };
        document.head.appendChild(script);
        setTimeout(()=>{ if(settled) return; settled = true; const ok = !!global.XLSX && !global.XLSX.__placeholder && !!global.XLSX.read; resolve(ok); }, timeoutMs);
      });
      if(ok) return true;
    }
    return !!(global.XLSX && !global.XLSX.__placeholder && global.XLSX.read);
  }

  async function parseXlsxArrayBuffer(ab){
    try{
      const ok = await ensureXlsxLib();
      if(!ok || !global.XLSX || !global.XLSX.read) throw new Error('XLSX library unavailable');
      const wb = global.XLSX.read(ab, { type:'array' });
      const sheetName = wb.SheetNames && wb.SheetNames[0];
      const sheet = sheetName ? wb.Sheets[sheetName] : null;
      if(!sheet) return [];
      return global.XLSX.utils.sheet_to_json(sheet, { defval:'', raw:true });
    }catch(e){ throw new Error('XLSX parse failed: '+(e && e.message || e)); }
  }
  async function maybeDecompressFile(file){ if(file.name.endsWith('.gz')){ try{ const ds=new DecompressionStream('gzip'); const ab=await file.arrayBuffer(); const decompressed=await new Response(new Blob([ab]).stream().pipeThrough(ds)).arrayBuffer(); return new File([decompressed], file.name.replace(/\.gz$/,''), {type:'text/plain'}); }catch(e){ /* swallow */ } } return file; }
  async function clientSideAggregate(files, opts={}){ const aggregated=[]; const status=[]; const errors=[]; for(const f of files){ try{ const processed=await maybeDecompressFile(f); const name=processed.name.toLowerCase(); if(name.match(/\.(csv|tsv|log|txt)$/)){ const text=await processed.text(); const rows=parseCsvText(text); status.push(`${f.name}: ${rows.length} rows (csv)`); aggregated.push(...rows); } else if(name.match(/\.(xlsx|xlsm)$/)){ const ab=await processed.arrayBuffer(); const rows=await parseXlsxArrayBuffer(ab); status.push(`${f.name}: ${rows.length} rows (xlsx)`); aggregated.push(...rows); } else if(name.match(/\.(xls|ods|zip)$/)){ status.push(`${f.name}: server parse required`); } else { status.push(`${f.name}: skipped (unsupported)`); } } catch(e){ errors.push(`${f.name}: ${(e.message||e)}`); } } return { rows: aggregated, status, errors }; }
  function summarizeParsed(rows){ if(!rows.length) return 'No tabular rows parsed client-side'; const cols=Object.keys(rows[0]||{}); return `Client parsed ${rows.length} rows, ${cols.length} columns`; }
  global.parseTabular = { ensureXlsxLib, parseCsvText, parseXlsxArrayBuffer, maybeDecompressFile, clientSideAggregate, summarizeParsed };
})(window);
