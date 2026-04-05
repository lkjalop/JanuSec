const http=require('http');
http.get('http://127.0.0.1:8080/static/csv_analyzer.html', res=>{
  let d=''; res.on('data', c=> d+=c); res.on('end', ()=>{
    const inline = [];
    const re = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
    let m; let idx=0;
    while((m=re.exec(d))!==null){ const attrs = m[1]; const src = /src=["']([^"']+)["']/.exec(attrs); if(!src){ inline.push({idx: idx++, code: m[2].trim().slice(0,2000), full: m[2]}); } }
    console.log('Found', inline.length, 'inline scripts');
    for(const s of inline){
      console.log('\n--- Inline script', s.idx, 'length', s.full.length, '---');
      try{
        new Function(s.full);
        console.log('  parse OK');
      }catch(e){ console.log('  parse ERROR:', e && e.message); console.log('  snippet:', s.full.slice(-200)); }
    }
  });
}).on('error', e=>{ console.error(e); process.exit(1); });