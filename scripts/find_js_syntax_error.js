const http = require('http');
const https = require('https');
const { URL } = require('url');
const fs = require('fs');

function fetch(url){
  return new Promise((res, rej)=>{
    const lib = url.startsWith('https:') ? https : http;
    lib.get(url, (r)=>{
      let body='';
      r.on('data', c=> body+=c.toString());
      r.on('end', ()=> res({ status:r.statusCode, body, headers:r.headers }));
    }).on('error', rej);
  });
}

(async ()=>{
  try{
    const base = process.env.BASE_URL || 'http://localhost:8080';
    const pageUrl = base + '/static/csv_analyzer.html';
    console.log('fetching', pageUrl);
    const pageResp = await fetch(pageUrl);
    if(pageResp.status !== 200){ console.error('page fetch failed', pageResp.status); process.exit(1); }
    const html = pageResp.body;
    const scriptSrcs = [];
    // naive script src extractor
    const re = /<script[^>]+src=["']([^"']+)["'][^>]*><\/script>/gi;
    let m;
    while((m=re.exec(html))!==null){ scriptSrcs.push(m[1]); }
    console.log('found', scriptSrcs.length, 'script tags');
    for(const src of scriptSrcs){
      let url = src;
      if(!/https?:\/\//.test(src)){
        url = base.replace(/\/$/, '') + '/' + src.replace(/^\//, '');
      }
      console.log('fetching script', url);
      const r = await fetch(url);
      if(r.status !== 200){ console.warn('script fetch failed', r.status, url); continue; }
      const body = r.body;
      try{
        new Function(body);
        console.log('parsed OK:', src);
      }catch(e){
        console.error('PARSE_ERROR in', src, '\n', e && e.stack? e.stack : e);
        // write file to disk for inspection
        try{ fs.writeFileSync('debug_bad_'+src.replace(/[^a-z0-9]/gi,'_')+'.js', body); }catch(_){ }
        process.exit(0);
      }
    }
    console.log('All scripts parsed OK');
  }catch(e){ console.error('failure', e.stack||e); process.exit(2); }
})();
