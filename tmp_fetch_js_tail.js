const http = require('http');
http.get('http://127.0.0.1:8080/static/js/csv_analyzer.js', res=>{
  let data='';
  res.on('data', c=> data+=c.toString());
  res.on('end', ()=>{
    const lines = data.split(/\r?\n/);
    const tail = lines.slice(-200).join('\n');
    console.log(tail);
  });
}).on('error', e=>{ console.error('fetch error', e); process.exit(1); });