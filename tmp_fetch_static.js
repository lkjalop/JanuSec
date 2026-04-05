const http = require('http');
const urls = ['/static/js/parse_tabular.js','/static/js/csv_ingest_shared.js','/static/js/csv_analyzer.js'];
(async()=>{
  for(const u of urls){
    await new Promise((res,rej)=>{
      http.get({host:'localhost',port:8080,path:u}, r=>{
        console.log('\n====',u,r.statusCode);
        let s=''; r.on('data',c=>s+=c); r.on('end',()=>{ console.log(s.split('\n').slice(0,80).join('\n')); res(); });
      }).on('error', e=>{ console.log('ERR',u,e.message); res(); });
    });
  }
})();