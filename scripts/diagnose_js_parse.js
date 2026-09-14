const fs = require('fs');
const path = 'd:/AI/Threat_thy_sniffer/frontend/static/js/csv_analyzer.js';
const s = fs.readFileSync(path,'utf8');
function testLen(n){ try{ new Function(s.slice(0,n)); return true; }catch(e){ return e; } }
let step = 2000; let i;
for(i=step;i<=s.length;i+=step){ let r=testLen(i); if(r!==true){ console.log('fail_at',i); console.log(r.toString()); break; } }
if(i> s.length){ let r=testLen(s.length); if(r===true){ console.log('full ok'); process.exit(0);} else { console.log('fail at end'); console.log(r.toString()); process.exit(1);} }
let lo=i-step, hi=i; while(lo+1<hi){ let mid=Math.floor((lo+hi)/2); let r=testLen(mid); if(r===true) lo=mid; else hi=mid; }
console.log('first_bad_at',hi);
console.log('context around bad:');
console.log(s.slice(Math.max(0,hi-200), Math.min(s.length, hi+200)));
console.log('--- EOF ---');
