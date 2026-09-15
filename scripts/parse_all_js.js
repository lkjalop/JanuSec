const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'frontend', 'static', 'js');
function walk(dir){
  let files = [];
  for(const name of fs.readdirSync(dir)){
    const p = path.join(dir, name);
    const stat = fs.statSync(p);
    if(stat.isDirectory()) files = files.concat(walk(p));
    else if(p.endsWith('.js')) files.push(p);
  }
  return files;
}
const files = walk(dir);
let failed = 0;
for(const f of files){
  try{
    const s = fs.readFileSync(f,'utf8');
    new Function(s);
    console.log('OK', f.replace(process.cwd(),'').replace('\\','/'));
  }catch(e){
    failed++;
    console.error('PARSE_FAIL', f.replace(process.cwd(),'').replace('\\','/'), e && e.message ? e.message : e);
  }
}
console.log('Done. failures=', failed);
process.exit(failed?1:0);
