const fs = require('fs');
const vm = require('vm');
const path = require('path');
const target = process.argv[2];
if(!target){ console.error('Usage: node tmp_check_js_syntax.js <file>'); process.exit(2); }
try{
  const code = fs.readFileSync(target, 'utf8');
  // Try to compile as a Script to get accurate syntax errors
  new vm.Script(code, { filename: path.basename(target) });
  console.log('OK: parsed');
} catch (e){
  console.error('PARSE_ERROR');
  console.error(e && e.stack ? e.stack : String(e));
  process.exit(1);
}
