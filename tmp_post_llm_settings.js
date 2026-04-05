const fetch = require('node-fetch');
(async()=>{
  const url = 'http://127.0.0.1:8080/api/v1/llm/settings';
  const payload = { ollama_base_url: 'http://127.0.0.1:11434', ollama_model: 'llama3:8b' };
  try{
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key':'devkey123' }, body: JSON.stringify(payload) });
    console.log('Status', r.status);
    const j = await r.json(); console.log('JSON:', j);
  }catch(e){ console.error('ERR', e.message); }
})();