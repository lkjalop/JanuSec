const fetch = require('node-fetch');
(async()=>{
  const url = 'http://127.0.0.1:8080/api/v1/compliance/summarize';
  const payload = { provider: 'ollama', text: 'short test', max_tokens: 32 };
  try{
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key':'devkey123' }, body: JSON.stringify(payload) });
    console.log('Status', r.status);
    const text = await r.text(); console.log('Body:', text.slice(0,1000));
  }catch(e){ console.error('ERR', e.message); }
})();