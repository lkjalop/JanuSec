const fetch = require('node-fetch');
(async()=>{
  const url = 'http://127.0.0.1:8080/api/v1/insights/generate';
  const payload = {
    insight_type: 'tier1',
    provider: 'ollama',
    row: { process_name: 'bad.exe', host: 'host-01', verdict: 'suspicious', factors: ['process_injection','unsigned_binary'], row_index: 5 },
    pipeline_context: { request_id: 'test-tier1-ollama-002', overrides: { ollama_host: 'http://127.0.0.1:11434', ollama_model: 'llama3:8b', ollama_generate_path: '/api/generate' } }
  };
  try{
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key':'devkey123' }, body: JSON.stringify(payload) });
    console.log('Status', r.status);
    const j = await r.json(); console.log('JSON:', j);
  }catch(e){ console.error('ERR', e.message); }
})();