export function FactorSimilarity(el){
  el.innerHTML = `<h2>Factor Similarity</h2>
  <input id="sim_q" placeholder="e.g. privilege escalation" size="40" />
  <button id="sim_btn">Search</button>
  <pre id="sim_box">Enter a query above.</pre>`;
  const q = el.querySelector('#sim_q');
  const btn = el.querySelector('#sim_btn');
  const box = el.querySelector('#sim_box');
  btn.onclick = async ()=>{
    if(!q.value) return;
    box.textContent = 'Searching...';
    const resp = await fetch(`/api/v1/query/factors?similar=${encodeURIComponent(q.value)}&limit=10`,{
      headers: authHeaders()
    });
    if(!resp.ok){ box.textContent = 'Auth or server error'; return; }
    const data = await resp.json();
    box.textContent = JSON.stringify(data.results, null, 2);
  };
}

function authHeaders(){
  const key = localStorage.getItem('apiKey');
  return key ? { 'x-api-key': key } : {};
}
