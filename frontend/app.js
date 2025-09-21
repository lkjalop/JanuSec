async function refresh(){
  try {
    const d = await fetch('/api/v1/decisions/recent').then(r=>r.json());
    document.getElementById('decisions').textContent = JSON.stringify(d.decisions, null, 2);
  } catch(e){ console.error(e); }
  try {
    const a = await fetch('/api/v1/alerts/recent').then(r=>r.json());
    document.getElementById('alerts').textContent = JSON.stringify(a.alerts, null, 2);
  } catch(e){ console.error(e); }
}
async function loadChain(){
  const id = document.getElementById('chainId').value; if(!id) return;
  try {
    const c = await fetch('/api/v1/chain/'+id).then(r=>r.json());
    document.getElementById('chainBox').textContent = JSON.stringify(c.chain, null, 2);
  } catch(e){ console.error(e); }
}
refresh();
setInterval(refresh, 10000);
