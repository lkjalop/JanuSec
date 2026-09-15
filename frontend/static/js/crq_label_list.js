async function fetchLabels(limit=200){
    try{
        const res = await fetch(`/api/v1/crq/labels?limit=${limit}`);
        if(!res.ok) return [];
        const j = await res.json();
        return j.labels || [];
    }catch(e){ return []; }
}

function renderLabels(containerId, labels){
    const c = document.getElementById(containerId);
    if(!c) return;
    if(!labels || labels.length===0){ c.innerText='No labels yet'; return; }
    const tbl = document.createElement('table');
    tbl.style.width='100%';
    tbl.style.borderCollapse='collapse';
    labels.forEach(l=>{
        const r = tbl.insertRow();
        r.insertCell().innerText = l.obs_id || '';
        r.insertCell().innerText = l.label || '';
        r.insertCell().innerText = l.annotator || '';
        r.insertCell().innerText = new Date((l.ts||0)*1000).toLocaleString();
        r.insertCell().innerText = l.notes || '';
    });
    c.innerHTML='';
    c.appendChild(tbl);
}

window.addEventListener('DOMContentLoaded', async ()=>{
    const labels = await fetchLabels();
    renderLabels('labelsList', labels);
});
