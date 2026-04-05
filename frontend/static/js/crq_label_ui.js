async function postCrqLabel(obs_id, label, notes) {
    try {
        const res = await fetch('/api/v1/crq/label', {
            method: 'POST',
            headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
            body: JSON.stringify({obs_id, label, annotator: (localStorage.getItem('userName')||'analyst'), notes})
        });
        return await res.json();
    } catch (e) {
        return {error: String(e)};
    }
}

function attachLabelButtons(containerId) {
    const c = document.getElementById(containerId);
    if(!c) return;
    c.querySelectorAll('.crq-item').forEach(el=>{
        const id = el.dataset.obsId;
        if(!id) return;
        const btns = document.createElement('div');
        btns.style.marginTop='6px';
        ['tp','fp','undetermined'].forEach(l=>{
            const b = document.createElement('button');
            b.className='btn';
            b.style.marginRight='6px';
            b.innerText = l.toUpperCase();
            b.onclick = async ()=>{
                b.disabled = true;
                const res = await postCrqLabel(id, l, 'labeled via UI');
                b.disabled = false;
                if(res && res.status==='ok') {
                    b.innerText = 'Saved';
                    setTimeout(()=>{ b.innerText = l.toUpperCase(); }, 2000);
                }
            };
            btns.appendChild(b);
        });
        el.appendChild(btns);
    });
}

// Auto-wire after DOM load
window.addEventListener('DOMContentLoaded', ()=>{ setTimeout(()=>attachLabelButtons('crqExplainList'), 800); });
