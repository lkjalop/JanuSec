async function fetchRecentCrq(limit=5){
    try{
        const res = await fetch(`/api/v1/crq/recent?limit=${limit}`);
        if(!res.ok) return [];
        return await res.json();
    }catch(e){
        return [];
    }
}

function renderExplanationCard(containerId, items){
    const c = document.getElementById(containerId);
    if(!c) return;
    if(!items || items.length===0){
        c.innerText = 'No recent observations';
        return;
    }
    c.innerHTML = '';
    items.forEach(it=>{
        const el = document.createElement('div');
        el.style.marginBottom = '8px';
        el.className = 'crq-item';
        el.dataset.obsId = it.id || it.obs_id || '';
        el.style.padding = '8px';
        el.style.border = '1px solid var(--border)';
        el.style.borderRadius = '6px';
        const hdr = document.createElement('div');
        hdr.style.fontSize = '12px';
        hdr.style.color = 'var(--muted)';
        hdr.innerText = `${it.ts || ''} ${it.tenant ? '• ' + it.tenant : ''}`;
        el.appendChild(hdr);
        const score = document.createElement('div');
        score.style.fontWeight='600';
        score.style.margin='4px 0';
        score.innerText = `Score: ${it.tfidf_score !== undefined ? it.tfidf_score.toFixed(3) : 'n/a'}`;
        el.appendChild(score);
        const explain = document.createElement('div');
        explain.style.fontSize='12px';
        if(it.score_explanation && it.score_explanation.raw){
            const items = Object.entries(it.score_explanation.raw).slice(0,5);
            explain.innerHTML = items.map(([k,v])=>`<div><strong>${k}</strong>: ${Number(v).toFixed(4)}</div>`).join('');
        }else if(it.tfidf_score === null || it.tfidf_score === undefined){
            explain.innerText = 'Classifier not trained — explanation unavailable';
        }else{
            explain.innerText = 'No explanation available';
        }
        el.appendChild(explain);
        // click to open label modal
        el.addEventListener('click', (e)=>{
            e.stopPropagation();
            openCrqLabelModal(el.dataset.obsId || '', it);
        });
        c.appendChild(el);
    });
}

// Auto-run when console loads
document.addEventListener('DOMContentLoaded', async ()=>{
    const items = await fetchRecentCrq(5);
    // server returns list nested in key 'observations' or raw list
    const list = Array.isArray(items) ? items : (items.observations || []);
    renderExplanationCard('crqExplainList', list);
    // create modal container
    const modal = document.createElement('div');
    modal.id = 'crqLabelModal';
    modal.style.display='none';
    modal.style.position='fixed'; modal.style.left='0'; modal.style.top='0'; modal.style.width='100%'; modal.style.height='100%'; modal.style.background='rgba(0,0,0,0.5)'; modal.style.zIndex='9999';
    modal.innerHTML = '<div style="background:var(--bg-secondary);padding:20px;border-radius:8px;max-width:600px;margin:60px auto;color:var(--text-primary)">' +
        '<h3 id="modalTitle">Label Observation</h3>' +
        '<div id="modalBody"></div>' +
        '<div style="margin-top:12px;"><button id="modalTp" class="btn">TP</button> <button id="modalFp" class="btn">FP</button> <button id="modalUnd" class="btn">Undetermined</button> <button id="modalClose" class="btn">Close</button></div>' +
        '</div>';
    document.body.appendChild(modal);
    document.getElementById('modalClose').addEventListener('click', ()=>{ modal.style.display='none'; });
    document.getElementById('modalTp').addEventListener('click', async ()=>{ await modalSubmit('tp'); });
    document.getElementById('modalFp').addEventListener('click', async ()=>{ await modalSubmit('fp'); });
    document.getElementById('modalUnd').addEventListener('click', async ()=>{ await modalSubmit('undetermined'); });
    window._crq_modal_current = null;
    window.openCrqLabelModal = function(id, item){
        window._crq_modal_current = id;
        document.getElementById('modalBody').innerText = JSON.stringify(item, null, 2);
        modal.style.display='block';
    }
    async function modalSubmit(label){
        const id = window._crq_modal_current;
        const res = await postCrqLabel(id, label, 'labeled via modal');
        if(res && res.status==='ok'){
            alert('Saved');
            document.getElementById('crqLabelModal').style.display='none';
        } else {
            alert('Save failed');
        }
    }
});
