// Simple command palette (Ctrl+K)
(function(){
  const cmds = [
    { id:'goto-endpoint', label:'Go: Endpoint Hunting', action:()=>location.href='/static/hunt_endpoint.html' },
    { id:'goto-network', label:'Go: Network Hunting', action:()=>location.href='/static/hunt_network.html' },
    { id:'goto-integrations', label:'Go: Integrations Settings', action:()=>location.href='/static/integrations.html' },
    { id:'goto-sbom', label:'Go: SBOM & Vulns', action:()=>location.href='/static/sbom.html' },
    { id:'goto-mitre', label:'Go: MITRE Heatmap', action:()=>location.href='/static/mitre.html' },
    { id:'toggle-theme', label:'Toggle Theme', action:()=>{ document.body.classList.toggle('theme-light'); window.showToast('Theme toggled'); } },
    { id:'refresh-auth', label:'Refresh Auth State', action:()=>{ window.refreshAuthState && window.refreshAuthState(); window.showToast('Auth state refreshed','success'); } },
    { id:'show-health', label:'Health: Show Status', action:()=>{
        try{
          const last = window.__healthLastOk || 0;
          const ageMs = Date.now()-last;
          const secs = Math.round(ageMs/1000);
          const banner = document.getElementById('globalBanner');
          const degraded = banner && banner.style.display==='block';
          const msg = degraded ? `DEGRADED – last SSE ${secs}s ago` : `Healthy – last SSE ${secs}s ago`;
          window.showToast(msg, degraded? 'warn':'success');
        }catch{ window.showToast('Health status unavailable'); }
      } }
  ];
  let palette, input, list;
  function build(){
    palette = document.createElement('div');
    palette.style.cssText='position:fixed;top:80px;left:50%;transform:translateX(-50%);width:420px;background:var(--color-bg-secondary);border:1px solid var(--color-border);border-radius:var(--radius-md);padding:12px;z-index:var(--z-modal);display:none;box-shadow:var(--shadow-lg);';
    input = document.createElement('input'); input.type='text'; input.placeholder='Type a command...'; input.style.cssText='width:100%;padding:8px 10px;background:var(--color-bg-tertiary);border:1px solid var(--color-border);color:var(--color-text-primary);margin-bottom:10px;border-radius:var(--radius-sm);';
    list = document.createElement('div'); list.style.cssText='max-height:240px;overflow-y:auto;font-size:13px;';
    palette.appendChild(input); palette.appendChild(list); document.body.appendChild(palette);
    input.addEventListener('input', render);
    input.addEventListener('keydown', ev=>{ if(ev.key==='Escape'){ hide(); } });
  }
  function render(){
    const q = (input.value||'').toLowerCase();
    const filtered = cmds.filter(c=>c.label.toLowerCase().includes(q));
    list.innerHTML = filtered.map(c=>`<div class='cmd-item' data-id='${c.id}' style='padding:6px 8px;cursor:pointer;border-radius:4px;'>${c.label}</div>`).join('') || '<div style="opacity:.6;font-size:12px;">No matches</div>';
    list.querySelectorAll('.cmd-item').forEach(el=>{
      el.addEventListener('click', ()=>{ const id=el.getAttribute('data-id'); const cmd=cmds.find(c=>c.id===id); if(cmd){ hide(); cmd.action(); } });
    });
  }
  function show(){ if(!palette) build(); render(); palette.style.display='block'; input.value=''; input.focus(); }
  function hide(){ if(palette) palette.style.display='none'; }
  document.addEventListener('keydown', ev=>{ if((ev.ctrlKey||ev.metaKey) && ev.key==='k'){ ev.preventDefault(); show(); } });
  window._commandPalette = { show, hide };
})();
