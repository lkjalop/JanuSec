/* Helper to show a simple 'update available' banner when a new SW activates */
function showSwUpdate(version){
  try{
    if(document.getElementById('sw-update-banner')) return;
    const b = document.createElement('div');
    b.id = 'sw-update-banner';
    b.style.position = 'fixed';
    b.style.right = '12px';
    b.style.bottom = '12px';
    b.style.background = '#ffedcc';
    b.style.padding = '8px 12px';
    b.style.border = '1px solid #d6b86a';
    b.style.borderRadius = '6px';
    b.style.zIndex = 99999;
    b.textContent = `Update available (${version}). `;
    const btn = document.createElement('button');
    btn.textContent = 'Reload';
    btn.className = 'btn';
    btn.style.marginLeft = '8px';
    btn.onclick = () => location.reload();
    b.appendChild(btn);
    document.body.appendChild(b);
  }catch(e){ console.warn('sw banner error', e); }
}

window.showSwUpdate = showSwUpdate;
