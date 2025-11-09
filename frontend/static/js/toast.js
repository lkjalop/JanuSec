// Toast system
(function(){
  const containerId = 'toastContainer';
  function ensureContainer(){ let el = document.getElementById(containerId); if(!el){ el=document.createElement('div'); el.id=containerId; document.body.appendChild(el);} return el; }
  function showToast(msg, type){
    const el = ensureContainer();
    const toast = document.createElement('div'); toast.className='toast'+(type? ' '+type:'');
    toast.setAttribute('role','alert');
    toast.innerHTML = `<div style="flex:1">${msg}</div><button type="button" aria-label="Dismiss">✕</button>`;
    const btn = toast.querySelector('button');
    btn.addEventListener('click', ()=>{ toast.remove(); });
    el.appendChild(toast);
    setTimeout(()=>{ toast.classList.add('visible'); },10);
    setTimeout(()=>{ if(toast.parentNode) toast.remove(); }, 6500);
  }
  window.showToast = showToast;
  window.showNotification = (msg,type)=>showToast(msg,type); // legacy alias
})();
