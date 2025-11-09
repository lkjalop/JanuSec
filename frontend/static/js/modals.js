/* JanuSec Modal Component for Confirmations */
(function(){
  const css = `
    .janusec-modal-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:10000;animation:fadeIn .2s ease}
    .janusec-modal{background:#1a1f2e;border:1px solid #4a5568;border-radius:8px;max-width:500px;width:90%;box-shadow:0 10px 40px rgba(0,0,0,.5);animation:slideUp .3s ease}
    .janusec-modal-header{padding:20px;border-bottom:1px solid #2a3142;display:flex;align-items:center;justify-content:space-between}
    .janusec-modal-title{font-size:18px;font-weight:600;color:#e6e6e6;display:flex;align-items:center;gap:10px}
    .janusec-modal-close{background:none;border:none;color:#93a0b1;font-size:24px;cursor:pointer;padding:0;line-height:1}
    .janusec-modal-close:hover{color:#e6e6e6}
    .janusec-modal-body{padding:20px;color:#e6e6e6;line-height:1.6}
    .janusec-modal-details{background:#0e1117;padding:12px;border-radius:6px;margin:12px 0;font-family:monospace;font-size:13px}
    .janusec-modal-footer{padding:20px;border-top:1px solid #2a3142;display:flex;gap:10px;justify-content:flex-end}
    .janusec-modal-btn{padding:10px 20px;border-radius:6px;border:none;font-size:14px;font-weight:500;cursor:pointer;transition:all .2s ease}
    .janusec-modal-btn-cancel{background:#2a3142;color:#e6e6e6}
    .janusec-modal-btn-cancel:hover{background:#3a4152}
    .janusec-modal-btn-confirm{background:#e74c3c;color:#fff}
    .janusec-modal-btn-confirm:hover{background:#c0392b}
    .janusec-modal-btn-confirm.info{background:#3498db}
    .janusec-modal-btn-confirm.info:hover{background:#2980b9}
    @keyframes fadeIn{from{opacity:0}to{opacity:1}}
    @keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}`;
  const styleEl = document.createElement('style'); styleEl.textContent = css; document.head.appendChild(styleEl);

  window.JanuSecModal = {
    confirm: function(options){
      return new Promise((resolve)=>{
        const { title='Confirm Action', message='Are you sure?', details=null, icon='warning', confirmText='Confirm', cancelText='Cancel', onConfirm=null, onCancel=null } = (options||{});
        const overlay = document.createElement('div'); overlay.className='janusec-modal-overlay'; overlay.setAttribute('role','dialog'); overlay.setAttribute('aria-modal','true');
        const modal = document.createElement('div'); modal.className='janusec-modal';
        modal.innerHTML = `
          <div class="janusec-modal-header">
            <div class="janusec-modal-title"><span>${icon === 'danger' ? '⚠️' : icon === 'info' ? 'ℹ️' : '⚠️'}</span><span>${title}</span></div>
            <button class="janusec-modal-close" aria-label="Close">&times;</button>
          </div>
          <div class="janusec-modal-body">
            <p>${message}</p>
            ${details ? `<div class="janusec-modal-details">${details}</div>` : ''}
          </div>
          <div class="janusec-modal-footer">
            ${cancelText ? `<button class="janusec-modal-btn janusec-modal-btn-cancel">${cancelText}</button>` : ''}
            <button class="janusec-modal-btn janusec-modal-btn-confirm ${icon === 'info' ? 'info' : ''}">${confirmText}</button>
          </div>`;
        overlay.appendChild(modal); document.body.appendChild(overlay);
        const closeBtn = modal.querySelector('.janusec-modal-close');
        const cancelBtn = modal.querySelector('.janusec-modal-btn-cancel');
        const confirmBtn = modal.querySelector('.janusec-modal-btn-confirm');
        function close(confirmed){ overlay.style.animation='fadeIn .2s ease reverse'; setTimeout(()=>{ overlay.remove(); }, 200); if(confirmed){ if(onConfirm) try{ onConfirm(); }catch(_){} resolve(true);} else { if(onCancel) try{ onCancel(); }catch(_){} resolve(false);} }
        if(closeBtn) closeBtn.addEventListener('click', ()=>close(false));
        if(cancelBtn) cancelBtn.addEventListener('click', ()=>close(false));
        if(confirmBtn) confirmBtn.addEventListener('click', ()=>close(true));
        function handleEscape(e){ if(e.key==='Escape'){ close(false); document.removeEventListener('keydown', handleEscape); } }
        document.addEventListener('keydown', handleEscape);
        overlay.addEventListener('click', (e)=>{ if(e.target === overlay) close(false); });
        if(confirmBtn) confirmBtn.focus();
      });
    },
    alert: function(options){ if(typeof options === 'string'){ options = { message: options }; } return this.confirm({ ...(options||{}), icon: (options && options.icon) || 'info', confirmText:'OK', cancelText:null }); }
  };
})();

