// Notifications utility used across static pages
(function(global){
  function makeNotification(message, type){
    const notification = document.createElement('div');
    notification.className = 'notification';
    const colors = { info: 'var(--accent)', success: 'var(--safe)', error: 'var(--critical)', warning: 'var(--accent)' };
    const wrapper = document.createElement('div'); wrapper.style.display='flex'; wrapper.style.alignItems='center'; wrapper.style.gap='8px';
    const dot = document.createElement('div'); dot.style.width='8px'; dot.style.height='8px'; dot.style.background = colors[type] || colors.info; dot.style.borderRadius='50%';
    const msgSpan = document.createElement('span'); msgSpan.textContent = message;
    wrapper.appendChild(dot); wrapper.appendChild(msgSpan); notification.appendChild(wrapper);
    document.body.appendChild(notification);
    return notification;
  }

  function showNotification(message, type='info', opts={}){
    try{
      const n = makeNotification(message, type);
      const ttl = opts.ttl || 4000;
      setTimeout(()=>{ n.style.animation='slideOut 0.3s ease'; setTimeout(()=>n.remove(), 300); }, ttl);
    }catch(e){ console.log('notify:', message, type); }
  }

  function showToast(message, ttl=1600){ showNotification(message,'info',{ttl}); }

  global.notifications = { showNotification, showToast };
  // Backwards-compatible global helper
  global.showNotification = function(m,t){ return global.notifications.showNotification(m,t); };
  global.showToast = function(m,t){ return global.notifications.showToast(m,t); };
})(window);
