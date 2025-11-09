// theme.js - runtime theme toggling (dark/light)
// Provides applyTheme(mode) and initTheme() for future interactive toggles.
// Dark tokens come from theme.css; light mode derives by overriding CSS variables on :root.
(function(){
  const LIGHT_OVERRIDES = {
    '--bg-primary': '#f5f7fa', '--bg-secondary': '#ffffff', '--bg-tertiary': '#eef2f7', '--bg-hover': '#e2e8f0', '--bg-elevated': '#ffffff',
    '--border': '#cbd5e1', '--border-soft': '#d9e2ec', '--text-primary': '#1e293b', '--text-secondary': '#334155', '--text-muted': '#64748b', '--text-inverse': '#ffffff',
    '--accent': '#4A63E7', '--accent-hover': '#5C74F2', '--accent-subtle': '#dbe5ff',
    '--critical': '#DC2626', '--high': '#EA580C', '--medium': '#D97706', '--low': '#059669', '--safe': '#10B981', '--info': '#2563EB'
  };
  function applyTheme(mode){
    try{
      const root = document.documentElement;
      if(mode === 'light'){
        Object.entries(LIGHT_OVERRIDES).forEach(([k,v])=>root.style.setProperty(k, v));
        root.setAttribute('data-theme','light');
      } else { // dark (default)
        Object.keys(LIGHT_OVERRIDES).forEach(k=>root.style.removeProperty(k));
        root.setAttribute('data-theme','dark');
      }
      try{ localStorage.setItem('themeMode', mode); }catch(_){ }
    }catch(e){ console.warn('applyTheme failed', e); }
  }
  function initTheme(){
    let m = 'dark';
    try{ m = localStorage.getItem('themeMode') || 'dark'; }catch(_){ }
    applyTheme(m);
  }
  window.applyTheme = applyTheme;
  window.initTheme = initTheme;
  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initTheme); else initTheme();
})();
