/* Tiny ARC admin widget */
        #arc-admin-widget { position: fixed; right: 18px; bottom: 18px; width: 320px; background: var(--bg-elevated); border:1px solid var(--border); padding:12px; border-radius:8px; box-shadow: 0 6px 18px rgba(0,0,0,0.4); z-index:12000; }
        #arc-admin-widget h4 { margin:0 0 8px 0; color:var(--text-primary); font-size:14px }
        #arc-admin-widget label { display:block; font-size:12px; color:var(--text-muted); margin-top:6px }
        #arc-admin-widget input, #arc-admin-widget select { width:100%; margin-top:6px; padding:6px; background:var(--bg-primary); border:1px solid var(--border); color:var(--text-primary); }
        #arc-admin-widget .row { display:flex; gap:8px; margin-top:8px }
        #arc-admin-widget .row button { flex:1 }
        // Small shared helpers that must be available early
        window.authHeaders = function(){ try { const key = (localStorage.getItem('apiKey') || 'devkey123'); const tenant = localStorage.getItem('tenantId'); const h = { 'x-api-key': key }; if (tenant) h['X-Tenant-ID'] = tenant; return h; } catch (_){ return { 'x-api-key': 'devkey123' }; } };
        window._htmlEsc = function(s){ try{ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }catch(_){return '';} };