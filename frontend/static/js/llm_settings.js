/* Lightweight LLM Settings UI helpers
   - persists per-user overrides to localStorage.llm_settings
   - exposes testConnection() to call /api/v1/llm/health
   - provides helper to return overrides for use in deep-analyze enqueue
*/
(function(){
  function getSettings(){
    try{
      const raw = localStorage.getItem('llm_settings');
      if(!raw) return {};
      return JSON.parse(raw);
    }catch(e){
      return {};
    }
  }

  function saveSettings(s){
    try{
      localStorage.setItem('llm_settings', JSON.stringify(s));
      return true;
    }catch(e){
      return false;
    }
  }

  function setInputValues(){
    const s = getSettings();
    document.getElementById('llm-ollama-host').value = s.ollama_host || '';
    document.getElementById('llm-ollama-model').value = s.ollama_model || '';
    document.getElementById('llm-ollama-generate-path').value = s.ollama_generate_path || '';
    // interactive model input for small-prompt fallback
    const im = document.getElementById('llm-interactive-model');
    if(im) im.value = s.interactive_model || '';
  }

  async function testConnection(){
    const btn = document.getElementById('llm-test-conn-btn');
    btn.disabled = true;
    btn.innerText = 'Testing...';
    try{
      const res = await fetch('/api/v1/llm/health');
      const j = await res.json();
      alert('Health: ' + JSON.stringify(j));
    }catch(e){
      alert('Test failed: ' + e);
    }finally{
      btn.disabled = false;
      btn.innerText = 'Test Connection';
    }
  }

  function saveFromForm(){
    const host = document.getElementById('llm-ollama-host').value.trim();
    const model = document.getElementById('llm-ollama-model').value.trim();
    const path = document.getElementById('llm-ollama-generate-path').value.trim();
    const interactive = (document.getElementById('llm-interactive-model')||{}).value || '';
    const s = getSettings();
    s.ollama_host = host || null;
    s.ollama_model = model || null;
    s.ollama_generate_path = path || null;
    s.interactive_model = interactive || null;
    saveSettings(s);
    alert('Saved');
  }

  function getOverridesForRequest(){
    const s = getSettings();
    const out = {};
    if(s.ollama_host) out.ollama_host = s.ollama_host;
    if(s.ollama_model) out.ollama_model = s.ollama_model;
    if(s.ollama_generate_path) out.ollama_generate_path = s.ollama_generate_path;
    if(s.interactive_model) out.interactive_model = s.interactive_model;
    return out;
  }

  window.LLMSettingsUI = {
    getSettings, saveSettings, setInputValues, testConnection, saveFromForm, getOverridesForRequest
  };

  // Initialize form when modal opens (if using dynamic modal show)
  document.addEventListener('DOMContentLoaded', function(){
    const btn = document.getElementById('open-llm-settings');
    if(btn){
      btn.addEventListener('click', function(){
        setTimeout(setInputValues, 50);
      });
    }
  });

})();
