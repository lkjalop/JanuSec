// csv_analyzer.js - Production CSV Analyzer logic
// Single, cleaned implementation with severity sort, inline details, persistence and simple resizing
(function(){
  try { window.__csvReady = true; } catch(_){ }
  window.parseTabular = window.parseTabular || { ensureXlsxLib: function(){} };
  var FILTER_MODE = localStorage.getItem('csv_filter_mode') || 'all';
  var SELECTED_ROWS = new Set();
  var VERDICT_VIEW_MODE = localStorage.getItem('csv_verdict_view') || 'initial';
  
  function getInitialVerdict(rec){
    if(!rec) return '';
    if(rec._initial_verdict){
      return rec._initial_verdict;
    }
    if(rec.verdict){
      return String(rec.verdict).toUpperCase();
    }
    return '';
  }
  
  function getPipelineVerdict(rec){
    if(!rec) return '';
    if(rec._pipeline_verdict){
      return rec._pipeline_verdict;
    }
    return '';
  }
  
  function getVerdictForView(rec){
    if(!rec) return '';
    if(VERDICT_VIEW_MODE === 'pipeline'){
      return getPipelineVerdict(rec) || getInitialVerdict(rec) || '';
    }
    return getInitialVerdict(rec) || getPipelineVerdict(rec) || '';
  }

  function formatConfidenceValue(input){
    try{
      if(input === null || typeof input === 'undefined'){
        return '';
      }
      var value = typeof input === 'number' ? input : parseFloat(input);
      if(isNaN(value)){
        return '';
      }
      if(value <= 1 && value >= 0){
        return Math.round(value * 100) + '%';
      }
      if(value >= 0 && value <= 100){
        return Math.round(value) + '%';
      }
      return Number(value).toFixed(2);
    }catch(_){
      return '';
    }
  }

  function setVerdictViewMode(mode){
    if(mode !== 'pipeline') mode = 'initial';
    VERDICT_VIEW_MODE = mode;
    try{ localStorage.setItem('csv_verdict_view', mode); }catch(_){}
    updateVerdictViewButtons();
    renderTableFromResults();
  }

  function updateVerdictViewButtons(){
    try{
      var initBtn = document.getElementById('btnVerdictViewInitial');
      var pipeBtn = document.getElementById('btnVerdictViewPipeline');
      if(initBtn){
        var initActive = VERDICT_VIEW_MODE === 'initial';
        initBtn.classList.toggle('active-view', initActive);
        initBtn.setAttribute('aria-pressed', initActive ? 'true' : 'false');
      }
      if(pipeBtn){
        var pipeActive = VERDICT_VIEW_MODE === 'pipeline';
        pipeBtn.classList.toggle('active-view', pipeActive);
        pipeBtn.setAttribute('aria-pressed', pipeActive ? 'true' : 'false');
      }
      var info = document.getElementById('verdictViewInfo');
      if(info){
        info.textContent = VERDICT_VIEW_MODE === 'pipeline' ? 'Post-pipeline verdicts' : 'Initial heuristics';
      }
    }catch(_){ }
  }
  
  // Expose a safe accessor for selected row indexes so other modules (e.g. Deep Analyze
  // attachment IIFE) can read them without direct scope access. This prevents ReferenceError
