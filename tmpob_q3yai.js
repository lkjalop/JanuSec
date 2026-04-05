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
