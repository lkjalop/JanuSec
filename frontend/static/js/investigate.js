/**
 * investigate.js — Core logic for the JanuSec Unified Investigation Console.
 * Handles: file upload + auto-detection, pipeline dispatch, persona report rendering,
 * evidence table, severity breakdown, tab switching, detail panel, keyboard shortcuts.
 *
 * Dependencies: XLSX (SheetJS), Lucide icons — loaded in investigate.html.
 * Backend: /api/v1/csv/deep_analyze, persona report generation, assessment polling.
 */
(function () {
  'use strict';

  // ── Constants ────────────────────────────────────────────────────────────
  var API_KEY = localStorage.getItem('apiKey') || 'devkey123';
  var MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
  var PERSONAS = ['soc_analyst', 'ciso', 'executive', 'threat_hunter', 'forensics', 'compliance', 'audit', 'mssp'];
  var PERSONA_LABELS = { soc_analyst: 'SOC Analyst', ciso: 'CISO', executive: 'Executive', threat_hunter: 'Threat Hunter', forensics: 'Forensics', compliance: 'Compliance', audit: 'Audit', mssp: 'MSSP' };
  var SEV_COLORS = { critical: '#E54848', high: '#FF8A3C', medium: '#E0C446', low: '#3FA860' };
  var PERSONA_ALIASES = { soc_analyst: 'soc_analyst', ciso: 'ciso', executive: 'executive', threat_hunter: 'threat_hunter', forensics: 'forensics', compliance: 'compliance', audit: 'audit', mssp: 'mssp' };

  // ── State ────────────────────────────────────────────────────────────────
  var state = {
    sources: [],       // [{name, type, rows:[], rowCount, status:'ok'|'err'|'pending'}]
    allRows: [],       // flattened rows from all sources
    assessment: null,  // latest assessment object from backend
    assessmentId: null,
    currentPersona: 'soc_analyst',
    reportArtifacts: {},  // persona -> artifact
    activeFilter: 'all',
    sortCol: 'triage_score',
    sortDir: 'desc',
    _gateApproved: false, // human-gate: set true after analyst approves escalation personas
    workbookMeta: null,   // sheet summary + entity pivots + CRQ from workbook_sheets endpoint
  };

  // ── DOM refs ─────────────────────────────────────────────────────────────
  var $ = function (id) { return document.getElementById(id); };

  // ── Helpers ──────────────────────────────────────────────────────────────
  function authHeaders() {
    var h = { 'x-api-key': API_KEY };
    var tenant = localStorage.getItem('tenantId');
    if (tenant) h['X-Tenant-ID'] = tenant;
    return h;
  }

  function toast(msg, type) {
    var el = document.createElement('div');
    el.className = 'toast' + (type ? ' toast--' + type : '');
    el.textContent = msg;
    $('toastContainer').appendChild(el);
    setTimeout(function () { el.remove(); }, 5000);
  }

  function escHtml(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  // ── Tab switching ────────────────────────────────────────────────────────
  function switchTab(name) {
    document.querySelectorAll('.tab-btn').forEach(function (btn) {
      var isTarget = btn.getAttribute('data-tab') === name;
      btn.classList.toggle('active', isTarget);
      btn.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    });
    document.querySelectorAll('.tab-content').forEach(function (panel) {
      panel.classList.toggle('active', panel.id === 'tab' + name.charAt(0).toUpperCase() + name.slice(1));
    });
  }

  document.querySelectorAll('.tab-btn').forEach(function (btn) {
    btn.addEventListener('click', function () { switchTab(btn.getAttribute('data-tab')); });
  });

  // ── Keyboard shortcuts ───────────────────────────────────────────────────
  document.addEventListener('keydown', function (e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
    if (e.ctrlKey || e.metaKey) {
      var tabs = ['report', 'evidence', 'graph', 'timeline'];
      var num = parseInt(e.key, 10);
      if (num >= 1 && num <= 4) { e.preventDefault(); switchTab(tabs[num - 1]); }
      if (e.shiftKey && e.key.toLowerCase() === 'd') { e.preventDefault(); detachCurrentTab(); }
    }
  });

  // ── File detection ───────────────────────────────────────────────────────
  function detectFileType(name, content) {
    var ext = (name || '').split('.').pop().toLowerCase();
    if (ext === 'csv') return 'csv';
    if (ext === 'xlsx' || ext === 'xls') return 'xlsx';
    if (ext === 'jsonl') return 'jsonl';
    if (ext === 'json' && content) {
      try {
        var parsed = typeof content === 'string' ? JSON.parse(content) : content;
        if (parsed.Records && Array.isArray(parsed.Records)) return 'aws_cloudtrail';
        if (parsed.Findings && Array.isArray(parsed.Findings)) {
          var first = parsed.Findings[0] || {};
          if (first.DetectorId) return 'aws_guardduty';
          if (first.ProductArn) return 'aws_securityhub';
          return 'aws_findings';
        }
        if (parsed.records && Array.isArray(parsed.records)) {
          var r0 = parsed.records[0] || {};
          if (r0.macAddress && r0.properties) return 'azure_nsg_flow';
          return 'json_records';
        }
        if (parsed.value && Array.isArray(parsed.value)) {
          var v0 = parsed.value[0] || {};
          if (v0.classification || v0.determination) return 'azure_defender';
          return 'json_value';
        }
        if (parsed.configurationItems) return 'aws_config';
        if (parsed.complianceResults) return 'aws_config';
        if (Array.isArray(parsed)) {
          var s0 = parsed[0] || {};
          if (s0.userPrincipalName && s0.appDisplayName) return 'azure_signin';
          if (s0.activityDisplayName && s0.loggedByService) return 'azure_audit';
          if (s0.operationName && s0.resourceGroupName) return 'azure_activity';
          if (s0.riskEventType && s0.riskLevel) return 'azure_idp_risk';
          if (s0.appliedPolicies) return 'azure_conditional_access';
          return 'json_array';
        }
        if (parsed.pack_id) return 'manifest';
      } catch (_) { /* not valid JSON */ }
    }
    return ext || 'unknown';
  }

  var TYPE_LABELS = {
    csv: 'CSV', xlsx: 'Excel', jsonl: 'JSONL', json_array: 'JSON',
    aws_cloudtrail: 'AWS CloudTrail', aws_guardduty: 'AWS GuardDuty',
    aws_securityhub: 'AWS SecurityHub', aws_config: 'AWS Config', aws_findings: 'AWS Findings',
    azure_signin: 'Azure Sign-In', azure_audit: 'Azure Audit', azure_activity: 'Azure Activity',
    azure_defender: 'Azure Defender', azure_idp_risk: 'Azure IdP Risk',
    azure_nsg_flow: 'Azure NSG Flow', azure_conditional_access: 'Azure CA',
    json_records: 'JSON Records', json_value: 'JSON Value', manifest: 'Test Pack',
    unknown: 'Unknown',
  };

  var TYPE_ICONS = {
    csv: 'file-spreadsheet', xlsx: 'file-spreadsheet', jsonl: 'file-json',
    aws_cloudtrail: 'cloud', aws_guardduty: 'shield-alert', aws_securityhub: 'shield',
    aws_config: 'settings', azure_signin: 'log-in', azure_audit: 'clipboard-list',
    azure_activity: 'activity', azure_defender: 'siren', azure_idp_risk: 'alert-triangle',
    azure_nsg_flow: 'network', azure_conditional_access: 'key', manifest: 'folder',
  };

  // ── Parse files ──────────────────────────────────────────────────────────
  function parseFile(file) {
    return new Promise(function (resolve, reject) {
      if (file.size > MAX_FILE_SIZE) {
        reject(new Error('File too large: ' + file.name + ' (' + Math.round(file.size / 1024 / 1024) + 'MB > 50MB limit)'));
        return;
      }
      var ext = (file.name || '').split('.').pop().toLowerCase();
      if (ext === 'xlsx' || ext === 'xls') {
        var reader = new FileReader();
        reader.onload = function (e) {
          try {
            var wb = XLSX.read(e.target.result, { type: 'array' });
            var rows = [];
            wb.SheetNames.forEach(function (sheetName) {
              var ws = wb.Sheets[sheetName];
              var data = XLSX.utils.sheet_to_json(ws, { defval: null });
              data.forEach(function (row, idx) {
                row._source = file.name;
                row._sheet = sheetName;
                row.row_index = idx;
                rows.push(row);
              });
            });
            resolve({ name: file.name, type: detectFileType(file.name, null), rows: rows });
          } catch (err) { reject(err); }
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
      } else {
        var textReader = new FileReader();
        textReader.onload = function (e) {
          var text = e.target.result;
          var type = detectFileType(file.name, text);
          var rows = [];
          try {
            if (ext === 'csv') {
              rows = parseCsv(text, file.name);
            } else if (ext === 'jsonl') {
              text.split('\n').filter(Boolean).forEach(function (line, idx) {
                try {
                  var obj = JSON.parse(line);
                  obj._source = file.name; obj.row_index = idx;
                  rows.push(obj);
                } catch (_) { /* skip bad lines */ }
              });
            } else {
              rows = extractJsonRows(text, type, file.name);
            }
          } catch (err) { reject(err); return; }
          resolve({ name: file.name, type: type, rows: rows });
        };
        textReader.onerror = reject;
        textReader.readAsText(file);
      }
    });
  }

  function parseCsv(text, sourceName) {
    var lines = text.split('\n');
    if (lines.length < 2) return [];
    var headers = lines[0].split(',').map(function (h) { return h.trim().replace(/^["']|["']$/g, ''); });
    var rows = [];
    for (var i = 1; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var vals = line.split(',');
      var row = { _source: sourceName, row_index: i - 1 };
      headers.forEach(function (h, idx) {
        var v = (vals[idx] || '').trim().replace(/^["']|["']$/g, '');
        row[h] = v;
      });
      rows.push(row);
    }
    return rows;
  }

  function extractJsonRows(text, type, sourceName) {
    var parsed = JSON.parse(text);
    var rows = [];
    var arr = [];
    if (type === 'aws_cloudtrail') arr = parsed.Records || [];
    else if (type === 'aws_guardduty' || type === 'aws_securityhub' || type === 'aws_findings') arr = parsed.Findings || [];
    else if (type === 'azure_nsg_flow' || type === 'json_records') arr = parsed.records || [];
    else if (type === 'azure_defender' || type === 'json_value') arr = parsed.value || [];
    else if (type === 'aws_config') arr = parsed.configurationItems || parsed.complianceResults || [];
    else if (Array.isArray(parsed)) arr = parsed;
    else { arr = [parsed]; }

    arr.forEach(function (item, idx) {
      if (typeof item === 'object' && item !== null) {
        item._source = sourceName;
        item._detected_type = type;
        item.row_index = idx;
        rows.push(item);
      }
    });
    return rows;
  }

  // ── Source list rendering ────────────────────────────────────────────────
  function renderSourceList() {
    var container = $('sourceList');
    var totalRows = 0;
    container.innerHTML = '';
    state.sources.forEach(function (src, idx) {
      totalRows += src.rows.length;
      var iconName = TYPE_ICONS[src.type] || 'file';
      var sheetLabel = (src.meta && src.meta.sheets)
        ? ' <span style="font-size:10px;color:var(--accent);">' + src.meta.sheets + ' sheets' +
          (src.meta.pivots > 0 ? ' · ' + src.meta.pivots + ' pivots' : '') + '</span>'
        : '';
      var el = document.createElement('div');
      el.className = 'source-item';
      el.innerHTML =
        '<i data-lucide="' + iconName + '" class="source-item__icon"></i>' +
        '<span class="source-item__name">' + escHtml(src.name) + sheetLabel + '</span>' +
        '<span class="source-item__type">' + escHtml(TYPE_LABELS[src.type] || src.type) + '</span>' +
        '<span class="source-item__count">' + src.rows.length + ' rows</span>' +
        '<span class="source-item__status source-item__status--' + (src.status || 'ok') + '"></span>';
      container.appendChild(el);
    });
    $('sourceListRow').style.display = state.sources.length ? '' : 'none';
    // Show workbook CRQ if available
    var wbMeta = state.workbookMeta;
    if (wbMeta && wbMeta.crq) {
      var crq = wbMeta.crq;
      var crqTier = (crq.exposure_tier || '').toLowerCase();
      // Always show range, never exact dollar, in the source-list pill
      var crqDisplay = crq.exposure_range_formatted || crq.exposure_tier || '';
      $('sourceSummary').innerHTML =
        state.sources.length + ' source' + (state.sources.length !== 1 ? 's' : '') + ', ' + totalRows + ' rows' +
        ' &nbsp;|&nbsp; <span class="sev-pill sev-pill--' + crqTier + '" title="CRQ planning range (unvalidated)">' +
        escHtml(crqDisplay) + '</span>' +
        ' <span style="font-size:10px;color:var(--text-muted);">\u26A0\uFE0F unvalidated</span>';
    } else {
      $('sourceSummary').textContent = state.sources.length + ' source' + (state.sources.length !== 1 ? 's' : '') + ', ' + totalRows + ' rows';
    }
    $('btnAnalyze').disabled = totalRows === 0;
    state.allRows = [];
    state.sources.forEach(function (src) {
      state.allRows = state.allRows.concat(src.rows);
    });
    // Re-init lucide icons in newly added DOM
    if (window.lucide) lucide.createIcons();
  }

  // ── Upload handling ──────────────────────────────────────────────────────
  // For Excel workbooks we first let SheetJS parse all sheets locally (to
  // give immediate feedback), then re-upload to /api/v1/upload/workbook_sheets
  // so the backend can:
  //   • skip metadata-only sheets (Overview, Summary, etc.)
  //   • assign domain context per data sheet
  //   • run cross-sheet entity pivot detection
  //   • compute a CRQ financial-exposure estimate
  // The server-normalized rows replace the client-parsed rows so the
  // deep_analyze pipeline gets properly structured events.

  async function enhanceExcelWithBackend(file, clientRows) {
    var ext = (file.name || '').split('.').pop().toLowerCase();
    if (ext !== 'xlsx' && ext !== 'xlsm') return null;
    try {
      var fd = new FormData();
      fd.append('files', file);
      var resp = await fetch('/api/v1/upload/workbook_sheets', {
        method: 'POST',
        headers: authHeaders(),   // no Content-Type — FormData sets its own boundary
        body: fd,
      });
      if (!resp.ok) return null;
      var data = await resp.json();
      var result = (data.results || [])[0];
      if (!result || result.status !== 'parsed') return null;
      return result;
    } catch (_) { return null; }
  }

  function handleFiles(fileList) {
    var files = Array.from(fileList);
    if (!files.length) return;

    var promises = files.map(function (f) {
      return parseFile(f).then(async function (result) {
        var ext = (f.name || '').split('.').pop().toLowerCase();
        var isExcel = ext === 'xlsx' || ext === 'xlsm';

        if (isExcel) {
          // Always attempt backend enhancement for XLSX — it provides cross-sheet
          // correlation, domain tagging, and CRQ that client-side XLSX.js cannot.
          var backendResult = await enhanceExcelWithBackend(f, result.rows);
          if (backendResult && backendResult.rows && backendResult.rows.length > 0) {
            var backendRows = backendResult.rows;
            var sheetSummaries = backendResult.sheet_summaries || [];
            var parsedSheets = sheetSummaries.filter(function (s) { return s.status === 'parsed'; });

            // Merge any client-side rows from sheets the backend returned 0 rows for
            // (shouldn't happen, but belt-and-braces).
            var backendRowIdx = new Set(backendRows.map(function (r) {
              return (r._sheet || '') + '|' + r.row_index;
            }));

            // Store workbook context in state for the report panel
            state.workbookMeta = {
              filename: f.name,
              sheets: parsedSheets,
              entityPivots: backendResult.entity_pivots || {},
              pivotedRowCount: backendResult.pivoted_row_count || 0,
              crq: backendResult.crq || null,
              sha256: backendResult.sha256 || null,
            };

            var sheetList = parsedSheets.map(function (s) {
              return s.sheet + ' (' + s.row_count + ')';
            }).join(', ');

            toast('\u2714 Workbook parsed: ' + backendRows.length + ' events across ' + parsedSheets.length + ' sheet(s): ' + sheetList, 'success');

            state.sources.push({
              name: f.name,
              type: result.type,
              rows: backendRows,
              rowCount: backendRows.length,
              status: backendRows.length > 0 ? 'ok' : 'err',
              meta: { sheets: parsedSheets.length, pivots: backendResult.pivoted_row_count || 0 },
            });
            return;
          }
          // Backend unavailable — fall back to client-parsed rows with a warning
          toast('\u26A0 Backend workbook parse unavailable — using client-parsed rows (' + result.rows.length + '). Cross-sheet correlation may be limited.', 'warning');
        }

        state.sources.push({
          name: result.name,
          type: result.type,
          rows: result.rows,
          rowCount: result.rows.length,
          status: result.rows.length > 0 ? 'ok' : 'err',
        });
      }).catch(function (err) {
        toast('Failed to parse ' + f.name + ': ' + err.message, 'error');
        state.sources.push({ name: f.name, type: 'unknown', rows: [], rowCount: 0, status: 'err' });
      });
    });

    Promise.all(promises).then(function () {
      renderSourceList();
      // Only show default-toast if we haven't already shown a workbook-specific one
      if (!state.workbookMeta) {
        toast(files.length + ' file' + (files.length !== 1 ? 's' : '') + ' loaded', 'success');
      }
    });
  }

  // Wire upload zone
  var uploadZone = $('uploadZone');
  var fileInput = $('fileInput');

  uploadZone.addEventListener('click', function () { fileInput.click(); });
  uploadZone.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener('change', function () { handleFiles(fileInput.files); fileInput.value = ''; });

  uploadZone.addEventListener('dragover', function (e) { e.preventDefault(); uploadZone.classList.add('dragover'); });
  uploadZone.addEventListener('dragleave', function () { uploadZone.classList.remove('dragover'); });
  uploadZone.addEventListener('drop', function (e) {
    e.preventDefault(); uploadZone.classList.remove('dragover');
    handleFiles(e.dataTransfer.files);
  });

  $('btnClearSources').addEventListener('click', function () {
    state.sources = []; state.allRows = [];
    state.workbookMeta = null;
    renderSourceList();
    $('sevSummary').classList.remove('has-data');
    $('reportEmpty').style.display = '';
    $('reportContent').style.display = 'none';
    $('evidenceBody').innerHTML = '';
    $('evidenceEmpty').style.display = '';
    $('evidenceBadge').textContent = '0';
  });

  $('btnAddMore').addEventListener('click', function () { fileInput.click(); });

  // Personas requiring human-gate approval before reports are generated.
  // CISO/Executive/Audit = management gate (analyst must certify findings).
  // SOC/TH/Compliance = NLP confirmation gate (analyst writes free-text verdict).
  var GATED_PERSONAS = ['ciso', 'executive', 'audit'];
  var NLP_GATED_PERSONAS = ['soc_analyst', 'threat_hunter', 'compliance'];  // require analyst NLP confirmation

  // Analyst approves the gate — POSTs to backend and unlocks gated persona chips
  function approveHumanGate() {
    var aid = state.assessmentId;
    if (!aid) { toast('Run analysis first before approving gate', 'error'); return; }
    fetch('/api/v1/assessments/' + encodeURIComponent(aid) + '/gate', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({
        gate_verdict: 'approve',
        reviewer_tag: 'analyst',
        notes: 'Approved from investigation console',
        gate_personas: GATED_PERSONAS,
      }),
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.ok) {
        state._gateApproved = true;
        toast('Gate approved — CISO, Executive, and Audit reports are now unlocked', 'success');
        renderPersonaChips();
      } else {
        toast('Gate approval failed: ' + (d.detail || 'unknown error'), 'error');
      }
    }).catch(function () {
      toast('Gate approval failed — server error', 'error');
    });
  }

  // ── NLP confirmation gate (SOC / Threat Hunter / Compliance) ─────────────
  // Each NLP-gated persona shows a text-input where the analyst writes their
  // verdict before the report is displayed. The text is submitted to the gate
  // endpoint with gate_verdict='nlp_confirm' so it is persisted in the audit.
  function submitNlpGate(persona, text) {
    var aid = state.assessmentId;
    if (!aid) { toast('Run analysis first', 'error'); return; }
    var nlpText = (text || '').trim();
    if (nlpText.length < 10) { toast('Please enter at least 10 characters to confirm your assessment.', 'error'); return; }
    fetch('/api/v1/assessments/' + encodeURIComponent(aid) + '/gate', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({
        gate_verdict: 'nlp_confirm',
        reviewer_tag: persona,
        notes: nlpText,
        gate_personas: [persona],
      }),
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.ok) {
        state._nlpGateConfirmed = state._nlpGateConfirmed || {};
        state._nlpGateConfirmed[persona] = nlpText;
        toast('Assessment confirmed — ' + PERSONA_LABELS[persona] + ' report generated', 'success');
        renderPersonaChips();
        renderReport();
      } else {
        toast('Confirmation failed: ' + (d.detail || 'unknown error'), 'error');
      }
    }).catch(function () { toast('Confirmation failed — server error', 'error'); });
  }

  // ── Persona chip rendering ───────────────────────────────────────────────
  function renderPersonaChips() {
    var container = $('personaChips');
    container.innerHTML = '';
    PERSONAS.forEach(function (p) {
      var chip = document.createElement('button');
      var isGated = GATED_PERSONAS.indexOf(p) >= 0;
      var isApproved = state._gateApproved;
      var lockIcon = (isGated && !isApproved) ? ' 🔒' : '';
      chip.className = 'persona-chip' + (p === state.currentPersona ? ' active' : '');
      chip.textContent = PERSONA_LABELS[p] + lockIcon;
      chip.title = (isGated && !isApproved)
        ? 'Human review gate required — click Approve Gate below to unlock this persona report'
        : '';
      chip.addEventListener('click', function () {
        if (isGated && !isApproved) {
          toast('Gate required: complete analyst review and click "Approve Gate" before generating ' + PERSONA_LABELS[p] + ' reports.', 'error');
          return;
        }
        state.currentPersona = p;
        $('personaSelect').value = p;
        renderPersonaChips();
        renderReport();
      });
      container.appendChild(chip);
    });
    // Gate approval button — appears once an assessment exists
    // NLP-gate confirmation badges for SOC/TH/Compliance personas
    if (state.assessmentId) {
      NLP_GATED_PERSONAS.forEach(function (np) {
        var confirmed = (state._nlpGateConfirmed || {})[np];
        if (!confirmed) return;
        var badge = document.createElement('span');
        badge.style.cssText = 'margin-left:4px;font-size:10px;padding:2px 6px;border-radius:10px;background:rgba(63,168,96,.15);color:#3FA860;border:1px solid rgba(63,168,96,.3);';
        badge.textContent = '✓ ' + (PERSONA_LABELS[np] || np);
        badge.title = 'NLP-confirmed: ' + confirmed.slice(0, 80);
        container.appendChild(badge);
      });
    }
    if (state.assessmentId) {
      var gateBtn = document.createElement('button');
      gateBtn.id = 'btnApproveGate';
      gateBtn.className = 'btn-secondary' + (state._gateApproved ? ' btn-secondary--active' : '');
      gateBtn.style.cssText = 'margin-left:8px;font-size:11px;padding:4px 10px;';
      gateBtn.textContent = state._gateApproved ? '✓ Gate Approved' : '🔓 Approve Gate';
      gateBtn.title = 'Certify that you have reviewed the triage findings — unlocks CISO, Executive, and Audit persona reports';
      gateBtn.addEventListener('click', function () {
        if (state._gateApproved) return;
        approveHumanGate();
      });
      container.appendChild(gateBtn);
    }
  }

  $('personaSelect').addEventListener('change', function () {
    state.currentPersona = this.value;
    renderPersonaChips();
    renderReport();
  });

  // ── Analyze button — runs pipeline + generates report ────────────────────
  $('btnAnalyze').addEventListener('click', function () { runAnalysis(); });

  var _activeWs = null;

  function connectProgressWs(assessmentId, onPct) {
    if (_activeWs) { try { _activeWs.close(); } catch(_) {} _activeWs = null; }
    var proto = location.protocol === 'https:' ? 'wss' : 'ws';
    var wsUrl = proto + '://' + location.host + '/api/v1/csv/deep_analyze/ws/progress/' + encodeURIComponent(assessmentId);
    try {
      var ws = new WebSocket(wsUrl);
      _activeWs = ws;
      ws.addEventListener('message', function (e) {
        try {
          var msg = JSON.parse(e.data);
          if (msg.pct != null) onPct(msg.pct);
          if (msg.status === 'complete' || msg.status === 'completed' || msg.event === 'complete') {
            ws.close();
          }
        } catch (_) {}
      });
      ws.addEventListener('error', function () { _activeWs = null; });
      ws.addEventListener('close', function () { _activeWs = null; });
    } catch (_) { /* WebSocket not available — progress bar uses manual steps */ }
  }

  async function runAnalysis() {
    if (!state.allRows.length) { toast('No rows to analyze', 'error'); return; }

    $('btnAnalyze').disabled = true;
    $('pipelineBar').classList.add('running');
    $('pipelineBarFill').style.width = '10%';
    $('reportEmpty').style.display = 'none';
    $('reportContent').style.display = 'none';
    $('reportLoading').style.display = '';

    try {
      // Step 1: Send to deep_analyze (pipeline enrichment, NO auto-LLM)
      $('pipelineBarFill').style.width = '20%';
      var payload = {
        rows: state.allRows.slice(0, 1000).map(function (r, idx) {
          return { row_index: typeof r.row_index === 'number' ? r.row_index : idx, raw: r };
        }),
        options: { auto_llm: false },
        org: localStorage.getItem('org') || 'local',
        analyze_mode: 'basic',
      };

      var analyzeResp = await fetch('/api/v1/csv/deep_analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify(payload),
      });

      if (!analyzeResp.ok) throw new Error('Pipeline failed: ' + analyzeResp.status);
      var analyzeData = await analyzeResp.json();
      state.assessmentId = analyzeData.assessment_id || analyzeData.report_id;
      $('pipelineBarFill').style.width = '50%';

      // Connect WebSocket for real-time progress updates (falls back to manual steps if unavailable)
      if (state.assessmentId) {
        connectProgressWs(state.assessmentId, function (pct) {
          var clampedPct = Math.max(50, Math.min(90, Math.round(pct * 100)));
          $('pipelineBarFill').style.width = clampedPct + '%';
        });
      }

      // Step 2: Poll for assessment completion (quick — pipeline stages are fast)
      var assessment = await pollAssessment(state.assessmentId);
      state.assessment = assessment;
      $('pipelineBarFill').style.width = '70%';

      // Step 3: Build enriched evidence rows from assessment
      buildEvidenceFromAssessment(assessment);

      // Step 3b: Render graph + timeline visualizations  [B1 fix: graphCanvas not graphContent]
      $('graphEmpty').style.display = 'none';
      $('graphCanvas').style.display = 'flex';
      $('timelineEmpty').style.display = 'none';
      $('timelineContent').style.display = '';
      renderGraph(state.evidenceRows);
      renderTimeline(state.evidenceRows);

      // Step 4: Generate persona report
      $('pipelineBarFill').style.width = '85%';
      await generatePersonaReport(assessment);

      $('pipelineBarFill').style.width = '100%';
      toast('Analysis complete — ' + state.allRows.length + ' events processed', 'success');

      // Save to assessment history
      var headline = (state.assessment && (state.assessment.headline || state.assessment.summary || state.assessment.report_title)) || (state.allRows.length + ' events from ' + state.sources.length + ' source(s)');
      saveToHistory(state.assessmentId, String(headline).slice(0, 80), state.sources);
    } catch (err) {
      toast('Analysis error: ' + err.message, 'error');
      console.error('Analysis error:', err);
      $('reportLoading').style.display = 'none';
      $('reportEmpty').style.display = '';
    } finally {
      $('btnAnalyze').disabled = false;
      setTimeout(function () {
        $('pipelineBar').classList.remove('running');
        $('pipelineBarFill').style.width = '0';
      }, 800);
    }
  }

  async function pollAssessment(id, maxWait) {
    maxWait = maxWait || 30000;
    var start = Date.now();
    while (Date.now() - start < maxWait) {
      try {
        var resp = await fetch('/api/v1/csv/deep_analyze/assessments/' + encodeURIComponent(id), {
          headers: authHeaders(),
        });
        if (resp.ok) {
          var data = await resp.json();
          if (data.status === 'complete' || data.status === 'completed' || data.rows_processed > 0) {
            return data;
          }
        }
      } catch (_) { /* retry */ }
      await new Promise(function (r) { setTimeout(r, 1000); });
    }
    // Return whatever we have even if not fully complete
    return state.assessment || {};
  }

  // ── Build evidence rows from assessment ──────────────────────────────────
  function buildEvidenceFromAssessment(assessment) {
    var rows = state.allRows.map(function (original, idx) {
      var severity = classifySeverity(original);
      var isCorrelated = detectCorrelation(original, idx);
      var entity = extractPrimaryEntity(original);
      var description = extractDescription(original);
      var triage = computeLocalTriageScore(original, severity, isCorrelated);

      return {
        row_index: idx,
        source: original._source || 'unknown',
        severity: severity,
        type: isCorrelated ? 'correlated' : 'isolated',
        entity: entity,
        description: description,
        triage_score: triage,
        raw: original,
        _hasLlm: false,
        _llmSummary: null,
      };
    });

    // Sort by triage_score descending
    rows.sort(function (a, b) { return b.triage_score - a.triage_score; });
    state.evidenceRows = rows;

    updateSeveritySummary(rows);
    renderEvidenceTable(rows);
    $('evidenceBadge').textContent = String(rows.length);
  }

  function classifySeverity(row) {
    // Priority-ordered heuristic check
    var sev = (row.severity || row.Severity || row.riskLevel || row.risk_level || '').toString().toLowerCase();
    if (sev === 'critical' || sev === 'crit') return 'critical';
    if (sev === 'high') return 'high';
    if (sev === 'medium' || sev === 'med') return 'medium';
    if (sev === 'low' || sev === 'informational' || sev === 'info') return 'low';

    // AWS GuardDuty: numeric severity
    var numSev = parseFloat(row.Severity || row.severity);
    if (!isNaN(numSev)) {
      if (numSev >= 7) return 'critical';
      if (numSev >= 5) return 'high';
      if (numSev >= 3) return 'medium';
      return 'low';
    }

    // Azure IdP risk
    if (row.riskLevel) {
      var rl = row.riskLevel.toLowerCase();
      if (rl === 'high') return 'critical';
      if (rl === 'medium') return 'high';
      if (rl === 'low') return 'medium';
    }

    // Keyword checks on common fields
    var text = JSON.stringify(row).toLowerCase();
    if (text.includes('exfil') || text.includes('ransomware') || text.includes('admin')) return 'high';
    if (text.includes('suspicious') || text.includes('anomal')) return 'medium';

    return 'low';
  }

  function detectCorrelation(row, idx) {
    // Simple heuristic: if the row has cross-source entity overlap, mark as correlated
    // In production, HopGraph provides real correlation. For now, check if entity appears in >1 source.
    var entity = extractPrimaryEntity(row);
    if (!entity || entity === '-') return false;
    var sourceCount = 0;
    var seen = {};
    state.allRows.forEach(function (r) {
      var src = r._source || '';
      if (!seen[src] && extractPrimaryEntity(r) === entity) {
        seen[src] = true;
        sourceCount++;
      }
    });
    return sourceCount > 1;
  }

  function extractPrimaryEntity(row) {
    return row.userPrincipalName || row.userIdentity && (row.userIdentity.userName || row.userIdentity.arn) ||
      row.userId || row.user || row.src_ip || row.sourceIPAddress ||
      row.ipAddress || row.entity || row.path || row.process || '-';
  }

  function extractDescription(row) {
    return row.Description || row.description || row.eventName || row.operationName ||
      row.activityDisplayName || row.riskEventType || row.displayName ||
      row.category || row.proto || '';
  }

  function computeLocalTriageScore(row, severity, isCorrelated) {
    var base = { critical: 0.9, high: 0.7, medium: 0.4, low: 0.15 }[severity] || 0.1;
    if (isCorrelated) base += 0.15;
    // Boost for known bad indicators
    var text = JSON.stringify(row).toLowerCase();
    if (text.includes('185.220.101')) base += 0.1;  // Tor exit known
    if (text.includes('exfil')) base += 0.1;
    if (text.includes('administrator') || text.includes('globaladmin')) base += 0.08;
    return Math.min(1.0, Math.round(base * 100) / 100);
  }

  // ── Severity summary ────────────────────────────────────────────────────
  function updateSeveritySummary(rows) {
    var counts = { correlated: { critical: 0, high: 0, medium: 0, low: 0 }, isolated: { critical: 0, high: 0, medium: 0, low: 0 } };
    rows.forEach(function (r) {
      var bucket = r.type === 'correlated' ? 'correlated' : 'isolated';
      counts[bucket][r.severity] = (counts[bucket][r.severity] || 0) + 1;
    });

    ['correlated', 'isolated'].forEach(function (bucket) {
      var container = $('sev' + bucket.charAt(0).toUpperCase() + bucket.slice(1));
      var total = 0;
      container.querySelectorAll('.sev-box').forEach(function (box) {
        var filterKey = box.getAttribute('data-filter');
        var sev = filterKey.split('-')[1];
        var count = counts[bucket][sev] || 0;
        total += count;
        box.querySelector('.sev-box__count').textContent = String(count);
      });
      $('sev' + bucket.charAt(0).toUpperCase() + bucket.slice(1) + 'Total').textContent = total + ' total';
    });

    $('sevSummary').classList.add('has-data');
  }

  // Severity box click → filter evidence table
  document.querySelectorAll('.sev-box').forEach(function (box) {
    box.addEventListener('click', function () {
      var filter = box.getAttribute('data-filter');
      state.activeFilter = filter;
      switchTab('evidence');
      renderEvidenceTable(state.evidenceRows);
      // Update filter chips
      document.querySelectorAll('[data-ev-filter]').forEach(function (c) { c.classList.remove('active'); });
    });
  });

  // ── Evidence table ───────────────────────────────────────────────────────
  function renderEvidenceTable(rows) {
    var filtered = filterRows(rows);
    var tbody = $('evidenceBody');
    tbody.innerHTML = '';
    $('evidenceEmpty').style.display = filtered.length ? 'none' : '';
    $('evidenceCount').textContent = filtered.length + ' of ' + rows.length + ' events';

    filtered.forEach(function (row) {
      var tr = document.createElement('tr');
      tr.setAttribute('data-idx', row.row_index);
      tr.innerHTML =
        '<td>' + row.row_index + '</td>' +
        '<td><span class="corr-icon" title="' + (row.type === 'correlated' ? 'Correlated across sources' : 'Isolated') + '">' + (row.type === 'correlated' ? '●' : '') + '</span></td>' +
        '<td><span class="text-xs">' + escHtml(shortSource(row.source)) + '</span></td>' +
        '<td><span class="sev-pill sev-pill--' + row.severity + '">' + row.severity.toUpperCase() + '</span></td>' +
        '<td><span class="text-xs">' + escHtml(row.type) + '</span></td>' +
        '<td title="' + escHtml(row.entity) + '">' + escHtml(truncate(row.entity, 30)) + '</td>' +
        '<td title="' + escHtml(row.description) + '">' + escHtml(truncate(row.description, 40)) + '</td>' +
        '<td style="font-weight:600; color:' + scoreColor(row.triage_score) + '">' + row.triage_score.toFixed(2) + '</td>' +
        '<td>' + (row._hasLlm ? '<span style="color:var(--safe)">✓</span>' : '<button class="btn-secondary" style="padding:2px 6px;font-size:10px;" data-llm="' + row.row_index + '">T1</button>') + '</td>';
      tr.addEventListener('click', function () { showDetail(row); });
      tbody.appendChild(tr);
    });
  }

  function filterRows(rows) {
    var f = state.activeFilter;
    if (f === 'all') return rows;
    // Compound filter like "correlated-critical"
    if (f.includes('-')) {
      var parts = f.split('-');
      return rows.filter(function (r) { return r.type === parts[0] && r.severity === parts[1]; });
    }
    // Single filter
    if (['critical', 'high', 'medium', 'low'].indexOf(f) >= 0) {
      return rows.filter(function (r) { return r.severity === f; });
    }
    if (f === 'correlated' || f === 'isolated') {
      return rows.filter(function (r) { return r.type === f; });
    }
    return rows;
  }

  function shortSource(name) {
    if (!name) return '?';
    return name.length > 20 ? name.substring(0, 18) + '…' : name;
  }

  function truncate(s, max) {
    if (!s) return '';
    return s.length > max ? s.substring(0, max - 1) + '…' : s;
  }

  function scoreColor(score) {
    if (score >= 0.8) return 'var(--critical)';
    if (score >= 0.6) return 'var(--high)';
    if (score >= 0.35) return 'var(--medium)';
    return 'var(--low)';
  }

  // Filter chips
  document.querySelectorAll('[data-ev-filter]').forEach(function (chip) {
    chip.addEventListener('click', function () {
      document.querySelectorAll('[data-ev-filter]').forEach(function (c) { c.classList.remove('active'); });
      chip.classList.add('active');
      state.activeFilter = chip.getAttribute('data-ev-filter');
      renderEvidenceTable(state.evidenceRows || []);
    });
  });

  // Column sorting
  document.querySelectorAll('.ev-table th[data-sort]').forEach(function (th) {
    th.addEventListener('click', function () {
      var col = th.getAttribute('data-sort');
      if (state.sortCol === col) {
        state.sortDir = state.sortDir === 'desc' ? 'asc' : 'desc';
      } else {
        state.sortCol = col;
        state.sortDir = 'desc';
      }
      if (state.evidenceRows) {
        state.evidenceRows.sort(function (a, b) {
          var av = a[col], bv = b[col];
          if (typeof av === 'number' && typeof bv === 'number') return state.sortDir === 'desc' ? bv - av : av - bv;
          return state.sortDir === 'desc' ? String(bv || '').localeCompare(String(av || '')) : String(av || '').localeCompare(String(bv || ''));
        });
        renderEvidenceTable(state.evidenceRows);
      }
    });
  });

  // ── Per-row LLM (on-demand T1) ──────────────────────────────────────────
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-llm]');
    if (!btn) return;
    e.stopPropagation();
    var idx = parseInt(btn.getAttribute('data-llm'), 10);
    requestRowLLM(idx, btn);
  });

  async function requestRowLLM(idx, btn) {
    // Get selected thinking mode from the dropdown (if present)
    var modeEl = document.getElementById('thinkingModeSelect');
    var thinkingMode = (modeEl && modeEl.value) || 'preserved';
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    try {
      if (!state.assessmentId) { toast('No assessment — run Analyze first', 'error'); return; }
      var row = state.allRows[idx] || {};
      // Use the tier2_thinking endpoint for full thinking-mode support (B5 fix)
      var resp = await fetch('/api/v1/csv/tier2_thinking', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({
          rows: [{ row_index: idx, raw: row }],
          org: localStorage.getItem('org') || 'local',
          assessment_id: state.assessmentId,
          persona: state.currentPersona || 'soc_analyst',
          thinking_mode: thinkingMode,
          thinking_budget: 1024,
        }),
      });
      if (!resp.ok) throw new Error('LLM request failed: ' + resp.status);
      var data = await resp.json();
      // Compose the LLM summary object with thinking blocks
      var llmSummary = {
        summary: data.text || '',
        thinking_blocks: data.thinking_blocks || [],
        thinking_mode: data.thinking_mode || thinkingMode,
        reasoning_summary: data.reasoning_summary || '',
        meta: data.meta || {},
      };
      var evRow = state.evidenceRows && state.evidenceRows.find(function (r) { return r.row_index === idx; });
      if (evRow) {
        evRow._hasLlm = true;
        evRow._llmSummary = llmSummary;
        showDetail(evRow);
      }
      renderEvidenceTable(state.evidenceRows || []);
      toast('T1 summary generated (' + thinkingMode + ' thinking) for row ' + idx, 'success');
    } catch (err) {
      toast('LLM error: ' + err.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'T1'; }
    }
  }

  // ── Generate persona report ──────────────────────────────────────────────
  async function generatePersonaReport(assessment) {
    var persona = PERSONA_ALIASES[state.currentPersona] || state.currentPersona;
    try {
      var url = '/api/v1/report/ingestion?format=json&persona=' + encodeURIComponent(persona) + '&include_model=true&include_scenarios=true';
      var resp = await fetch(url, { headers: authHeaders() });
      if (resp.ok) {
        var reportData = await resp.json();
        if (buildBackendReport(reportData, assessment)) return;
      }
    } catch (_) { /* fall through */ }
    buildLocalReport(assessment);
  }

  function buildBackendReport(reportData, assessment) {
    if (!reportData) return false;
    var narrative = (reportData.narrative || (reportData.summary && reportData.summary.narrative) || '').trim();
    var title = (reportData.title || (reportData.summary && reportData.summary.title) || '').trim();
    var personaData = reportData.persona_sections || reportData.sections || {};
    var sections = [];
    if (Array.isArray(personaData)) {
      sections = personaData.map(function (s) {
        return { title: s.heading || s.title || 'Section', html: '<p>' + escHtml(s.text || s.content || '') + '</p>' };
      });
    } else if (personaData && typeof personaData === 'object') {
      Object.keys(personaData).forEach(function (key) {
        var val = personaData[key];
        sections.push({ title: key.replace(/_/g, ' '), html: '<p>' + escHtml(typeof val === 'string' ? val : JSON.stringify(val)) + '</p>' });
      });
    }
    if (narrative && sections.length === 0) sections.push({ title: 'Analysis', html: '<p>' + escHtml(narrative) + '</p>' });
    if (sections.length === 0) return false;
    var evRows = state.evidenceRows || [];
    var critCount = evRows.filter(function (r) { return r.severity === 'critical'; }).length;
    var highCount = evRows.filter(function (r) { return r.severity === 'high'; }).length;
    var headline = title || (critCount > 0 ? 'P1 — ' + critCount + ' critical finding(s)' : highCount > 0 ? 'P2 — High severity events' : 'P3 — Review complete');
    state.reportArtifacts[state.currentPersona] = { headline: headline, sections: sections };
    renderReport();
    return true;
  }

  function buildLocalReport(assessment) {
    var canonical = assessment.canonical || {};
    var mappings = assessment.mappings || {};
    var rows = state.allRows || [];
    var evRows = state.evidenceRows || [];
    var persona = state.currentPersona || 'soc_analyst';

    // Build headline based on severity distribution
    var critCount = evRows.filter(function (r) { return r.severity === 'critical'; }).length;
    var highCount = evRows.filter(function (r) { return r.severity === 'high'; }).length;
    var corrCount = evRows.filter(function (r) { return r.type === 'correlated'; }).length;
    var sourceCount = state.sources.length;
    var totalRows = evRows.length;

    var headline;
    if (critCount > 0) {
      headline = 'P1 — ' + critCount + ' critical event' + (critCount !== 1 ? 's' : '') +
        ' across ' + sourceCount + ' source' + (sourceCount !== 1 ? 's' : '') +
        (corrCount > 0 ? ' | ' + corrCount + ' correlated' : '');
    } else if (highCount > 0) {
      headline = 'P2 — ' + highCount + ' high-severity event' + (highCount !== 1 ? 's' : '') +
        ' need investigation | ' + totalRows + ' total events';
    } else {
      headline = 'P3 — ' + totalRows + ' events reviewed | No confirmed threat';
    }

    // Build report sections — persona-differentiated content
    var sections = [];

    // ── Persona-specific introduction ────────────────────────────────────
    var personaIntros = {
      soc_analyst: 'You are reviewing this dataset as a <b>Tier 1 SOC Analyst</b>. Your objective is triage: ' +
        'identify true-positive events, isolate affected hosts, and escalate confirmed findings within SLA. ' +
        'Evidence is ranked by triage score. Focus on Critical/High correlated events first.',
      ciso: 'This report is framed for <b>CISO-level review</b>. The focus is on business risk, control-gap ' +
        'remediation, and board communication. Precise technical details are available in the Evidence tab.',
      executive: 'This <b>Executive Summary</b> conveys material risk, estimated business impact, and immediate actions ' +
        'in plain language. No technical jargon. Board and management communication ready.',
      threat_hunter: 'You are operating as a <b>Threat Hunter</b>. This view emphasises behavioral rarity, correlated ' +
        'kill-chain paths, and hypothesis-driven hunting leads. Prioritize anomalous events that evade signature detection.',
      forensics: 'This <b>Digital Forensics</b> view supports court-admissible documentation. Each finding includes ' +
        'its chain of custody context. Preserve evidence order and do not apply remediation before forensic capture.',
      compliance: 'This <b>Compliance review</b> maps findings against NDB Scheme, APRA CPS 234, ISO 27001, and relevant ' +
        'controls. Each critical event includes a notification-trigger assessment.',
      audit: 'This <b>Audit-ready report</b> documents control effectiveness, identifies nonconformities, and tracks ' +
        'remediation obligations per ISO 19011 audit standards.',
      mssp: 'This report is framed for <b>MSSP operations</b>. Multi-tenant context is included. SLA breach risks, ' +
        'escalation thresholds, and client notification requirements are highlighted.',
    };
    if (personaIntros[persona]) {
      sections.push({ title: 'Analyst Context — ' + (PERSONA_LABELS[persona] || persona), html: '<p>' + personaIntros[persona] + '</p>' });
    }

    // What We Found
    var findingsHtml = '<p>';
    if (corrCount > 0) {
      findingsHtml += 'Correlation detected across <b>' + sourceCount + '</b> security sources. ';
      findingsHtml += '<b>' + corrCount + '</b> events share entities (IPs, users, resources) across multiple sources, ';
      findingsHtml += 'suggesting a coordinated chain rather than isolated alerts.';
    } else {
      findingsHtml += totalRows + ' events were analyzed from ' + sourceCount + ' source' + (sourceCount !== 1 ? 's' : '') + '. ';
      findingsHtml += 'No cross-source correlation was detected at this time.';
    }
    findingsHtml += '</p>';
    sections.push({ title: 'What We Found', html: findingsHtml });

    // Persona-specific action lists
    var actionsByPersona = {
      soc_analyst: critCount > 0
        ? '<li><b>NOW:</b> Isolate affected entities — open incident before any remediation. Do not reboot (volatile memory matters).</li>' +
          '<li><b>NOW:</b> Correlated events = same incident, do not close independently.</li>' +
          '<li><b>60min:</b> Confirm or deny each critical finding. Post triage result to incident ticket.</li>'
        : '<li><b>Next:</b> Review all High events within 4h SLA. Mark benign activity as tuning candidates.</li>',
      threat_hunter: '<li><b>Pivot:</b> For each correlated entity, pivot to MITRE ATT&CK Execution / Persistence sub-techniques.</li>' +
        '<li><b>Hunt:</b> Check for LOLBAS usage and beacon jitter patterns in Network source.</li>' +
        '<li><b>IOC:</b> Extract process hashes, destination IPs, and JA3 fingerprints for proactive hunting across other tenants.</li>',
      forensics: '<li><b>Preserve:</b> Memory dump and full PCAP before containment — capture per ISO 19011 §6.4.5.</li>' +
        '<li><b>Chain of custody:</b> Document each artefact with hash, timestamp, and analyst identity before transfer.</li>' +
        '<li><b>Do NOT:</b> Apply patches or cleanup until forensic capture is complete.</li>',
      compliance: '<li><b>NDB:</b> Assess whether eligible data breach threshold under s.26WB is met (serious harm test).</li>' +
        '<li><b>CPS 234:</b> Determine if the finding meets APRA §36 "material incident" notification obligation.</li>' +
        '<li><b>ISO 27001:</b> Log each critical event as a Nonconformity under clause 10.1 with remediation owner and date.</li>',
      ciso: '<li><b>Risk:</b> Review board risk register — update threat landscape rating if P1 confirmed.</li>' +
        '<li><b>Control gaps:</b> Identify which Annex A controls failed and schedule remediation review.</li>' +
        '<li><b>Communication:</b> Prepare brief for board/exec within 24h if P1 confirmed; include business impact and recovery plan.</li>',
    };
    var defaultActions = (critCount > 0
      ? '<li><b>NOW:</b> Review the ' + critCount + ' critical event' + (critCount !== 1 ? 's' : '') + ' in the Evidence tab.</li>'
      : '') +
      (highCount > 0 ? '<li><b>4h:</b> Investigate ' + highCount + ' high-severity events.</li>' : '') +
      '<li><b>Next:</b> Use Evidence tab. Click T1 for per-row AI summary.</li>';
    var actionsHtml = '<ul>' + (actionsByPersona[persona] || defaultActions) + '</ul>';
    sections.push({ title: 'Immediate Actions', html: actionsHtml });

    // Source Summary
    var sourcesHtml = '<table class="ev-table" style="font-size:12px;"><thead><tr><th>Source</th><th>Type</th><th>Events</th><th>Critical</th><th>High</th></tr></thead><tbody>';
    state.sources.forEach(function (src) {
      var srcRows = evRows.filter(function (r) { return r.source === src.name; });
      var srcCrit = srcRows.filter(function (r) { return r.severity === 'critical'; }).length;
      var srcHigh = srcRows.filter(function (r) { return r.severity === 'high'; }).length;
      sourcesHtml += '<tr><td>' + escHtml(src.name) + '</td><td>' + escHtml(TYPE_LABELS[src.type] || src.type) + '</td><td>' + srcRows.length + '</td>';
      sourcesHtml += '<td>' + (srcCrit ? '<span class="sev-pill sev-pill--critical">' + srcCrit + '</span>' : '0') + '</td>';
      sourcesHtml += '<td>' + (srcHigh ? '<span class="sev-pill sev-pill--high">' + srcHigh + '</span>' : '0') + '</td></tr>';
    });
    sourcesHtml += '</tbody></table>';
    sections.push({ title: 'Source Summary', html: sourcesHtml });

    // ── CRQ Financial Exposure (from workbook_sheets endpoint or assessment) ─
    // Display a *range* (not a point estimate) and always mark as unvalidated.
    // Exact dollar figures require a human gate: GRC/CISO/finance must confirm
    // affected asset class, records count, regulatory obligations, and insurance
    // coverage before a precise breach-loss number is credible.
    var crq = (state.workbookMeta && state.workbookMeta.crq) ||
              (assessment && assessment.crq_shadow) ||
              (assessment && assessment.crq) || null;
    if (crq) {
      var crqTier = (crq.exposure_tier || '').toUpperCase();
      var crqColor = {CRITICAL:'#E54848',HIGH:'#FF8A3C',MEDIUM:'#E0C446',LOW:'#3FA860'}[crqTier] || 'var(--text-muted)';

      // Prefer the new range format; fall back gracefully to old exact format
      // (old format kept for backward compatibility, always shown as unvalidated).
      var er = crq.exposure_range || null;
      var crqRangeDisplay = er
        ? escHtml(crq.exposure_range_formatted || (er.low + ' – ' + er.high))
        : (crq.expected_loss_formatted
            ? escHtml(crq.expected_loss_formatted) + ' <em style="font-size:10px;font-weight:400;">(unvalidated)</em>'
            : 'Range unavailable');

      var crqHtml = '<div style="padding:12px;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border);">';

      // Tier pill + unvalidated label
      crqHtml += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">' +
        '<span class="sev-pill sev-pill--' + (crqTier || 'info').toLowerCase() + '">' + escHtml(crqTier || 'UNKNOWN') + ' Exposure</span>' +
        '<span style="font-size:10px;color:var(--text-muted);background:rgba(255,200,0,0.12);padding:2px 7px;border-radius:4px;border:1px solid rgba(255,200,0,0.3);">' +
        '\u26A0\uFE0F Unvalidated planning estimate</span>' +
        '</div>';

      // Range display — NOT a precise dollar figure
      crqHtml += '<div style="font-size:15px;font-weight:700;color:' + crqColor + ';margin-bottom:4px;">' +
        crqRangeDisplay +
        '</div>';
      crqHtml += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">' +
        'Telemetry-based range estimate &mdash; wide band reflects uncertainty without validated FAIR inputs.</div>';

      // Severity distribution
      var sevCounts = crq.severity_counts || {};
      if (Object.keys(sevCounts).some(function (k) { return sevCounts[k] > 0; })) {
        crqHtml += '<div style="margin-bottom:8px;font-size:11px;color:var(--text-muted);">Event distribution: ' +
          ['critical', 'high', 'medium', 'low', 'unknown'].map(function (s) {
            return sevCounts[s] ? '<span class="sev-pill sev-pill--' + (s === 'unknown' ? 'info' : s) + '" style="margin:0 2px;">' + (sevCounts[s] || 0) + ' ' + s + '</span>' : '';
          }).filter(Boolean).join(' ') + '</div>';
      }

      // Confidence signal
      if (crq.confidence) {
        var confColors = {high:'#3FA860', medium:'#E0C446', low:'#FF8A3C'};
        crqHtml += '<div style="font-size:11px;margin-bottom:8px;">' +
          'Classification confidence: <span style="color:' + (confColors[crq.confidence] || 'var(--text-muted)') + ';font-weight:600;">' + escHtml(crq.confidence) + '</span>' +
          (crq.confidence === 'low' ? ' &mdash; many rows have no explicit severity signal' : '') + '</div>';
      }

      // Entity pivot summary
      if (state.workbookMeta && state.workbookMeta.pivotedRowCount > 0) {
        var ep = state.workbookMeta.entityPivots || {};
        var pivotIps = Object.keys(ep.ips || {});
        var pivotUsers = Object.keys(ep.users || {});
        crqHtml += '<div style="padding:8px;background:rgba(var(--accent-rgb,59,130,246),0.08);border-radius:6px;' +
          'border:1px solid rgba(var(--accent-rgb,59,130,246),0.2);font-size:11px;">' +
          '<span style="color:var(--accent);font-weight:600;">\u24D8 Cross-sheet pivots:</span> ' +
          state.workbookMeta.pivotedRowCount + ' rows share entities across multiple domain sheets.' +
          (pivotIps.length ? ' <b>IPs:</b> ' + pivotIps.slice(0,4).map(function(x){return escHtml(x);}).join(', ') + (pivotIps.length > 4 ? ' +' + (pivotIps.length-4) + ' more' : '') + '.' : '') +
          (pivotUsers.length ? ' <b>Users:</b> ' + pivotUsers.slice(0,3).map(function(x){return escHtml(x);}).join(', ') + '.' : '') +
          ' Tagged <code>cross_sheet_pivot</code> — elevated triage weighting applied.' +
          '</div>';
      }

      // Required validation note
      crqHtml += '<div style="margin-top:8px;padding:6px 8px;background:rgba(255,200,0,0.06);border-left:3px solid #E0C446;font-size:10px;color:var(--text-muted);">' +
        '<b>Requires human validation</b> &mdash; ' +
        escHtml((crq.validation_note || 'Engage GRC/finance to confirm affected asset class, records at risk, regulatory obligations, insurance, and business interruption costs.')) +
        '</div>';

      crqHtml += '</div>';

      // Persona-specific section titles
      var crqTitles = {
        ciso: 'Financial Risk Quantification (CRQ) \u2014 Planning Stage',
        executive: 'Estimated Business Exposure (Unvalidated)',
        compliance: 'Regulatory Exposure Estimate (Unvalidated)',
        audit: 'Financial Risk Register Input',
        mssp: 'Client Exposure Planning Estimate',
      };
      sections.push({ title: crqTitles[persona] || 'CRQ Exposure Estimate (Unvalidated)', html: crqHtml });
    }

    // Sheet breakdown (if workbook meta available)
    if (state.workbookMeta && state.workbookMeta.sheets && state.workbookMeta.sheets.length > 1) {
      var sheetsHtml = '<table class="ev-table" style="font-size:12px;"><thead><tr><th>Sheet</th><th>Domain</th><th>Events</th></tr></thead><tbody>';
      state.workbookMeta.sheets.forEach(function (s) {
        sheetsHtml += '<tr><td>' + escHtml(s.sheet) + '</td><td><span class="sev-pill sev-pill--info">' + escHtml(s.domain || '') + '</span></td><td>' + (s.row_count || 0) + '</td></tr>';
      });
      sheetsHtml += '</tbody></table>';
      sections.push({ title: 'Workbook Sheet Breakdown', html: sheetsHtml });
    }

    // Framework Mappings (if available)
    if (mappings.mitre && Object.keys(mappings.mitre).length) {
      var mitreHtml = '<div class="text-sm">';
      var techniques = mappings.mitre.techniques || Object.keys(mappings.mitre);
      techniques.slice(0, 10).forEach(function (t) {
        mitreHtml += '<span class="sev-pill sev-pill--info" style="margin:2px 4px 2px 0;">' + escHtml(typeof t === 'string' ? t : t.id || t.technique_id || JSON.stringify(t)) + '</span>';
      });
      mitreHtml += '</div>';
      sections.push({ title: 'MITRE ATT&CK Mapping', html: mitreHtml });
    }

    // Still Unknown
    sections.push({
      title: 'Still Unknown',
      html: '<ul>' +
        '<li>Whether any data left the environment (requires network egress analysis).</li>' +
        '<li>Whether additional accounts or systems were affected outside this evidence window.</li>' +
        '<li>Whether observed activity was authorized administrative work or malicious.</li>' +
        '</ul>',
    });

    // Store and render
    state.reportArtifacts[state.currentPersona] = { headline: headline, sections: sections };
    renderReport();
  }

  function renderReport() {
    var artifact = state.reportArtifacts[state.currentPersona];
    var persona = state.currentPersona || 'soc_analyst';

    // NLP gate: for SOC/TH/Compliance, if not yet confirmed, show confirmation form
    if (artifact && NLP_GATED_PERSONAS.indexOf(persona) >= 0 && state.assessmentId) {
      var confirmed = (state._nlpGateConfirmed || {})[persona];
      if (!confirmed) {
        $('reportEmpty').style.display = 'none';
        $('reportLoading').style.display = 'none';
        $('reportContent').style.display = '';
        var headlineEl = $('reportHeadline');
        headlineEl.textContent = 'NLP Confirmation Required — ' + (PERSONA_LABELS[persona] || persona);
        headlineEl.style.borderLeftColor = 'var(--accent)';
        var body = $('reportBody');
        var nlpPrompts = {
          soc_analyst: 'Document your triage verdict: summarise what you have reviewed, any true positives confirmed, and your recommended immediate action.',
          threat_hunter: 'Record your hunting hypothesis: what technique or attacker behaviour are you assessing, and what evidence confirms or denies it?',
          compliance: 'State your compliance determination: which regulatory obligations are triggered, and what notification or remediation actions are required?',
        };
        body.innerHTML =
          '<div class="report-section">' +
          '<div class="report-section__title">Analyst NLP Confirmation — ' + escHtml(PERSONA_LABELS[persona] || persona) + '</div>' +
          '<div class="report-section__body">' +
          '<p style="font-size:12px;">' + escHtml(nlpPrompts[persona] || 'Confirm your assessment before the report is generated.') + '</p>' +
          '<textarea id="nlpGateInput" style="width:100%;min-height:80px;margin-top:8px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);padding:8px;font-family:inherit;font-size:12px;resize:vertical;" placeholder="Enter your confirmation..."></textarea>' +
          '<div style="margin-top:8px;display:flex;gap:8px;">' +
          '<button class="btn-primary" id="btnNlpConfirm" style="font-size:12px;padding:6px 14px;">\uD83E\uDD16 Confirm &amp; Generate Report</button>' +
          '</div></div></div>';
        var confirmBtn = document.getElementById('btnNlpConfirm');
        if (confirmBtn) {
          confirmBtn.addEventListener('click', function () {
            var txt = (document.getElementById('nlpGateInput') || {}).value || '';
            submitNlpGate(persona, txt);
          });
        }
        renderPersonaChips();
        return;
      }
    }

    if (!artifact) {
      $('reportEmpty').style.display = '';
      $('reportContent').style.display = 'none';
      $('reportLoading').style.display = 'none';
      return;
    }

    $('reportEmpty').style.display = 'none';
    $('reportLoading').style.display = 'none';
    $('reportContent').style.display = '';

    // Update headline severity color
    var headlineEl = $('reportHeadline');
    headlineEl.textContent = artifact.headline;
    if (artifact.headline.startsWith('P1')) headlineEl.style.borderLeftColor = 'var(--critical)';
    else if (artifact.headline.startsWith('P2')) headlineEl.style.borderLeftColor = 'var(--high)';
    else headlineEl.style.borderLeftColor = 'var(--accent)';

    // Render sections
    var body = $('reportBody');
    body.innerHTML = '';
    artifact.sections.forEach(function (sec) {
      var div = document.createElement('div');
      div.className = 'report-section';
      div.innerHTML = '<div class="report-section__title">' + escHtml(sec.title) + '</div>' +
        '<div class="report-section__body">' + sec.html + '</div>';
      body.appendChild(div);
    });

    // Show NLP confirmation badge if confirmed
    var confirmed = (state._nlpGateConfirmed || {})[persona];
    if (confirmed) {
      var badge = document.createElement('div');
      badge.style.cssText = 'margin-top:10px;padding:8px 12px;background:rgba(63,168,96,.1);border:1px solid rgba(63,168,96,.3);border-radius:6px;font-size:11px;color:#3FA860;';
      badge.innerHTML = '<b>\u2713 NLP Confirmed by ' + escHtml(PERSONA_LABELS[persona] || persona) + ':</b> ' + escHtml(confirmed.slice(0, 160)) + (confirmed.length > 160 ? '\u2026' : '');
      body.appendChild(badge);
    }

    renderPersonaChips();
  }

  // ── Detail panel ─────────────────────────────────────────────────────────
  // Dimension metadata: label, evidence description, confirm-logs, deny-logs, playbook per persona-group
  var BREAKDOWN_META = {
    dread: {
      label: 'Threat Severity (DREAD)',
      desc: 'Composite of Damage Potential, Reproducibility, Exploitability, Affected Scope, and Discoverability. High score means the technique is well-understood, easy to repeat, and impacts many users.',
      confirm: 'EDR process tree · AV/NDR alert feed · VirusTotal hash submission · Endpoint sysmon EventID 1/3',
      deny: 'Patch management records (verify vuln is patched) · Application allow-list entries · Admin scheduled-task logs',
      playbook: {
        soc: 'P1 SLA: isolate affected host(s) before any remediation. Open incident ticket with triage_score and DREAD value attached. Do not reboot — volatile memory contains live attacker artefacts.',
        hunter: 'Pivot to ATT&CK Execution/Persistence sub-techniques. Scan all endpoints sharing the same parent process, user, or destination IP. Check LOLBAS for the process name.',
        forensics: 'Capture memory dump (winpmem/volatility3) and full PCAP NOW — before containment. Each DREAD sub-dimension maps to a separate forensic artefact; log them individually.',
        compliance: 'High DREAD satisfies the "serious harm" test under NDB Scheme s.26WB. Start notification clock. Review whether APRA CPS 234 §36 material incident threshold is met.',
      },
    },
    correlation: {
      label: 'Campaign Correlation',
      desc: 'How many other events in this session share the same entity, actor, or infrastructure. High score means this is part of a coordinated, multi-event attack rather than an isolated alert.',
      confirm: 'DNS/proxy logs for same source IP across the full time window · SIEM query: same user or host across all indexes · Zeek conn.log for repeated outbound pattern',
      deny: 'Legitimate scheduled task / backup job logs · Helpdesk records for admin work on those systems · Deployment pipeline logs (CI/CD artifact pushes)',
      playbook: {
        soc: 'Search SIEM for all events sharing the correlated pivot (IP/user/domain). Scope the blast radius. Alert: do not dismiss other events in this session — they are the same incident.',
        hunter: 'Build a kill-chain timeline across all correlated events. Use the shared pivot as the hunt root. Lateral movement to adjacent subnets is the most probable next phase.',
        forensics: 'Chain-of-custody must span ALL correlated events. Document each artefact separately but link under one root-cause finding. ISO 19011 §6.5.4 requires chronological continuity.',
        compliance: 'Multiple correlated events increase the count of affected data subjects — the key NDB Scheme determinant. Aggregate all correlated events in the notification scope assessment.',
      },
    },
    density: {
      label: 'Attack Complexity (Factor Density)',
      desc: 'How many distinct threat behaviors (factors) appear in one event. High score means complex, multi-technique activity — often a sign of hands-on-keyboard or toolkit-driven intrusion.',
      confirm: 'Full PCAP around the event timestamp · Parent process tree (sysmon EventID 1+13) · Registry snapshot (Autoruns or sysmon EventID 13) · Scheduled task export (schtasks /query)',
      deny: 'Application crash/test logs · Developer workstation exception reports · Anti-malware scan showing clean result on the same hash',
      playbook: {
        soc: 'Escalate to Tier 2 immediately — multi-technique events are not handled safely by single-analyst triage. Do not attempt to remediate individual factors without the full kill-chain picture.',
        hunter: 'High density suggests automated toolkit (Cobalt Strike, Sliver, Havoc, Brute Ratel). Run YARA rules for C2 framework beacon signatures. Check beacon intervals in Zeek conn.log or Suricata.',
        forensics: 'Each factor = a separate forensic artefact requiring separate provenance documentation. Do not combine them into a single exhibit — it obscures the attack sequence in legal/regulatory review.',
        compliance: 'Multiple distinct control failures in one event = multiple separate ISO 27001 Annex A Major Nonconformities. Document each individually — grouping understates audit scope.',
      },
    },
    confidence: {
      label: 'Detection Confidence',
      desc: 'How certain the detection model is in its verdict. Low score means the evidence is partial or ambiguous — human validation is required before any containment action.',
      confirm: 'Raw event re-parse with manual analyst review · Second-source corroboration (e.g., network + endpoint for the same event) · Threat intel feed query on the entity',
      deny: 'Nothing — low confidence means validate first; do not dismiss without a documented reason. Check known-good baseline for the same entity.',
      playbook: {
        soc: 'Do NOT contain based on low-confidence alerts alone. Pull the raw event and manually confirm process lineage and network destination before any host isolation or IP block.',
        hunter: 'Run hypothesis queries below before generating more alerts from this event. Low confidence means the technique is not yet confirmed — validate IOCs via VirusTotal and ANY.RUN sandbox.',
        forensics: 'Capture evidence passively but do not apply remediation labels. Document the confidence limitation in the workpaper — ISO 19011 §6.4.5: evidence must be verifiable.',
        compliance: 'Low confidence does not reset the notification clock. Document the confidence level in the preliminary assessment and submit with a "best endeavours" qualifier to the regulator.',
      },
    },
    rarity: {
      label: 'Behavioral Rarity',
      desc: 'How unusual this behavior is versus the established baseline. High score means first-seen activity with no prior precedent — potential zero-day, supply-chain compromise, or novel technique.',
      confirm: 'Threat intel feed query for the entity/hash/domain · MITRE ATT&CK search for technique sub-variants · EDR baseline comparison for the same host over last 30 days · ANY.RUN or Hybrid Analysis sandbox',
      deny: 'Admin change log (new software deployment, patch rollout) · User change log (role change, new device) · Asset inventory (new system recently provisioned)',
      playbook: {
        soc: 'Flag for threat intelligence escalation — possible zero-day indicator. Do not dismiss as FP without written justification and second-analyst sign-off. Check VirusTotal for the process hash.',
        hunter: 'Cross-reference MITRE ATT&CK for novel technique categories. Generate a specific IoC set (hash, domain, IP) for threat intel enrichment and proactive hunting across other tenants.',
        forensics: 'Preserve the full binary sample for sandbox analysis. First-seen behavior may constitute unique evidence in prosecution or regulatory review — chain-of-custody is critical here.',
        compliance: 'First-seen activity that cannot be explained by authorised admin action satisfies the NDB Scheme eligible breach threshold. Precautionary notification + provisional risk assessment recommended.',
      },
    },
  };

  var PERSONA_TO_PLAYBOOK_KEY = {
    soc_analyst: 'soc', threat_hunter: 'hunter', forensics: 'forensics',
    compliance: 'compliance', audit: 'compliance', ciso: 'compliance',
    executive: 'soc', mssp: 'soc',
  };

  function buildBreakdownSection(row) {
    var bd = (row.raw && row.raw._triage_breakdown) || null;
    // Derive from local signals if server breakdown unavailable
    if (!bd) {
      var sevMap = { critical: 0.9, high: 0.7, medium: 0.45, low: 0.2 };
      var dreadEst = sevMap[row.severity] || 0.3;
      var corrEst = row.type === 'correlated' ? 0.75 : 0.15;
      var factors = (row.raw && (row.raw.factors || (row.raw._factors))) || [];
      var densEst = Math.min(1.0, (Array.isArray(factors) ? factors.length : 0) / 6);
      bd = { dread: dreadEst, correlation: corrEst, density: densEst, confidence: 0.4, rarity: 0.2 };
    }
    var dims = ['dread', 'correlation', 'density', 'confidence', 'rarity'];
    var BAR_COLORS = { dread: '#E54848', correlation: '#FF8A3C', density: '#E0C446', confidence: '#3FA860', rarity: '#5b9bd5' };
    var topDim = dims.reduce(function (a, b) { return (bd[a] || 0) >= (bd[b] || 0) ? a : b; });
    var pkKey = PERSONA_TO_PLAYBOOK_KEY[state.currentPersona] || 'soc';
    var meta = BREAKDOWN_META[topDim] || BREAKDOWN_META.dread;

    var barsHtml = dims.map(function (d) {
      var val = Math.max(0, Math.min(1, bd[d] || 0));
      var pct = Math.round(val * 100);
      var col = BAR_COLORS[d];
      var m = BREAKDOWN_META[d] || {};
      return '<div style="margin:4px 0;">' +
        '<div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:2px;">' +
        '<span style="color:var(--text-secondary);">' + escHtml(m.label || d) + '</span>' +
        '<span style="font-weight:600;color:' + col + ';">' + pct + '%</span>' +
        '</div>' +
        '<div style="height:6px;border-radius:3px;background:var(--bg-tertiary,#1e2a3a);overflow:hidden;">' +
        '<div style="height:100%;width:' + pct + '%;background:' + col + ';border-radius:3px;transition:width .4s"></div>' +
        '</div></div>';
    }).join('');

    // Per-dimension evidence analysis detail (collapsed)
    var dimDetailHtml = dims.map(function (d) {
      var val = Math.round((bd[d] || 0) * 100);
      var m = BREAKDOWN_META[d] || {};
      return '<div style="margin-top:8px;padding:8px;background:var(--bg-tertiary,#1e2a3a);border-radius:4px;font-size:11px;">' +
        '<strong style="color:' + BAR_COLORS[d] + ';">' + escHtml(m.label || d) + ' — ' + val + '%</strong>' +
        '<p style="margin:4px 0 2px;color:var(--text-secondary);">' + escHtml(m.desc || '') + '</p>' +
        '<p style="margin:2px 0;"><span style="color:#3FA860;">✓ Confirm with:</span> ' + escHtml(m.confirm || '—') + '</p>' +
        '<p style="margin:2px 0 0;"><span style="color:#E54848;">✗ Deny with:</span> ' + escHtml(m.deny || '—') + '</p>' +
        '</div>';
    }).join('');

    var playbookSteps = meta.playbook || {};
    var playbookHtml = Object.keys(playbookSteps).map(function (role) {
      var roleLabel = { soc: 'SOC Analyst', hunter: 'Threat Hunter', forensics: 'Forensics', compliance: 'Compliance/Audit' }[role] || role;
      var isActive = role === pkKey;
      return '<div style="margin:4px 0;padding:6px 8px;border-left:3px solid ' + (isActive ? BAR_COLORS[topDim] : 'var(--border)') + ';' +
        (isActive ? 'background:var(--bg-tertiary,#1e2a3a);' : 'opacity:.65;') + 'border-radius:0 4px 4px 0;font-size:11px;">' +
        '<strong>' + escHtml(roleLabel) + ':</strong> ' + escHtml(playbookSteps[role]) +
        '</div>';
    }).join('');

    return '<div class="report-section">' +
      '<div class="report-section__title">Score Breakdown — Top driver: ' + escHtml(meta.label) + '</div>' +
      '<div class="report-section__body">' +
      barsHtml +
      '<details style="margin-top:8px;font-size:11px;">' +
      '<summary style="cursor:pointer;color:var(--text-muted);font-weight:500;">Evidence Analysis — per dimension (expand)</summary>' +
      dimDetailHtml +
      '</details>' +
      '<div style="margin-top:10px;"><strong style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted);">Next Steps by Role</strong>' +
      playbookHtml + '</div>' +
      '</div></div>';
  }

  function buildRagNeighboursSection(row) {
    var rag = (row.raw && row.raw.rag_context) || null;
    if (!rag || !rag.rag_available) return '';
    var neighbours = rag.neighbours || [];
    if (!neighbours.length && !rag.summary_hint) return '';
    var html = '<div class="report-section"><div class="report-section__title">Similar Prior Events (TemporalRAG)</div><div class="report-section__body">';
    if (rag.summary_hint) {
      html += '<p style="font-size:12px;color:var(--text-secondary);margin:0 0 8px;">' + escHtml(rag.summary_hint) + '</p>';
    }
    if (neighbours.length) {
      html += '<table style="width:100%;font-size:11px;border-collapse:collapse;">' +
        '<thead><tr style="color:var(--text-muted);text-align:left;">' +
        '<th style="padding:3px 6px;">Rank</th><th style="padding:3px 6px;">Score</th><th style="padding:3px 6px;">Time Delta</th><th style="padding:3px 6px;">Entity / Description</th>' +
        '</tr></thead><tbody>';
      neighbours.slice(0, 6).forEach(function (n, i) {
        var ts = n.ts ? new Date(n.ts * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';
        var desc = n.text ? n.text.slice(0, 80) : (n.entity || '—');
        html += '<tr style="border-top:1px solid var(--border);">' +
          '<td style="padding:3px 6px;color:var(--text-muted);">#' + (i + 1) + '</td>' +
          '<td style="padding:3px 6px;font-weight:600;">' + (n.score ? n.score.toFixed(3) : '—') + '</td>' +
          '<td style="padding:3px 6px;">' + escHtml(ts) + '</td>' +
          '<td style="padding:3px 6px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escHtml(n.text || '') + '">' + escHtml(desc) + '</td>' +
          '</tr>';
      });
      html += '</tbody></table>';
    }
    html += '</div></div>';
    return html;
  }

  function showDetail(row) {
    var panel = $('detailPanel');
    panel.classList.remove('detail-panel--hidden');
    panel.classList.add('open');
    $('detailBackdrop').classList.add('open');

    $('detailTitle').textContent = 'Event #' + row.row_index + ' — ' + (row.entity || 'Unknown');

    var html = '';
    html += '<div class="mb-2"><span class="sev-pill sev-pill--' + row.severity + '">' + row.severity.toUpperCase() + '</span>';
    html += ' <span class="sev-pill sev-pill--' + (row.type === 'correlated' ? 'info' : 'low') + '">' + row.type + '</span></div>';

    html += '<div class="report-section"><div class="report-section__title">Overview</div><div class="report-section__body">';
    html += '<p><b>Source:</b> ' + escHtml(row.source) + '</p>';
    html += '<p><b>Entity:</b> ' + escHtml(row.entity) + '</p>';
    html += '<p><b>Description:</b> ' + escHtml(row.description || 'N/A') + '</p>';
    html += '<p><b>Triage Score:</b> <span style="color:' + scoreColor(row.triage_score) + ';font-weight:600;">' + row.triage_score.toFixed(2) + '</span></p>';
    html += '</div></div>';

    // Score breakdown accordion with evidence analysis and role playbook
    html += buildBreakdownSection(row);

    // TemporalRAG neighbours from pipeline
    html += buildRagNeighboursSection(row);

    // LLM summary if available
    if (row._llmSummary) {
      var llm = row._llmSummary;
      html += '<div class="report-section"><div class="report-section__title">AI Summary (T1)</div><div class="report-section__body">';
      html += '<p>' + escHtml(llm.summary || llm.llm_summary || llm.narrative || JSON.stringify(llm).substring(0, 500)) + '</p>';
      // Render thinking blocks if present (B5: LLM thinking modes)
      var blocks = llm.thinking_blocks || [];
      if (blocks.length) {
        var thinkBlocks = blocks.filter(function(b) { return b.type === 'thinking'; });
        var thinkMode = llm.thinking_mode || 'preserved';
        if (thinkBlocks.length) {
          html += '<details style="margin-top:8px;font-size:11px;"><summary style="cursor:pointer;color:var(--text-muted);font-weight:500;">\uD83E\uDDE0 Chain-of-Thought — ' + escHtml(thinkMode) + ' (' + thinkBlocks.length + ' turn' + (thinkBlocks.length !== 1 ? 's' : '') + ')</summary>';
          html += '<div style="margin-top:6px;display:flex;flex-direction:column;gap:6px;">';
          thinkBlocks.forEach(function(b) {
            html += '<div style="padding:6px 10px;background:rgba(74,99,231,.08);border-left:3px solid var(--accent);border-radius:0 4px 4px 0;font-size:11px;color:var(--text-secondary);">' +
              '<span style="font-size:10px;font-weight:600;color:var(--accent);letter-spacing:.04em;">Turn ' + (b.turn || '?') + '</span><br>' +
              escHtml(b.content) + '</div>';
          });
          html += '</div></details>';
        }
        if (llm.reasoning_summary) {
          html += '<p style="margin-top:6px;font-size:11px;color:var(--text-muted);font-style:italic;">\uD83D\uDD0D Reasoning summary: ' + escHtml(llm.reasoning_summary) + '</p>';
        }
      }
      html += '</div></div>';
    } else {
      html += '<div class="mt-3" style="display:flex;gap:6px;flex-wrap:wrap;">';
      html += '<button class="btn-primary" id="btnDetailLLM" data-idx="' + row.row_index + '">';
      html += '<i data-lucide="sparkles" style="width:14px;height:14px;"></i> Generate T1 Summary</button>';
      // Thinking mode dropdown
      html += '<select id="thinkingModeSelect" style="font-size:11px;padding:4px 8px;"><option value="preserved">Preserved Thinking</option><option value="turn_level">Turn-Level Thinking</option><option value="interleaved">Interleaved Thinking</option></select>';
      html += '</div>';
    }

    // Raw data (collapsed)
    html += '<details class="mt-3" style="font-size:12px;"><summary style="cursor:pointer;color:var(--text-muted);font-weight:500;">Raw Event Data</summary>';
    html += '<pre style="margin-top:8px;white-space:pre-wrap;word-break:break-all;color:var(--text-secondary);font-size:11px;max-height:300px;overflow:auto;background:var(--bg-tertiary);padding:10px;border-radius:var(--radius-sm);">' + escHtml(JSON.stringify(row.raw, null, 2)) + '</pre>';
    html += '</details>';

    // Wired action buttons
    html += '<div class="mt-3" style="display:flex;gap:6px;flex-wrap:wrap;">';
    html += '<button class="btn-secondary" id="btnDetailFP" data-idx="' + row.row_index + '"><i data-lucide="check-circle" style="width:12px;height:12px;"></i> Mark FP</button>';
    html += '<button class="btn-secondary" id="btnDetailEscalate" data-idx="' + row.row_index + '"><i data-lucide="alert-triangle" style="width:12px;height:12px;"></i> Escalate</button>';
    html += '<button class="btn-secondary" id="btnDetailIncident" data-idx="' + row.row_index + '"><i data-lucide="siren" style="width:12px;height:12px;"></i> Create Incident</button>';
    html += '</div>';

    $('detailBody').innerHTML = html;
    if (window.lucide) lucide.createIcons();

    // Wire T1 summary button
    var llmBtn = document.getElementById('btnDetailLLM');
    if (llmBtn) {
      llmBtn.addEventListener('click', function () {
        requestRowLLM(parseInt(llmBtn.getAttribute('data-idx'), 10), llmBtn);
      });
    }

    // Mark FP → PUT review status=dismissed
    var fpBtn = document.getElementById('btnDetailFP');
    if (fpBtn) {
      fpBtn.addEventListener('click', function () {
        var idx = parseInt(fpBtn.getAttribute('data-idx'), 10);
        rowReviewAction(idx, 'dismissed', 'analyst').then(function () {
          toast('Row #' + idx + ' marked as False Positive', 'success');
          fpBtn.disabled = true;
          fpBtn.textContent = 'Marked FP';
        }).catch(function () { toast('Could not save FP — check assessment ID', 'error'); });
      });
    }

    // Escalate → PUT review status=escalated
    var escBtn = document.getElementById('btnDetailEscalate');
    if (escBtn) {
      escBtn.addEventListener('click', function () {
        var idx = parseInt(escBtn.getAttribute('data-idx'), 10);
        rowReviewAction(idx, 'escalated', 'analyst').then(function () {
          toast('Row #' + idx + ' escalated to Tier 2', 'success');
          escBtn.disabled = true;
          escBtn.textContent = 'Escalated';
        }).catch(function () { toast('Escalation failed — check assessment ID', 'error'); });
      });
    }

    // Create Incident → POST /api/v1/incidents
    var incBtn = document.getElementById('btnDetailIncident');
    if (incBtn) {
      incBtn.addEventListener('click', function () {
        var idx = parseInt(incBtn.getAttribute('data-idx'), 10);
        createIncidentFromRow(row, idx, incBtn);
      });
    }

    // Highlight selected row in table
    document.querySelectorAll('#evidenceBody tr').forEach(function (tr) {
      tr.classList.toggle('selected', tr.getAttribute('data-idx') === String(row.row_index));
    });
  }

  // Send row review status to the backend
  function rowReviewAction(rowIndex, status, reviewerTag) {
    var aid = state.assessmentId;
    if (!aid) return Promise.reject(new Error('no_assessment_id'));
    return fetch('/api/v1/assessments/' + encodeURIComponent(aid) + '/rows/' + rowIndex + '/review', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ status: status, reviewer_tag: reviewerTag || 'analyst', notes: '' }),
    }).then(function (r) {
      if (!r.ok) throw new Error('http_' + r.status);
      return r.json();
    });
  }

  // Create incident from a detail-panel row
  function createIncidentFromRow(row, rowIndex, btn) {
    var raw = row.raw || {};
    var payload = {
      event_id: raw.event_id || ('row-' + rowIndex),
      host: raw.host || raw.hostname || raw.computer || row.entity || 'unknown',
      user: raw.user || raw.username || 'unknown',
      severity: row.severity || 'high',
      description: row.description || 'Escalated from investigation console — row #' + rowIndex,
      generated_persona: state.currentPersona || 'soc_analyst',
      assessment_id: state.assessmentId || null,
      triage_score: row.triage_score,
    };
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
    fetch('/api/v1/incidents', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify(payload),
    }).then(function (r) { return r.json(); }).then(function (d) {
      toast('Incident ' + (d.incident_id || d.id || 'created') + ' — row #' + rowIndex, 'success');
      if (btn) { btn.textContent = 'Incident Created'; }
      // Also mark row as escalated in the review store
      rowReviewAction(rowIndex, 'escalated', 'analyst').catch(function () {});
    }).catch(function () {
      toast('Incident creation failed — server error', 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Create Incident'; }
    });
  }

  // Close detail panel
  $('btnCloseDetail').addEventListener('click', closeDetail);
  $('detailBackdrop').addEventListener('click', closeDetail);

  function closeDetail() {
    $('detailPanel').classList.add('detail-panel--hidden');
    $('detailPanel').classList.remove('open');
    $('detailBackdrop').classList.remove('open');
  }

  // ── Detach panels ────────────────────────────────────────────────────────
  function detachCurrentTab() {
    var active = document.querySelector('.tab-btn.active');
    if (!active) return;
    var tabName = active.getAttribute('data-tab');
    detachTab(tabName);
  }

  function detachTab(name) {
    var content = document.getElementById('tab' + name.charAt(0).toUpperCase() + name.slice(1));
    if (!content) return;
    var win = window.open('/static/investigate-shell.html?tab=' + encodeURIComponent(name), '_blank', 'width=1000,height=750');
    if (!win) { toast('Pop-up blocked — allow pop-ups for detach', 'error'); return; }
    var html = content.innerHTML;
    // Serialize full state for re-rendering live graphs in the shell
    var statePayload = null;
    try {
      statePayload = {
        evidenceRows: (state.evidenceRows || []).slice(0, 200).map(function (r) {
          return { row_index: r.row_index, source: r.source, severity: r.severity, type: r.type, entity: r.entity, description: r.description, triage_score: r.triage_score };
        }),
        sources: (state.sources || []).map(function (s) { return { name: s.name, type: s.type, rowCount: s.rowCount }; }),
        currentPersona: state.currentPersona,
      };
    } catch (_) {}
    var timer = setTimeout(function () { sendContent(); }, 1800);
    function onMsg(e) {
      if (e.source !== win) return;
      if (e.data && e.data.type === 'ready') {
        clearTimeout(timer);
        window.removeEventListener('message', onMsg);
        sendContent();
      }
    }
    window.addEventListener('message', onMsg);
    function sendContent() {
      try { win.postMessage({ type: 'content', tab: name, html: html, state: statePayload }, '*'); } catch (_) {}
      toast(name + ' detached to new window', 'success');
    }
  }

  // Wire detach buttons
  ['Report', 'Evidence', 'Graph', 'Timeline', 'Detail'].forEach(function (name) {
    var btn = $('btnDetach' + name);
    if (btn) btn.addEventListener('click', function () { detachTab(name.toLowerCase()); });
  });

  // Wire graph control buttons (Zoom-Fit, Layout re-heat)
  var _btnZoomFit = $('btnGraphZoomFit');
  if (_btnZoomFit) {
    _btnZoomFit.addEventListener('click', function () {
      if (_hopGraphState.svg && _hopGraphState.zoom) {
        _hopGraphState.svg.transition().duration(400).call(
          _hopGraphState.zoom.transform, d3.zoomIdentity
        );
      }
    });
  }
  var _btnLayout = $('btnGraphLayout');
  if (_btnLayout) {
    _btnLayout.addEventListener('click', function () {
      if (_hopGraphState.sim) {
        _hopGraphState.sim.alphaTarget(0.3).restart();
        setTimeout(function () {
          if (_hopGraphState.sim) _hopGraphState.sim.alphaTarget(0);
        }, 1500);
      }
    });
  }

  // ── Export ───────────────────────────────────────────────────────────────
  $('btnExportEvidence').addEventListener('click', function () {
    if (!state.evidenceRows || !state.evidenceRows.length) { toast('No evidence to export', 'error'); return; }
    var csv = 'row_index,source,severity,type,entity,description,triage_score\n';
    state.evidenceRows.forEach(function (r) {
      csv += [r.row_index, '"' + (r.source || '') + '"', r.severity, r.type, '"' + (r.entity || '') + '"', '"' + (r.description || '').replace(/"/g, '""') + '"', r.triage_score].join(',') + '\n';
    });
    var blob = new Blob([csv], { type: 'text/csv' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = 'janusec_evidence_' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click(); URL.revokeObjectURL(url);
    toast('Evidence exported', 'success');
  });

  $('btnExportPDF').addEventListener('click', function () {
    // Trigger server-side PDF generation
    window.open('/api/v1/report/ingestion?format=html&include_model=true&include_scenarios=true', '_blank');
  });

  // ── Send to SIEM (B4 fix: was unwired) ──────────────────────────────────
  $('btnSendSIEM').addEventListener('click', function () {
    if (!state.evidenceRows || !state.evidenceRows.length) { toast('No evidence to send — run Analyze first', 'error'); return; }
    var critCount = state.evidenceRows.filter(function (r) { return r.severity === 'critical'; }).length;
    var highCount = state.evidenceRows.filter(function (r) { return r.severity === 'high'; }).length;
    var payload = {
      source: 'janusec-investigation',
      assessment_id: state.assessmentId || null,
      persona: state.currentPersona || 'soc_analyst',
      org: localStorage.getItem('org') || 'local',
      event_count: state.evidenceRows.length,
      critical: critCount,
      high: highCount,
      headline: state.assessment && (state.assessment.headline || state.assessment.report_title) || (state.evidenceRows.length + ' events'),
      evidence_summary: state.evidenceRows.slice(0, 20).map(function (r) {
        return { severity: r.severity, entity: r.entity, description: r.description, triage_score: r.triage_score };
      }),
    };
    fetch('/api/v1/webhooks/test', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ service: 'siem', payload: payload }),
    }).then(function (r) { return r.json(); }).then(function (d) {
      toast('Dispatched to SIEM — ' + (d.message || d.status || 'ok'), 'success');
    }).catch(function (e) {
      // Graceful degradation: copy to clipboard as JSON for manual SIEM paste
      try {
        navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
        toast('SIEM webhook unavailable — evidence copied to clipboard', 'error');
      } catch (_) {
        toast('SIEM dispatch failed: ' + e.message, 'error');
      }
    });
  });

  // ── Graph Viz B: D3 Force Graph ──────────────────────────────────────────
  function renderGraph(evRows) {
    var canvas = $('graphCanvas');
    if (!canvas || !evRows || !evRows.length) return;
    canvas.innerHTML = '';
    if (typeof d3 === 'undefined') {
      canvas.innerHTML = '<p class="text-sm text-muted" style="padding:16px">D3 library unavailable.</p>';
      return;
    }
    var W = canvas.clientWidth || 800;
    var H = Math.max(420, canvas.clientHeight || 500);

    var entityMap = {};
    evRows.forEach(function (row) {
      var e = row.entity;
      if (!e || e === '-') return;
      if (!entityMap[e]) {
        entityMap[e] = { id: e, label: e.length > 22 ? e.slice(0, 20) + '…' : e, nodeType: guessEntityType(e, row), severity: row.severity, count: 0, srcList: [] };
      }
      entityMap[e].count++;
      if (entityMap[e].srcList.indexOf(row.source) < 0) entityMap[e].srcList.push(row.source);
      var sevOrd = ['low', 'medium', 'high', 'critical'];
      if (sevOrd.indexOf(row.severity) > sevOrd.indexOf(entityMap[e].severity)) entityMap[e].severity = row.severity;
    });

    var entityNodes = Object.values(entityMap).slice(0, 50);
    var srcNodeMap = {};
    var srcNodes = [];
    state.sources.forEach(function (src) {
      var nid = '__src__' + src.name;
      srcNodeMap[src.name] = nid;
      srcNodes.push({ id: nid, label: shortSource(src.name), nodeType: 'source', severity: 'low', count: src.rows.length, srcList: [], isSource: true });
    });
    var nodes = entityNodes.concat(srcNodes);
    var nodeIds = {};
    nodes.forEach(function (n) { nodeIds[n.id] = true; });

    var links = [];
    var seenL = {};
    entityNodes.forEach(function (en) {
      en.srcList.forEach(function (srcName) {
        var sid = srcNodeMap[srcName];
        if (!sid || !nodeIds[sid]) return;
        var key = en.id + '|||' + sid;
        if (seenL[key]) return;
        seenL[key] = true;
        links.push({ source: en.id, target: sid, correlated: en.srcList.length > 1 });
      });
    });

    var NODE_COLORS = { user: '#4A63E7', ip: '#E54848', resource: '#2DB67C', detection: '#FF8A3C', source: '#708090', other: '#E0C446' };
    var SEV_R = { critical: 10, high: 8, medium: 6, low: 5 };

    var zoom = d3.zoom().scaleExtent([0.25, 3]).on('zoom', function (event) { g.attr('transform', event.transform); });
    var svg = d3.select(canvas).append('svg').attr('width', W).attr('height', H).style('display', 'block').style('border-radius', 'var(--radius-lg)');
    var g = svg.append('g');
    svg.call(zoom);
    _hopGraphState.svg = svg;
    _hopGraphState.zoom = zoom;

    var lgData = [{ l: 'User', c: NODE_COLORS.user }, { l: 'IP', c: NODE_COLORS.ip }, { l: 'Resource', c: NODE_COLORS.resource }, { l: 'Detection', c: NODE_COLORS.detection }, { l: 'Source', c: NODE_COLORS.source }];
    var lg = svg.append('g').attr('transform', 'translate(8,8)');
    lgData.forEach(function (ld, i) {
      lg.append('circle').attr('cx', 6).attr('cy', i * 18 + 6).attr('r', 5).attr('fill', ld.c).attr('opacity', 0.85);
      lg.append('text').attr('x', 15).attr('y', i * 18 + 10).attr('fill', 'var(--text-muted)').attr('font-size', '10px').text(ld.l);
    });

    var sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(function (d) { return d.id; }).distance(90))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collide', d3.forceCollide().radius(22));
    _hopGraphState.sim = sim;

    var link = g.append('g').selectAll('line').data(links).join('line')
      .attr('stroke', function (d) { return d.correlated ? 'rgba(74,99,231,0.6)' : 'rgba(255,255,255,0.12)'; })
      .attr('stroke-width', function (d) { return d.correlated ? 2 : 1; })
      .attr('stroke-dasharray', function (d) { return d.correlated ? '5,3' : ''; });

    var node = g.append('g').selectAll('g').data(nodes).join('g').attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', function (event, d) { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', function (event, d) { d.fx = event.x; d.fy = event.y; })
        .on('end', function (event, d) { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

    node.append('circle')
      .attr('r', function (d) { return d.isSource ? 12 : (SEV_R[d.severity] || 6); })
      .attr('fill', function (d) { return NODE_COLORS[d.nodeType] || NODE_COLORS.other; })
      .attr('opacity', 0.85)
      .attr('stroke', function (d) { return d.srcList && d.srcList.length > 1 ? 'rgba(229,72,72,0.9)' : 'rgba(255,255,255,0.15)'; })
      .attr('stroke-width', function (d) { return d.srcList && d.srcList.length > 1 ? 2.5 : 1; });

    node.append('text').attr('x', 0).attr('y', function (d) { return (d.isSource ? 12 : (SEV_R[d.severity] || 6)) + 13; })
      .attr('text-anchor', 'middle').attr('fill', 'var(--text-muted)').attr('font-size', '10px').text(function (d) { return d.label; });

    node.append('title').text(function (d) {
      return d.id + (d.srcList && d.srcList.length > 1 ? '\nCorrelated: ' + d.srcList.join(', ') : '') + '\nCount: ' + d.count;
    });

    sim.on('tick', function () {
      link.attr('x1', function (d) { return d.source.x; }).attr('y1', function (d) { return d.source.y; })
        .attr('x2', function (d) { return d.target.x; }).attr('y2', function (d) { return d.target.y; });
      node.attr('transform', function (d) { return 'translate(' + d.x + ',' + d.y + ')'; });
    });
  }

  function guessEntityType(entity, row) {
    if (!entity) return 'other';
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(entity)) return 'ip';
    if (entity.indexOf('@') >= 0) return 'user';
    if (/^[a-z]{2,6}:\/\//.test(entity)) return 'resource';
    var raw = (row && row.raw) || row || {};
    var rt = ((raw.type || raw.userType || raw.resourceType || raw.eventSource || '') + '').toLowerCase();
    if (rt.indexOf('user') >= 0 || rt.indexOf('member') >= 0) return 'user';
    if (rt.indexOf('vm') >= 0 || rt.indexOf('storage') >= 0 || rt.indexOf('resource') >= 0) return 'resource';
    if (rt.indexOf('alert') >= 0 || rt.indexOf('finding') >= 0) return 'detection';
    return 'other';
  }

  // ── Swimlane Timeline (Graph Viz B) ──────────────────────────────────────
  function renderTimeline(evRows) {
    var canvas = $('timelineCanvas');
    if (!canvas || !evRows || !evRows.length) return;
    canvas.innerHTML = '';
    var rowsWithTime = evRows.map(function (row) {
      return { ts: extractTimestamp(row), row: row };
    }).filter(function (r) { return r.ts; });
    if (!rowsWithTime.length) {
      canvas.innerHTML = '<p class="text-sm text-muted" style="padding:8px">No timestamp fields detected. Supported: eventTime, timestamp, createdDateTime, activityDateTime, TimeGenerated.</p>';
      return;
    }
    var allTs = rowsWithTime.map(function (r) { return r.ts; });
    var minTs = Math.min.apply(null, allTs);
    var maxTs = Math.max.apply(null, allTs);
    var srcGroups = {};
    rowsWithTime.forEach(function (r) {
      var src = r.row.source || 'unknown';
      if (!srcGroups[src]) srcGroups[src] = [];
      srcGroups[src].push(r);
    });
    var sources = Object.keys(srcGroups);
    var PAD_L = 160; var PAD_R = 40; var PAD_TOP = 48; var LANE_H = 64;
    var svgW = Math.max(800, (canvas.clientWidth || 900) - 4);
    var svgH = PAD_TOP + sources.length * LANE_H + 20;
    var timeW = svgW - PAD_L - PAD_R;
    var span = maxTs - minTs || 1;
    function xScale(ts) { return PAD_L + ((ts - minTs) / span) * timeW; }
    function fmtTs(ts) { return new Date(ts).toISOString().slice(0, 16).replace('T', ' '); }
    var parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="' + svgW + '" height="' + svgH + '" style="display:block;font-family:Inter,system-ui,sans-serif;">' ];
    parts.push('<text x="' + PAD_L + '" y="18" fill="var(--text-muted)" font-size="10">' + fmtTs(minTs) + '</text>');
    parts.push('<text x="' + (PAD_L + timeW) + '" y="18" fill="var(--text-muted)" font-size="10" text-anchor="end">' + fmtTs(maxTs) + '</text>');
    parts.push('<text x="' + (PAD_L + timeW / 2) + '" y="18" fill="var(--text-muted)" font-size="10" text-anchor="middle">— time →</text>');
    for (var ti = 0; ti <= 4; ti++) {
      var tx = PAD_L + (ti / 4) * timeW;
      parts.push('<line x1="' + tx + '" y1="22" x2="' + tx + '" y2="' + svgH + '" stroke="rgba(255,255,255,0.04)"/>');
    }
    var entityFirst = {};
    sources.forEach(function (src, idx) {
      var y = PAD_TOP + idx * LANE_H;
      var cy = y + LANE_H / 2;
      if (idx % 2 === 0) parts.push('<rect x="0" y="' + y + '" width="' + svgW + '" height="' + LANE_H + '" fill="rgba(255,255,255,0.015)"/>');
      var lbl = src.length > 22 ? src.slice(0, 20) + '…' : src;
      parts.push('<text x="8" y="' + (cy + 4) + '" fill="var(--text-muted)" font-size="11">' + escHtml(lbl) + '</text>');
      parts.push('<line x1="' + PAD_L + '" y1="' + cy + '" x2="' + (PAD_L + timeW) + '" y2="' + cy + '" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>');
      (srcGroups[src] || []).forEach(function (r) {
        var cx = xScale(r.ts);
        var color = SEV_COLORS[r.row.severity] || '#666';
        var rad = r.row.type === 'correlated' ? 7 : 5;
        var entity = r.row.entity || '';
        if (entity && entity !== '-') {
          if (!entityFirst[entity]) entityFirst[entity] = {};
          if (!entityFirst[entity][src]) entityFirst[entity][src] = { cx: cx, cy: cy };
        }
        var ttip = escHtml((entity || '?') + ' — ' + (r.row.description || r.row.severity) + ' (' + fmtTs(r.ts) + ')');
        if (r.row.type === 'correlated') parts.push('<circle cx="' + cx + '" cy="' + cy + '" r="' + (rad + 4) + '" fill="none" stroke="' + color + '" stroke-width="1.5" opacity="0.4"/>');
        parts.push('<circle cx="' + cx + '" cy="' + cy + '" r="' + rad + '" fill="' + color + '" opacity="0.8"><title>' + ttip + '</title></circle>');
      });
    });
    Object.keys(entityFirst).forEach(function (entity) {
      var srcs = Object.keys(entityFirst[entity]);
      if (srcs.length < 2) return;
      var pts = srcs.map(function (s) { return entityFirst[entity][s]; });
      for (var pi = 0; pi < pts.length - 1; pi++) {
        parts.push('<line x1="' + pts[pi].cx + '" y1="' + pts[pi].cy + '" x2="' + pts[pi + 1].cx + '" y2="' + pts[pi + 1].cy + '" stroke="rgba(74,99,231,0.45)" stroke-width="1.5" stroke-dasharray="5,3"/>');
      }
    });
    parts.push('</svg>');
    canvas.innerHTML = parts.join('');
  }

  function extractTimestamp(row) {
    var fields = ['eventTime', 'ts', 'timestamp', 'time', 'createdDateTime', 'activityDateTime',
      'UpdatedDateTime', 'TimeGenerated', 'start', 'date', 'datetime', '@timestamp', 'event_time'];
    var raw = (row && row.raw) || row || {};
    for (var i = 0; i < fields.length; i++) {
      var v = raw[fields[i]] || row[fields[i]];
      if (v) { var d = new Date(v); if (!isNaN(d.getTime())) return d.getTime(); }
    }
    return null;
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  // Expose toast globally for inline onclick handlers
  window.toast = toast;

  renderPersonaChips();

  // Assessment History ─────────────────────────────────────────────────────────
  var HISTORY_KEY = 'janusec_history';
  var HISTORY_MAX = 40;

  function saveToHistory(assessmentId, headline, sourcesArr) {
    var list = loadHistory();
    var existing = list.findIndex(function (h) { return h.id === assessmentId; });
    var entry = {
      id: assessmentId,
      ts: Date.now(),
      headline: headline || 'Untitled Assessment',
      sources: (sourcesArr || []).map(function (s) { return s.name || s; }).slice(0, 6),
      rows: (state.evidenceRows || []).length
    };
    if (existing >= 0) list.splice(existing, 1);
    list.unshift(entry);
    if (list.length > HISTORY_MAX) list = list.slice(0, HISTORY_MAX);
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch (_) {}
    renderHistory();
  }

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch (_) { return []; }
  }

  function clearHistory() {
    if (!confirm('Clear all saved assessment history?')) return;
    try { localStorage.removeItem(HISTORY_KEY); } catch (_) {}
    renderHistory();
    toast('History cleared', 'info');
  }

  function toggleHistorySidebar() {
    var el = document.getElementById('historySidebar');
    var btn = document.getElementById('btnToggleHistory');
    if (!el) return;
    var hidden = el.hasAttribute('hidden');
    if (hidden) { el.removeAttribute('hidden'); if (btn) btn.classList.add('active'); renderHistory(); }
    else { el.setAttribute('hidden', ''); if (btn) btn.classList.remove('active'); }
    if (window.lucide) lucide.createIcons();
  }

  function renderHistory() {
    var container = document.getElementById('historyList');
    if (!container) return;
    var q = (document.getElementById('historySearchInput') || {}).value || '';
    var list = loadHistory();
    if (q) {
      var lq = q.toLowerCase();
      list = list.filter(function (h) {
        return (h.headline || '').toLowerCase().indexOf(lq) >= 0 ||
          (h.sources || []).some(function (s) { return s.toLowerCase().indexOf(lq) >= 0; });
      });
    }
    if (!list.length) {
      container.innerHTML = '<p class="history-empty">' + (q ? 'No matches.' : 'No previous assessments.') + '</p>';
      return;
    }
    container.innerHTML = list.map(function (h) {
      var ago = _timeAgo(h.ts);
      var isActive = h.id === state.assessmentId;
      return '<div class="history-item' + (isActive ? ' active' : '') + '" onclick="loadHistoryEntry(\'' + h.id + '\')" title="' + (h.headline || '').replace(/"/g, '&quot;') + '">' +
        '<div class="history-item__headline">' + _htmlEsc(h.headline || 'Assessment') + '</div>' +
        '<div class="history-item__meta">' +
        '<span>' + ago + '</span>' +
        '<span class="history-item__badge">' + (h.rows || 0) + ' rows</span>' +
        (h.sources && h.sources.length ? '<span>' + _htmlEsc(h.sources.join(', ').slice(0, 30)) + '</span>' : '') +
        '</div></div>';
    }).join('');
  }

  function loadHistoryEntry(assessmentId) {
    if (!assessmentId) return;
    var apiKey = localStorage.getItem('apiKey') || 'devkey123';
    fetch('/api/v1/csv/deep_analyze/assessments/' + encodeURIComponent(assessmentId), { headers: { 'x-api-key': apiKey } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        var rows = data.rows || data.evidence_rows || data.evidenceRows || [];
        if (!rows.length) { toast('Assessment has no rows', 'warn'); return; }
        state.assessmentId = assessmentId;
        state.evidenceRows = rows;
        rebuildFilteredRows();
        switchTab('evidence');
        toast('Loaded ' + rows.length + ' rows from history', 'info');
        renderHistory();
      })
      .catch(function (err) { toast('Could not load assessment: ' + err, 'error'); });
  }

  function _timeAgo(ts) {
    var d = Math.round((Date.now() - ts) / 1000);
    if (d < 60) return d + 's ago';
    if (d < 3600) return Math.floor(d / 60) + 'm ago';
    if (d < 86400) return Math.floor(d / 3600) + 'h ago';
    return Math.floor(d / 86400) + 'd ago';
  }

  function _htmlEsc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

  window.toggleHistorySidebar = toggleHistorySidebar;
  window.clearHistory = clearHistory;
  window.loadHistoryEntry = loadHistoryEntry;
  window.renderHistory = renderHistory;
  window.toast = toast;

})();
