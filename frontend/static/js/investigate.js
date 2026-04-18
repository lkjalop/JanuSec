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
    queueView: null,      // operator queue view from /api/v1/queue/{assessment_id}
    clusterMap: {},        // cluster_id -> cluster object from correlation_clusters
    activeClusterId: null, // currently open cluster in drawer
  };
  window.state = state;
  var _hopGraphState = { svg: null, zoom: null, sim: null };

  // ── DOM refs ─────────────────────────────────────────────────────────────
  var $ = function (id) { return document.getElementById(id); };

  // ── Helpers ──────────────────────────────────────────────────────────────
  function authHeaders() {
    var h = { 'x-api-key': API_KEY };
    var tenant = localStorage.getItem('tenantId') || 'default';
    h['X-Tenant-ID'] = tenant;
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
        // Janusec dataset envelope: object with "events" array
        if (parsed.events && Array.isArray(parsed.events)) return 'json_array';
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
    else {
      // Try common array envelope keys before wrapping the whole object as 1 row
      var _envKeys = ['events', 'items', 'data', 'alerts', 'logs', 'entries', 'results', 'rows'];
      for (var _ki = 0; _ki < _envKeys.length; _ki++) {
        if (Array.isArray(parsed[_envKeys[_ki]])) { arr = parsed[_envKeys[_ki]]; break; }
      }
      if (!arr.length) arr = [parsed];
    }

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
        ensurePersonaReportForCurrent();
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
    ensurePersonaReportForCurrent();
  });

  // ── Analyze button — runs pipeline + generates report ────────────────────
  $('btnAnalyze').addEventListener('click', function () { runAnalysis(); });

  var _activeWs = null;

  function connectProgressWs(assessmentId, onPct) {
    if (!window.ENABLE_INVESTIGATE_PROGRESS_WS) return;
    if (_activeWs) { try { _activeWs.close(); } catch(_) {} _activeWs = null; }
    var proto = location.protocol === 'https:' ? 'wss' : 'ws';
    var wsUrl = proto + '://' + location.host + '/api/v1/assessments/ws/progress/' + encodeURIComponent(assessmentId);
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
          return { row_index: idx, raw: r };
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
      // Use the POST response as the initial assessment — it already contains
      // results, canonical, and mappings. Polling may enrich it but must not block.
      state.assessment = analyzeData;
      $('pipelineBarFill').style.width = '50%';

      // Connect WebSocket for real-time progress updates (falls back to manual steps if unavailable)
      if (state.assessmentId) {
        connectProgressWs(state.assessmentId, function (pct) {
          var clampedPct = Math.max(50, Math.min(90, Math.round(pct * 100)));
          $('pipelineBarFill').style.width = clampedPct + '%';
        });
      }

      // Step 2: Best-effort quick poll — 5 s cap. Falls back to POST response if slow.
      var polled = await pollAssessment(state.assessmentId, 5000);
      // Merge: prefer analyzeData clusters if poll returns early without them
      var assessment = Object.assign({}, analyzeData, polled || {});
      if (!(polled && polled.correlation_clusters && polled.correlation_clusters.length)) {
        assessment.correlation_clusters = analyzeData.correlation_clusters || [];
      }
      if (!(polled && polled.evidence_rows && polled.evidence_rows.length)) {
        assessment.evidence_rows = analyzeData.evidence_rows || analyzeData.rows || [];
      }
      if (!assessment.assessment_id) assessment = analyzeData;
      state.assessment = assessment;
      $('pipelineBarFill').style.width = '70%';

      // Step 3c: Store clusters first so buildEvidenceFromAssessment can mark correlated rows
      storeClusters(assessment.correlation_clusters || []);
      // Step 3: Build enriched evidence rows from assessment (uses clusterMap for correlation flags)
      buildEvidenceFromAssessment(assessment);

      // Step 3b: Render graph + timeline visualizations  [B1 fix: graphCanvas not graphContent]
      $('graphEmpty').style.display = 'none';
      $('graphCanvas').style.display = 'flex';
      $('timelineEmpty').style.display = 'none';
      $('timelineContent').style.display = '';
      renderGraph(state.evidenceRows);
      renderTimeline(state.evidenceRows);
      renderDecisionPanel();

      // Step 4: Generate persona report
      $('pipelineBarFill').style.width = '85%';
      await generatePersonaReport(assessment);

      // Step 5: Build operator queue from assessment clusters
      if (state.assessmentId) {
        try {
          var qResp = await fetch('/api/v1/queue/' + encodeURIComponent(state.assessmentId) + '/build', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...authHeaders() },
            body: JSON.stringify({ persona: state.currentPersona }),
          });
          if (qResp.ok) {
            var qData = await qResp.json();
            state.queueView = qData.queue || null;
            renderQueuePanel();
          }
        } catch (_qe) { /* queue building is best-effort */ }
      }

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
    maxWait = maxWait || 5000; // default 5 s — GET endpoint may be slow
    var start = Date.now();
    while (Date.now() - start < maxWait) {
      try {
        var ctrl = new AbortController();
        var _pt = setTimeout(function () { ctrl.abort(); }, 3000); // 3 s per-request timeout
        var resp = await fetch('/api/v1/assessments/' + encodeURIComponent(id), {
          headers: authHeaders(), signal: ctrl.signal,
        });
        clearTimeout(_pt);
        if (resp.ok) {
          var data = await resp.json();
          if (data.status === 'complete' || data.status === 'completed' || data.rows_processed > 0) {
            return data;
          }
        }
      } catch (_) { /* timed out or network error — retry or give up */ }
      await new Promise(function (r) { setTimeout(r, 500); });
    }
    // Return whatever we have (POST response was already stored as state.assessment)
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
    // 1. Explicit severity string field
    var sev = (row.severity || row.Severity || row.riskLevel || row.risk_level || '').toString().toLowerCase();
    if (sev === 'critical' || sev === 'crit') return 'critical';
    if (sev === 'high') return 'high';
    if (sev === 'medium' || sev === 'med') return 'medium';
    if (sev === 'low' || sev === 'informational' || sev === 'info') return 'low';

    // 2. confirmed_malicious review state
    var rs = (row.review_state || '').toLowerCase();
    if (rs === 'confirmed_malicious') return 'critical';

    // 3. threat_confidence (0-100 scale — NET fixture)
    var tc = parseFloat(row.threat_confidence);
    if (!isNaN(tc)) {
      if (tc >= 90) return 'critical';
      if (tc >= 70) return 'high';
      if (tc >= 40) return 'medium';
      return 'low';
    }

    // 4. risk_score: detect scale (OKTA uses 1-10, others 0-100)
    var rs2 = parseFloat(row.risk_score);
    if (!isNaN(rs2)) {
      var scale = rs2 <= 10 ? 10 : 100;
      var pct = (rs2 / scale) * 100;
      if (pct >= 80) return 'critical';
      if (pct >= 60) return 'high';
      if (pct >= 30) return 'medium';
      return 'low';
    }

    // 5. AWS GuardDuty / numeric severity (0-10)
    var numSev = parseFloat(row.Severity || row.severity);
    if (!isNaN(numSev)) {
      if (numSev >= 7) return 'critical';
      if (numSev >= 5) return 'high';
      if (numSev >= 3) return 'medium';
      return 'low';
    }

    // 6. Azure IdP riskLevel string
    if (row.riskLevel) {
      var rl = row.riskLevel.toLowerCase();
      if (rl === 'high') return 'critical';
      if (rl === 'medium') return 'high';
      if (rl === 'low') return 'medium';
    }

    // 7. Threat intel category keyword
    var tic = (row.threat_intel_category || '').toLowerCase();
    if (tic.includes('malware') || tic.includes('c2') || tic.includes('ransomware') || tic.includes('exfil')) return 'critical';
    if (tic.includes('spray') || tic.includes('brute') || tic.includes('scan') || tic.includes('recon')) return 'high';

    // 8. needs_investigation with no other signal = medium
    if (rs === 'needs_investigation') return 'medium';

    // 9. Keyword fallback
    var text = JSON.stringify(row).toLowerCase();
    if (text.includes('exfil') || text.includes('ransomware') || text.includes('c2_beacon')) return 'critical';
    if (text.includes('suspicious') || text.includes('anomal') || text.includes('spray')) return 'high';

    return 'low';
  }

  function detectCorrelation(row, idx) {
    // Use backend cluster membership (set by storeClusters before buildEvidenceFromAssessment)
    if (state.clusterMap && Object.keys(state.clusterMap).length) {
      for (var cid in state.clusterMap) {
        var refs = state.clusterMap[cid].row_refs || [];
        if (refs.indexOf(idx) !== -1) return true;
      }
      return false;
    }
    // Fallback when no clusters: cross-source entity match heuristic
    var entity = extractPrimaryEntity(row);
    if (!entity || entity === '-') return false;
    var seen = {};
    var sourceCount = 0;
    state.allRows.forEach(function (r) {
      var src = r._source || '';
      if (!seen[src] && extractPrimaryEntity(r) === entity) { seen[src] = true; sourceCount++; }
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

    function setText(id, value) {
      var el = $(id);
      if (el) el.textContent = String(value);
    }

    function setBucket(bucket, prefix, totalId) {
      var total = 0;
      [
        ['critical', 'crit'],
        ['high', 'high'],
        ['medium', 'med'],
        ['low', 'low'],
      ].forEach(function (pair) {
        var count = counts[bucket][pair[0]] || 0;
        total += count;
        setText(prefix + '_' + pair[1], count);
      });
      setText(totalId, total + ' total');
    }

    setBucket('correlated', 'sc', 'sc_total');
    setBucket('isolated', 'si', 'si_total');

    var summary = $('sevSummary');
    if (summary) summary.classList.add('has-data');
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
      var ctrl = new AbortController();
      var _tmo = setTimeout(function () { ctrl.abort(); }, 8000); // 8s hard timeout — LLM may hang
      var url = '/api/v1/report/ingestion?format=json&persona=' + encodeURIComponent(persona) + '&include_model=true&include_scenarios=true';
      var resp = await fetch(url, { headers: authHeaders(), signal: ctrl.signal });
      clearTimeout(_tmo);
      if (resp.ok) {
        var reportData = await resp.json();
        if (buildBackendReport(reportData, assessment)) return;
      }
    } catch (_) { /* timed out or endpoint unavailable — fall through to local report */ }
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

  function ensurePersonaReportForCurrent() {
    if (!state.assessment) {
      renderReport();
      return;
    }
    if (!state.reportArtifacts[state.currentPersona]) {
      buildLocalReport(state.assessment);
      return;
    }
    renderReport();
  }

  function renderDecisionPanel() {
    var table = $('decisionTable');
    var body = $('decisionBody');
    var empty = $('decisionEmpty');
    if (!table || !body || !empty) return;

    var assessment = state.assessment || {};
    var decision = assessment.decision_record || {};
    var verdict = decision.verdict || decision.decision || assessment.final_verdict || assessment.verdict || assessment.severity || '';
    var confidence = decision.confidence || assessment.final_confidence || assessment.confidence || '';
    var rationale = decision.rationale || decision.reason || decision.summary || assessment.final_verdict || assessment.verdict || '';
    var severity = assessment.severity || assessment.final_severity || '';

    body.innerHTML = '';
    if (!verdict && !rationale && !(state.evidenceRows || []).length) {
      table.style.display = 'none';
      empty.style.display = '';
      return;
    }

    var tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + escHtml(verdict || 'Review required') + '</td>' +
      '<td><span class="sev-pill sev-pill--' + escHtml(String(severity || 'medium').toLowerCase()) + '">' + escHtml(severity || 'medium') + '</span></td>' +
      '<td>' + escHtml(confidence || 'pending') + '</td>' +
      '<td>' + escHtml(rationale || 'Assessment produced evidence requiring analyst disposition.') + '</td>';
    body.appendChild(tr);
    table.style.display = '';
    empty.style.display = 'none';
  }

  // ── Operator Queue Panel ─────────────────────────────────────────────────
  // Renders the Active/Remainder/Escalated/Deferred/Cleared operator queue
  // derived from the assessment's clusters and high-score isolated rows.
  // The Active item is the highest-priority open item; Remainder is the
  // sorted backlog.  Analysts can Confirm / Deny / Defer / Escalate each item.

  var _QUEUE_STATE_COLORS = {
    remainder: 'var(--accent)',
    escalated: '#E54848',
    deferred: '#E0C446',
    cleared: '#3FA860',
  };
  var _QUEUE_SEV_COLORS = {
    critical: '#E54848', high: '#FF8A3C', medium: '#E0C446', low: '#3FA860', unknown: 'var(--text-muted)',
  };

  function renderQueuePanel() {
    var view = state.queueView;
    // Find or create the queue panel element next to the report panel.
    // We inject it into the right-rail panel area using an existing container.
    var panelEl = $('operatorQueuePanel');
    if (!panelEl) return; // element must exist in HTML

    if (!view || !view.counts || view.counts.total === 0) {
      panelEl.innerHTML = '<div style="padding:12px;font-size:12px;color:var(--text-muted);">No queue items — run analysis to build the operator queue.</div>';
      return;
    }

    var html = '';

    // ── Active item ──────────────────────────────────────────────────────────
    var active = view.active;
    if (active) {
      var sevColor = _QUEUE_SEV_COLORS[active.severity] || 'var(--text-muted)';
      html += '<div class="queue-item queue-item--active" data-item-id="' + escHtml(active.item_id) + '">' +
        '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">' +
        '<span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--accent);">▶ Active</span>' +
        '<span class="sev-pill sev-pill--' + escHtml(active.severity) + '">' + escHtml(active.severity) + '</span>' +
        '<span style="font-size:10px;color:var(--text-muted);">score: ' + active.priority_score.toFixed(3) + '</span>' +
        (active.new_evidence_available ? '<span style="font-size:10px;color:#E0C446;margin-left:auto;">\u26A0\uFE0F new evidence</span>' : '') +
        '</div>' +
        '<div style="font-size:12px;font-weight:600;color:var(--text-primary);margin-bottom:4px;">' + escHtml(active.title) + '</div>' +
        (active.summary ? '<div style="font-size:11px;color:var(--text-secondary);margin-bottom:6px;">' + escHtml(active.summary.slice(0, 120)) + '</div>' : '') +
        _renderEntityChips(active) +
        _renderQueueActions(active) +
        '</div>';
    }

    // ── Counts bar ───────────────────────────────────────────────────────────
    var c = view.counts;
    html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0;font-size:11px;">' +
      ['remainder', 'escalated', 'deferred', 'cleared'].map(function (s) {
        var count = c[s] || 0;
        return '<span style="padding:2px 8px;border-radius:4px;background:rgba(255,255,255,0.05);color:' +
          (_QUEUE_STATE_COLORS[s] || 'var(--text-muted)') + ';">' +
          s + ': ' + count + '</span>';
      }).join('') +
      '</div>';

    // ── Remainder list ───────────────────────────────────────────────────────
    if (view.remainder && view.remainder.length) {
      html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted);margin-bottom:4px;">Remainder (' + view.remainder.length + ')</div>';
      view.remainder.slice(0, 8).forEach(function (item) {
        html += _renderQueueItemRow(item, 'remainder');
      });
      if (view.remainder.length > 8) {
        html += '<div style="font-size:11px;color:var(--text-muted);padding:4px 0;">... and ' + (view.remainder.length - 8) + ' more</div>';
      }
    }

    // ── Escalated ────────────────────────────────────────────────────────────
    if (view.escalated && view.escalated.length) {
      html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#E54848;margin:8px 0 4px 0;">Escalated (' + view.escalated.length + ')</div>';
      view.escalated.slice(0, 4).forEach(function (item) { html += _renderQueueItemRow(item, 'escalated'); });
    }

    // ── Deferred ─────────────────────────────────────────────────────────────
    if (view.deferred && view.deferred.length) {
      html += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#E0C446;margin:8px 0 4px 0;">Deferred (' + view.deferred.length + ')</div>';
      view.deferred.slice(0, 4).forEach(function (item) { html += _renderQueueItemRow(item, 'deferred'); });
    }

    // ── Cleared ──────────────────────────────────────────────────────────────
    if (view.cleared && view.cleared.length) {
      html += '<details style="margin-top:8px;"><summary style="font-size:11px;color:var(--text-muted);cursor:pointer;">Cleared (' + view.cleared.length + ')</summary>';
      view.cleared.slice(0, 6).forEach(function (item) { html += _renderQueueItemRow(item, 'cleared'); });
      html += '</details>';
    }

    panelEl.innerHTML = html;
    // Bind action buttons
    panelEl.querySelectorAll('.queue-action-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        handleQueueAction(btn.dataset.itemId, btn.dataset.action);
      });
    });
  }

  function _renderEntityChips(item) {
    var chips = [];
    (item.shared_ips || []).slice(0, 3).forEach(function (ip) {
      chips.push('<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(239,68,68,.15);color:#E54848;">' + escHtml(ip) + '</span>');
    });
    (item.shared_accounts || []).slice(0, 2).forEach(function (u) {
      chips.push('<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(59,130,246,.15);color:#60a5fa;">' + escHtml(u) + '</span>');
    });
    (item.shared_hosts || []).slice(0, 2).forEach(function (h) {
      chips.push('<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(16,185,129,.15);color:#34d399;">' + escHtml(h) + '</span>');
    });
    if (!chips.length) return '';
    return '<div style="display:flex;flex-wrap:wrap;gap:3px;margin-bottom:6px;">' + chips.join('') + '</div>';
  }

  function _renderQueueActions(item) {
    var id = escHtml(item.item_id);
    var state_ = item.state;
    var btns = [];
    if (state_ === 'remainder') {
      btns.push('<button class="queue-action-btn" data-item-id="' + id + '" data-action="confirm" style="font-size:11px;padding:3px 10px;background:rgba(16,185,129,.2);border:1px solid #34d399;border-radius:4px;color:#34d399;cursor:pointer;">\u2714 Confirm</button>');
      btns.push('<button class="queue-action-btn" data-item-id="' + id + '" data-action="deny" style="font-size:11px;padding:3px 10px;background:rgba(148,163,184,.1);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);cursor:pointer;">\u2718 Deny</button>');
      btns.push('<button class="queue-action-btn" data-item-id="' + id + '" data-action="escalate" style="font-size:11px;padding:3px 10px;background:rgba(239,68,68,.15);border:1px solid #E54848;border-radius:4px;color:#E54848;cursor:pointer;">\u2191 Escalate</button>');
      btns.push('<button class="queue-action-btn" data-item-id="' + id + '" data-action="defer" style="font-size:11px;padding:3px 10px;background:rgba(234,179,8,.1);border:1px solid #E0C446;border-radius:4px;color:#E0C446;cursor:pointer;">\u23F8 Defer</button>');
    } else if (state_ === 'escalated' || state_ === 'deferred') {
      btns.push('<button class="queue-action-btn" data-item-id="' + id + '" data-action="reopen" style="font-size:11px;padding:3px 10px;background:rgba(59,130,246,.15);border:1px solid var(--accent);border-radius:4px;color:var(--accent);cursor:pointer;">\u21BA Reopen</button>');
    } else if (state_ === 'cleared') {
      btns.push('<button class="queue-action-btn" data-item-id="' + id + '" data-action="reopen" style="font-size:11px;padding:3px 10px;background:rgba(59,130,246,.1);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);cursor:pointer;">\u21BA Reopen</button>');
    }
    if (!btns.length) return '';
    return '<div style="display:flex;gap:6px;flex-wrap:wrap;">' + btns.join('') + '</div>';
  }

  function _renderQueueItemRow(item, stateLabel) {
    var sevColor = _QUEUE_SEV_COLORS[item.severity] || 'var(--text-muted)';
    return '<div class="queue-item-row" style="padding:6px 0;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:8px;">' +
      '<div style="flex:1;min-width:0;">' +
      '<div style="font-size:11px;font-weight:600;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escHtml(item.title) + '">' +
      '<span style="color:' + sevColor + ';margin-right:4px;">\u25CF</span>' +
      escHtml(item.title) + '</div>' +
      (item.new_evidence_available ? '<span style="font-size:10px;color:#E0C446;">\u26A0\uFE0F new evidence</span>' : '') +
      '</div>' +
      '<div style="font-size:10px;color:var(--text-muted);white-space:nowrap;">' + item.evidence_refs.length + ' ref' + (item.evidence_refs.length !== 1 ? 's' : '') + '</div>' +
      '<div>' + _renderQueueActions(item) + '</div>' +
      '</div>';
  }

  async function handleQueueAction(itemId, action) {
    if (!state.assessmentId) return;
    var url = '/api/v1/queue/' + encodeURIComponent(state.assessmentId) + '/action';
    var body = { item_id: itemId, action: action, actor: 'analyst' };

    // Defer needs a reopen_at — default to 7 days from now
    if (action === 'defer') {
      body.reopen_at = Date.now() / 1000 + 7 * 24 * 3600;
      body.reopen_conditions = ['corroboration_count >= 2'];
    }

    try {
      var resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify(body),
      });
      if (!resp.ok) { toast('Queue action failed', 'error'); return; }
      var data = await resp.json();
      toast('Item ' + action + 'd → ' + (data.new_state || ''), 'success');
      // Refresh queue view
      var qResp = await fetch('/api/v1/queue/' + encodeURIComponent(state.assessmentId), {
        headers: authHeaders(),
      });
      if (qResp.ok) {
        var qData = await qResp.json();
        state.queueView = qData.queue || null;
        renderQueuePanel();
      }
    } catch (err) {
      toast('Queue error: ' + err.message, 'error');
    }
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

    try {
      window._lastHopGraphRender = {
        nodes: (nodes || []).length,
        links: (links || []).length,
        renderedAt: Date.now(),
        hasClusters: Object.keys(state.clusterMap || {}).length > 0,
      };
    } catch (_e) {}
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

    try {
      window._lastTimelineRender = {
        rows: (rowsWithTime || []).length,
        sources: Object.keys(srcGroups || {}),
        renderedAt: Date.now(),
        hasTimestamps: (rowsWithTime || []).length > 0,
      };
    } catch (_e) {}
  }

  function extractTimestamp(row) {
    var fields = ['eventTime', 'ts', 'timestamp', 'time', 'createdDateTime', 'activityDateTime',
      'UpdatedDateTime', 'TimeGenerated', 'start', 'date', 'datetime', '@timestamp', 'event_time',
      'timestamp_utc', 'detected_at', 'first_seen', 'last_seen', 'LogTimestamp', 'evt_time'];
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

  // ══════════════════════════════════════════════════════════════════════════
  // INVESTIGATE TAB — Build narrative + EXPAND task cards
  // ══════════════════════════════════════════════════════════════════════════

  var _investigateState = {
    investigateId: null,
    status: 'idle',       // idle | building | ready | failed
    record: null,         // last fetched investigate record
    _pollTimer: null,
    expandCache: {},      // taskId -> expand result
  };

  // ── Show/hide actions bar based on assessmentId availability ─────────────
  function _syncInvestigateActions() {
    var act = $('investigateActions');
    var empty = $('investigateEmpty');
    if (!act || !empty) return;
    if (state.assessmentId) {
      act.style.display = 'flex';
      empty.style.display = 'none';
    } else {
      act.style.display = 'none';
      empty.style.display = '';
    }
  }

  // Wire up tab switch to sync actions
  var _origSwitchTab = switchTab;
  switchTab = function (name) {
    _origSwitchTab(name);
    if (name === 'investigate') _syncInvestigateActions();
  };

  // ── Build investigate ────────────────────────────────────────────────────
  async function buildInvestigate() {
    if (!state.assessmentId) { toast('Run analysis first', 'warn'); return; }
    var persona = ($('investigatePersonaSelect') || {}).value || 'soc';
    var btn = $('btnBuildInvestigate');
    if (btn) btn.disabled = true;

    $('investigateResults').style.display = 'none';
    $('investigateLoading').style.display = '';
    $('investigateStatusBadge').textContent = 'Queuing…';
    _investigateState.status = 'building';
    // show badge on tab
    var badge = $('investigateBadge');
    if (badge) { badge.style.display = ''; badge.textContent = '⏳'; }

    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) + '/investigate/build',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ persona: persona }),
        }
      );
      if (!resp.ok) throw new Error('build returned ' + resp.status);
      var data = await resp.json();
      _investigateState.investigateId = data.investigate_id;
      $('investigateStatusBadge').textContent = 'Building…';
      _pollInvestigateStatus();
    } catch (err) {
      $('investigateLoading').style.display = 'none';
      $('investigateStatusBadge').textContent = 'Error: ' + err.message;
      if (btn) btn.disabled = false;
      toast('Investigate build failed: ' + err.message, 'error');
    }
  }

  // ── Poll for investigate completion ──────────────────────────────────────
  function _pollInvestigateStatus() {
    if (_investigateState._pollTimer) clearTimeout(_investigateState._pollTimer);
    var attempt = 0;
    var maxAttempts = 80; // 80 × 3s = 4 min

    function _poll() {
      if (!_investigateState.investigateId || !state.assessmentId) return;
      var pollMsg = $('investigatePollingMsg');
      if (pollMsg) pollMsg.textContent = 'Building narrative… (' + attempt + 's elapsed)';
      attempt += 3;

      fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
        '/investigate/' + encodeURIComponent(_investigateState.investigateId),
        { headers: authHeaders() }
      )
        .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
        .then(function (rec) {
          var st = rec.status || '';
          if (st === 'ready') {
            _investigateState.status = 'ready';
            _investigateState.record = rec;
            _renderInvestigateResults(rec);
          } else if (st === 'failed') {
            _investigateState.status = 'failed';
            $('investigateLoading').style.display = 'none';
            $('investigateStatusBadge').textContent = 'Failed: ' + (rec.error || 'unknown');
            var btn = $('btnBuildInvestigate');
            if (btn) btn.disabled = false;
            toast('Investigate failed: ' + (rec.error || ''), 'error');
          } else if (attempt < maxAttempts * 3) {
            _investigateState._pollTimer = setTimeout(_poll, 3000);
          } else {
            $('investigateLoading').style.display = 'none';
            $('investigateStatusBadge').textContent = 'Timed out waiting for narrative';
            var btn = $('btnBuildInvestigate');
            if (btn) btn.disabled = false;
          }
        })
        .catch(function () {
          if (attempt < maxAttempts * 3) {
            _investigateState._pollTimer = setTimeout(_poll, 3000);
          }
        });
    }
    _investigateState._pollTimer = setTimeout(_poll, 2000);
  }

  // ── Render results ────────────────────────────────────────────────────────
  function _renderInvestigateResults(rec) {
    $('investigateLoading').style.display = 'none';
    $('investigateResults').style.display = '';
    $('investigateStatusBadge').textContent = 'Ready';
    var btn = $('btnBuildInvestigate');
    if (btn) btn.disabled = false;
    var badge = $('investigateBadge');
    if (badge) { badge.style.display = ''; badge.textContent = '✓'; }

    // Narrative block
    var narrativeEl = $('investigateNarrative');
    if (narrativeEl) {
      narrativeEl.innerHTML =
        '<div class="report-section__title">Composite Narrative</div>' +
        '<div class="report-section__body">' +
        '<p>' + escHtml(rec.narrative || 'No narrative generated.') + '</p>' +
        (rec.missing_logs && rec.missing_logs.length
          ? '<p style="color:var(--text-muted);font-size:11px;margin-top:8px;">Missing log classes: ' + escHtml(rec.missing_logs.join(', ')) + '</p>'
          : '') +
        '</div>';
    }

    // Task cards from persona_expanded
    var cardsEl = $('investigateTaskCards');
    if (!cardsEl) return;
    cardsEl.innerHTML = '';

    var persona = ($('investigatePersonaSelect') || {}).value || 'soc';
    var tasks = _extractTasksFromRecord(rec, persona);
    if (!tasks.length) {
      cardsEl.innerHTML = '<p style="font-size:12px;color:var(--text-muted);padding:8px 0;">No structured tasks found in this narrative.</p>';
      return;
    }

    tasks.forEach(function (task, idx) {
      var taskId = _stableTaskId(task.text, persona);
      var card = _buildTaskCard(task, taskId, idx, persona);
      cardsEl.appendChild(card);
    });
  }

  // ── Extract tasks from investigate record ────────────────────────────────
  function _extractTasksFromRecord(rec, persona) {
    // Try persona_expanded first
    var expanded = rec.persona_expanded;
    if (expanded && typeof expanded === 'object') {
      var pKey = persona === 'soc' ? 'soc_analyst' : persona;
      var pData = expanded[pKey] || expanded[persona] || expanded['soc_analyst'] || expanded['soc'] || null;
      if (pData) {
        var lines = _splitIntoTasks(pData);
        if (lines.length) return lines.map(function (t) { return { text: t }; });
      }
    }
    // Fall back to splitting narrative into paragraphs
    var narrative = rec.narrative || '';
    return _splitIntoTasks(narrative).map(function (t) { return { text: t }; });
  }

  function _splitIntoTasks(text) {
    if (!text) return [];
    // Split on numbered lines (1. ..., • ...) or double-newline paragraphs
    var lines = String(text)
      .split(/\n+/)
      .map(function (l) { return l.trim(); })
      .filter(function (l) { return l.length > 20; });
    // If only 1 line (no structure), split on '. ' sentence boundary
    if (lines.length === 1 && lines[0].length > 200) {
      lines = lines[0].match(/[^.!?]+[.!?]+/g) || lines;
      lines = lines.filter(function (l) { return l.trim().length > 20; });
    }
    return lines.slice(0, 12); // max 12 task cards
  }

  function _stableTaskId(text, persona) {
    // Simple client-side hash (djb2) to produce a stable short ID
    var s = (persona + '::' + text.trim().toLowerCase());
    var h = 5381;
    for (var i = 0; i < s.length; i++) {
      h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  // ── Build a single task card DOM element ────────────────────────────────
  function _buildTaskCard(task, taskId, idx, persona) {
    var card = document.createElement('div');
    card.className = 'task-card';
    card.setAttribute('data-task-id', taskId);

    var headerDiv = document.createElement('div');
    headerDiv.className = 'task-card__header';
    headerDiv.innerHTML =
      '<span style="font-size:10px;color:var(--text-muted);min-width:20px;">#' + (idx + 1) + '</span>' +
      '<span class="task-card__title">' + escHtml(task.text.slice(0, 180)) + (task.text.length > 180 ? '…' : '') + '</span>' +
      '<button class="task-card__expand-btn" data-task-id="' + taskId + '" data-persona="' + persona + '">' +
      'EXPAND ▼</button>';

    var bodyDiv = document.createElement('div');
    bodyDiv.className = 'task-card__body';
    bodyDiv.id = 'expand-body-' + taskId;

    card.appendChild(headerDiv);
    card.appendChild(bodyDiv);

    // Toggle body on header click
    headerDiv.addEventListener('click', function (e) {
      if (e.target.classList.contains('task-card__expand-btn')) return;
      bodyDiv.classList.toggle('open');
    });

    // EXPAND button: call backend
    var expandBtn = headerDiv.querySelector('.task-card__expand-btn');
    if (expandBtn) {
      expandBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        bodyDiv.classList.add('open');
        _triggerExpand(task.text, taskId, persona, bodyDiv, expandBtn);
      });
    }

    return card;
  }

  // ── Trigger EXPAND API call ───────────────────────────────────────────────
  async function _triggerExpand(taskText, taskId, persona, bodyEl, btnEl) {
    if (!state.assessmentId) { toast('No assessment loaded', 'warn'); return; }

    // Check in-memory cache first
    if (_investigateState.expandCache[taskId]) {
      _renderExpandPanel(bodyEl, _investigateState.expandCache[taskId]);
      return;
    }

    if (btnEl) btnEl.disabled = true;
    bodyEl.innerHTML = '<div class="expand-loading">⏳ Expanding… querying LLM and running automated checks…</div>';

    // Pin EXPAND to the active cluster when one is open
    var activeCid = state.activeClusterId || null;
    var cluster = activeCid ? (state.clusterMap || {})[activeCid] : null;
    var rowRefs = cluster ? (cluster.row_refs || cluster.row_indices || []) : [];
    var modelEl = activeCid ? document.getElementById('llmModelSel_' + activeCid) : null;
    var model = (modelEl && modelEl.value) || null;

    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
        '/tasks/' + encodeURIComponent(taskId) + '/expand',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({
            task_text: taskText,
            persona: persona,
            investigate_id: _investigateState.investigateId || undefined,
            cluster_id: activeCid || undefined,
            row_refs: rowRefs.length ? rowRefs : undefined,
            model: model || undefined,
          }),
        }
      );
      if (!resp.ok) throw new Error('expand returned ' + resp.status);
      var data = await resp.json();
      _investigateState.expandCache[taskId] = data;
      _renderExpandPanel(bodyEl, data);
    } catch (err) {
      bodyEl.innerHTML = '<div class="expand-error">Expand failed: ' + escHtml(err.message) + '</div>';
    } finally {
      if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'EXPAND ▲'; }
    }
  }

  // ── Render expand panel content ───────────────────────────────────────────
  function _renderExpandPanel(bodyEl, data) {
    var html = '<div class="expand-panel">';

    // Entity chips
    var ef = data.entity_fields || {};
    var allEntities = [];
    ['users', 'ips', 'hosts'].forEach(function (cat) {
      (ef[cat] || []).slice(0, 4).forEach(function (v) {
        allEntities.push('<span class="entity-chip">' + escHtml(v) + '</span>');
      });
    });
    if (allEntities.length) {
      html += '<div class="entity-chips">' + allEntities.join('') + '</div>';
    }

    // Automated check badges
    var checks = data.check_results || [];
    var triggered = checks.filter(function (c) { return c.triggered; });
    if (triggered.length) {
      html += '<div class="expand-check-badges">';
      triggered.forEach(function (c) {
        var cls = 'expand-badge--' + (c.severity || 'info');
        html += '<span class="expand-badge ' + escHtml(cls) + '" title="' + escHtml(c.detail || '') + '">' +
          escHtml(c.label) + '</span>';
      });
      html += '</div>';
    }

    // Summary
    if (data.summary) {
      html += '<div class="expand-panel__summary">' + escHtml(data.summary) + '</div>';
    }

    // Subtasks
    var subtasks = data.subtasks || [];
    if (subtasks.length) {
      html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted);margin-bottom:5px;">Subtasks</div>';
      html += '<ul class="expand-subtask-list">';
      subtasks.forEach(function (st) {
        var priCls = 'stask-priority--' + (st.priority || 'medium');
        var refs = (st.evidence_refs || []).slice(0, 5);
        var refsHtml = refs.length ? ' <span style="font-size:9px;color:var(--text-muted);font-family:monospace;">[rows: ' + refs.join(', ') + ']</span>' : '';
        var criteria = st.success_criteria ? '<div style="font-size:10px;color:var(--text-muted);padding-left:8px;margin-top:2px;">✓ ' + escHtml(st.success_criteria) + '</div>' : '';
        html += '<li style="flex-direction:column;align-items:flex-start;">' +
          '<div style="display:flex;align-items:center;gap:6px;width:100%;">' +
          '<span class="stask-priority ' + priCls + '">' + escHtml(st.priority || 'med') + '</span>' +
          '<span style="flex:1;">' + escHtml(st.action || '') + '</span>' +
          (st.entity ? '<span style="font-size:10px;color:var(--text-muted);font-family:monospace;">' + escHtml(st.entity) + '</span>' : '') +
          refsHtml +
          '</div>' +
          criteria +
          '</li>';
      });
      html += '</ul>';
    }

    // IOCs
    var iocs = data.iocs || [];
    if (iocs.length) {
      html += '<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted);margin-bottom:5px;">Indicators</div>';
      html += '<ul class="expand-ioc-list">';
      iocs.slice(0, 8).forEach(function (ioc) {
        html += '<li><span class="ioc-type">' + escHtml(ioc.type || 'ioc') + '</span>' +
          escHtml(ioc.value || '') +
          (ioc.context ? ' <span style="color:var(--text-muted);font-size:10px;">— ' + escHtml(ioc.context) + '</span>' : '') +
          '</li>';
      });
      html += '</ul>';
    }

    // MITRE techniques
    var ttps = data.mitre_techniques || [];
    if (ttps.length) {
      html += '<div style="margin-bottom:8px;"><span style="font-size:10px;color:var(--text-muted);">MITRE: </span>' +
        ttps.slice(0, 6).map(function (t) {
          return '<span style="font-size:10px;font-family:monospace;padding:1px 5px;background:rgba(74,99,231,.1);border-radius:3px;color:var(--accent,#4A63E7);margin-right:4px;">' + escHtml(t) + '</span>';
        }).join('') + '</div>';
    }

    // Next pivot
    if (data.next_pivot) {
      html += '<div class="expand-pivot">🔍 <b>Next pivot:</b> ' + escHtml(data.next_pivot) + '</div>';
    }

    // Confidence + latency meta
    html += '<div style="margin-top:10px;font-size:10px;color:var(--text-muted);">' +
      'Confidence: ' + Math.round((data.confidence || 0) * 100) + '%' +
      (data.cache_hit ? ' · cache hit' : '') +
      (data.latency_ms ? ' · ' + data.latency_ms + 'ms' : '') +
      '</div>';

    html += '</div>';
    bodyEl.innerHTML = html;
  }

  // ── Wire up Build Investigate button ────────────────────────────────────
  var btnBuild = $('btnBuildInvestigate');
  if (btnBuild) {
    btnBuild.addEventListener('click', function () { buildInvestigate(); });
  }

  // Sync investigate actions whenever assessmentId changes
  // (hooked by overriding the pipeline completion path)
  var _origGeneratePersonaReport = generatePersonaReport;
  generatePersonaReport = async function (assessment) {
    var result = await _origGeneratePersonaReport(assessment);
    _syncInvestigateActions();
    return result;
  };

  window.buildInvestigate = buildInvestigate;

  // ── Cluster Map + Drawer ─────────────────────────────────────────────────

  var CLUSTER_MODELS = [
    { value: 'qwen2.5:14b',          label: 'Qwen 2.5 14B  ★ (best overall · fast)' },
    { value: 'qwen3:14b',            label: 'Qwen 3 14B (deep reasoning · slower)' },
    { value: 'qwen3:30b',            label: 'Qwen 3 30B (highest quality · slowest)' },
    { value: 'mistral-small3.2:24b', label: 'Mistral Small 3.2 24B (fastest · latency)' },
  ]; // fallback only — overwritten by loadModelCatalog()

  async function loadModelCatalog() {
    try {
      var resp = await fetch('/api/v1/llm/models/catalog', { headers: authHeaders() });
      if (!resp.ok) return;
      var data = await resp.json();
      var models = (data.models || []).filter(function (m) { return m.tier === 'local'; });
      if (!models.length) return;
      CLUSTER_MODELS = models.map(function (m) {
        return {
          value: m.id,
          label: m.label + (m.recommended ? '  ★' : '') + (!m.available ? '  (offline)' : ''),
          disabled: !m.available,
        };
      });
    } catch (_e) { /* keep fallback */ }
  }

  loadModelCatalog();

  function storeClusters(clusters) {
    state.clusterMap = {};
    if (!Array.isArray(clusters)) return;
    clusters.forEach(function (c) {
      var cid = String(c.cluster_id || c.id || '');
      if (cid) state.clusterMap[cid] = c;
    });
    renderClusterList();
  }

  function renderClusterList() {
    var panel = $('clusterListPanel');
    if (!panel) return;
    var ids = Object.keys(state.clusterMap);
    if (!ids.length) { panel.style.display = 'none'; return; }
    panel.style.display = '';
    var html = '<div class="cluster-list-header">Clusters (' + ids.length + ')</div>';
    ids.forEach(function (cid) {
      var c = state.clusterMap[cid];
      var sev = (c.severity || 'medium').toLowerCase();
      var rows = c.row_count || (c.row_refs || []).length || 0;
      var label = c.label || c.summary || ('Cluster ' + cid);
      html += '<div class="cluster-item cluster-item--' + sev + '">' +
        '<span class="cluster-item__sev" onclick="window.openClusterDetail(\'' + escHtml(cid) + '\')">' + escHtml(sev.toUpperCase()) + '</span>' +
        '<span class="cluster-item__label" onclick="window.openClusterDetail(\'' + escHtml(cid) + '\')">' + escHtml(String(label).slice(0, 60)) + '</span>' +
        '<span class="cluster-item__rows">' + rows + ' rows</span>' +
        '<button class="btn-secondary" style="font-size:10px;padding:2px 8px;" ' +
          'onclick="event.stopPropagation(); window.openTier2Canvas(\'' + escHtml(cid) + '\')">' +
          'Open Tier 2' +
        '</button>' +
        '</div>';
    });
    panel.innerHTML = html;
  }

  window.openClusterDetail = function (clusterId) {
    state.activeClusterId = String(clusterId);
    var drawer = $('clusterDrawer');
    if (!drawer) return;
    var c = state.clusterMap[clusterId] || {};
    var sev = (c.severity || 'medium').toLowerCase();
    var label = c.label || c.summary || ('Cluster ' + clusterId);
    var rows = c.row_count || (c.row_refs || []).length || 0;
    var entities = (c.entities || c.top_entities || []).slice(0, 6);

    $('clusterDrawerTitle').textContent = label;
    $('clusterDrawerMeta').innerHTML =
      '<span class="sev-pill sev-pill--' + sev + '">' + sev.toUpperCase() + '</span> ' +
      rows + ' rows' +
      (entities.length ? ' · ' + entities.map(function (e) { return '<span class="entity-chip">' + escHtml(String(e)) + '</span>'; }).join(' ') : '');

    // Reset result containers
    var summaryEl = $('llmSummaryResult_' + clusterId);
    var enrichEl  = $('enrichResult_'    + clusterId);
    var huntEl    = $('huntResult_'      + clusterId);
    if (summaryEl) summaryEl.innerHTML = '';
    if (enrichEl)  enrichEl.innerHTML  = '';
    if (huntEl)    huntEl.innerHTML    = '';

    // Ensure per-cluster elements exist inside the drawer template
    _ensureClusterElements(clusterId);

    drawer.classList.add('open');
    drawer.style.display = '';
  };

  window.openTier2Canvas = function (clusterId) {
    if (!state.assessmentId) { toast('Run Analyze first', 'warn'); return; }
    var persona = state.currentPersona || 'soc_analyst';
    var modelEl = document.getElementById('llmModelSel_' + clusterId);
    var model = (modelEl && modelEl.value) || 'qwen2.5:14b';
    var url = '/static/tier2_investigation.html' +
              '?assessment_id=' + encodeURIComponent(state.assessmentId) +
              '&cluster_id='    + encodeURIComponent(clusterId) +
              '&persona='       + encodeURIComponent(persona) +
              '&llm_model='     + encodeURIComponent(model);
    window.open(url, '_blank', 'width=1400,height=900');
  };

  function _ensureClusterElements(cid) {
    var container = $('clusterDrawerBody');
    if (!container) return;
    if ($('llmSummaryResult_' + cid)) return; // already created
    var frag = document.createElement('div');
    frag.id = 'clusterResultsFor_' + cid;
    frag.innerHTML =
      '<div id="llmSummaryResult_' + cid + '" class="cluster-result-block" style="display:none;"></div>' +
      '<div id="enrichResult_'    + cid + '" class="cluster-result-block" style="display:none;"></div>' +
      '<div id="huntResult_'      + cid + '" class="cluster-result-block" style="display:none;"></div>';
    container.appendChild(frag);
    // Model selector
    var sel = $('llmModelSel_' + cid);
    if (!sel) {
      var selWrap = $('clusterModelSelWrap');
      if (selWrap) {
        var newSel = document.createElement('select');
        newSel.id = 'llmModelSel_' + cid;
        newSel.className = 'cluster-model-sel';
        CLUSTER_MODELS.forEach(function (m) {
          var opt = document.createElement('option');
          opt.value = m.value; opt.textContent = m.label;
          if (m.disabled) opt.disabled = true;
          newSel.appendChild(opt);
        });
        selWrap.appendChild(newSel);
      }
    }
  }

  window._triggerLlmSummary = async function (clusterId, assessmentId, forceRefresh, persona) {
    assessmentId = assessmentId || state.assessmentId;
    clusterId    = clusterId    || state.activeClusterId;
    persona      = persona      || state.currentPersona || 'soc_analyst';
    forceRefresh = !!forceRefresh;
    var selEl = $('llmModelSel_' + clusterId);
    var model = (selEl && selEl.value) || 'qwen2.5:14b';
    _ensureClusterElements(clusterId);
    var el = $('llmSummaryResult_' + clusterId);
    if (el) { el.style.display = ''; el.innerHTML = '<span class="loading-dot">Summarising with ' + model + '…</span>'; }
    try {
      var url = '/api/v1/assessments/' + encodeURIComponent(assessmentId) +
                '/clusters/' + encodeURIComponent(clusterId) +
                '/tier2/llm-summary?model=' + encodeURIComponent(model) +
                (forceRefresh ? '&force_refresh=true' : '');
      var ctrl = new AbortController();
      var _tmo = setTimeout(function () { ctrl.abort(); }, 180000); // 3 min for Mistral
      var resp = await fetch(url, {
        headers: Object.assign({ 'x-persona': persona }, authHeaders()),
        signal: ctrl.signal,
      });
      clearTimeout(_tmo);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var data = await resp.json();
      if (el) el.innerHTML = _renderLlmSummary(data, clusterId, model);
    } catch (err) {
      if (el) el.innerHTML = '<span class="cluster-error">Summarise failed: ' + escHtml(err.message) + '</span>';
      toast('LLM summary failed: ' + err.message, 'error');
    }
  };

  window._triggerClusterEnrich = async function (clusterId, assessmentId, forceRefresh, model) {
    assessmentId = assessmentId || state.assessmentId;
    clusterId    = clusterId    || state.activeClusterId;
    forceRefresh = !!forceRefresh;
    model        = model || (($('llmModelSel_' + clusterId) || {}).value) || 'qwen2.5:14b';
    _ensureClusterElements(clusterId);
    var el = $('enrichResult_' + clusterId);
    if (el) { el.style.display = ''; el.innerHTML = '<span class="loading-dot">Running CRAG enrich…</span>'; }
    try {
      var url = '/api/v1/assessments/' + encodeURIComponent(assessmentId) +
                '/clusters/' + encodeURIComponent(clusterId) + '/enrich';
      var ctrl = new AbortController();
      var _tmo = setTimeout(function () { ctrl.abort(); }, 60000);
      var resp = await fetch(url, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({ tenant_id: 'default', force_refresh: forceRefresh, model: model }),
        signal: ctrl.signal,
      });
      clearTimeout(_tmo);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var data = await resp.json();
      if (el) el.innerHTML = _renderEnrichResult(data);
    } catch (err) {
      if (el) el.innerHTML = '<span class="cluster-error">CRAG enrich failed: ' + escHtml(err.message) + '</span>';
      toast('CRAG enrich failed: ' + err.message, 'error');
    }
  };

  window._triggerHuntSweep = async function (clusterId, assessmentId, forceRefresh) {
    assessmentId = assessmentId || state.assessmentId;
    clusterId    = clusterId    || state.activeClusterId;
    forceRefresh = !!forceRefresh;
    _ensureClusterElements(clusterId);
    var el = $('huntResult_' + clusterId);
    if (el) { el.style.display = ''; el.innerHTML = '<span class="loading-dot">Running Hunt Sweep…</span>'; }
    try {
      var url = '/api/v1/assessments/' + encodeURIComponent(assessmentId) +
                '/clusters/' + encodeURIComponent(clusterId) + '/tier2';
      var ctrl = new AbortController();
      var _tmo = setTimeout(function () { ctrl.abort(); }, 60000);
      var resp = await fetch(url, {
        headers: authHeaders(),
        signal: ctrl.signal,
      });
      clearTimeout(_tmo);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var data = await resp.json();
      if (el) el.innerHTML = _renderHuntResult(data);
    } catch (err) {
      if (el) el.innerHTML = '<span class="cluster-error">Hunt sweep failed: ' + escHtml(err.message) + '</span>';
    }
  };

  function _renderLlmSummary(data, clusterId, model) {
    var sections = data.sections || {};
    var steps    = data.persona_steps || [];
    var persona  = data.persona_label || data.persona || '';
    var focus    = data.persona_focus || '';
    var fallback = data.fallback_generated ? '<span class="badge badge--warn">deterministic fallback</span> ' : '';
    var html = '<div class="llm-summary-block">' +
      fallback +
      (persona ? '<strong>' + escHtml(persona) + '</strong>' : '') +
      (focus   ? ' · <em>' + escHtml(focus) + '</em>' : '') +
      ' <span style="font-size:10px;color:var(--text-muted);">via ' + escHtml(model) + '</span>';
    if (sections.what_to_do)        html += '<p><strong>What to do:</strong> ' + escHtml(sections.what_to_do) + '</p>';
    if (sections.investigate_next)  html += '<p><strong>Investigate next:</strong> ' + escHtml(sections.investigate_next) + '</p>';
    if (sections.business_impact)   html += '<p><strong>Business impact:</strong> ' + escHtml(sections.business_impact) + '</p>';
    if (steps.length) {
      html += '<ol class="persona-steps">';
      steps.forEach(function (s) {
        html += '<li><strong>' + escHtml(s.title || s.action || '') + '</strong>';
        if (s.owner)    html += ' <span class="badge">' + escHtml(s.owner) + '</span>';
        if (s.priority) html += ' <span class="badge badge--' + (s.priority === 'P1' ? 'crit' : 'info') + '">' + escHtml(s.priority) + '</span>';
        if (s.subtasks && s.subtasks.length) {
          html += '<ul>' + s.subtasks.map(function (t) { return '<li>' + escHtml(t) + '</li>'; }).join('') + '</ul>';
        }
        if (s.evidence_refs && s.evidence_refs.length) {
          html += '<div style="font-size:10px;color:var(--text-muted);">refs: ' + s.evidence_refs.join(', ') + '</div>';
        }
        html += '</li>';
      });
      html += '</ol>';
    }
    html += '</div>';
    return html;
  }

  function _renderEnrichResult(data) {
    var verdict = (data.verdict || data.crag_verdict || '').toUpperCase();
    var score   = data.composite_score != null ? Math.round(data.composite_score * 100) + '%' : '';
    var cls     = verdict === 'ACCEPT' ? 'badge--ok' : verdict === 'REFINE' ? 'badge--warn' : 'badge--crit';
    return '<div class="enrich-block">' +
      '<span class="badge ' + cls + '">CRAG: ' + (verdict || 'N/A') + '</span>' +
      (score ? ' <span class="badge">' + score + ' quality</span>' : '') +
      (data.evidence_quality_notes ? '<p>' + escHtml(data.evidence_quality_notes) + '</p>' : '') +
      (data.skip_reason ? '<p style="color:var(--text-muted);">Skipped: ' + escHtml(data.skip_reason) + '</p>' : '') +
      '<span style="font-size:10px;color:var(--text-muted);">Evidence-quality gate · not an authoritative verdict</span>' +
      '</div>';
  }

  function _renderHuntResult(data) {
    var rows = data.member_rows || [];
    return '<div class="hunt-block">' +
      '<strong>Tier 2 Context</strong> — ' + rows.length + ' member rows<br>' +
      (data.cluster_detail && data.cluster_detail.summary ? '<p>' + escHtml(data.cluster_detail.summary) + '</p>' : '') +
      '</div>';
  }

  window.storeClusters = storeClusters;
  window.renderClusterList = renderClusterList;

})();
