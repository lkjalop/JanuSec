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
  var esc = escHtml;

  // Lightweight markdown → safe HTML (headers, bold, bullets, line breaks)
  function mdToHtml(s) {
    if (!s) return '';
    var lines = String(s).split('\n');
    var out = [];
    lines.forEach(function(line) {
      var t = line
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      if (/^#{3,}\s/.test(t))      { out.push('<div style="font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted,#7a7f8e);margin:8px 0 3px;">' + t.replace(/^#{3,}\s/,'') + '</div>'); return; }
      if (/^##\s/.test(t))         { out.push('<div style="font-size:11px;font-weight:700;color:var(--text,#e8ebf0);margin:10px 0 3px;">' + t.replace(/^##\s/,'') + '</div>'); return; }
      if (/^#\s/.test(t))          { out.push('<div style="font-size:12px;font-weight:700;color:var(--text,#e8ebf0);margin:10px 0 4px;">' + t.replace(/^#\s/,'') + '</div>'); return; }
      if (/^[-*]\s/.test(t))       { out.push('<div style="padding-left:14px;margin:1px 0;">• ' + t.replace(/^[-*]\s/,'').replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>') + '</div>'); return; }
      if (/^\d+\.\s/.test(t))      { out.push('<div style="padding-left:14px;margin:1px 0;">' + t.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>') + '</div>'); return; }
      if (t.trim() === '')         { out.push('<div style="height:5px;"></div>'); return; }
      out.push('<div style="margin:1px 0;">' + t.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>').replace(/`([^`]+)`/g,'<code style="font-size:10px;background:rgba(255,255,255,.07);padding:1px 4px;border-radius:3px;">$1</code>') + '</div>');
    });
    return out.join('');
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
      // Expose for Playwright tests and external tooling — read-only snapshot of the last assessment
      window._lastAssessment = assessment;
      window._investigateState = {
        assessmentId: assessment.assessment_id || state.assessmentId,
        correlationClusters: assessment.correlation_clusters || [],
        evidenceRows: assessment.evidence_rows || assessment.rows || [],
        status: 'ready',
      };
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

  // ── Build a row_index → cluster lookup ───────────────────────────────────
  function buildRowClusterIndex() {
    var idx = {}; // row_index -> {cluster_id, severity, label, row_refs}
    if (!state.clusterMap) return idx;
    for (var cid in state.clusterMap) {
      var c = state.clusterMap[cid];
      var refs = c.row_refs || [];
      refs.forEach(function(r) { idx[r] = { cluster_id: cid, severity: c.severity || 'low', label: c.label || c.cluster_label || cid, row_refs: refs }; });
    }
    return idx;
  }

  // ── Semantic source tag from filename + row fields ────────────────────────
  function semanticSource(row) {
    var src = (row._source || '').toLowerCase();
    var notes = (row.analyst_notes || row.llm_summary || '').toLowerCase();
    if (src.includes('okta') || row.activityDisplayName || row.userPrincipalName) return 'identity · okta';
    if (src.includes('m365') || src.includes('exchange') || row.MailboxOwnerUPN) return 'email · m365';
    if (src.includes('mimecast') || src.includes('proofpoint')) return 'email · gateway';
    if (src.includes('sailpoint')) return 'identity · iam';
    if (src.includes('entra') || src.includes('aad') || src.includes('azure')) return 'cloud · azure';
    if (src.includes('cloudtrail') || src.includes('guardduty') || src.includes('aws')) return 'cloud · aws';
    if (src.includes('zeek') || src.includes('net') || src.includes('bgp') || src.includes('c2')) return 'network';
    if (src.includes('sysmon') || src.includes('evtx') || src.includes('endpoint')) return 'endpoint';
    if (notes.includes('c2') || notes.includes('beacon')) return 'network · c2';
    if (row.dns_query) return 'network · dns';
    if (row.proto === 'smb' || row.port === 445) return 'network · smb';
    return shortSource(row._source || '?');
  }

  // ── Build evidence rows from assessment ──────────────────────────────────
  function buildEvidenceFromAssessment(assessment) {
    var rowClusterIdx = buildRowClusterIndex();

    var rows = state.allRows.map(function (original, idx) {
      var severity = classifySeverity(original);
      var clusterInfo = rowClusterIdx[idx] || null;
      var isCorrelated = !!clusterInfo || detectCorrelation(original, idx);
      var entity = extractPrimaryEntity(original);
      var description = extractDescription(original);
      var triage = computeLocalTriageScore(original, severity, isCorrelated);

      return {
        row_index: idx,
        source: original._source || 'unknown',
        source_label: semanticSource(original),
        severity: clusterInfo ? (clusterInfo.severity || severity) : severity,
        type: isCorrelated ? 'correlated' : 'isolated',
        cluster_id: clusterInfo ? clusterInfo.cluster_id : null,
        cluster_label: clusterInfo ? clusterInfo.label : null,
        cluster_severity: clusterInfo ? clusterInfo.severity : null,
        cluster_row_refs: clusterInfo ? clusterInfo.row_refs : [],
        entity: entity,
        description: description,
        mitre: original.mitre_technique || original.mitre_techniques || original.technique_id || null,
        analyst_notes: original.analyst_notes || original.llm_summary || null,
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
      row.category || row.proto ||
      row.analyst_notes || row.llm_summary || row.summary ||
      row.dns_query || row.user_agent ||
      (row.target_app_or_resource ? 'Target: ' + row.target_app_or_resource : '') ||
      (row.mitre_technique ? 'MITRE: ' + row.mitre_technique : '') ||
      (row.technique_id ? 'MITRE: ' + row.technique_id : '') ||
      (row.event_id ? 'Event ID: ' + row.event_id : '') ||
      (row.file_hash ? 'Hash: ' + row.file_hash : '') ||
      '';
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
    var hasRows = filtered.length > 0;
    var tbl = $('evidenceTable');
    if (tbl) tbl.style.display = hasRows ? '' : 'none';
    $('evidenceEmpty').style.display = hasRows ? 'none' : '';
    $('evidenceCount').textContent = filtered.length + ' of ' + rows.length + ' events';

    filtered.forEach(function (row) {
      var tr = document.createElement('tr');
      tr.setAttribute('data-idx', row.row_index);

      // Cluster chip
      var clusterChip = row.cluster_id
        ? '<span style="font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;background:rgba(124,106,247,.15);color:#a89cf7;border:1px solid rgba(124,106,247,.3);cursor:pointer;" data-open-cluster="' + escHtml(row.cluster_id) + '" title="Open cluster drawer">' + escHtml(row.cluster_id) + '</span>'
        : '<span style="font-size:9px;color:var(--text-muted,#7a7f8e);padding:1px 5px;">isolated</span>';

      // MITRE chip
      var mitreChip = row.mitre
        ? ' <span style="font-size:9px;padding:1px 5px;border-radius:3px;background:rgba(224,196,70,.1);color:#e0c446;border:1px solid rgba(224,196,70,.25);" title="' + escHtml(row.mitre) + '">' + escHtml(String(row.mitre).split(',')[0].trim().substring(0,12)) + '</span>'
        : '';

      // Description — use analyst_notes if description empty
      var desc = row.description || row.analyst_notes || '';

      tr.innerHTML =
        '<td style="color:var(--text-muted);font-size:10px;">' + row.row_index + '</td>' +
        '<td>' + clusterChip + '</td>' +
        '<td><span class="text-xs" style="color:var(--text-muted);">' + escHtml(row.source_label || shortSource(row.source)) + '</span></td>' +
        '<td><span class="sev-pill sev-pill--' + row.severity + '">' + row.severity.toUpperCase() + '</span></td>' +
        '<td title="' + escHtml(row.entity) + '" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escHtml(truncate(row.entity, 28)) + '</td>' +
        '<td title="' + escHtml(desc) + '" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escHtml(truncate(desc, 55)) + mitreChip + '</td>' +
        '<td style="font-weight:600;color:' + scoreColor(row.triage_score) + ';font-size:11px;">' + row.triage_score.toFixed(2) + '</td>' +
        '<td style="white-space:nowrap;">' +
          (row._hasLlm ? '<span style="color:var(--safe);font-size:10px;">✓ T1</span>' : '<button class="btn-secondary" style="padding:2px 5px;font-size:10px;" data-llm="' + row.row_index + '">T1</button>') +
          ' <button class="btn-secondary" style="padding:2px 5px;font-size:10px;background:rgba(124,106,247,.1);border-color:rgba(124,106,247,.3);color:#a89cf7;" data-ev-expand="' + row.row_index + '">EXPAND</button>' +
        '</td>';

      // Row click → detail panel
      tr.addEventListener('click', function (e) {
        // Don't trigger detail if clicking cluster chip or expand button
        if (e.target.closest('[data-open-cluster]') || e.target.closest('[data-ev-expand]')) return;
        showDetail(row);
      });

      // Cluster chip click → open cluster drawer
      tr.querySelector('[data-open-cluster]') && tr.querySelector('[data-open-cluster]').addEventListener('click', function(e) {
        e.stopPropagation();
        var cid = e.currentTarget.getAttribute('data-open-cluster');
        if (window._cdOpen) window._cdOpen(cid);
      });

      // EXPAND button click → row expand drawer
      tr.querySelector('[data-ev-expand]') && tr.querySelector('[data-ev-expand]').addEventListener('click', function(e) {
        e.stopPropagation();
        showDetail(row);
      });

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
    // Strip common filename noise: extensions, UUIDs, version strings
    var s = name.replace(/\.(csv|json|xlsx|xls|txt|log)$/i, '').replace(/_v\d+[\.\d]*/i, '').replace(/janusec_/i, '');
    return s.length > 22 ? s.substring(0, 20) + '…' : s;
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

    // Cluster membership banner
    if (row.cluster_id) {
      var clusterRefs = row.cluster_row_refs || [];
      html += '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 12px;margin-bottom:10px;border-radius:6px;background:rgba(124,106,247,.08);border:1px solid rgba(124,106,247,.25);">';
      html += '<span style="font-size:10px;font-weight:700;color:#a89cf7;">CLUSTER</span>';
      html += '<span style="font-size:11px;font-weight:700;color:var(--text,#e8ebf0);">' + escHtml(row.cluster_id) + '</span>';
      if (row.cluster_label && row.cluster_label !== row.cluster_id) html += '<span style="font-size:10px;color:var(--text-muted);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + escHtml(row.cluster_label) + '</span>';
      html += '<span class="sev-pill sev-pill--' + (row.cluster_severity || row.severity) + '" style="font-size:9px;">' + (row.cluster_severity || row.severity).toUpperCase() + '</span>';
      html += '<span style="font-size:10px;color:var(--text-muted);">' + clusterRefs.length + ' rows</span>';
      html += '<button class="btn-secondary" style="padding:2px 8px;font-size:10px;" onclick="if(window._cdOpen) window._cdOpen(\'' + escHtml(row.cluster_id) + '\')">Open Cluster →</button>';
      html += '</div>';

      // Related rows in same cluster (same entity or same cluster)
      var related = (state.evidenceRows || []).filter(function(r) {
        return r.row_index !== row.row_index && r.cluster_id === row.cluster_id;
      }).slice(0, 8);
      if (related.length) {
        html += '<div class="report-section"><div class="report-section__title">Related Rows — ' + escHtml(row.cluster_id) + '</div><div class="report-section__body" style="display:flex;flex-direction:column;gap:3px;">';
        related.forEach(function(r) {
          var rdesc = truncate(r.description || r.analyst_notes || r.entity || '', 50);
          html += '<div style="display:flex;align-items:center;gap:6px;font-size:11px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04);cursor:pointer;" onclick="showDetail(' + JSON.stringify({row_index:r.row_index,source:r.source,source_label:r.source_label,severity:r.severity,type:r.type,cluster_id:r.cluster_id,cluster_label:r.cluster_label,cluster_severity:r.cluster_severity,cluster_row_refs:r.cluster_row_refs,entity:r.entity,description:r.description,mitre:r.mitre,analyst_notes:r.analyst_notes,triage_score:r.triage_score,_hasLlm:r._hasLlm,_llmSummary:r._llmSummary,raw:r.raw}).replace(/'/g,"&#39;") + ')">';
          html += '<span style="color:var(--text-muted);min-width:28px;">row[' + r.row_index + ']</span>';
          html += '<span class="sev-pill sev-pill--' + r.severity + '" style="font-size:9px;">' + r.severity.substring(0,4).toUpperCase() + '</span>';
          html += '<span style="flex:1;color:var(--text,#e8ebf0);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + escHtml(rdesc || r.entity) + '</span>';
          if (r.mitre) html += '<span style="font-size:9px;color:#e0c446;">' + escHtml(String(r.mitre).split(',')[0].trim().substring(0,12)) + '</span>';
          html += '</div>';
        });
        if (clusterRefs.length > 9) html += '<div style="font-size:10px;color:var(--text-muted);padding-top:3px;">+' + (clusterRefs.length - 8) + ' more rows in this cluster</div>';
        html += '</div></div>';
      }
    }

    html += '<div class="report-section"><div class="report-section__title">Overview</div><div class="report-section__body">';
    html += '<p><b>Source:</b> ' + escHtml(row.source_label || row.source) + '</p>';
    html += '<p><b>Entity:</b> ' + escHtml(row.entity) + '</p>';
    var displayDesc = row.description || row.analyst_notes || '';
    html += '<p><b>Description:</b> ' + escHtml(displayDesc || '—') + '</p>';
    if (row.mitre) html += '<p><b>MITRE:</b> <span style="color:#e0c446;font-family:monospace;">' + escHtml(row.mitre) + '</span></p>';
    html += '<p><b>Triage Score:</b> <span style="color:' + scoreColor(row.triage_score) + ';font-weight:600;">' + row.triage_score.toFixed(2) + '</span></p>';
    // Analyst notes (full text if different from description)
    if (row.analyst_notes && row.analyst_notes !== row.description) {
      html += '<details style="margin-top:6px;"><summary style="font-size:11px;color:var(--text-muted);cursor:pointer;">Analyst Notes</summary>';
      html += '<p style="font-size:11px;margin-top:4px;white-space:pre-wrap;color:var(--text,#e8ebf0);">' + escHtml(row.analyst_notes) + '</p></details>';
    }
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

    // ── Graph cluster filter bar ──────────────────────────────────────────
    var grFilter = $('graphClusterFilter');
    if (!grFilter) {
      grFilter = document.createElement('div');
      grFilter.id = 'graphClusterFilter';
      grFilter.style.cssText = 'display:flex;align-items:center;gap:6px;padding:6px 10px;border-bottom:1px solid var(--border,#2a2d3a);flex-shrink:0;flex-wrap:wrap;';
      canvas.parentNode.insertBefore(grFilter, canvas);
    }
    var grClusterIds = ['all'];
    if (state.clusterMap) Object.keys(state.clusterMap).sort().forEach(function(cid) { grClusterIds.push(cid); });
    var activeGrFilter = window._grActiveFilter || 'all';
    var showInternalIPs = window._grShowInternal !== false;
    grFilter.innerHTML = '<span style="font-size:10px;color:var(--text-muted);font-weight:600;">Cluster:</span>' +
      grClusterIds.map(function(cid) {
        var isActive = cid === activeGrFilter;
        var c = state.clusterMap && state.clusterMap[cid];
        var label = cid === 'all' ? 'All' : cid + (c ? ' (' + (c.row_refs||[]).length + ')' : '');
        return '<button style="font-size:10px;padding:2px 7px;border-radius:4px;cursor:pointer;border:1px solid ' + (isActive?'var(--accent,#7c6af7)':'var(--border,#2a2d3a)') + ';background:' + (isActive?'rgba(124,106,247,.15)':'transparent') + ';color:' + (isActive?'#a89cf7':'var(--text-muted)') + ';" data-gr-filter="' + escHtml(cid) + '">' + escHtml(label) + '</button>';
      }).join('') +
      '<span style="margin-left:8px;font-size:10px;color:var(--text-muted);">|</span>' +
      '<label style="font-size:10px;color:var(--text-muted);cursor:pointer;user-select:none;">' +
        '<input type="checkbox" id="grShowInternal" style="margin-right:3px;"' + (showInternalIPs ? ' checked' : '') + '>Internal IPs</label>' +
      '<span style="font-size:10px;color:var(--text-muted);">Legend:</span>' +
      '<span style="font-size:10px;padding:1px 6px;border-radius:3px;background:rgba(229,72,72,.2);color:#E54848;border:1px solid rgba(229,72,72,.3);">● External IP</span>' +
      '<span style="font-size:10px;padding:1px 6px;border-radius:3px;background:rgba(74,99,231,.2);color:#8899f7;border:1px solid rgba(74,99,231,.3);">● Internal IP</span>' +
      '<span style="font-size:10px;padding:1px 6px;border-radius:3px;background:rgba(63,168,96,.2);color:#3FA860;border:1px solid rgba(63,168,96,.3);">● User</span>';

    grFilter.querySelectorAll('[data-gr-filter]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        window._grActiveFilter = btn.getAttribute('data-gr-filter');
        renderGraph(state.evidenceRows);
      });
    });
    var grIntCheck = document.getElementById('grShowInternal');
    if (grIntCheck) grIntCheck.addEventListener('change', function() {
      window._grShowInternal = grIntCheck.checked;
      renderGraph(state.evidenceRows);
    });

    // Apply cluster filter to rows
    var filteredEvRows = evRows;
    if (activeGrFilter !== 'all') {
      filteredEvRows = evRows.filter(function(r) { return r.cluster_id === activeGrFilter; });
    }

    var W = canvas.clientWidth || 800;
    var H = Math.max(420, canvas.clientHeight || 500);

    var entityMap = {};
    filteredEvRows.forEach(function (row) {
      var e = row.entity;
      if (!e || e === '-') return;
      var isInternal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(e);
      if (isInternal && !showInternalIPs) return;
      var nt = guessEntityType(e, row);
      // Distinguish internal vs external IPs by nodeType
      if (nt === 'ip') nt = isInternal ? 'ip_internal' : 'ip_external';
      if (!entityMap[e]) {
        entityMap[e] = { id: e, label: e.length > 22 ? e.slice(0, 20) + '…' : e, nodeType: nt, severity: row.severity, count: 0, srcList: [], cluster_id: row.cluster_id, isInternal: isInternal };
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

    var NODE_COLORS = { user: '#3FA860', ip_external: '#E54848', ip_internal: '#4A63E7', ip: '#E54848', resource: '#2DB67C', detection: '#FF8A3C', source: '#708090', other: '#E0C446' };
    var SEV_R = { critical: 10, high: 8, medium: 6, low: 5 };

    var zoom = d3.zoom().scaleExtent([0.25, 3]).on('zoom', function (event) { g.attr('transform', event.transform); });
    var svg = d3.select(canvas).append('svg').attr('width', W).attr('height', H).style('display', 'block').style('border-radius', 'var(--radius-lg)');
    var g = svg.append('g');
    svg.call(zoom);
    _hopGraphState.svg = svg;
    _hopGraphState.zoom = zoom;

    var lgData = [{ l: 'User', c: NODE_COLORS.user }, { l: 'External IP', c: NODE_COLORS.ip_external }, { l: 'Internal IP', c: NODE_COLORS.ip_internal }, { l: 'Resource', c: NODE_COLORS.resource }, { l: 'Source', c: NODE_COLORS.source }];
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

    // ── Cluster filter bar ────────────────────────────────────────────────
    var tlFilter = $('tlClusterFilter');
    if (!tlFilter) {
      tlFilter = document.createElement('div');
      tlFilter.id = 'tlClusterFilter';
      tlFilter.style.cssText = 'display:flex;align-items:center;gap:6px;padding:6px 10px;border-bottom:1px solid var(--border,#2a2d3a);flex-shrink:0;flex-wrap:wrap;';
      canvas.parentNode.insertBefore(tlFilter, canvas);
    }
    var clusterIds = ['all'];
    if (state.clusterMap) Object.keys(state.clusterMap).sort().forEach(function(cid) { clusterIds.push(cid); });
    var activeTlFilter = window._tlActiveFilter || 'all';
    tlFilter.innerHTML = '<span style="font-size:10px;color:var(--text-muted);font-weight:600;">Cluster:</span>' +
      clusterIds.map(function(cid) {
        var c = state.clusterMap && state.clusterMap[cid];
        var sev = c ? c.severity : '';
        var label = cid === 'all' ? 'All' : cid + (c ? ' (' + (c.row_refs||[]).length + ')' : '');
        var isActive = cid === activeTlFilter;
        return '<button style="font-size:10px;padding:2px 8px;border-radius:4px;cursor:pointer;border:1px solid ' +
          (isActive ? 'var(--accent,#7c6af7)' : 'var(--border,#2a2d3a)') +
          ';background:' + (isActive ? 'rgba(124,106,247,.15)' : 'transparent') +
          ';color:' + (isActive ? '#a89cf7' : 'var(--text-muted)') + ';" data-tl-filter="' + escHtml(cid) + '">' + escHtml(label) + '</button>';
      }).join('');
    tlFilter.querySelectorAll('[data-tl-filter]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        window._tlActiveFilter = btn.getAttribute('data-tl-filter');
        renderTimeline(state.evidenceRows);
      });
    });

    // Apply cluster filter
    var filteredEvRows = evRows;
    if (activeTlFilter !== 'all') {
      filteredEvRows = evRows.filter(function(r) { return r.cluster_id === activeTlFilter; });
    }

    var rowsWithTime = filteredEvRows.map(function (row) {
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
        var ttip = escHtml((entity || '?') + ' — ' + (r.row.description || r.row.analyst_notes || r.row.severity) + ' (' + fmtTs(r.ts) + ')');
        if (r.row.type === 'correlated') parts.push('<circle cx="' + cx + '" cy="' + cy + '" r="' + (rad + 4) + '" fill="none" stroke="' + color + '" stroke-width="1.5" opacity="0.4"/>');
        parts.push('<circle cx="' + cx + '" cy="' + cy + '" r="' + rad + '" fill="' + color + '" opacity="0.85" style="cursor:pointer;" data-row-idx="' + r.row.row_index + '"><title>' + ttip + '</title></circle>');
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

    // ── Dot click-through → showDetail ───────────────────────────────────
    canvas.querySelectorAll('circle[data-row-idx]').forEach(function(circle) {
      circle.addEventListener('click', function(e) {
        var idx = parseInt(circle.getAttribute('data-row-idx'), 10);
        var evRow = (state.evidenceRows || []).find(function(r) { return r.row_index === idx; });
        if (evRow) { switchTab('evidence'); showDetail(evRow); }
      });
    });

    // ── Deterministic cluster story panel ────────────────────────────────
    var storyContainer = $('tlStoryPanel');
    if (!storyContainer) {
      storyContainer = document.createElement('div');
      storyContainer.id = 'tlStoryPanel';
      storyContainer.style.cssText = 'padding:10px 14px;border-top:1px solid var(--border,#2a2d3a);max-height:260px;overflow-y:auto;';
      canvas.parentNode.appendChild(storyContainer);
    }
    storyContainer.innerHTML = _buildTimelineStory(activeTlFilter, rowsWithTime);

    try {
      window._lastTimelineRender = {
        rows: (rowsWithTime || []).length,
        sources: Object.keys(srcGroups || {}),
        renderedAt: Date.now(),
        hasTimestamps: (rowsWithTime || []).length > 0,
      };
    } catch (_e) {}
  }

  // ── Deterministic cluster story builder ──────────────────────────────────
  function _buildTimelineStory(clusterId, rowsWithTime) {
    var rows = rowsWithTime.slice().sort(function(a,b) { return a.ts - b.ts; });
    if (!rows.length) return '';

    var title = clusterId === 'all' ? 'Campaign Timeline' : 'Cluster Story — ' + clusterId;
    var minTs = rows[0].ts;

    // Group into phases by time delta buckets
    var phases = [];
    var cur = null;
    rows.forEach(function(r) {
      var dayN = Math.floor((r.ts - minTs) / 86400000);
      var ev = r.row;
      var desc = ev.description || ev.analyst_notes || ev.llm_summary || ev.eventName || ev.operationName || ev.activityDisplayName || '';
      var entity = ev.entity || '-';
      var mitre = ev.mitre || ev.mitre_technique || ev.technique_id || '';
      var sev = ev.severity || 'low';
      var cid = ev.cluster_id || (clusterId !== 'all' ? clusterId : null);

      if (!cur || cur.dayN !== dayN) {
        cur = { dayN: dayN, events: [], mitre: new Set(), entities: new Set(), maxSev: sev };
        phases.push(cur);
      }
      cur.events.push({ desc: desc, entity: entity, mitre: mitre, sev: sev, idx: ev.row_index, cid: cid });
      if (mitre) mitre.split(',').forEach(function(m) { cur.mitre.add(m.trim()); });
      if (entity && entity !== '-') cur.entities.add(entity);
      var sevOrder = {critical:4,high:3,medium:2,low:1};
      if ((sevOrder[sev]||0) > (sevOrder[cur.maxSev]||0)) cur.maxSev = sev;
    });

    var SEV_COLORS_MAP = {critical:'#E54848',high:'#ffaa55',medium:'#e0c446',low:'#7a7f8e'};
    var html = '<div style="font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted,#7a7f8e);margin-bottom:8px;">' + escHtml(title) + ' <span style="font-weight:400;">(' + rows.length + ' events · ' + phases.length + ' day' + (phases.length!==1?'s':'') + ' · evidence-grounded)</span></div>';
    html += '<div style="display:flex;flex-direction:column;gap:4px;">';

    phases.forEach(function(ph) {
      var topEv = ph.events[0];
      var moreCount = ph.events.length - 1;
      var mitreList = Array.from(ph.mitre).slice(0,3).join(', ');
      var entityList = Array.from(ph.entities).slice(0,2).join(', ');
      var sevColor = SEV_COLORS_MAP[ph.maxSev] || '#7a7f8e';
      var rowRef = topEv.idx !== undefined ? 'row[' + topEv.idx + ']' : '';

      html += '<div style="display:flex;gap:8px;align-items:flex-start;padding:5px 8px;border-radius:4px;background:rgba(255,255,255,.025);border-left:3px solid ' + sevColor + ';">';
      html += '<span style="font-size:10px;font-weight:700;color:' + sevColor + ';min-width:44px;flex-shrink:0;">Day ' + (ph.dayN + 1) + '</span>';
      html += '<div style="flex:1;min-width:0;">';
      html += '<div style="font-size:11px;color:var(--text,#e8ebf0);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="' + escHtml(topEv.desc) + '">' + escHtml(truncate(topEv.desc || topEv.entity, 70)) + '</div>';
      if (entityList) html += '<div style="font-size:10px;color:var(--text-muted);margin-top:1px;">Entities: <b style="color:var(--text,#e8ebf0);">' + escHtml(entityList) + '</b>' + (moreCount > 0 ? ' +' + moreCount + ' event' + (moreCount>1?'s':'') : '') + '</div>';
      if (mitreList) html += '<div style="font-size:10px;color:#e0c446;margin-top:1px;font-family:monospace;">' + escHtml(mitreList) + '</div>';
      html += '</div>';
      if (rowRef) html += '<span style="font-size:10px;color:var(--accent,#7c6af7);flex-shrink:0;cursor:pointer;" onclick="var r=(state.evidenceRows||[]).find(function(x){return x.row_index===' + topEv.idx + '});if(r){switchTab(\'evidence\');showDetail(r);}">' + escHtml(rowRef) + '</span>';
      html += '</div>';
    });

    html += '</div>';
    return html;
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
      var eta = attempt < 60 ? 'usually 2-4 min for large datasets' : attempt < 180 ? 'still running — LLM generating…' : 'taking longer than expected — model may be slow';
      if (pollMsg) pollMsg.textContent = 'Building composite narrative… ' + attempt + 's elapsed · ' + eta;
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
    window._invPollTimer = _investigateState._pollTimer;
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
    { value: 'qwen3:14b',            label: 'Qwen 3 14B  ★ (default · deep reasoning)' },
    { value: 'qwen2.5:14b',          label: 'Qwen 2.5 14B (legacy fast)' },
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

  // ══════════════════════════════════════════════════════════════════
  // CLUSTER DRAWER — persona-tabs, confirm/deny, EXPAND, threat models
  // ══════════════════════════════════════════════════════════════════

  var PERSONA_TABS = [
    { key: 'soc_analyst',   label: 'SOC Analyst' },
    { key: 'threat_hunter', label: 'Threat Hunter' },
    { key: 'ciso',          label: 'CISO' },
    { key: 'forensics',     label: 'Forensics' },
    { key: 'compliance',    label: 'Compliance' },
    { key: 'mssp',          label: 'MSSP' },
    { key: 'threat_model',  label: 'Threat Model', icon: '\u29C1' },
    { key: 'report',        label: '\uD83D\uDCCB Report' },
  ];

  // Per-cluster drawer state
  // _cd[cid] = { persona, width, pdata:{p:{status,data}}, tasks:{key:bool|null}, expands:{key:{status,qs}}, tmodels:{type:{status,data}} }
  var _cd = {};

  function _cdState(cid) {
    if (!_cd[cid]) {
      var pdata = {};
      PERSONA_TABS.forEach(function (t) { pdata[t.key] = { status: 'idle', data: null }; });
      _cd[cid] = { persona: 'soc_analyst', width: 640, pdata: pdata, tasks: {}, taskDecisions: {}, expands: {},
                   tmodels: { pasta: {status:'idle',data:null}, diamond: {status:'idle',data:null}, maestro: {status:'idle',data:null}, stride: {status:'idle',data:null}, dread: {status:'idle',data:null} },
                   dreadOverrides: {}, activeExpand: null, notes: {},
                   complianceMap: {}, riskRegister: {}, crqOverrides: {}, gapsOnly: {} };
    }
    return _cd[cid];
  }

  function _cdTaskKey(cid, persona, taskIdx, subIdx) {
    return cid + ':' + persona + ':' + taskIdx + (subIdx != null ? ':' + subIdx : '');
  }

  window._cdClose = function () {
    var d = $('clusterDrawer');
    if (d) { d.classList.remove('open'); d.style.display = 'none'; }
  };

  window._cdPopOut = function () {
    var cid = state.activeClusterId;
    if (!cid) return;
    var aid = state.assessmentId;
    var url = '/static/investigate.html?cluster=' + encodeURIComponent(cid) + '&assessment=' + encodeURIComponent(aid || '');
    window.open(url, 'cluster_' + cid, 'width=960,height=900,resizable=yes,scrollbars=yes');
  };

  function _cdModelSel() {
    var sel = $('cdModelSel');
    if (!sel) return 'qwen3:14b';
    return sel.value || 'qwen3:14b';
  }

  function _cdPopulateModelSel() {
    var sel = $('cdModelSel');
    if (!sel) return;
    sel.innerHTML = '';
    CLUSTER_MODELS.forEach(function (m) {
      var opt = document.createElement('option');
      opt.value = m.value;
      opt.textContent = m.label;
      if (m.disabled) opt.disabled = true;
      sel.appendChild(opt);
    });
  }

  // Drag-resize from left edge
  (function () {
    var dragging = false, startX = 0, startW = 0;
    function onMouseDown(e) {
      dragging = true; startX = e.clientX;
      var panel = $('cdPanel');
      startW = panel ? panel.offsetWidth : 640;
      document.body.style.userSelect = 'none';
      document.body.style.cursor = 'col-resize';
    }
    function onMouseMove(e) {
      if (!dragging) return;
      var dx = startX - e.clientX;
      var newW = Math.max(360, Math.min(window.innerWidth * 0.9, startW + dx));
      var panel = $('cdPanel');
      if (panel) { panel.style.setProperty('--cd-width', newW + 'px'); panel.style.width = newW + 'px'; }
      var cid = state.activeClusterId;
      if (cid && _cd[cid]) {
        _cd[cid].width = newW;
        _cdUpdateLayout(cid, _cd[cid].persona);
      }
    }
    function onMouseUp() {
      if (!dragging) return;
      dragging = false;
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    }
    document.addEventListener('DOMContentLoaded', function () {
      var h = $('cdResizeHandle');
      if (h) {
        h.addEventListener('mousedown', onMouseDown);
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
      }
    });
  })();

  window.openClusterDetail = function (clusterId) {
    state.activeClusterId = String(clusterId);
    var drawer = $('clusterDrawer');
    if (!drawer) return;
    var cs = _cdState(clusterId);
    var c  = state.clusterMap[clusterId] || {};
    var sev = (c.severity || 'medium').toLowerCase();
    var label = c.label || c.summary || ('Cluster ' + clusterId);
    var rows  = c.row_count || (c.row_refs || []).length || 0;
    var entities = (c.entities || c.top_entities || []).slice(0, 5);

    $('clusterDrawerTitle').textContent = label;
    $('clusterDrawerMeta').innerHTML =
      '<span class="sev-pill sev-pill--' + sev + '">' + sev.toUpperCase() + '</span> ' +
      rows + ' rows' +
      (entities.length ? ' · ' + entities.map(function (e) {
        return '<span class="entity-chip">' + escHtml(String(e)) + '</span>';
      }).join(' ') : '');

    // Restore panel width from state
    var panel = $('cdPanel');
    if (panel && cs.width) panel.style.width = cs.width + 'px';

    _cdPopulateModelSel();
    _cdBuildTabs(clusterId);

    drawer.style.display = '';
    drawer.classList.add('open');

    // Lazy tier1_prefill: if cluster has no incident_name yet, request it on-demand
    if (!c.tier1_prefill || !c.tier1_prefill.incident_name) {
      _cdFetchTier1Prefill(clusterId);
    }

    // Auto-load SOC Analyst tab on open if idle
    if (cs.pdata.soc_analyst.status === 'idle') {
      _cdLoadPersona(clusterId, 'soc_analyst');
    } else {
      _cdShowPane(clusterId, cs.persona || 'soc_analyst');
    }
  };

  function _cdFetchTier1Prefill(clusterId) {
    if (!state.assessmentId) return;
    var base = (state.apiBase || '').replace(/\/$/, '');
    var url = base + '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
              '/clusters/' + encodeURIComponent(clusterId) + '/tier1-summary';
    var headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    var apiKey = localStorage.getItem('apiKey');
    if (apiKey) headers['X-API-Key'] = apiKey;
    var model = _cdModelSel();

    fetch(url, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ model: model }),
    })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        var c = state.clusterMap[clusterId];
        if (!c) return;
        c.tier1_prefill = data.tier1_prefill || data;
        var name = (c.tier1_prefill || {}).incident_name;
        if (name) {
          c.label = name;
          // Update drawer title if still open on this cluster
          if (state.activeClusterId === String(clusterId)) {
            var titleEl = document.getElementById('clusterDrawerTitle');
            if (titleEl) titleEl.textContent = name;
          }
          renderClusterList();
        }
      })
      .catch(function () { /* silent — prefill is best-effort */ });
  }

  window.openTier2Canvas = function (clusterId) {
    if (!state.assessmentId) { toast('Run Analyze first', 'warn'); return; }
    var url = '/static/tier2_investigation.html' +
              '?assessment_id=' + encodeURIComponent(state.assessmentId) +
              '&cluster_id=' + encodeURIComponent(clusterId) +
              '&persona=' + encodeURIComponent(state.currentPersona || 'soc_analyst') +
              '&llm_model=' + encodeURIComponent(_cdModelSel());
    window.open(url, '_blank', 'width=1400,height=900');
  };

  function _cdBuildTabs(cid) {
    var tabsEl = $('cdPersonaTabs');
    if (!tabsEl) return;
    tabsEl.innerHTML = '';
    PERSONA_TABS.forEach(function (t) {
      var btn = document.createElement('button');
      btn.className = 'cd-ptab';
      btn.setAttribute('role', 'tab');
      btn.setAttribute('data-persona', t.key);
      btn.textContent = t.label;
      btn.onclick = function () { _cdSwitchPersona(cid, t.key); };
      tabsEl.appendChild(btn);
    });
    _cdMarkActiveTab(cid);
  }

  function _cdMarkActiveTab(cid) {
    var cs = _cdState(cid);
    document.querySelectorAll('#cdPersonaTabs .cd-ptab').forEach(function (btn) {
      var p = btn.getAttribute('data-persona');
      btn.classList.toggle('active', p === cs.persona);
      // Mark done if all tasks answered
      if (p !== 'report' && _cdAllTasksDone(cid, p)) btn.classList.add('done');
    });
  }

  function _cdAllTasksDone(cid, persona) {
    var cs = _cdState(cid);
    var pd = cs.pdata[persona];
    if (!pd || pd.status !== 'loaded' || !pd.data) return false;
    var steps = pd.data.persona_steps || [];
    if (!steps.length) return false;
    return steps.every(function (s, ti) {
      return cs.tasks[_cdTaskKey(cid, persona, ti, null)] != null;
    });
  }

  function _cdSwitchPersona(cid, persona) {
    var cs = _cdState(cid);
    cs.persona = persona;
    _cdMarkActiveTab(cid);
    if (persona === 'report') {
      _cdShowReportPane(cid);
      return;
    }
    if (persona === 'threat_model') {
      _cdShowThreatModelTab(cid);
      return;
    }
    var pd = cs.pdata[persona];
    if (!pd) return;
    if (pd.status === 'idle') {
      _cdLoadPersona(cid, persona);
    } else {
      _cdShowPane(cid, persona);
    }
  }

  function _cdShowPane(cid, persona) {
    var bodyEl = $('cdBody');
    if (!bodyEl) return;
    document.querySelectorAll('#cdBody .cd-pane').forEach(function (p) {
      p.classList.remove('active');
    });
    var paneEl = document.getElementById('cdPane_' + cid + '_' + persona);
    if (paneEl) {
      paneEl.classList.add('active');
    } else {
      _cdRenderPane(cid, persona);
    }
  }

  async function _cdLoadPersona(cid, persona) {
    var cs = _cdState(cid);
    var pd = cs.pdata[persona];
    pd.status = 'loading';
    _cdShowPane(cid, persona);
    var aid = state.assessmentId;
    var model = _cdModelSel();
    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(aid) +
        '/clusters/' + encodeURIComponent(cid) +
        '/tier2/llm-summary?model=' + encodeURIComponent(model),
        { headers: Object.assign({ 'x-persona': persona }, authHeaders()),
          signal: AbortSignal.timeout(180000) }
      );
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      pd.data = await resp.json();
      pd.status = 'loaded';
    } catch (err) {
      pd.status = 'error';
      pd.error = err.message;
    }
    _cdRenderPane(cid, persona);
    _cdMarkActiveTab(cid);
  }

  function _cdRenderPane(cid, persona) {
    var bodyEl = $('cdBody');
    if (!bodyEl) return;
    var paneId = 'cdPane_' + cid + '_' + persona;
    var existing = document.getElementById(paneId);
    if (existing) existing.remove();

    // Deactivate all other panes
    document.querySelectorAll('#cdBody .cd-pane').forEach(function (p) { p.classList.remove('active'); });

    var pane = document.createElement('div');
    pane.className = 'cd-pane active';
    pane.id = paneId;

    var cs = _cdState(cid);
    var pd = cs.pdata[persona];

    // 3-column layout wrapper
    var layout = document.createElement('div');
    layout.className = 'cd-col-layout';
    layout.id = 'cdLayout_' + cid + '_' + persona;
    layout.setAttribute('data-cols', '1');

    // ── Column 1: Summary ─────────────────────────────────────────────
    var col1 = document.createElement('div');
    col1.className = 'cd-col cd-col--summary';
    col1.id = 'cdColSummary_' + cid + '_' + persona;
    if (pd.status === 'loading' || pd.status === 'idle') {
      col1.innerHTML = '<div class="cd-loading"><div class="cd-spinner"></div>Generating ' + escHtml(persona.replace(/_/g,' ')) + ' briefing… (30-120s)</div>';
    } else if (pd.status === 'error') {
      col1.innerHTML = '<div class="cd-error">Failed: ' + escHtml(pd.error || 'unknown error') +
        '<br><button class="btn-secondary" style="margin-top:8px;font-size:11px;" onclick="window._cdRetry(\'' + escHtml(cid) + '\',\'' + escHtml(persona) + '\')">Retry</button></div>';
    } else if (pd.data) {
      col1.innerHTML = _cdBuildPersonaHTML(cid, persona, pd.data, cs);
    }

    // ── Column 2: EXPAND investigate ──────────────────────────────────
    var col2 = document.createElement('div');
    col2.className = 'cd-col cd-col--expand';
    col2.id = 'cdColExpand_' + cid + '_' + persona;
    col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs);

    layout.appendChild(col1);
    layout.appendChild(col2);
    pane.appendChild(layout);
    bodyEl.appendChild(pane);

    // Wire confirm/deny buttons
    if (pd.status === 'loaded') _cdWireButtons(col1, cid, persona);

    // Activate columns based on current state + panel width
    _cdUpdateLayout(cid, persona);
  }

  window._cdRetry = function (cid, persona) {
    var cs = _cdState(cid);
    cs.pdata[persona].status = 'idle';
    _cdLoadPersona(cid, persona);
  };

  function _cdBuildPersonaHTML(cid, persona, data, cs) {
    var sections = data.sections || {};
    var steps    = data.persona_steps || [];
    var model    = data.model || _cdModelSel();
    var fallback = data.fallback_generated;
    var rawText  = data.raw_text || '';
    var aid      = data.assessment_id || state.assessmentId || '';

    var verdict  = sections.verdict_line || sections.is_this_real || '';
    var vCls = 'unc';
    var vu = verdict.toUpperCase();
    if (vu.indexOf('LIKELY REAL') !== -1 || vu.indexOf('CONFIRMED') !== -1 || vu.indexOf('MALICIOUS') !== -1) vCls = 'real';
    else if (vu.indexOf('FALSE POSITIVE') !== -1 || vu.indexOf('BENIGN') !== -1) vCls = 'fp';
    var vLabel = vCls === 'real' ? 'LIKELY REAL' : vCls === 'fp' ? 'LIKELY FALSE POSITIVE' : 'UNCERTAIN';
    var vReason = verdict.replace(/^(LIKELY REAL|FALSE POSITIVE|LIKELY FALSE POSITIVE|UN?CERTAIN|CONFIRMED)[\s:—-]*/i,'').trim().slice(0,280);

    var h = '';
    // Meta
    h += '<div style="font-size:10px;color:var(--text-muted,#7a7f8e);margin-bottom:12px;">';
    h += (fallback ? '<span class="badge badge--warn" style="margin-right:4px;">fallback</span>' : '');
    h += escHtml(data.persona_label || persona.replace('_',' ')) + ' · via ' + escHtml(model);
    h += '</div>';

    // Verdict — P0-4: remove overflow hidden so text wraps fully
    if (vLabel) {
      h += '<div class="cd-verdict" style="flex-wrap:wrap;align-items:flex-start;">';
      h += '<span class="cd-verdict-badge vb--' + vCls + '" style="flex-shrink:0;">' + vLabel + '</span>';
      if (vReason) h += '<span class="cd-verdict-text" style="min-width:100%;flex:0 0 100%;margin-top:5px;">' + escHtml(vReason) + '</span>';
      h += '</div>';
    }

    // P0-3: cap "no direct evidence" occurrences to 1 across what_is_happening
    function _capNDE(text) {
      var count = 0;
      return text.replace(/no direct evidence/gi, function(m) {
        return ++count <= 1 ? m : '[see above]';
      });
    }

    // WHAT IS HAPPENING
    if (sections.what_is_happening) {
      h += '<div class="cd-section"><div class="cd-section__hd">WHAT IS HAPPENING</div>';
      h += '<div class="cd-section__body">' + escHtml(_capNDE(sections.what_is_happening)) + '</div></div>';
    }

    // WHY IT MATTERS
    if (sections.why_it_matters) {
      h += '<div class="cd-section"><div class="cd-section__hd">WHY IT MATTERS</div>';
      h += '<div class="cd-section__body">' + escHtml(sections.why_it_matters) + '</div></div>';
    }

    // TOP ACTIONS
    var hasSteps = steps && steps.length > 0;
    var hasTodo = !!(sections.what_to_do && sections.what_to_do.trim());
    if (hasSteps || hasTodo) {
      h += '<div class="cd-section"><div class="cd-section__hd">TOP ACTIONS</div>';
      if (hasSteps) {
        h += '<div class="cd-actions">';
        steps.forEach(function (s, ti) {
          var cardId = 'cdc_' + escHtml(cid) + '_' + persona + '_' + ti;
          var title  = s.title || s.action || ('Action ' + (ti + 1));
          var prio   = s.priority || '';
          var owner  = s.owner || '';
          var pCls   = (prio === 'P1' || prio === 'Critical' || prio === 'High') ? 'badge--crit' : 'badge--warn';
          var taskDone = cs.tasks[_cdTaskKey(cid, persona, ti, null)];
          var taskCls  = taskDone === true ? 'style="border-color:#3FA860;"' : taskDone === false ? 'style="border-color:#E54848;"' : '';

          h += '<div class="cd-card" ' + taskCls + '>';
          h += '<div class="cd-card__hd" onclick="(function(){var b=document.getElementById(\'' + cardId + '_body\');var ch=document.getElementById(\'' + cardId + '_chev\');if(b){b.classList.toggle(\'open\');if(ch)ch.classList.toggle(\'open\');}})();">';
          h += '<span class="cd-card__title">' + escHtml(title) + '</span>';
          h += '<span class="cd-card__badges">';
          if (owner) h += '<span class="badge" style="font-size:10px;">' + escHtml(owner) + '</span>';
          if (prio)  h += '<span class="badge ' + pCls + '" style="font-size:10px;">' + escHtml(prio) + '</span>';
          h += '</span>';
          h += '<button class="cd-card__expand-btn" onclick="event.stopPropagation();window._cdExpand(\'' + escHtml(cid) + '\',\'' + escHtml(persona) + '\',' + ti + ',\'' + escHtml(title.replace(/'/g, '&#39;')) + '\')">EXPAND</button>';
          h += '<span class="cd-card__chev" id="' + cardId + '_chev">▼</span>';
          h += '</div>'; // hd

          h += '<div class="cd-card__body" id="' + cardId + '_body">';
          // Subtasks
          if (s.subtasks && s.subtasks.length) {
            h += '<ul class="cd-subtasks">';
            s.subtasks.forEach(function (sub, si) {
              var label = (sub && typeof sub === 'object') ? (sub.label || '') : String(sub);
              var refs  = (sub && typeof sub === 'object' && sub.evidence_refs && sub.evidence_refs.length)
                ? 'rows: ' + sub.evidence_refs.join(',') : '';
              var subKey = _cdTaskKey(cid, persona, ti, si);
              var subDone = cs.tasks[subKey];
              h += '<li class="cd-subtask">';
              h += '<span class="cd-subtask__text">' + escHtml(label) + '</span>';
              if (refs) h += '<span class="cd-subtask__ref">' + escHtml(refs) + '</span>';
              h += '<span class="cd-subtask__btns">';
              h += '<button class="cd-confirm-btn' + (subDone === true ? ' active' : '') + '" data-ck="' + escHtml(subKey) + '" data-val="true">✓</button>';
              h += '<button class="cd-deny-btn'    + (subDone === false? ' active' : '') + '" data-ck="' + escHtml(subKey) + '" data-val="false">✗</button>';
              h += '</span></li>';
            });
            h += '</ul>';
          }
          // Task-level confirm/deny
          h += '<div style="display:flex;align-items:center;gap:6px;margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,255,255,.06);">';
          h += '<span style="font-size:10px;color:var(--text-muted,#7a7f8e);flex:1;">Task verdict:</span>';
          var tKey = _cdTaskKey(cid, persona, ti, null);
          h += '<button class="cd-confirm-btn' + (taskDone === true ? ' active' : '') + '" data-ck="' + escHtml(tKey) + '" data-val="true">✓ Confirm</button>';
          h += '<button class="cd-deny-btn'    + (taskDone === false? ' active' : '') + '" data-ck="' + escHtml(tKey) + '" data-val="false">✗ Deny</button>';
          h += '</div>';
          // EXPAND results placeholder
          h += '<div id="' + cardId + '_expand"></div>';
          h += '</div>'; // body
          h += '</div>'; // card
        });
        h += '</div>'; // cd-actions
      } else {
        h += '<div class="cd-section__body">' + escHtml(sections.what_to_do) + '</div>';
      }
      h += '</div>'; // cd-section
    }

    // INVESTIGATE NEXT
    if (sections.investigate_next) {
      h += '<div class="cd-section"><div class="cd-section__hd">INVESTIGATE NEXT</div>';
      h += '<div class="cd-section__body">' + escHtml(sections.investigate_next) + '</div></div>';
    }

    // ANSWER TO SHARPEN ANALYSIS
    var pq = sections.persona_questions || {};
    var qText = (typeof pq === 'object' && !Array.isArray(pq))
      ? (pq[persona] || pq.soc_analyst || Object.values(pq)[0] || '') : String(pq || '');
    if (qText) {
      var qaId = 'cdQA_' + escHtml(cid) + '_' + persona;
      h += '<div class="cd-section"><div class="cd-section__hd">ANSWER TO SHARPEN ANALYSIS</div>';
      h += '<div style="font-size:11px;color:var(--text-muted,#7a7f8e);margin-bottom:5px;">' + escHtml(qText) + '</div>';
      h += '<textarea id="' + qaId + '" class="cd-sharpen-input" placeholder="Your answer (optional)…" rows="2"></textarea>';
      h += '</div>';
    }

    // Raw output (collapsed)
    if (rawText && rawText.length > 30) {
      h += '<details class="cd-raw-details"><summary>Raw LLM output (' + rawText.length + ' chars)</summary>';
      h += '<pre>' + escHtml(rawText.slice(0, 1500)) + (rawText.length > 1500 ? '\n…(truncated)' : '') + '</pre>';
      h += '</details>';
    }

    return h;
  }

  // ── Column 2: EXPAND investigation ────────────────────────────────────────

  function _cdFmtLag(seconds) {
    if (seconds == null || seconds < 0) return '';
    if (seconds < 60)   return seconds + 's';
    if (seconds < 3600) return Math.round(seconds / 60) + 'm';
    if (seconds < 86400) return Math.round(seconds / 3600) + 'h';
    return Math.round(seconds / 86400) + 'd';
  }

  function _cdFmtDelta(delta_s) {
    if (delta_s == null) return '';
    var abs = Math.abs(delta_s);
    var sign = delta_s >= 0 ? '+' : '-';
    return sign + _cdFmtLag(abs);
  }

  function _cdShortTs(ts) {
    if (!ts) return '—';
    // Try to show just date+time without timezone clutter
    var m = String(ts).match(/(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
    if (m) return m[1] + ' ' + m[2];
    return String(ts).slice(0, 16);
  }

  function _cdBuildExpandColHTML(cid, persona, cs) {
    var ae = cs.activeExpand;
    var h = '<div class="cd-col-hd">';
    h += '<span class="cd-col-title">' + (ae ? escHtml('Investigate: ' + (ae.stepTitle || '')) : 'Investigation') + '</span>';
    if (ae) {
      h += '<button class="cd-btn-icon" onclick="window._cdRegenExpand(\'' + escHtml(cid) + '\',\'' + escHtml(persona) + '\')" title="Regenerate questions" style="font-size:11px;">↺</button>';
      h += '<button class="cd-btn-icon" onclick="window._cdCloseExpand(\'' + escHtml(cid) + '\',\'' + escHtml(persona) + '\')" title="Close column">✕</button>';
    }
    h += '</div>';

    if (!ae) {
      h += '<div class="cd-placeholder">Click <strong>EXPAND</strong> on any task card<br>to open investigation Q&amp;A here.</div>';
      return h;
    }

    // ── Evidence rows (bitemporal table) — P0-5: sort by severity DESC ────────
    var evidence = (ae.rowEvidence || []).slice().sort(function(a, b) {
      var sRank = {critical:4,crit:4,high:3,medium:2,med:2,low:1};
      var ra = sRank[(a.severity||'').toLowerCase()] || 0;
      var rb = sRank[(b.severity||'').toLowerCase()] || 0;
      if (rb !== ra) return rb - ra;
      // secondary: risk_score if present
      return (b.risk_score || 0) - (a.risk_score || 0);
    });
    if (evidence.length) {
      h += '<div class="cd-section">';
      h += '<div class="cd-section__hd">EVIDENCE ROWS <span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:9px;color:var(--text-muted);">sorted by event time · bitemporal</span></div>';
      h += '<div class="cd-bt-table">';
      h += '<div class="cd-bt-thead">';
      h += '<span class="cd-bt-col cd-bt-col--row">Row</span>';
      h += '<span class="cd-bt-col cd-bt-col--sev">Sev</span>';
      h += '<span class="cd-bt-col cd-bt-col--vt">Event Time <span class="cd-bt-hint">(valid)</span></span>';
      h += '<span class="cd-bt-col cd-bt-col--tt">Ingested <span class="cd-bt-hint">(txn)</span></span>';
      h += '<span class="cd-bt-col cd-bt-col--lag">Lag</span>';
      h += '<span class="cd-bt-col cd-bt-col--Δt">Δt</span>';
      h += '<span class="cd-bt-col cd-bt-col--desc">Event / Entity</span>';
      h += '</div>';
      evidence.forEach(function (r) {
        var sevCls = (r.severity === 'critical' || r.severity === 'crit') ? 'badge--crit' :
                     r.severity === 'high' ? 'badge--warn' :
                     r.severity === 'medium' ? 'badge--ok' : '';
        var desc = r.description || r.hostname || r.user || r.src_ip || '—';
        var meta = [];
        if (r.user)      meta.push('👤 ' + r.user);
        if (r.hostname)  meta.push('🖥 ' + r.hostname);
        if (r.src_ip)    meta.push('🌐 ' + r.src_ip);
        if (r.technique) meta.push('🎯 ' + r.technique);
        h += '<div class="cd-bt-row">';
        h += '<span class="cd-bt-col cd-bt-col--row">' + escHtml(String(r.row)) + '</span>';
        h += '<span class="cd-bt-col cd-bt-col--sev"><span class="badge ' + sevCls + '" style="font-size:9px;">' + escHtml((r.severity||'').slice(0,4).toUpperCase()) + '</span></span>';
        h += '<span class="cd-bt-col cd-bt-col--vt cd-bt-ts">' + escHtml(_cdShortTs(r.valid_time)) + '</span>';
        h += '<span class="cd-bt-col cd-bt-col--tt cd-bt-ts cd-bt-ts--txn">' + escHtml(_cdShortTs(r.transaction_time)) + '</span>';
        h += '<span class="cd-bt-col cd-bt-col--lag cd-bt-delta">' + escHtml(_cdFmtLag(r.observed_lag_s)) + '</span>';
        h += '<span class="cd-bt-col cd-bt-col--Δt cd-bt-delta cd-bt-delta--seq">' + escHtml(_cdFmtDelta(r.delta_s)) + '</span>';
        h += '<span class="cd-bt-col cd-bt-col--desc">';
        h += '<div class="cd-bt-desc">' + escHtml(desc) + '</div>';
        if (meta.length) h += '<div class="cd-bt-meta">' + escHtml(meta.join('  ')) + '</div>';
        h += '</span>';
        h += '</div>';
      });
      h += '</div></div>'; // table + section
    }

    // ── Suggested tools ───────────────────────────────────────────────────────
    var tools = ae.suggestedTools || [];
    if (tools.length) {
      h += '<div class="cd-section"><div class="cd-section__hd">SUGGESTED TOOLS</div>';
      tools.forEach(function (t, ti) {
        var typeLabel = t.type === 'kql' ? 'KQL' : t.type === 'powershell' ? 'PS' : t.type === 'cmd' ? 'CMD' : 'CLI';
        var typeCls   = t.type === 'kql' ? 'cd-tool-badge--kql' : t.type === 'powershell' ? 'cd-tool-badge--ps' : 'cd-tool-badge--cli';
        h += '<div class="cd-tool-row">';
        h += '<span class="cd-tool-badge ' + typeCls + '">' + typeLabel + '</span>';
        h += '<div class="cd-tool-body">';
        h += '<div class="cd-tool-label">' + escHtml(t.label) + '</div>';
        h += '<code class="cd-tool-cmd" id="cdToolCmd_' + cid + '_' + ti + '">' + escHtml(t.cmd) + '</code>';
        h += '</div>';
        h += '<button class="cd-tool-copy" onclick="window._cdCopyTool(\'' + cid + '_' + ti + '\')" title="Copy command">⎘</button>';
        h += '</div>';
      });
      h += '</div>';
    }

    // ── Persona-specific Q&A / Hunt section ──────────────────────────────────
    var expKey = cid + ':' + ae.persona + ':' + ae.taskIdx;
    var expState = cs.expands[expKey];
    h += '<div id="cdExpandQA_' + escHtml(cid) + '_' + escHtml(persona) + '">';
    if (!expState || expState.status === 'loading') {
      var loadMsg = persona === 'threat_hunter' ? 'Building hunt package…' : 'Generating investigation questions…';
      h += '<div class="cd-loading"><div class="cd-spinner"></div>' + loadMsg + '</div>';
    } else if (expState.status === 'loaded') {
      if (persona === 'threat_hunter' && ae.huntData) {
        h += _cdRenderThreatHunterExpand(ae.huntData, cid, persona, ae.taskIdx);
      } else if (persona === 'ciso' || persona === 'executive') {
        h += _cdRenderCISOExpand(expState.questions, cid, persona, ae.taskIdx);
      } else if (persona === 'compliance' || persona === 'audit') {
        h += _cdRenderComplianceExpand(expState.questions, cid, persona, ae.taskIdx);
      } else {
        h += _cdRenderQASection(expState.questions, cid, persona, ae.taskIdx);
      }
    } else {
      h += '<div class="cd-error">Questions unavailable.</div>';
    }
    h += '</div>';

    // ── Analyst notes ─────────────────────────────────────────────────────────
    h += '<div class="cd-section"><div class="cd-section__hd">ANALYST NOTES</div>';
    h += '<textarea class="cd-note-input" id="cdNoteInput_' + escHtml(cid) + '_' + escHtml(persona) + '" placeholder="Add observation, IOC, or finding…" rows="2"></textarea>';
    h += '<button class="cd-expand-trigger" style="margin-top:5px;" onclick="window._cdAddNote(\'' + escHtml(cid) + '\',\'' + escHtml(persona) + '\')">+ Add to Report</button>';
    var noteKey = cid + ':' + persona;
    var notes = cs.notes[noteKey] || [];
    notes.forEach(function (n) {
      h += '<div class="cd-note-item">';
      h += '<span class="cd-note-item__text">' + escHtml(n.text) + '</span>';
      h += '<span class="cd-note-item__ts">' + escHtml(n.ts) + '</span>';
      h += '</div>';
    });
    h += '</div>';
    return h;
  }

  function _cdThCopyBtn(textToCopy) {
    // Returns inline onclick that copies the given string
    var escaped = textToCopy.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
    return "onclick=\"(function(b){navigator.clipboard.writeText('" + escaped + "').then(function(){var t=b.textContent;b.textContent='✓';setTimeout(function(){b.textContent=t},1500)}).catch(function(){})}).call(this)\"";
  }

  function _cdThQueryCopyBtn(elemId) {
    var eid = JSON.stringify(elemId);
    return "onclick=\"(function(){var el=document.getElementById(" + eid + ");if(!el)return;navigator.clipboard.writeText(el.textContent||el.innerText).then(function(){var b=el.closest('.cd-tool-row').querySelector('.cd-tool-copy');if(b){var t=b.textContent;b.textContent='✓';setTimeout(function(){b.textContent=t},1500)}})})()\"";
  }

  function _cdRenderThreatHunterExpand(huntData, cid, persona, taskIdx) {
    var cs = _cdState(cid);
    var h = '';
    var pivots  = huntData.pivots || [];
    var queries = huntData.hunt_queries || [];
    var iocs    = huntData.iocs || [];

    if (!pivots.length && !queries.length && !iocs.length) {
      h += '<div style="font-size:11px;color:var(--text-muted,#7a7f8e);padding:8px 0;">No hunt data generated — try ↺ Regenerate.</div>';
      return h;
    }

    // ── PIVOT OPPORTUNITIES ───────────────────────────────────────────────────
    if (pivots.length) {
      h += '<div class="cd-section"><div class="cd-section__hd">PIVOT OPPORTUNITIES</div>';
      h += '<div class="cd-th-pivot-list">';
      pivots.forEach(function (p, pi) {
        var ck  = _cdTaskKey(cid, persona, taskIdx, 'pivot' + pi);
        var dec = cs.tasks[ck];
        var dt  = cs.taskDecisions[ck];
        h += '<div class="cd-th-pivot-card">';
        // Header row: entity + arrow + action + copy
        h += '<div class="cd-th-pivot-row">';
        h += '<span class="cd-th-pivot-entity">' + escHtml(p.entity) + '</span>';
        if (p.action) h += '<span class="cd-th-pivot-arrow">→</span><span class="cd-th-pivot-action">' + escHtml(p.action) + '</span>';
        h += '<button class="cd-tool-copy" ' + _cdThCopyBtn(p.entity) + ' title="Copy entity" style="margin-left:auto;flex-shrink:0;">⎘</button>';
        h += '</div>';
        if (p.row_refs) h += '<div class="cd-th-pivot-ref">rows: ' + escHtml(p.row_refs) + '</div>';
        // Confirm / deny
        h += '<div class="cd-th-verdict-row">';
        h += '<span class="cd-th-verdict-label">Pivot verified?</span>';
        h += '<button class="cd-confirm-btn' + (dec===true?' active':'') + '" data-ck="' + escHtml(ck) + '" data-val="true">✓ Confirmed</button>';
        h += '<button class="cd-deny-btn'    + (dec===false?' active':'') + '" data-ck="' + escHtml(ck) + '" data-val="false">✗ Not found</button>';
        h += '<span class="cd-dec-ts" data-dec="' + escHtml(ck) + '">' + (dt ? escHtml(dt.ts) : '') + '</span>';
        h += '</div>';
        h += '</div>'; // pivot-card
      });
      h += '</div></div>';
    }

    // ── HUNTING QUERIES ───────────────────────────────────────────────────────
    if (queries.length) {
      h += '<div class="cd-section"><div class="cd-section__hd">HUNTING QUERIES</div>';
      queries.forEach(function (q, qi) {
        var ck  = _cdTaskKey(cid, persona, taskIdx, 'hunt' + qi);
        var dec = cs.tasks[ck];
        var dt  = cs.taskDecisions[ck];
        var typeLabel = q.type === 'kql' ? 'KQL' : q.type === 'powershell' ? 'PS' : q.type === 'splunk' ? 'SPL' : q.type === 'grep' ? 'GREP' : (q.type || 'CLI').toUpperCase();
        var typeCls   = q.type === 'kql' ? 'cd-tool-badge--kql' : q.type === 'powershell' ? 'cd-tool-badge--ps' : 'cd-tool-badge--cli';
        var qid = 'cdHuntQ_' + cid + '_' + persona + '_' + taskIdx + '_' + qi;
        h += '<div class="cd-th-query-card">';
        h += '<div class="cd-tool-row">';
        h += '<span class="cd-tool-badge ' + typeCls + '">' + typeLabel + '</span>';
        h += '<div class="cd-tool-body">';
        h += '<div class="cd-tool-label">' + escHtml(q.label) + '</div>';
        h += '<code class="cd-tool-cmd" id="' + escHtml(qid) + '">' + escHtml(q.query) + '</code>';
        if (q.row_refs) h += '<div class="cd-th-pivot-ref" style="margin-top:3px;">rows: ' + escHtml(q.row_refs) + '</div>';
        h += '</div>';
        h += '<button class="cd-tool-copy" ' + _cdThQueryCopyBtn(qid) + ' title="Copy query">⎘</button>';
        h += '</div>';
        // Confirm / deny
        h += '<div class="cd-th-verdict-row">';
        h += '<span class="cd-th-verdict-label">Ran query?</span>';
        h += '<button class="cd-confirm-btn' + (dec===true?' active':'') + '" data-ck="' + escHtml(ck) + '" data-val="true">✓ Ran / Found IOCs</button>';
        h += '<button class="cd-deny-btn'    + (dec===false?' active':'') + '" data-ck="' + escHtml(ck) + '" data-val="false">✗ Ran / Nothing</button>';
        h += '<span class="cd-dec-ts" data-dec="' + escHtml(ck) + '">' + (dt ? escHtml(dt.ts) : '') + '</span>';
        h += '</div>';
        h += '</div>'; // query-card
      });
      h += '</div>';
    }

    // ── IOC EXPANSION ─────────────────────────────────────────────────────────
    if (iocs.length) {
      h += '<div class="cd-section"><div class="cd-section__hd">IOC EXPANSION</div>';
      h += '<div class="cd-th-ioc-list">';
      iocs.forEach(function (ioc, ii) {
        var ck  = _cdTaskKey(cid, persona, taskIdx, 'ioc' + ii);
        var dec = cs.tasks[ck];
        var dt  = cs.taskDecisions[ck];
        var confCls = ioc.confidence === 'HIGH' ? 'cd-th-conf--high' :
                      ioc.confidence === 'MEDIUM' ? 'cd-th-conf--med' : 'cd-th-conf--low';
        h += '<div class="cd-th-ioc-card">';
        h += '<div class="cd-th-ioc-row">';
        h += '<span class="cd-th-ioc-type">' + escHtml((ioc.type || '').toUpperCase()) + '</span>';
        h += '<span class="cd-th-ioc-val">' + escHtml(ioc.value) + '</span>';
        h += '<span class="cd-th-conf ' + confCls + '">' + escHtml(ioc.confidence || '?') + '</span>';
        h += '<button class="cd-tool-copy" ' + _cdThCopyBtn(ioc.value) + ' title="Copy IOC" style="flex-shrink:0;">⎘</button>';
        h += '</div>';
        if (ioc.reason)    h += '<div class="cd-th-ioc-reason">' + escHtml(ioc.reason) + '</div>';
        if (ioc.row_refs)  h += '<div class="cd-th-pivot-ref">rows: ' + escHtml(ioc.row_refs) + '</div>';
        // Confirm / deny
        h += '<div class="cd-th-verdict-row">';
        h += '<span class="cd-th-verdict-label">IOC verdict:</span>';
        h += '<button class="cd-confirm-btn' + (dec===true?' active':'') + '" data-ck="' + escHtml(ck) + '" data-val="true">✓ Confirmed IOC</button>';
        h += '<button class="cd-deny-btn'    + (dec===false?' active':'') + '" data-ck="' + escHtml(ck) + '" data-val="false">✗ FP / Benign</button>';
        h += '<span class="cd-dec-ts" data-dec="' + escHtml(ck) + '">' + (dt ? escHtml(dt.ts) : '') + '</span>';
        h += '</div>';
        h += '</div>'; // ioc-card
      });
      h += '</div></div>';
    }

    return h;
  }

  function _cdRenderQASection(questions, cid, persona, taskIdx) {
    if (!questions || !questions.length) {
      return '<div style="font-size:11px;color:var(--text-muted,#7a7f8e);padding:8px 0;">No questions generated for this step.</div>';
    }
    var cs = _cdState(cid);
    var h = '<div class="cd-section"><div class="cd-section__hd">CONFIRM / DENY</div>';
    questions.forEach(function (q, qi) {
      var qKey  = _cdTaskKey(cid, persona, taskIdx, 'eq' + qi);
      var qDone = cs.tasks[qKey];
      var dec   = cs.taskDecisions[qKey];
      h += '<div class="cd-expand-q">';
      h += '<div class="cd-expand-q__question">' + escHtml(q.question || '') + '</div>';
      var cmd = q.check || q.cli_command || '';
      if (cmd) h += '<div class="cd-expand-q__check">$ ' + escHtml(cmd) + '</div>';
      var ref = q.row_ref || q.row_evidence || '';
      if (ref) h += '<div class="cd-expand-q__ref">Evidence: ' + escHtml(ref) + '</div>';
      h += '<div class="cd-expand-q__btns">';
      h += '<button class="cd-confirm-btn' + (qDone===true?' active':'') + '" data-ck="' + escHtml(qKey) + '" data-val="true">✓ YES</button>';
      h += '<button class="cd-deny-btn'    + (qDone===false?' active':'') + '" data-ck="' + escHtml(qKey) + '" data-val="false">✗ NO</button>';
      if (dec) h += '<span class="cd-dec-ts" data-dec="' + escHtml(qKey) + '">' + escHtml(dec.ts) + '</span>';
      else     h += '<span class="cd-dec-ts" data-dec="' + escHtml(qKey) + '"></span>';
      h += '</div></div>';
    });
    h += '</div>';
    return h;
  }

  // ── CISO / Executive expand — decision gates ──────────────────────────────
  function _cdRenderCISOExpand(questions, cid, persona, taskIdx) {
    var cs = _cdState(cid);
    // Fallback pattern-based urgency/owner for legacy responses without URGENCY:/OWNER: fields
    var GATE_URGENCY = { 'breach': 'NOW', 'legal': 'NOW', 'ir retainer': '4H', 'public statement': '4H', 'isolate': '4H', 'regulat': '24H' };
    var GATE_OWNER   = { 'breach': 'CISO+Legal', 'legal': 'General Counsel', 'ir retainer': 'CISO', 'public statement': 'PR+Legal', 'isolate': 'CISO+IT', 'regulat': 'DPO' };

    function _gateUrgency(q) {
      if (q.urgency) return q.urgency;
      var t = (q.question || '').toLowerCase();
      for (var k in GATE_URGENCY) { if (t.indexOf(k) !== -1) return GATE_URGENCY[k]; }
      return '4H';
    }
    function _gateOwner(q) {
      if (q.owner) return q.owner;
      var t = (q.question || '').toLowerCase();
      for (var k in GATE_OWNER) { if (t.indexOf(k) !== -1) return GATE_OWNER[k]; }
      return 'CISO';
    }

    if (!questions || !questions.length) {
      return '<div style="font-size:11px;color:var(--text-muted);padding:8px 0;">No decision gates available — try ↺ Regenerate.</div>';
    }
    var h = '<div class="cd-section"><div class="cd-section__hd">EXECUTIVE DECISION GATES</div>';
    h += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">Each gate requires CISO/executive sign-off. Record your decision to build the audit trail.</div>';
    questions.forEach(function (q, qi) {
      var qKey  = _cdTaskKey(cid, persona, taskIdx, 'gate' + qi);
      var qDone = cs.tasks[qKey];
      var dec   = cs.taskDecisions[qKey];
      var urgency = _gateUrgency(q);
      var owner   = _gateOwner(q);
      var urgCls  = urgency === 'NOW' ? 'badge--crit' : urgency === '4H' ? 'badge--warn' : '';
      h += '<div class="cd-ciso-gate">';
      h += '<div class="cd-ciso-gate__header">';
      h += '<span class="cd-ciso-gate__label">' + escHtml(q.question || 'Decision required') + '</span>';
      h += '<span class="badge ' + urgCls + '" style="font-size:9px;flex-shrink:0;">' + escHtml(urgency) + '</span>';
      h += '</div>';
      if (owner) h += '<div class="cd-ciso-gate__owner">Owner: ' + escHtml(owner) + '</div>';
      var cmd = q.check || q.cli_command || '';
      if (cmd) h += '<div class="cd-ciso-gate__rationale">' + escHtml(cmd) + '</div>';
      var ref = q.row_ref || q.row_evidence || '';
      if (ref) h += '<div class="cd-expand-q__ref">Evidence: ' + escHtml(ref) + '</div>';
      h += '<div class="cd-ciso-gate__btns">';
      h += '<button class="cd-ciso-btn--escalate' + (qDone===true?' active':'') + '" data-ck="' + escHtml(qKey) + '" data-val="true">\u2B06 ESCALATE</button>';
      h += '<button class="cd-ciso-btn--hold'     + (qDone==='hold'?' active':'') + '" data-ck="' + escHtml(qKey) + '" data-val="hold" style="background:rgba(224,196,70,.1);border-color:rgba(224,196,70,.4);color:#e0c446;">\u25C9 HOLD</button>';
      h += '<button class="cd-deny-btn'            + (qDone===false?' active':'') + '" data-ck="' + escHtml(qKey) + '" data-val="false">\u2717 CLOSE</button>';
      if (dec) h += '<span class="cd-dec-ts">' + escHtml(dec.ts) + '</span>';
      else     h += '<span class="cd-dec-ts" data-dec="' + escHtml(qKey) + '"></span>';
      h += '</div></div>';
    });
    h += '</div>';
    return h;
  }

  // ── Compliance / Audit expand — 2-column ISO 27001 + risk register ───────────
  function _cdRenderComplianceExpand(questions, cid, persona, taskIdx) {
    var cs = _cdState(cid);
    var esc = escHtml;

    // LEFT column: LLM control failures + breach clock + risk register
    var leftH = _cdBuildComplianceLeft(questions, cid, persona, taskIdx, cs);
    // RIGHT column: compliance map sections (ISO/GDPR/PCI/NIST/CRQ)
    var rightH = _cdBuildComplianceRight(cid, cs);

    var h = '<div class="cd-compliance-2col">';
    h += '<div class="cd-compliance-left">' + leftH + '</div>';
    h += '<div class="cd-compliance-right" id="cdCompRight_' + esc(cid) + '">' + rightH + '</div>';
    h += '</div>';

    // Bottom: auditor findings + export
    var noteKey = cid + ':' + persona + ':audit_findings';
    var findings = cs.notes[noteKey] || [];
    h += '<div class="cd-section" style="margin-top:10px;"><div class="cd-section__hd">AUDITOR FINDINGS</div>';
    h += '<textarea class="cd-note-input" id="cdAuditNote_' + esc(cid) + '" placeholder="Enter finding: control ref · gap description · evidence refs…" rows="3"></textarea>';
    h += '<div style="display:flex;gap:5px;margin-top:5px;">';
    h += '<button class="cd-expand-trigger" onclick="window._cdAddAuditFinding(\'' + esc(cid) + '\',\'' + esc(persona) + '\')">+ Record Finding</button>';
    h += '<button class="cd-send-btn cd-send-btn--active" onclick="window._cdExportISOGapReport(\'' + esc(cid) + '\',\'' + esc(persona) + '\')" style="font-size:10px;">⬇ ISO Gap Report</button>';
    h += '<button class="cd-send-btn cd-send-btn--active" onclick="window._cdExportRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\')" style="font-size:10px;">⬇ Risk Register</button>';
    h += '</div>';
    if (findings.length) {
      h += '<div style="margin-top:8px;">';
      findings.forEach(function(f) {
        h += '<div class="cd-note-item"><span class="cd-note-item__text">' + esc(f.text) + '</span><span class="cd-note-item__ts">' + esc(f.ts) + '</span></div>';
      });
      h += '</div>';
    }
    h += '</div>';
    return h;
  }

  function _cdBuildComplianceLeft(questions, cid, persona, taskIdx, cs) {
    var esc = escHtml;
    var h = '';

    // LLM control failures
    if (questions && questions.length) {
      h += '<div class="cd-section"><div class="cd-section__hd">CONTROL GAP ASSESSMENT</div>';
      h += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">LLM-generated. Verify each finding and record auditor judgement.</div>';
      questions.forEach(function (q, qi) {
        var qKey  = _cdTaskKey(cid, persona, taskIdx, 'ctrl' + qi);
        var qDone = cs.tasks[qKey];
        var dec   = cs.taskDecisions[qKey];
        var qText = q.question || '';
        var ctrlRef = q.ctrl_ref || (qText.match(/A\.\d+(\.\d+)?|NIST\s[\w.-]+|PCI DSS \d+\.\d+|GDPR Art\.\s*\d+/i) || [])[0] || '';
        var framework = q.framework || '';
        var status = q.status || '';
        var statusCls = status === 'GAP' ? 'cd-ctrl-status--gap' : status === 'PASSING' ? 'cd-ctrl-status--pass' : 'cd-ctrl-status--unknown';
        h += '<div class="cd-compliance-item">';
        h += '<div class="cd-compliance-item__header">';
        if (ctrlRef) h += '<span class="cd-compliance-ctrl-ref">' + esc(ctrlRef) + '</span>';
        if (framework) h += '<span class="cd-compliance-ctrl-ref" style="background:rgba(74,99,231,.12);border-color:rgba(74,99,231,.3);color:#8899f7;">' + esc(framework) + '</span>';
        if (status) h += '<span class="cd-ctrl-row ' + statusCls + '">' + esc(status) + '</span>';
        h += '<span class="cd-compliance-item__label">' + esc(qText) + '</span>';
        h += '</div>';
        var cmd = q.check || q.cli_command || '';
        if (cmd) h += '<div class="cd-compliance-item__detail">' + esc(cmd) + '</div>';
        var ref = q.row_ref || q.row_evidence || '';
        if (ref) h += '<div class="cd-expand-q__ref">Evidence rows: ' + esc(ref) + '</div>';
        h += '<div class="cd-th-verdict-row">';
        h += '<button class="cd-confirm-btn' + (qDone===true?' active':'') + '" data-ck="' + esc(qKey) + '" data-val="true">✓ Confirmed gap</button>';
        h += '<button class="cd-deny-btn'    + (qDone===false?' active':'') + '" data-ck="' + esc(qKey) + '" data-val="false">✗ Control in place</button>';
        h += '<span class="cd-dec-ts" data-dec="' + esc(qKey) + '">' + (dec ? esc(dec.ts) : '') + '</span>';
        h += '</div>';
        h += '</div>';
      });
      h += '</div>';
    } else {
      h += '<div style="font-size:11px;color:var(--text-muted);padding:8px 0;">No control gap questions available — try ↺ Regenerate.</div>';
    }

    // Breach notification clock
    var cm = cs.complianceMap[cid];
    var earliestRow = cm ? cm.earliest_row : '';
    var art33Status = (cm && cm.gdpr) ? (cm.gdpr.find(function(g){return g.ref==='Art.33';}) || {}).status || 'UNKNOWN' : 'UNKNOWN';
    h += '<div class="cd-section cd-breach-clock">';
    h += '<div class="cd-section__hd">GDPR ART.33 BREACH CLOCK</div>';
    h += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:6px;">72h notification window from point of awareness.</div>';
    h += '<div style="display:flex;gap:8px;align-items:center;">';
    h += '<span class="cd-ctrl-row ' + (art33Status === 'GAP' ? 'cd-ctrl-status--gap' : art33Status === 'PASSING' ? 'cd-ctrl-status--pass' : 'cd-ctrl-status--unknown') + '">' + esc(art33Status) + '</span>';
    if (earliestRow) h += '<span style="font-size:10px;color:var(--text-muted);">Earliest evidence: row[' + esc(String(earliestRow)) + ']</span>';
    h += '</div>';
    h += '<div style="margin-top:6px;font-size:10px;color:var(--text-muted);">Clock started: <input type="datetime-local" id="cdBreachClock_' + esc(cid) + '" style="background:var(--surface,#13161e);border:1px solid var(--border,#2a2d3a);border-radius:3px;color:var(--text,#e8ebf0);font-size:10px;padding:2px 5px;"></div>';
    h += '</div>';

    // Risk register entry
    var rr = cs.riskRegister[cid] || {};
    h += '<div class="cd-section cd-risk-register">';
    h += '<div class="cd-section__hd">RISK REGISTER ENTRY</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:10px;">';
    h += '<div><label style="color:var(--text-muted);">Risk ID</label><br>';
    h += '<input class="cd-sharpen-input" style="padding:3px 6px;" value="' + esc(rr.id || '') + '" oninput="window._cdUpdateRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\',\'id\',this.value)" placeholder="RISK-001"></div>';
    h += '<div><label style="color:var(--text-muted);">Category</label><br>';
    h += '<select class="cd-sharpen-input" style="padding:3px 6px;" onchange="window._cdUpdateRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\',\'category\',this.value)">';
    ['','Access Control','Data Breach','Malware','Insider Threat','Third Party','Supply Chain','Ransomware','Other'].forEach(function(o){
      h += '<option' + (rr.category===o?' selected':'') + '>' + esc(o) + '</option>';
    });
    h += '</select></div>';
    h += '<div><label style="color:var(--text-muted);">Inherent Risk</label><br>';
    h += '<select class="cd-sharpen-input" style="padding:3px 6px;" onchange="window._cdUpdateRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\',\'inherent\',this.value)">';
    ['','Critical','High','Medium','Low'].forEach(function(o){
      h += '<option' + (rr.inherent===o?' selected':'') + '>' + esc(o) + '</option>';
    });
    h += '</select></div>';
    h += '<div><label style="color:var(--text-muted);">Residual Risk</label><br>';
    h += '<select class="cd-sharpen-input" style="padding:3px 6px;" onchange="window._cdUpdateRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\',\'residual\',this.value)">';
    ['','Critical','High','Medium','Low'].forEach(function(o){
      h += '<option' + (rr.residual===o?' selected':'') + '>' + esc(o) + '</option>';
    });
    h += '</select></div>';
    h += '<div><label style="color:var(--text-muted);">Owner</label><br>';
    h += '<input class="cd-sharpen-input" style="padding:3px 6px;" value="' + esc(rr.owner || '') + '" oninput="window._cdUpdateRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\',\'owner\',this.value)" placeholder="e.g. CISO"></div>';
    h += '<div><label style="color:var(--text-muted);">Treatment</label><br>';
    h += '<select class="cd-sharpen-input" style="padding:3px 6px;" onchange="window._cdUpdateRiskRegister(\'' + esc(cid) + '\',\'' + esc(persona) + '\',\'treatment\',this.value)">';
    ['','Mitigate','Accept','Transfer','Avoid'].forEach(function(o){
      h += '<option' + (rr.treatment===o?' selected':'') + '>' + esc(o) + '</option>';
    });
    h += '</select></div>';
    h += '</div></div>';
    return h;
  }

  function _cdBuildComplianceRight(cid, cs) {
    var esc = escHtml;
    var cm = cs.complianceMap[cid];
    var h = '';

    if (!cm) {
      h += '<div class="cd-section">';
      h += '<div class="cd-section__hd">COMPLIANCE FRAMEWORK MAP</div>';
      h += '<div style="font-size:11px;color:var(--text-muted);margin-bottom:10px;">Rule-based MITRE → ISO/GDPR/PCI/NIST mapping. No LLM required.</div>';
      h += '<button class="cd-expand-trigger" onclick="window._cdLoadComplianceMap(\'' + esc(cid) + '\')">▶ Load Compliance Mapping</button>';
      h += '</div>';
      return h;
    }

    var gapsOnly = cs.gapsOnly[cid] || false;

    // Gaps only toggle
    h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:10px;">';
    h += '<label><input type="checkbox"' + (gapsOnly ? ' checked' : '') + ' onchange="window._cdToggleGapsOnly(\'' + esc(cid) + '\')" style="margin-right:4px;">Gaps only</label>';
    h += '<span style="color:var(--text-muted);">MITRE tags: ' + esc((cm.mitre_tags || []).join(', ') || 'none') + '</span>';
    h += '</div>';

    function ctrlRows(controls, refKey) {
      var out = '';
      (controls || []).forEach(function(c) {
        if (gapsOnly && c.status !== 'GAP') return;
        var statusCls = c.status === 'GAP' ? 'cd-ctrl-status--gap' : c.status === 'PASSING' ? 'cd-ctrl-status--pass' : 'cd-ctrl-status--unknown';
        var icon = c.status === 'GAP' ? '\u26A0' : c.status === 'PASSING' ? '\u2713' : '?';
        out += '<div class="cd-ctrl-row">';
        out += '<span class="' + statusCls + '" style="width:16px;text-align:center;flex-shrink:0;">' + icon + '</span>';
        out += '<span style="font-weight:700;min-width:70px;flex-shrink:0;">' + esc(c.ref) + '</span>';
        out += '<span style="flex:1;color:var(--text-muted);">' + esc(c.name) + '</span>';
        if (c.row_refs && c.row_refs.length) out += '<span style="font-size:9px;color:var(--accent,#7c6af7);">rows[' + esc(c.row_refs.join(',')) + ']</span>';
        if (c.note) out += '<span style="font-size:9px;color:var(--text-muted);margin-left:4px;">' + esc(c.note) + '</span>';
        out += '</div>';
      });
      return out || '<div style="font-size:10px;color:var(--text-muted);padding:4px 0;">No items to show.</div>';
    }

    // ISO 27001
    h += '<details open><summary class="cd-section__hd" style="cursor:pointer;list-style:none;">ISO 27001 Annex A</summary>';
    h += '<div style="margin-top:6px;">' + ctrlRows(cm.iso27001) + '</div></details>';

    // GDPR
    h += '<details open style="margin-top:8px;"><summary class="cd-section__hd" style="cursor:pointer;list-style:none;">GDPR Articles</summary>';
    h += '<div style="margin-top:6px;">' + ctrlRows(cm.gdpr) + '</div></details>';

    // PCI DSS
    h += '<details style="margin-top:8px;"><summary class="cd-section__hd" style="cursor:pointer;list-style:none;">PCI DSS Requirements</summary>';
    h += '<div style="margin-top:6px;">' + ctrlRows(cm.pci_dss) + '</div></details>';

    // NIST CSF
    h += '<details style="margin-top:8px;"><summary class="cd-section__hd" style="cursor:pointer;list-style:none;">NIST CSF Functions</summary>';
    h += '<div style="margin-top:6px;">' + ctrlRows(cm.nist_csf) + '</div></details>';

    // CRQ
    var crq = cm.crq || {};
    var crqOv = cs.crqOverrides[cid] || {};
    var expUsd = crqOv.expected_usd !== undefined ? crqOv.expected_usd : crq.expected_usd;
    var maxUsd  = crqOv.max_usd !== undefined ? crqOv.max_usd : crq.max_usd;
    h += '<div class="cd-crq-block" style="margin-top:10px;">';
    h += '<div class="cd-section__hd">CYBER RISK QUANTIFICATION</div>';
    h += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:6px;">' + esc(crq.note || '') + '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:10px;">';
    h += '<div><label style="color:var(--text-muted);">Expected loss (USD)</label><br>';
    h += '<input class="cd-sharpen-input" style="padding:3px 6px;" type="number" value="' + esc(String(expUsd || 0)) + '" oninput="window._cdUpdateCRQ(\'' + esc(cid) + '\',\'expected_usd\',this.value)"></div>';
    h += '<div><label style="color:var(--text-muted);">Max exposure (USD)</label><br>';
    h += '<input class="cd-sharpen-input" style="padding:3px 6px;" type="number" value="' + esc(String(maxUsd || 0)) + '" oninput="window._cdUpdateCRQ(\'' + esc(cid) + '\',\'max_usd\',this.value)"></div>';
    h += '<div><label style="color:var(--text-muted);">Recovery cost (USD)</label><br>';
    h += '<input class="cd-sharpen-input" style="padding:3px 6px;" type="number" value="' + esc(String(crqOv.recovery_cost_usd !== undefined ? crqOv.recovery_cost_usd : (crq.recovery_cost_usd || 0))) + '" oninput="window._cdUpdateCRQ(\'' + esc(cid) + '\',\'recovery_cost_usd\',this.value)"></div>';
    h += '<div style="display:flex;align-items:center;gap:6px;padding-top:14px;">';
    h += '<label><input type="checkbox"' + ((crqOv.insurance_trigger !== undefined ? crqOv.insurance_trigger : crq.insurance_trigger) ? ' checked' : '') + ' onchange="window._cdUpdateCRQ(\'' + esc(cid) + '\',\'insurance_trigger\',this.checked)" style="margin-right:4px;">Insurance trigger</label>';
    h += '</div>';
    h += '</div>';
    h += '<div style="margin-top:4px;font-size:10px;"><span style="color:var(--text-muted);">Confidence: </span><span style="color:#e0c446;">' + esc(crq.confidence || 'LOW') + '</span> (analyst overrides change this estimate)</div>';
    h += '</div>';

    return h;
  }

  window._cdLoadComplianceMap = async function (cid) {
    var cs = _cdState(cid);
    var rightEl = document.getElementById('cdCompRight_' + cid);
    if (rightEl) rightEl.innerHTML = '<div class="cd-loading"><div class="cd-spinner"></div>Loading compliance map…</div>';
    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
        '/clusters/' + encodeURIComponent(cid) + '/compliance-map',
        { headers: authHeaders(), signal: AbortSignal.timeout(15000) }
      );
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var data = await resp.json();
      cs.complianceMap[cid] = data;
    } catch (err) {
      if (rightEl) rightEl.innerHTML = '<div class="cd-error">Compliance map failed: ' + escHtml(err.message) + '</div>';
      return;
    }
    if (rightEl) rightEl.innerHTML = _cdBuildComplianceRight(cid, cs);
  };

  window._cdToggleGapsOnly = function (cid) {
    var cs = _cdState(cid);
    cs.gapsOnly[cid] = !cs.gapsOnly[cid];
    var rightEl = document.getElementById('cdCompRight_' + cid);
    if (rightEl) rightEl.innerHTML = _cdBuildComplianceRight(cid, cs);
  };

  window._cdUpdateRiskRegister = function (cid, persona, field, value) {
    var cs = _cdState(cid);
    if (!cs.riskRegister[cid]) cs.riskRegister[cid] = {};
    cs.riskRegister[cid][field] = value;
  };

  window._cdUpdateCRQ = function (cid, field, value) {
    var cs = _cdState(cid);
    if (!cs.crqOverrides[cid]) cs.crqOverrides[cid] = {};
    cs.crqOverrides[cid][field] = (field === 'insurance_trigger') ? value : Number(value);
  };

  window._cdAddAuditFinding = function (cid, persona) {
    var el = document.getElementById('cdAuditNote_' + cid);
    if (!el || !el.value.trim()) return;
    var cs = _cdState(cid);
    var key = cid + ':' + persona + ':audit_findings';
    if (!cs.notes[key]) cs.notes[key] = [];
    var ts = new Date().toISOString().slice(0,16).replace('T',' ');
    cs.notes[key].push({ text: el.value.trim(), ts: ts });
    el.value = '';
    var col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
    if (col2) { col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs); _cdWireButtons(col2, cid, persona); }
  };

  window._cdExportISOGapReport = function (cid, persona) {
    var cs = _cdState(cid);
    var cm = cs.complianceMap[cid];
    var lines = ['ISO 27001 Gap Report — Cluster ' + cid + ' — ' + new Date().toISOString(), ''];
    if (cm && cm.iso27001) {
      lines.push('=== ISO 27001 Annex A ===');
      cm.iso27001.forEach(function(c) { lines.push('[' + c.status + '] ' + c.ref + ' — ' + c.name + (c.row_refs && c.row_refs.length ? ' (rows: ' + c.row_refs.join(',') + ')' : '')); });
    }
    if (cm && cm.gdpr) {
      lines.push('', '=== GDPR ===');
      cm.gdpr.forEach(function(c) { lines.push('[' + c.status + '] ' + c.ref + ' — ' + c.name + (c.note ? ': ' + c.note : '')); });
    }
    if (cm && cm.pci_dss) {
      lines.push('', '=== PCI DSS ===');
      cm.pci_dss.forEach(function(c) { lines.push('[' + c.status + '] ' + c.ref + ' — ' + c.name); });
    }
    if (cm && cm.nist_csf) {
      lines.push('', '=== NIST CSF ===');
      cm.nist_csf.forEach(function(c) { lines.push('[' + c.status + '] ' + c.ref + ' — ' + c.name); });
    }
    var noteKey = cid + ':' + persona + ':audit_findings';
    var findings = cs.notes[noteKey] || [];
    if (findings.length) {
      lines.push('', '=== Auditor Findings ===');
      findings.forEach(function(f) { lines.push('[' + f.ts + '] ' + f.text); });
    }
    var blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a'); a.href = url; a.download = 'iso_gap_report_' + cid + '.txt'; a.click();
    URL.revokeObjectURL(url);
  };

  window._cdExportRiskRegister = function (cid, persona) {
    var cs = _cdState(cid);
    var rr = cs.riskRegister[cid] || {};
    var crqOv = cs.crqOverrides[cid] || {};
    var cm = cs.complianceMap[cid] || {};
    var crq = cm.crq || {};
    var lines = [
      'Risk Register Entry — Cluster ' + cid + ' — ' + new Date().toISOString(), '',
      'Risk ID: ' + (rr.id || 'TBD'),
      'Category: ' + (rr.category || 'TBD'),
      'Inherent Risk: ' + (rr.inherent || 'TBD'),
      'Residual Risk: ' + (rr.residual || 'TBD'),
      'Owner: ' + (rr.owner || 'TBD'),
      'Treatment: ' + (rr.treatment || 'TBD'),
      '',
      'CRQ — Expected Loss: $' + (crqOv.expected_usd !== undefined ? crqOv.expected_usd : (crq.expected_usd || 0)),
      'CRQ — Max Exposure: $' + (crqOv.max_usd !== undefined ? crqOv.max_usd : (crq.max_usd || 0)),
      'CRQ — Recovery Cost: $' + (crqOv.recovery_cost_usd !== undefined ? crqOv.recovery_cost_usd : (crq.recovery_cost_usd || 0)),
    ];
    var blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a'); a.href = url; a.download = 'risk_register_' + cid + '.txt'; a.click();
    URL.revokeObjectURL(url);
  };

  window._cdExportAuditFindings = function (cid, persona) {
    window._cdExportISOGapReport(cid, persona);
  };

  window._cdCloseExpand = function (cid, persona) {
    var cs = _cdState(cid);
    cs.activeExpand = null;
    var col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
    if (col2) { col2.classList.remove('active'); col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs); }
    var panel = document.getElementById('cdPanel');
    if (panel) panel.style.removeProperty('--cd-width');
    _cdUpdateLayout(cid, persona);
  };

  window._cdRegenExpand = function (cid, persona) {
    var cs = _cdState(cid);
    var ae = cs.activeExpand;
    if (!ae) return;
    var expKey = cid + ':' + persona + ':' + ae.taskIdx;
    delete cs.expands[expKey];
    window._cdExpand(cid, persona, ae.taskIdx, ae.stepTitle);
  };

  window._cdCopyTool = function (toolId) {
    var el = document.getElementById('cdToolCmd_' + toolId);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent || '').then(function () {
      var btn = el.closest('.cd-tool-row') && el.closest('.cd-tool-row').querySelector('.cd-tool-copy');
      if (btn) { btn.textContent = '✓'; setTimeout(function () { btn.textContent = '⎘'; }, 1500); }
    }).catch(function () {
      // Fallback for non-HTTPS
      var range = document.createRange();
      range.selectNode(el);
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      document.execCommand('copy');
      window.getSelection().removeAllRanges();
    });
  };

  window._cdAddNote = function (cid, persona) {
    var inputId = 'cdNoteInput_' + cid + '_' + persona;
    var input = document.getElementById(inputId);
    if (!input || !input.value.trim()) return;
    var cs = _cdState(cid);
    var noteKey = cid + ':' + persona;
    if (!cs.notes[noteKey]) cs.notes[noteKey] = [];
    var ts = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    cs.notes[noteKey].push({ text: input.value.trim(), ts: ts });
    input.value = '';
    var col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
    if (col2) {
      col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs);
      _cdWireButtons(col2, cid, persona);
    }
  };

  // ── Column 3: Threat model ─────────────────────────────────────────────────

  function _cdBuildTModelColHTML(cid, cs) {
    var h = '<div class="cd-col-hd">';
    h += '<span class="cd-col-title">Threat Modelling</span>';
    h += '<button class="cd-btn-icon" onclick="window._cdCloseTModel(\'' + escHtml(cid) + '\')" title="Close column">✕</button>';
    h += '</div>';

    var btns = {
      pasta:   'PASTA (7-stage)',
      diamond: 'Diamond Model',
      maestro: 'MAESTRO (AI/ML)',
      stride:  'STRIDE',
      dread:   'DREAD Score',
    };
    h += '<div class="cd-tm-btn-bar">';
    Object.keys(btns).forEach(function (type) {
      var tm = cs.tmodels[type] || { status: 'idle' };
      var done = tm.status === 'loaded';
      var loading = tm.status === 'loading';
      h += '<button class="cd-tm-run-btn' + (done ? ' cd-tm-run-btn--done' : '') + '" ';
      h += 'onclick="window._cdRunThreatModel(\'' + escHtml(cid) + '\',\'' + type + '\')">';
      h += (loading ? '⟳ ' : done ? '✓ ' : '▶ ') + escHtml(btns[type]);
      h += '</button>';
    });
    h += '</div>';

    h += '<div id="cdTModelArea_' + escHtml(cid) + '">';
    ['pasta','diamond','maestro','stride','dread'].forEach(function (type) {
      var tm = cs.tmodels[type] || { status: 'idle' };
      if (tm.status === 'loading') {
        h += '<div class="cd-loading" id="cdTM_' + escHtml(cid) + '_' + type + '"><div class="cd-spinner"></div>Running ' + type.toUpperCase() + '…</div>';
      } else if (tm.status === 'loaded' && tm.data) {
        h += _cdRenderThreatModelResult(type, tm.data, cid);
      }
    });
    h += '</div>';
    return h;
  }

  function _cdRenderThreatModelResult(type, data, cid) {
    var sections = data.sections || {};
    var labels = {
      pasta:   { objectives:'Stage 1: Objectives', technical_scope:'Stage 2: Technical Scope', app_decomposition:'Stage 3: App Decomposition', threat_analysis:'Stage 4: Threat Analysis', vulnerability_analysis:'Stage 5: Vulnerabilities', attack_modelling:'Stage 6: Attack Modelling', risk_impact:'Stage 7: Risk & Impact' },
      diamond: { adversary:'Adversary', capability:'Capability', infrastructure:'Infrastructure', victim:'Victim', adversary_victim:'Adversary–Victim', capability_infrastructure:'Capability–Infrastructure' },
      maestro: { model_algorithm:'L1: Model & Algorithm', data_layer:'L2: Data Layer', ecosystem:'L3: Ecosystem', agent_orchestration:'L4: Agent/Orchestration', evaluation:'L5: Evaluation', deployment:'L6: Deployment', user_org:'L7: User & Org', compliance:'Compliance Controls' },
      stride:  { spoofing:'Spoofing', tampering:'Tampering', repudiation:'Repudiation', information_disclosure:'Information Disclosure', denial_of_service:'Denial of Service', elevation_of_privilege:'Elevation of Privilege', stride_summary:'Summary & Mitigations', iso27001_controls:'ISO 27001 Annex A Mapping', nist_csf:'NIST CSF Functions', gdpr_relevance:'GDPR Relevance', pci_dss:'PCI DSS Requirements' },
      dread:   { damage:'Damage Potential', reproducibility:'Reproducibility', exploitability:'Exploitability', affected_users:'Affected Users', discoverability:'Discoverability', dread_score:'Overall DREAD Score', risk_treatment:'Risk Treatment Recommendation' },
    }[type] || {};
    var h = '<div class="cd-tm-result">';
    h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">';
    h += '<strong style="font-size:11px;">' + type.toUpperCase() + '</strong>';
    if (data.from_cache) h += '<span class="badge" style="font-size:10px;">cached</span>';
    h += '<label style="font-size:10px;color:var(--text-muted,#7a7f8e);margin-left:auto;">';
    h += '<input type="checkbox" id="cdTMReport_' + escHtml(cid) + '_' + type + '" style="margin-right:3px;">Include in report</label>';
    h += '</div>';
    Object.keys(sections).forEach(function (k) {
      if (!sections[k]) return;
      var lbl = labels[k] || k.replace(/_/g,' ');
      h += '<div class="cd-tm-stage"><div class="cd-tm-stage__label">' + escHtml(lbl) + '</div>';
      h += '<div class="cd-tm-stage__body">' + mdToHtml(sections[k]) + '</div></div>';
    });
    if (!Object.keys(sections).length && data.raw_text) {
      h += '<div class="cd-section__body" style="font-size:11px;">' + mdToHtml(data.raw_text.slice(0, 2000)) + '</div>';
    }
    h += '</div>';
    return h;
  }

  window._cdCloseTModel = function (cid) {
    var cs = _cdState(cid);
    _cdUpdateLayout(cid, cs.persona);
  };

  // ── Layout column manager ──────────────────────────────────────────────────

  function _cdUpdateLayout(cid, persona) {
    var panel = $('cdPanel');
    var w = panel ? panel.offsetWidth : 640;
    var cs = _cdState(cid);

    var layout = document.getElementById('cdLayout_' + cid + '_' + persona);
    if (!layout) return;

    var col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);

    var hasExpand = !!(cs.activeExpand);

    // Auto-widen panel when expand column is activated
    if (hasExpand && panel) {
      var minW = 860;
      var curW = parseInt(getComputedStyle(panel).getPropertyValue('--cd-width') || '640', 10) || panel.offsetWidth;
      if (curW < minW) panel.style.setProperty('--cd-width', minW + 'px');
    }

    if (col2) col2.classList.toggle('active', hasExpand);

    var cols = 1 + (hasExpand ? 1 : 0);
    layout.setAttribute('data-cols', String(cols));
  }

  function _cdWireButtons(pane, cid, persona) {
    pane.querySelectorAll('.cd-confirm-btn,.cd-deny-btn,.cd-ciso-btn--escalate,.cd-ciso-btn--hold').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var ck  = btn.getAttribute('data-ck');
        var rawVal = btn.getAttribute('data-val');
        var val = rawVal === 'true' ? true : rawVal === 'false' ? false : rawVal; // support 'hold' etc
        var cs  = _cdState(cid);
        // Toggle: clicking the active button clears it
        if (cs.tasks[ck] === val) {
          cs.tasks[ck] = null;
          delete cs.taskDecisions[ck];
          btn.classList.remove('active');
        } else {
          cs.tasks[ck] = val;
          var nowTs = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
          cs.taskDecisions[ck] = { val: val, ts: nowTs };
          var sibling = pane.querySelector('[data-ck="' + ck + '"]:not([data-val="' + btn.getAttribute('data-val') + '"])');
          if (sibling) sibling.classList.remove('active');
          btn.classList.add('active');
          var decEl = pane.querySelector('[data-dec="' + ck + '"]');
          if (decEl) decEl.textContent = nowTs;
        }
        _cdMarkActiveTab(cid);
      });
    });
  }

  window._cdExpand = async function (cid, persona, taskIdx, stepTitle) {
    var cs = _cdState(cid);
    var expKey = cid + ':' + persona + ':' + taskIdx;

    // If already loaded and same task, just show col 2
    if (cs.activeExpand && cs.activeExpand.taskIdx === taskIdx && cs.expands[expKey] && cs.expands[expKey].status === 'loaded') {
      var col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
      if (col2) { col2.classList.add('active'); col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs); _cdWireButtons(col2, cid, persona); }
      _cdUpdateLayout(cid, persona);
      return;
    }

    // Set loading state and activate col 2
    cs.activeExpand = { persona: persona, taskIdx: taskIdx, stepTitle: stepTitle, rowEvidence: [] };
    cs.expands[expKey] = { status: 'loading', questions: [] };

    var col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
    if (col2) { col2.classList.add('active'); col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs); }
    _cdUpdateLayout(cid, persona);

    var pd = cs.pdata[persona];
    var rowRefs = [];
    if (pd && pd.data && pd.data.persona_steps && pd.data.persona_steps[taskIdx]) {
      var step = pd.data.persona_steps[taskIdx];
      (step.subtasks || []).forEach(function (sub) {
        if (sub && sub.evidence_refs) rowRefs = rowRefs.concat(sub.evidence_refs);
      });
    }
    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
        '/clusters/' + encodeURIComponent(cid) + '/expand-step',
        { method: 'POST',
          headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
          body: JSON.stringify({ step_title: stepTitle, row_refs: rowRefs,
                                 persona: persona, model: _cdModelSel() }),
          signal: AbortSignal.timeout(120000) }
      );
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var data = await resp.json();
      cs.expands[expKey] = { status: 'loaded', questions: data.questions || [] };
      if (cs.activeExpand && cs.activeExpand.taskIdx === taskIdx) {
        cs.activeExpand.rowEvidence = data.row_evidence || [];
        cs.activeExpand.suggestedTools = data.suggested_tools || [];
        cs.activeExpand.huntData = data.hunt_data || null;
      }
      col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
      if (col2) { col2.innerHTML = _cdBuildExpandColHTML(cid, persona, cs); _cdWireButtons(col2, cid, persona); }
    } catch (err) {
      cs.expands[expKey] = { status: 'error', questions: [] };
      col2 = document.getElementById('cdColExpand_' + cid + '_' + persona);
      if (col2) {
        var qaEl = col2.querySelector('#cdExpandQA_' + cid + '_' + persona);
        if (qaEl) qaEl.innerHTML = '<div class="cd-error">EXPAND failed: ' + escHtml(err.message) + '</div>';
      }
    }
  };

  window._cdRunThreatModel = async function (cid, modelType) {
    var cs = _cdState(cid);
    cs.tmodels[modelType] = { status: 'loading', data: null };

    // Re-render the ThreatModel tab pane if active
    var tmPane = document.getElementById('cdPane_' + cid + '_threat_model');
    if (tmPane) tmPane.innerHTML = _cdBuildThreatModelPaneHTML(cid, cs);

    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
        '/clusters/' + encodeURIComponent(cid) + '/threat-model',
        { method: 'POST',
          headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
          body: JSON.stringify({ model_type: modelType, model: _cdModelSel() }),
          signal: AbortSignal.timeout(180000) }
      );
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      var data = await resp.json();
      cs.tmodels[modelType] = { status: 'loaded', data: data };
      tmPane = document.getElementById('cdPane_' + cid + '_threat_model');
      if (tmPane) tmPane.innerHTML = _cdBuildThreatModelPaneHTML(cid, cs);
      _cdWireDREADSliders(cid);
    } catch (err) {
      cs.tmodels[modelType] = { status: 'error', data: null };
      tmPane = document.getElementById('cdPane_' + cid + '_threat_model');
      if (tmPane) tmPane.innerHTML = _cdBuildThreatModelPaneHTML(cid, cs);
      toast('Threat model failed: ' + err.message, 'error');
    }
  };

  // ── ThreatModel persona tab — 3-column layout, no LLM summary ────────────────

  function _cdShowThreatModelTab(cid) {
    var bodyEl = $('cdBody');
    if (!bodyEl) return;
    document.querySelectorAll('#cdBody .cd-pane').forEach(function (p) { p.classList.remove('active'); });
    var paneId = 'cdPane_' + cid + '_threat_model';
    var existing = document.getElementById(paneId);
    if (existing) { existing.classList.add('active'); return; }
    var pane = document.createElement('div');
    pane.className = 'cd-pane active';
    pane.id = paneId;
    var cs = _cdState(cid);
    pane.innerHTML = _cdBuildThreatModelPaneHTML(cid, cs);
    bodyEl.appendChild(pane);
    _cdWireDREADSliders(cid);
  }

  function _cdBuildThreatModelPaneHTML(cid, cs) {
    var esc = escHtml;
    var h = '<div class="cd-tm-tab-layout">';

    // COL 1: Framework runners
    h += '<div class="cd-tm-tab-col" style="overflow-y:auto;padding:12px 14px;border-right:1px solid var(--border,#2a2d3a);">';
    h += '<div class="cd-col-hd"><span class="cd-col-title">Threat Frameworks</span></div>';
    var frameworks = [
      { key: 'pasta',   label: 'PASTA (7-stage)',  desc: 'Process for Attack Simulation & Threat Analysis' },
      { key: 'diamond', label: 'Diamond Model',    desc: 'Adversary · Capability · Infrastructure · Victim' },
      { key: 'maestro', label: 'MAESTRO (AI/ML)',  desc: '7-layer AI threat framework' },
      { key: 'stride',  label: 'STRIDE',           desc: 'Microsoft threat model with ISO 27001 / NIST CSF / GDPR mapping' },
      { key: 'dread',   label: 'DREAD Score',      desc: 'Damage · Reproducibility · Exploitability · Affected Users · Discoverability' },
    ];
    frameworks.forEach(function(fw) {
      var tm = cs.tmodels[fw.key] || { status: 'idle' };
      var isLoading = tm.status === 'loading';
      var isDone = tm.status === 'loaded';
      var isError = tm.status === 'error';
      h += '<div class="cd-tm-framework-card' + (isDone ? '' : ' cd-tm-framework-card__idle') + '">';
      h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">';
      h += '<strong style="font-size:11px;flex:1;">' + esc(fw.label) + '</strong>';
      if (isDone) h += '<span style="font-size:10px;color:#3FA860;">✓ Done</span>';
      if (isError) h += '<span style="font-size:10px;color:#E54848;">✗ Failed</span>';
      h += '</div>';
      h += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">' + esc(fw.desc) + '</div>';
      h += '<button class="cd-tm-run-btn' + (isDone ? ' cd-tm-run-btn--done' : '') + '"';
      h += ' onclick="window._cdRunThreatModel(\'' + esc(cid) + '\',\'' + fw.key + '\')">';
      h += (isLoading ? '\u27F3 Running…' : isDone ? '\u27F3 Re-run' : '\u25B6 Run') + ' ' + esc(fw.label);
      h += '</button>';
      h += '</div>';
    });
    h += '</div>';

    // COL 2: MITRE coverage table + STRIDE result if loaded
    h += '<div class="cd-tm-tab-col" style="overflow-y:auto;padding:12px 14px;border-right:1px solid var(--border,#2a2d3a);">';
    h += '<div class="cd-col-hd"><span class="cd-col-title">Analysis</span></div>';

    // MITRE coverage — extract from any loaded persona data
    var mitreList = [];
    var clusterData = state.clusterMap && state.clusterMap[cid];
    if (clusterData) {
      mitreList = (clusterData.top_mitre || clusterData.mitre || []).slice(0, 10);
    }
    if (!mitreList.length) {
      // Try to extract from loaded pdata
      var pdKeys = Object.keys(cs.pdata);
      for (var pi = 0; pi < pdKeys.length; pi++) {
        var pd = cs.pdata[pdKeys[pi]];
        if (pd && pd.data && pd.data.cluster_mitre) { mitreList = pd.data.cluster_mitre.slice(0, 10); break; }
      }
    }
    h += '<div class="cd-section"><div class="cd-section__hd">MITRE ATT&CK COVERAGE</div>';
    if (mitreList.length) {
      mitreList.forEach(function(t) {
        h += '<div class="cd-mitre-bar">';
        h += '<span style="font-size:10px;font-family:monospace;min-width:80px;color:var(--accent,#7c6af7);">' + esc(String(t)) + '</span>';
        h += '<div style="flex:1;height:6px;background:rgba(124,106,247,.2);border-radius:3px;overflow:hidden;">';
        h += '<div style="width:60%;height:100%;background:var(--accent,#7c6af7);border-radius:3px;"></div></div>';
        h += '</div>';
      });
    } else {
      h += '<div style="font-size:10px;color:var(--text-muted);">No MITRE tags available. Run a persona tab first or load data.</div>';
    }
    h += '</div>';

    // STRIDE results if loaded
    var strideTm = cs.tmodels['stride'];
    if (strideTm && strideTm.status === 'loaded' && strideTm.data) {
      h += '<div class="cd-section" style="margin-top:10px;"><div class="cd-section__hd">STRIDE ANALYSIS</div>';
      h += _cdRenderThreatModelResult('stride', strideTm.data, cid);
      h += '</div>';
    } else {
      h += '<div class="cd-section" style="margin-top:10px;"><div class="cd-section__hd">STRIDE</div>';
      h += '<div style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">Not yet run — click ▶ Run STRIDE in the frameworks column.</div>';
      h += '</div>';
    }
    h += '</div>';

    // COL 3: Compliance map + DREAD sliders
    h += '<div class="cd-tm-tab-col" style="overflow-y:auto;padding:12px 14px;">';
    h += '<div class="cd-col-hd"><span class="cd-col-title">Compliance & Scoring</span></div>';

    // DREAD sliders if loaded
    var dreadTm = cs.tmodels['dread'];
    if (dreadTm && dreadTm.status === 'loaded' && dreadTm.data) {
      h += '<div class="cd-section"><div class="cd-section__hd">DREAD SCORE — ANALYST ADJUSTMENT</div>';
      var dreadDims = ['damage','reproducibility','exploitability','affected_users','discoverability'];
      var dreadLabels = { damage:'Damage', reproducibility:'Reproducibility', exploitability:'Exploitability', affected_users:'Affected Users', discoverability:'Discoverability' };
      var dreadOv = cs.dreadOverrides[cid] || {};
      var sections = (dreadTm.data.sections || {});
      dreadDims.forEach(function(dim) {
        var llmVal = _cdParseDREADScore(sections[dim] || '');
        var analystVal = dreadOv[dim] !== undefined ? dreadOv[dim] : llmVal;
        h += '<div class="cd-dread-slider">';
        h += '<div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:3px;">';
        h += '<span>' + esc(dreadLabels[dim]) + '</span>';
        h += '<span style="color:var(--text-muted);">LLM: <b style="color:var(--text,#e8ebf0);">' + (llmVal||'?') + '</b>';
        if (dreadOv[dim] !== undefined && dreadOv[dim] !== llmVal) {
          h += ' → Adjusted: <b style="color:#e0c446;">' + analystVal + '</b>';
        }
        h += '</span></div>';
        h += '<input type="range" min="1" max="10" value="' + (analystVal || 5) + '"';
        h += ' data-cid="' + esc(cid) + '" data-dim="' + esc(dim) + '"';
        h += ' class="cd-dread-range" style="width:100%;accent-color:var(--accent,#7c6af7);">';
        h += '</div>';
      });
      // Overall DREAD score display
      var dims = dreadDims.map(function(d) { return dreadOv[d] !== undefined ? dreadOv[d] : _cdParseDREADScore(sections[d] || ''); });
      var validDims = dims.filter(function(v) { return v !== null && !isNaN(v); });
      var avgScore = validDims.length ? (validDims.reduce(function(a,b){return a+b;},0) / validDims.length).toFixed(1) : '?';
      h += '<div style="margin-top:8px;font-size:12px;font-weight:700;color:' + (parseFloat(avgScore) >= 7 ? '#E54848' : parseFloat(avgScore) >= 5 ? '#ffaa55' : '#3FA860') + ';">DREAD Score: ' + avgScore + ' / 10</div>';
      h += '</div>';
    } else if (dreadTm && dreadTm.status === 'loading') {
      h += '<div class="cd-section"><div class="cd-loading"><div class="cd-spinner"></div>Running DREAD…</div></div>';
    } else {
      h += '<div class="cd-section"><div class="cd-section__hd">DREAD SCORE</div>';
      h += '<div style="font-size:10px;color:var(--text-muted);">Run ▶ DREAD Score to get scored dimensions with analyst-adjustable sliders.</div>';
      h += '</div>';
    }

    // Compliance map — fast load from endpoint
    var cm = cs.complianceMap[cid];
    if (!cm) {
      h += '<div class="cd-section" style="margin-top:8px;"><div class="cd-section__hd">COMPLIANCE MAP</div>';
      h += '<button class="cd-expand-trigger" onclick="window._cdLoadComplianceMapTM(\'' + esc(cid) + '\')">▶ Load ISO/GDPR/PCI/NIST Map</button>';
      h += '</div>';
    } else {
      h += '<div class="cd-section" style="margin-top:8px;"><div class="cd-section__hd">ISO 27001 GAPS</div>';
      var gaps = (cm.iso27001 || []).filter(function(c){ return c.status === 'GAP'; });
      if (gaps.length) {
        gaps.forEach(function(c) {
          h += '<div class="cd-ctrl-row"><span class="cd-ctrl-status--gap">\u26A0</span><span style="font-weight:700;min-width:70px;">' + esc(c.ref) + '</span><span style="color:var(--text-muted);">' + esc(c.name) + '</span></div>';
        });
      } else {
        h += '<div style="font-size:10px;color:var(--text-muted);">No gaps detected from MITRE tags.</div>';
      }
      h += '</div>';

      var art33 = (cm.gdpr || []).find(function(g){return g.ref==='Art.33';});
      if (art33 && art33.status === 'GAP') {
        h += '<div class="cd-section cd-breach-clock" style="margin-top:8px;">';
        h += '<div class="cd-section__hd">GDPR ART.33 — BREACH CLOCK</div>';
        h += '<div style="font-size:10px;color:#E54848;font-weight:700;">TRIGGERED — 72h notification required</div>';
        h += '<div style="font-size:10px;color:var(--text-muted);margin-top:4px;">' + esc(art33.note || '') + '</div>';
        h += '</div>';
      }
    }
    h += '</div>'; // col 3
    h += '</div>'; // tm-tab-layout
    return h;
  }

  function _cdParseDREADScore(text) {
    // Extract a 1-10 number from a DREAD section text
    var m = text.match(/\b([1-9]|10)\s*\/\s*10\b/) || text.match(/\bscore[:\s]+([1-9]|10)\b/i) || text.match(/\b([1-9]|10)\b/);
    return m ? parseInt(m[1], 10) : null;
  }

  function _cdWireDREADSliders(cid) {
    var cs = _cdState(cid);
    var pane = document.getElementById('cdPane_' + cid + '_threat_model');
    if (!pane) return;
    pane.querySelectorAll('.cd-dread-range').forEach(function(input) {
      input.addEventListener('input', function() {
        var dim = input.getAttribute('data-dim');
        var val = parseInt(input.value, 10);
        if (!cs.dreadOverrides[cid]) cs.dreadOverrides[cid] = {};
        cs.dreadOverrides[cid][dim] = val;
        // Re-render the pane to update display
        pane.innerHTML = _cdBuildThreatModelPaneHTML(cid, cs);
        _cdWireDREADSliders(cid);
      });
    });
  }

  window._cdLoadComplianceMapTM = async function (cid) {
    var cs = _cdState(cid);
    // Re-use the same compliance map loader
    await window._cdLoadComplianceMap(cid);
    // Re-render the ThreatModel pane
    var pane = document.getElementById('cdPane_' + cid + '_threat_model');
    if (pane) {
      pane.innerHTML = _cdBuildThreatModelPaneHTML(cid, cs);
      _cdWireDREADSliders(cid);
    }
  };

  function _cdShowReportPane(cid) {
    var bodyEl = $('cdBody');
    if (!bodyEl) return;
    document.querySelectorAll('#cdBody .cd-pane').forEach(function (p) { p.classList.remove('active'); });
    var paneId = 'cdPane_' + cid + '_report';
    var existing = document.getElementById(paneId);
    if (existing) { existing.classList.add('active'); return; }

    var pane = document.createElement('div');
    pane.className = 'cd-pane active';
    pane.id = paneId;
    pane.innerHTML = _cdBuildReportHTML(cid);
    bodyEl.appendChild(pane);
    // Wire save button
    var saveBtn = pane.querySelector('#cdSaveReport_' + cid);
    if (saveBtn) saveBtn.addEventListener('click', function () { _cdSaveReport(cid); });
  }

  function _cdBuildReportHTML(cid) {
    var cs = _cdState(cid);
    var confirmed = [], denied = [], open = [];

    PERSONA_TABS.filter(function (t) { return t.key !== 'report'; }).forEach(function (t) {
      var pd = cs.pdata[t.key];
      if (!pd || pd.status !== 'loaded' || !pd.data) return;
      var steps = pd.data.persona_steps || [];
      steps.forEach(function (s, ti) {
        var tKey = _cdTaskKey(cid, t.key, ti, null);
        var done = cs.tasks[tKey];
        var title = (t.label + ': ' + (s.title || s.action || 'Task ' + (ti+1)));
        if (done === true)  confirmed.push(title);
        else if (done === false) denied.push(title);
        else open.push(title);
      });
    });

    var h = '<div class="cd-report-section">';
    h += '<div class="cd-report-section__hd">CONFIRMED FINDINGS (' + confirmed.length + ')</div>';
    if (confirmed.length) {
      confirmed.forEach(function (t) { h += '<div class="cd-report-item confirmed"><span class="cd-report-item__icon">✓</span><span>' + escHtml(t) + '</span></div>'; });
    } else {
      h += '<div style="color:var(--text-muted,#7a7f8e);font-size:11px;">None yet — confirm tasks in persona tabs</div>';
    }
    h += '</div>';

    h += '<div class="cd-report-section">';
    h += '<div class="cd-report-section__hd">DENIED / BENIGN (' + denied.length + ')</div>';
    denied.forEach(function (t) { h += '<div class="cd-report-item denied"><span class="cd-report-item__icon">✗</span><span>' + escHtml(t) + '</span></div>'; });
    h += '</div>';

    h += '<div class="cd-report-section">';
    h += '<div class="cd-report-section__hd">OPEN / UNRESOLVED (' + open.length + ')</div>';
    open.forEach(function (t) { h += '<div class="cd-report-item open"><span class="cd-report-item__icon">?</span><span>' + escHtml(t) + '</span></div>'; });
    h += '</div>';

    // Threat model inclusions
    var tmIncluded = [];
    ['pasta','diamond','maestro','stride','dread'].forEach(function (type) {
      if ((cs.tmodels[type]||{}).status === 'loaded') tmIncluded.push(type.toUpperCase());
    });
    if (tmIncluded.length) {
      h += '<div class="cd-report-section">';
      h += '<div class="cd-report-section__hd">THREAT MODELS AVAILABLE</div>';
      h += '<div style="font-size:11px;">' + tmIncluded.join(', ') + ' — check "Include in report" on each model pane to attach</div>';
      h += '</div>';
    }

    h += '<div style="border-top:1px solid var(--border,#2a2d3a);padding-top:12px;margin-top:4px;">';
    h += '<button id="cdSaveReport_' + escHtml(cid) + '" class="btn-primary" style="font-size:11px;padding:5px 14px;">💾 Save Report Locally</button>';
    h += '<div class="cd-send-row">';
    h += '<button class="cd-send-btn cd-send-btn--active" onclick="window._cdSaveReport(\'' + escHtml(cid) + '\')">📁 Save JSON</button>';
    h += '<button class="cd-send-btn cd-send-btn--disabled" title="Configure SMTP in .env to enable" disabled>📧 Email (unconfigured)</button>';
    h += '<button class="cd-send-btn cd-send-btn--disabled" title="Configure SLACK_WEBHOOK in .env to enable" disabled>Slack (unconfigured)</button>';
    h += '<button class="cd-send-btn cd-send-btn--disabled" title="Configure object storage in .env to enable" disabled>☁ Object Store (unconfigured)</button>';
    h += '</div></div>';
    return h;
  }

  window._cdSaveReport = async function (cid) {
    var cs = _cdState(cid);
    var confirmed = [], denied = [], openItems = [];
    PERSONA_TABS.filter(function (t) { return t.key !== 'report'; }).forEach(function (t) {
      var pd = cs.pdata[t.key];
      if (!pd || pd.status !== 'loaded' || !pd.data) return;
      (pd.data.persona_steps || []).forEach(function (s, ti) {
        var done = cs.tasks[_cdTaskKey(cid, t.key, ti, null)];
        var item = { persona: t.key, task: s.title || s.action || 'Task ' + (ti+1) };
        if (done === true) confirmed.push(item);
        else if (done === false) denied.push(item);
        else openItems.push(item);
      });
    });
    try {
      var resp = await fetch(
        '/api/v1/assessments/' + encodeURIComponent(state.assessmentId) +
        '/clusters/' + encodeURIComponent(cid) + '/investigation-report',
        { method: 'POST',
          headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
          body: JSON.stringify({ confirmed: confirmed, denied: denied, open: openItems,
                                 analyst_notes: '', generated_by: 'soc_analyst' }) }
      );
      var data = await resp.json();
      if (data.saved) toast('Report saved: ' + data.path, 'ok');
      else toast('Save failed: ' + (data.path || 'unknown'), 'error');
    } catch (err) {
      toast('Save failed: ' + err.message, 'error');
    }
  };

  // Backward compat shims (old code may still reference these)
  window._triggerLlmSummary = function (cid, aid, force, persona) {
    if (cid) { state.activeClusterId = cid; }
    var activeCid = state.activeClusterId;
    if (!activeCid) return;
    var p = persona || state.currentPersona || 'soc_analyst';
    var cs = _cdState(activeCid);
    if (force) cs.pdata[p].status = 'idle';
    _cdSwitchPersona(activeCid, p);
  };
  window._triggerClusterEnrich = function (cid) { toast('Use persona tab → CRAG tab coming soon', 'info'); };
  window._triggerHuntSweep     = function (cid) { toast('Use persona tab → Hunt Sweep coming soon', 'info'); };
  window._ensureClusterElements = function () {};


  window.storeClusters = storeClusters;  window.renderClusterList = renderClusterList;

  // ══════════════════════════════════════════════════════════════════
  // STREAMING LIVE FEED — polls /snapshot every 2s, incrementally
  // updates #clusterListPanel without full page re-render.
  // Call window.startStreamPolling(sessionId) to activate.
  // ══════════════════════════════════════════════════════════════════

  var _streamPollTimer = null;
  var _streamLastClusterCount = 0;

  function _streamLog(msg) {
    var el = document.getElementById('streamFeedLog');
    if (!el) return;
    var ts = new Date().toLocaleTimeString();
    el.innerHTML = '<span style="color:var(--text-muted);">[' + ts + ']</span> ' + escHtml(msg) + '<br>' + el.innerHTML;
    if (el.children.length > 10) el.removeChild(el.lastChild);
  }

  function _streamUpdateUI(snap) {
    var statsEl = document.getElementById('streamFeedStats');
    if (statsEl) {
      statsEl.textContent = (snap.total_ingested || 0) + ' rows · ' + (snap.cluster_count || 0) + ' clusters';
    }
    if ((snap.cluster_count || 0) > _streamLastClusterCount) {
      _streamLog((snap.cluster_count - _streamLastClusterCount) + ' new cluster(s) formed');
      _streamLastClusterCount = snap.cluster_count || 0;
    }
    var clusters = snap.clusters || [];
    if (clusters.length > 0) {
      // Merge into state.clusterMap without clearing existing entries
      clusters.forEach(function (c) {
        var cid = String(c.cluster_id || c.id || '');
        if (cid) state.clusterMap[cid] = c;
      });
      renderClusterList();
    }
  }

  function _streamPoll(sessionId) {
    var base = (state.apiBase || '').replace(/\/$/, '');
    var url = base + '/api/v1/stream/sessions/' + encodeURIComponent(sessionId) + '/snapshot';
    var headers = { 'Accept': 'application/json' };
    var apiKey = localStorage.getItem('apiKey');
    if (apiKey) headers['X-API-Key'] = apiKey;

    fetch(url, { headers: headers })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (snap) {
        _streamUpdateUI(snap);
        if (snap.status === 'closed') {
          _streamLog('Session closed — stopping poll');
          window.stopStreamPolling();
        }
      })
      .catch(function (err) {
        _streamLog('Poll error: ' + err);
      });
  }

  window.startStreamPolling = function (sessionId) {
    if (_streamPollTimer) {
      if (window.JanuSecPollers) window.JanuSecPollers.clear('investigate.stream');
      else clearInterval(_streamPollTimer);
      _streamPollTimer = null;
    }
    _streamLastClusterCount = 0;
    var panel = document.getElementById('streamFeedPanel');
    if (panel) panel.style.display = '';
    var sidEl = document.getElementById('streamFeedSessionId');
    if (sidEl) sidEl.textContent = sessionId;
    window._streamSessionId = sessionId;
    _streamLog('Streaming started');
    _streamPoll(sessionId);
    _streamPollTimer = window.JanuSecPollers
      ? window.JanuSecPollers.setInterval('investigate.stream', function () { _streamPoll(sessionId); }, 2000)
      : setInterval(function () { _streamPoll(sessionId); }, 2000);
  };

  window.stopStreamPolling = function () {
    if (_streamPollTimer) {
      if (window.JanuSecPollers) window.JanuSecPollers.clear('investigate.stream');
      else clearInterval(_streamPollTimer);
      _streamPollTimer = null;
    }
    var dot = document.getElementById('streamFeedDot');
    if (dot) { dot.style.animation = 'none'; dot.style.background = '#6b7280'; }
    _streamLog('Polling stopped');
  };

})();
