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
      var el = document.createElement('div');
      el.className = 'source-item';
      el.innerHTML =
        '<i data-lucide="' + iconName + '" class="source-item__icon"></i>' +
        '<span class="source-item__name">' + escHtml(src.name) + '</span>' +
        '<span class="source-item__type">' + escHtml(TYPE_LABELS[src.type] || src.type) + '</span>' +
        '<span class="source-item__count">' + src.rows.length + ' rows</span>' +
        '<span class="source-item__status source-item__status--' + (src.status || 'ok') + '"></span>';
      container.appendChild(el);
    });
    $('sourceListRow').style.display = state.sources.length ? '' : 'none';
    $('sourceSummary').textContent = state.sources.length + ' source' + (state.sources.length !== 1 ? 's' : '') + ', ' + totalRows + ' rows';
    $('btnAnalyze').disabled = totalRows === 0;
    state.allRows = [];
    state.sources.forEach(function (src) {
      state.allRows = state.allRows.concat(src.rows);
    });
    // Re-init lucide icons in newly added DOM
    if (window.lucide) lucide.createIcons();
  }

  // ── Upload handling ──────────────────────────────────────────────────────
  function handleFiles(fileList) {
    var files = Array.from(fileList);
    if (!files.length) return;

    var promises = files.map(function (f) {
      return parseFile(f).then(function (result) {
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
      toast(files.length + ' file' + (files.length !== 1 ? 's' : '') + ' loaded', 'success');
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
    renderSourceList();
    $('sevSummary').classList.remove('has-data');
    $('reportEmpty').style.display = '';
    $('reportContent').style.display = 'none';
    $('evidenceBody').innerHTML = '';
    $('evidenceEmpty').style.display = '';
    $('evidenceBadge').textContent = '0';
  });

  $('btnAddMore').addEventListener('click', function () { fileInput.click(); });

  // ── Persona chip rendering ───────────────────────────────────────────────
  function renderPersonaChips() {
    var container = $('personaChips');
    container.innerHTML = '';
    PERSONAS.forEach(function (p) {
      var chip = document.createElement('button');
      chip.className = 'persona-chip' + (p === state.currentPersona ? ' active' : '');
      chip.textContent = PERSONA_LABELS[p];
      chip.addEventListener('click', function () {
        state.currentPersona = p;
        $('personaSelect').value = p;
        renderPersonaChips();
        renderReport();
      });
      container.appendChild(chip);
    });
  }

  $('personaSelect').addEventListener('change', function () {
    state.currentPersona = this.value;
    renderPersonaChips();
    renderReport();
  });

  // ── Analyze button — runs pipeline + generates report ────────────────────
  $('btnAnalyze').addEventListener('click', function () { runAnalysis(); });

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

      // Step 2: Poll for assessment completion (quick — pipeline stages are fast)
      var assessment = await pollAssessment(state.assessmentId);
      state.assessment = assessment;
      $('pipelineBarFill').style.width = '70%';

      // Step 3: Build enriched evidence rows from assessment
      buildEvidenceFromAssessment(assessment);

      // Step 3b: Render graph + timeline visualizations
      $('graphEmpty').style.display = 'none';
      $('graphContent').style.display = '';
      $('timelineEmpty').style.display = 'none';
      $('timelineContent').style.display = '';
      renderGraph(state.evidenceRows);
      renderTimeline(state.evidenceRows);

      // Step 4: Generate persona report
      $('pipelineBarFill').style.width = '85%';
      await generatePersonaReport(assessment);

      $('pipelineBarFill').style.width = '100%';
      toast('Analysis complete — ' + state.allRows.length + ' events processed', 'success');
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
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    try {
      if (!state.assessmentId) { toast('No assessment — run Analyze first', 'error'); return; }
      var row = state.allRows[idx] || {};
      var resp = await fetch('/api/v1/csv/deep_analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({
          rows: [{ row_index: idx, raw: row }],
          options: { auto_llm: true },
          org: localStorage.getItem('org') || 'local',
        }),
      });
      if (!resp.ok) throw new Error('LLM request failed');
      var data = await resp.json();
      // Poll for the LLM result
      var aid = data.assessment_id;
      var result = await pollAssessment(aid, 60000);
      var llmRows = result.llm_rows || [];
      if (llmRows.length > 0 && state.evidenceRows) {
        var evRow = state.evidenceRows.find(function (r) { return r.row_index === idx; });
        if (evRow) {
          evRow._hasLlm = true;
          evRow._llmSummary = llmRows[0];
          showDetail(evRow);
        }
      }
      toast('T1 summary generated for row ' + idx, 'success');
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

    // Build report sections
    var sections = [];

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

    // Immediate Actions
    var actionsHtml = '<ul>';
    if (critCount > 0) {
      actionsHtml += '<li><b>NOW:</b> Review the ' + critCount + ' critical event' + (critCount !== 1 ? 's' : '') + ' in the Evidence tab — confirm whether affected entities require isolation.</li>';
      actionsHtml += '<li><b>NOW:</b> Check if correlated entities appear in other monitoring tools not included in this upload.</li>';
    }
    if (highCount > 0) {
      actionsHtml += '<li><b>4h:</b> Investigate ' + highCount + ' high-severity events — validate whether observed access changes were authorized.</li>';
    }
    actionsHtml += '<li><b>Next:</b> Use the Evidence tab to drill into individual events. Click T1 for AI-assisted summary of any row.</li>';
    actionsHtml += '</ul>';
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

    renderPersonaChips();
  }

  // ── Detail panel ─────────────────────────────────────────────────────────
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

    // LLM summary if available
    if (row._llmSummary) {
      var llm = row._llmSummary;
      html += '<div class="report-section"><div class="report-section__title">AI Summary (T1)</div><div class="report-section__body">';
      html += '<p>' + escHtml(llm.summary || llm.llm_summary || llm.narrative || JSON.stringify(llm).substring(0, 500)) + '</p>';
      html += '</div></div>';
    } else {
      html += '<div class="mt-3"><button class="btn-primary" id="btnDetailLLM" data-idx="' + row.row_index + '">';
      html += '<i data-lucide="sparkles" style="width:14px;height:14px;"></i> Generate T1 Summary</button></div>';
    }

    // Raw data (collapsed)
    html += '<details class="mt-3" style="font-size:12px;"><summary style="cursor:pointer;color:var(--text-muted);font-weight:500;">Raw Event Data</summary>';
    html += '<pre style="margin-top:8px;white-space:pre-wrap;word-break:break-all;color:var(--text-secondary);font-size:11px;max-height:300px;overflow:auto;background:var(--bg-tertiary);padding:10px;border-radius:var(--radius-sm);">' + escHtml(JSON.stringify(row.raw, null, 2)) + '</pre>';
    html += '</details>';

    // Quick actions
    html += '<div class="mt-3" style="display:flex;gap:6px;flex-wrap:wrap;">';
    html += '<button class="btn-secondary" onclick="toast(\'Marked as FP\',\'success\')"><i data-lucide="check-circle" style="width:12px;height:12px;"></i> Mark FP</button>';
    html += '<button class="btn-secondary" onclick="toast(\'Escalated\',\'success\')"><i data-lucide="alert-triangle" style="width:12px;height:12px;"></i> Escalate</button>';
    html += '<button class="btn-secondary" onclick="toast(\'Incident created\',\'success\')"><i data-lucide="siren" style="width:12px;height:12px;"></i> Create Incident</button>';
    html += '</div>';

    $('detailBody').innerHTML = html;
    if (window.lucide) lucide.createIcons();

    // Wire the T1 button in detail panel
    var llmBtn = document.getElementById('btnDetailLLM');
    if (llmBtn) {
      llmBtn.addEventListener('click', function () {
        requestRowLLM(parseInt(llmBtn.getAttribute('data-idx'), 10), llmBtn);
      });
    }

    // Highlight the selected row in the table
    document.querySelectorAll('#evidenceBody tr').forEach(function (tr) {
      tr.classList.toggle('selected', tr.getAttribute('data-idx') === String(row.row_index));
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
      try { win.postMessage({ type: 'content', tab: name, html: html }, '*'); } catch (_) {}
      toast(name + ' detached to new window', 'success');
    }
  }

  // Wire detach buttons
  ['Report', 'Evidence', 'Graph', 'Timeline', 'Detail'].forEach(function (name) {
    var btn = $('btnDetach' + name);
    if (btn) btn.addEventListener('click', function () { detachTab(name.toLowerCase()); });
  });

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

    var svg = d3.select(canvas).append('svg').attr('width', W).attr('height', H).style('display', 'block').style('border-radius', 'var(--radius-lg)');
    var g = svg.append('g');
    svg.call(d3.zoom().scaleExtent([0.25, 3]).on('zoom', function (event) { g.attr('transform', event.transform); }));

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

})();
