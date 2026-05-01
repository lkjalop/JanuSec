/* breach_cluster_tab.js — Cluster detail tab for breach.html
 *
 * Exposed global:
 *   BreachClusterTab.mount(containerId, cluster, allRows, assessmentId, allClusters)
 *
 * Features:
 *   - Header with verdict/confidence/incident_name (T1 prefill)
 *   - E8: verdict_reasoning block (removed — duplicated root_cause after prefill normalisation)
 *   - E9: Kill-chain timeline (GET /timeline, grouped by phase)
 *   - Persona tabs: SOC / Hunter / Forensics (E13: [Generate] button → tier2)
 *   - EXPAND per step → subtasks with tool_command
 *   - [Further tasks] button → POST /further-tasks when all steps expanded
 *   - E10: Analyst sticky notes (PATCH /notes, auto-save on blur)
 *   - E11: IOC export (client-side Blob download)
 *   - E12: Repeat entity detection (GET /repeat-entities)
 *   - A7: Sign-off row (CONFIRMED / ESCALATE / DISMISS / DEFER + Print)
 *
 * LLM gate: tier2 persona generation fires ONLY on [Generate for …] click.
 * Nothing fires on tab-switch, focus, or scroll.
 */
(function (global) {
  'use strict';

  var BreachClusterTab = {};

  // ── Helpers ──────────────────────────────────────────────────────────────────

  function _esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
                          .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _apiBase() { return window.JANUSEC_API_BASE || ''; }

  function _authHdrs(extra) {
    var k = '';
    var t = 'default';
    try { k = localStorage.getItem('apiKey') || ''; } catch (_) {}
    try { t = localStorage.getItem('tenantId') || 'default'; } catch (_) {}
    var h = Object.assign({ 'Content-Type': 'application/json' }, extra || {});
    if (k) h['x-api-key'] = k;
    h['x-tenant-id'] = t;
    return h;
  }

  function _get(path) {
    return fetch(_apiBase() + path, { headers: _authHdrs() });
  }

  function _post(path, body) {
    return fetch(_apiBase() + path, {
      method: 'POST',
      headers: _authHdrs(),
      body: JSON.stringify(body || {}),
    });
  }

  function _rowsForCluster(cluster) {
    var refs = new Set((cluster.row_refs || []).map(function (r) { return String(r); }));
    return ((_ctx && _ctx.allRows) || []).filter(function (row) {
      return refs.has(String(row.row_index)) || refs.has(String(row.row_number));
    });
  }

  function _mitreForCluster(cluster, p) {
    var explicit = p.mitre_techniques || cluster.mitre_techniques || cluster.top_mitre || [];
    if (Array.isArray(explicit) && explicit.length) return explicit;
    var seen = new Set();
    _rowsForCluster(cluster).forEach(function (row) {
      var values = [];
      if (row.mitre_technique) values.push(row.mitre_technique);
      if (Array.isArray(row.mitre)) values = values.concat(row.mitre);
      if (Array.isArray(row.mitre_techniques)) values = values.concat(row.mitre_techniques);
      values.forEach(function (t) {
        t = String(t || '').trim();
        if (t) seen.add(t);
      });
    });
    return Array.from(seen);
  }

  function _patch(path, body) {
    return fetch(_apiBase() + path, {
      method: 'PATCH',
      headers: _authHdrs(),
      body: JSON.stringify(body || {}),
    });
  }

  var SEV_COLOR = { critical: '#E54848', high: '#FF8A3C', medium: '#E0C446', low: '#3FA860', info: '#5B8FD4' };
  var VERDICT_COLOR = {
    'VALIDATED_BREACH': '#E54848', 'CONFIRMED_INTRUSION': '#FF8A3C',
    'LIKELY_COMPROMISE': '#E0C446', 'SUSPICIOUS_ACTIVITY': '#90BA55',
    'INSUFFICIENT_TELEMETRY': '#5B8FD4', 'BENIGN_EXPECTED': '#3FA860',
    'CONFIRMED': '#E54848', 'LIKELY REAL': '#FF8A3C', 'LIKELY': '#FF8A3C',
    'UNCERTAIN': '#E0C446', 'BENIGN': '#3FA860',
  };
  var GATE_STYLE = {
    URGENT: { color: '#ff9090', border: '#e05252', bg: '#3d0a0a', label: 'URGENT SIGN-OFF REQUIRED' },
    HIGH:   { color: '#ffb090', border: '#ff7c3c', bg: '#3d1a00', label: 'SIGN-OFF REQUIRED' },
    NORMAL: { color: '#ffe090', border: '#e0c446', bg: '#2a2000', label: 'HUMAN VALIDATION REQUIRED' },
    LOW:    { color: '#a6e3a1', border: '#3fa860', bg: '#0d1a0d', label: 'AUTO TRIAGED' },
  };
  var PHASE_COLOR = {
    'Reconnaissance': '#9B8EC4', 'Resource Development': '#9B8EC4',
    'Initial Access': '#E54848', 'Execution': '#FF8A3C',
    'Persistence': '#E0C446', 'Privilege Escalation': '#FF8A3C',
    'Defense Evasion': '#5B8FD4', 'Credential Access': '#E54848',
    'Discovery': '#5B8FD4', 'Lateral Movement': '#FF8A3C',
    'Collection': '#E0C446', 'Command & Control': '#E54848',
    'Exfiltration': '#E54848', 'Impact': '#E54848', 'Unknown': '#555',
  };

  var PERSONA_META = {
    soc_analyst: { label: 'SOC Analyst', icon: '🛡', focus: 'Contain & Triage' },
    threat_hunter: { label: 'Threat Hunter', icon: '🔍', focus: 'Pivot & Hunt' },
    forensics: { label: 'Forensics', icon: '🔬', focus: 'Preserve & Analyse' },
  };

  // Tab state — which persona tab is active
  var _activePersona = 'soc_analyst';
  // Track which steps are expanded
  var _expandedSteps = {};
  // Current cluster data references (set on mount)
  var _ctx = {};

  function _selectedModel() {
    try { return localStorage.getItem('selectedModel') || 'qwen3:30b'; } catch (_) { return 'qwen3:30b'; }
  }

  function _caseTitle(cluster, p) {
    p = p || {};
    var title = p.incident_name || cluster.incident_name || '';
    if (title && !/^cluster-\d+$/i.test(title)) return title;
    var fallback = cluster.lead_description || cluster.reason_summary || 'Threat Case';
    if (/^DAY\s+\d+\s*:/i.test(fallback) || fallback.length > 72) return 'Threat Case';
    return fallback;
  }

  function _rawCorrelationText(s) {
    // Catches old correlation-engine boilerplate AND generic phase-count metadata strings.
    return /shared attacker|shared identity|same network|same host sequence|same ATT&CK|identity compromise or shared actor|external infrastructure appears|\d+\s+attack\s+phases?\s+observed|\d+\s+telemetry\s+sources?\b/i.test(String(s || ''));
  }

  function _caseSubtitle(cluster, p, title) {
    var sub = String((p || {}).headline_subtitle || '').trim();
    if (sub && !_rawCorrelationText(sub)) return sub;
    var text = [title, cluster.lead_description, cluster.reason_summary, cluster.business_significance].join(' ').toLowerCase();
    var rows = (cluster.row_refs || []).length;
    if (/bec|mailbox|wire|finance/.test(text)) return rows + ' evidence rows connect identity compromise, mailbox activity, and payment-risk evidence.';
    if (/dns|c2|beacon|command/.test(text)) return rows + ' evidence rows show command-and-control activity requiring containment and egress review.';
    if (/npm|supply|github|token|secret/.test(text)) return rows + ' evidence rows show developer or supply-chain activity requiring token and repository review.';
    return rows + ' correlated evidence rows require analyst review before closure.';
  }

  function _caseNarrative(cluster, p, title, subtitle) {
    var narrative = String((p || {}).what_happened || (p || {}).short_narrative || '').trim();
    if (narrative && !_rawCorrelationText(narrative)) return narrative;
    if (/bec|mailbox|wire|finance/i.test(title + ' ' + subtitle)) return 'JanuSec linked identity access, mailbox activity, and payment-risk evidence into a business email compromise threat case.';
    if (/dns|c2|beacon|command/i.test(title + ' ' + subtitle)) return 'JanuSec linked repeated network egress and endpoint evidence into a command-and-control threat case.';
    if (/npm|supply|github|token|secret/i.test(title + ' ' + subtitle)) return 'JanuSec linked developer activity, token exposure, and repository evidence into a supply-chain threat case.';
    return subtitle || narrative;
  }

  function _renderGateBanner(cluster) {
    if (!cluster.human_validation_required && !cluster.gate_urgency) return '';
    var urgency = String(cluster.gate_urgency || (cluster.human_validation_required ? 'NORMAL' : 'LOW')).toUpperCase();
    var style = GATE_STYLE[urgency] || GATE_STYLE.NORMAL;
    var status = cluster.playbook_status || (cluster.human_validation_required ? 'awaiting_signoff' : 'auto_triaged');
    return [
      '<div class="hvr-gate gate-banner" data-testid="bct-hvr-gate" style="margin:0 0 10px 0;padding:8px 10px;border-left:3px solid ',
      style.border,
      ';background:', style.bg,
      ';color:', style.color,
      ';border-radius:6px;font-size:11px;display:flex;justify-content:space-between;gap:12px;">',
      '<strong>', _esc(style.label), '</strong>',
      '<span style="opacity:.75;">', _esc(status), '</span>',
      '</div>',
    ].join('');
  }

  // ── Mount entry point ────────────────────────────────────────────────────────

  BreachClusterTab.mount = function (containerId, cluster, allRows, assessmentId, allClusters) {
    var container = document.getElementById(containerId);
    if (!container) return;

    _ctx = { containerId: containerId, cluster: cluster, allRows: allRows, assessmentId: assessmentId, allClusters: allClusters };
    _expandedSteps = {};

    container.innerHTML = _buildSkeleton(cluster, assessmentId);
    _wireSignOff(cluster, assessmentId);
    _wireNotes(cluster, assessmentId);
    _wireIocExport(cluster, allRows, assessmentId);
    _wireThreatModelRefresh(cluster, assessmentId);

    // Fetch timeline (E9)
    _loadTimeline(cluster, assessmentId);
    // Fetch repeat entities (E12)
    _loadRepeatEntities(cluster, assessmentId);
    // Crown jewels human gate panel
    _loadCrownJewelsReview(cluster);
    // Load persona tab (from tier2 cache if available, no LLM call)
    _loadPersonaTab(_activePersona, cluster, assessmentId, false);
  };

  // ── Skeleton (synchronous HTML) ──────────────────────────────────────────────

  function _displayVerdict(verdict) {
    var raw = String(verdict || '').toUpperCase();
    if (raw === 'VALIDATED_BREACH' || raw === 'CONFIRMED_INTRUSION' || raw === 'CONFIRMED_BREACH') return 'CONFIRMED BREACH';
    if (raw === 'NO_VALIDATED_BREACH') return 'NO CONFIRMED BREACH';
    if (raw === 'ANALYSIS_INCOMPLETE') return 'ANALYSIS INCOMPLETE';
    return raw.replace(/_/g, ' ') || 'UNCERTAIN';
  }

  function _staleClusterBadge(cluster) {
    if (cluster.cluster_kind) return '';
    return '<span class="bct-stale-badge" style="background:#7c2d2d;color:#fca5a5;font-size:11px;padding:2px 6px;border-radius:3px;margin-left:8px;" title="Cluster was produced without canonical fields — re-ingest required for typed analysis">stale</span>';
  }

  function _dreadScoreBadge(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var ds = p.dread_score;
    if (!ds || typeof ds.total === 'undefined') return '';
    var total = ds.total || 0;
    var tier  = ds.risk_tier || '';
    var color = total > 35 ? '#ef4444' : total > 20 ? '#f97316' : '#eab308';
    var dims  = ['D', 'R', 'E', 'A', 'D'].map(function (letter, i) {
      var keys = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'];
      var val  = ds[keys[i]];
      return letter + ':' + (typeof val === 'number' ? val : '?');
    }).join(' ');
    var tip = 'DREAD: ' + dims + ' — ' + tier + ' (' + total + '/50)';
    return '<span class="bct-dread-badge" title="' + _esc(tip) + '" style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:12px;border:1px solid ' + color + ';color:' + color + ';font-size:11px;font-weight:600;margin-left:8px;cursor:default;">'
      + '<svg width="11" height="11" viewBox="0 0 20 20"><circle cx="10" cy="10" r="8" fill="none" stroke="' + color + '" stroke-width="3" stroke-dasharray="' + Math.round(total * 50.3 / 50) + ' 503" stroke-linecap="round" transform="rotate(-90 10 10)"/></svg>'
      + _esc(total + '/50') + ' ' + _esc(tier)
      + '</span>';
  }

  function _dreadInfo(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var dn = p.dread_narrative || {};
    var frags = dn.fragments || {};
    var order = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'];
    var parts = order.filter(function (k) { return !!frags[k]; }).map(function (k) {
      return { key: k, label: k.replace(/_/g, ' ').toUpperCase(), text: String(frags[k]) };
    });
    var hasPasta = !!(p.pasta_summary && (p.pasta_summary.threat_profile || p.pasta_summary.exploitation_path || p.pasta_summary.business_impact));
    var hasDiamond = !!(p.diamond_model && (p.diamond_model.adversary || (p.diamond_model.capability && p.diamond_model.capability.length)));
    var provenance;
    if (dn.rendered) {
      provenance = 'LLM-rendered DREAD';
    } else if (parts.length) {
      provenance = 'Deterministic DREAD fragments';
    } else if (hasPasta) {
      provenance = 'PASTA threat model';
    } else if (hasDiamond) {
      provenance = 'DIAMOND threat model';
    } else {
      provenance = 'Legacy fallback';
    }
    return { dn: dn, frags: frags, parts: parts, has: !!(dn.rendered || parts.length), hasPasta: hasPasta, hasDiamond: hasDiamond, provenance: provenance };
  }

  function _rowChips(text, limit) {
    var out = [];
    String(text || '').replace(/\brows?\s+([0-9][0-9,\s+]*(?:\+\s*\d+\s+more)?)/ig, function (_, group) {
      var clean = String(group || '').replace(/\+\s*\d+\s*(?:more)?/ig, '');
      (clean.match(/\d+/g) || []).forEach(function (n) {
        if (out.indexOf(n) === -1 && out.length < (limit || 18)) out.push(n);
      });
      return _;
    });
    if (!out.length) return '';
    return '<div class="bct-rowchips">Evidence refs: ' + out.map(function (n) {
      return '<a class="bct-rowchip" href="/static/breach.html?assessment=' + encodeURIComponent(_ctx.assessmentId) + '&tab=evidence&row=' + encodeURIComponent(n) + '">[' + _esc(n) + ']</a>';
    }).join(' ') + '</div>';
  }

  function _whyConfirmed(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    var full = (d.parts.map(function (x) { return x.text; }).join(' ') + ' ' + JSON.stringify(p.observed_impact || {})).toLowerCase();
    var gates = [
      ['Data movement', /exfil|copy into|unload|rclone|cloud sync|transferred data|cloud storage/.test(full)],
      ['Repeated activity', /recurred|distinct days|same command|reproduc/.test(full)],
      ['Affected users', /account|user|service_account|privileged|affected users/.test(full)],
      ['Control gap', /no dlp|no pam|control gap|unconstrained|no inspection|no gate/.test(full)],
      ['Crown jewel', /crown jewel|regulated data|critical data|protected data|ndb|cps234/.test(full)],
      ['Multi-source correlation', /cross-source|source types|multiple sources|correlation/.test(full)]
    ];
    return '<div class="bct-why-ladder">' + gates.map(function (g) {
      return '<span class="bct-why-chip ' + (g[1] ? 'bct-why-chip--ok' : 'bct-why-chip--miss') + '">' + (g[1] ? 'OK ' : '? ') + _esc(g[0]) + '</span>';
    }).join('') + '</div>';
  }

  function _buildEvidenceNarrative(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    if (!d.has) return '';
    var body = d.dn.rendered
      ? '<p>' + _esc(d.dn.rendered) + '</p>' + _rowChips(d.dn.rendered, 12)
      : d.parts.map(function (part) {
          return '<div class="bct-dread-frag"><strong>' + _esc(part.label) + '</strong><span>' + _esc(part.text) + '</span>' + _rowChips(part.text, 8) + '</div>';
        }).join('');
    var sabsa = d.dn.sabsa_coda_draft ? '<div class="bct-sabsa"><strong>SABSA:</strong> ' + _esc(d.dn.sabsa_coda_draft) + '</div>' : '';
    return [
      '<div class="bct-section bct-evidence-narrative" data-testid="bct-evidence-narrative">',
      '  <div class="bct-section-head">EVIDENCE NARRATIVE <span class="bct-source-strip">source: ' + _esc(d.provenance) + '</span></div>',
      _whyConfirmed(cluster),
      body,
      sabsa,
      '  <div class="bct-framework-lite">',
      (function() {
        var ds = p.dread_score;
        if (ds && typeof ds.total === 'number') {
          var color = ds.total > 35 ? '#ef4444' : ds.total > 20 ? '#f97316' : '#eab308';
          var dimHtml = [
            ['Damage', 'damage', 'damage_detail'],
            ['Reproducibility', 'reproducibility', 'reproducibility_detail'],
            ['Exploitability', 'exploitability', 'exploitability_detail'],
            ['Affected Users', 'affected_users', 'affected_users_detail'],
            ['Discoverability', 'discoverability', 'discoverability_detail'],
          ].map(function (row) {
            var score = ds[row[1]];
            var detail = _esc(String(ds[row[2]] || '').replace(/\.$/, ''));
            return '<div style="display:flex;gap:8px;align-items:baseline;margin:2px 0;">'
              + '<span style="font-size:11px;color:var(--text-muted);width:110px;">' + _esc(row[0]) + '</span>'
              + '<span style="font-weight:700;color:' + color + ';width:18px;">' + (typeof score === 'number' ? score : '?') + '</span>'
              + (detail ? '<span style="font-size:11px;color:var(--text-muted);">' + detail + '</span>' : '')
              + '</div>';
          }).join('');
          return '<div style="margin:6px 0 8px;">'
            + '<strong>DREAD score:</strong> <span style="color:' + color + ';font-weight:700;">' + ds.total + '/50 — ' + _esc(ds.risk_tier) + '</span>'
            + '<div style="margin-top:4px;padding-left:8px;">' + dimHtml + '</div>'
            + '</div>';
        }
        return '<div><strong>DREAD:</strong> ' + _esc(d.parts.map(function (x) { return x.label; }).join(' / ')) + '</div>';
      })(),
      '    <div><strong>Diamond:</strong> adversary, capability, infrastructure, and victim are derived from cited rows.</div>',
      '    <div><strong>PASTA:</strong> threat action to control gap to business impact is visible in Damage and Exploitability.</div>',
      '    <div><strong>SABSA:</strong> ' + _esc((d.dn.sabsa_attributes || []).join(', ') || 'not mapped') + '</div>',
      '    <div><strong>MITRE:</strong> ' + _esc((_mitreForCluster(cluster, p) || []).slice(0, 8).join(', ') || 'not mapped') + '</div>',
      '    <div><strong>Controls:</strong> DLP, PAM, cloud egress, endpoint preservation, and regulatory assessment stay tied to cited rows.</div>',
      '  </div>',
      '</div>'
    ].join('');
  }

  function _firstNonEmpty(values, fallback) {
    for (var i = 0; i < values.length; i++) {
      var v = values[i];
      if (Array.isArray(v) && v.length) return v.join(', ');
      if (v && String(v).trim()) return String(v).trim();
    }
    return fallback || '';
  }

  function _rowsSummary(cluster) {
    var refs = (cluster.row_refs || []).slice(0, 8);
    if (!refs.length) return 'No row references attached to this case.';
    return refs.join(' | ') + ((cluster.row_refs || []).length > refs.length ? ' | +' + ((cluster.row_refs || []).length - refs.length) + ' more' : '');
  }

  function _modelAnswer(title, question, answer, evidenceText) {
    return '<div class="bct-model-answer">'
      + '<div class="bct-model-answer__title">' + _esc(title) + '</div>'
      + '<div class="bct-model-answer__question">' + _esc(question) + '</div>'
      + '<div class="bct-model-answer__body">' + _esc(answer || 'Not answered yet from current evidence. Generate or verify with row-level evidence before making a decision.') + '</div>'
      + _rowChips(evidenceText || answer || '', 8)
      + '</div>';
  }

  function _buildDreadWorkbench(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var d = _dreadInfo(cluster);
    var ds = p.dread_score || {};
    var frags = d.frags || {};
    var impact = p.observed_impact || {};
    return '<details class="bct-model-section" open data-model-section="dread">'
      + '<summary>DREAD <span>blast radius, repeatability, exploitation, affected users, discoverability</span></summary>'
      + _modelAnswer('Damage',
          'What exact infrastructure, accounts, subnets, cloud resources, data stores, and data classes are affected or plausibly exposed?',
          frags.damage || ds.damage_detail || _firstNonEmpty([impact.data, impact.operational], 'Blast radius is not fully proven. Verify asset contents, subnet/security group scope, destination ownership, and whether the data is PII, credentials, scripts, or non-sensitive operational data.'),
          frags.damage || '')
      + _modelAnswer('Reproducibility',
          'Can this be repeated with the same credentials, session, command pattern, tool, token, route, or schedule?',
          frags.reproducibility || ds.reproducibility_detail || 'Check whether the same command, session, account, host, cloud role, or destination recurs over time and whether credentials remain valid.',
          frags.reproducibility || '')
      + _modelAnswer('Exploitability',
          'How hard is the observed or suspected technique to run, and what missing controls made it practical?',
          frags.exploitability || ds.exploitability_detail || 'Assess whether commodity tooling was enough, whether admin privilege was required, and whether DLP, PAM, egress, MFA, or segmentation should have blocked it.',
          frags.exploitability || '')
      + _modelAnswer('Affected Users',
          'Who was affected, what privileges did they have, and was their access normal for their role and history?',
          frags.affected_users || ds.affected_users_detail || _firstNonEmpty([impact.identity], 'Verify user privilege level, group membership, MFA state, role changes, lateral movement, and whether this behavior matches the account baseline.'),
          frags.affected_users || '')
      + _modelAnswer('Discoverability',
          'What should have detected this, what actually detected it, and what telemetry missed it?',
          frags.discoverability || ds.discoverability_detail || 'Map the activity window to alert coverage. Identify missing SIEM rules, DLP alerts, identity analytics, EDR telemetry, cloud audit logs, data warehouse logs, or bitemporal decision trace gaps.',
          frags.discoverability || '')
      + '</details>';
  }

  function _buildPastaWorkbench(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var pasta = p.pasta_summary || {};
    var d = _dreadInfo(cluster);
    var damage = (d.frags || {}).damage || '';
    var exploit = (d.frags || {}).exploitability || '';
    return '<details class="bct-model-section" open data-model-section="pasta">'
      + '<summary>PASTA <span>business objective to attack path to impact</span></summary>'
      + _modelAnswer('Business objective',
          'Which business process, asset, data class, or regulatory obligation are we protecting in this case?',
          pasta.business_objective || pasta.business_impact || 'Protect the affected business process and data until asset classification and ownership are verified.',
          pasta.business_impact || damage)
      + _modelAnswer('Technical scope',
          'Which users, hosts, shares, cloud accounts, buckets, subnets, security groups, and integrations are in scope?',
          pasta.technical_scope || 'Scope must be built from the affected identity, host/resource, destination, network path, and cited rows.',
          damage)
      + _modelAnswer('Architecture / trust boundaries',
          'Where did activity cross trust boundaries such as user to host, host to subnet, subnet to internet, cloud role to storage, or tenant to third party?',
          pasta.trust_boundaries || 'Verify VPC/subnet/security group, identity boundary, egress path, cloud account, and third-party storage ownership.',
          damage + ' ' + exploit)
      + _modelAnswer('Attack path',
          'What sequence links initial access, credential/session use, privilege, lateral movement, collection, and exfiltration?',
          pasta.exploitation_path || pasta.threat_profile || _caseNarrative(cluster, p, _caseTitle(cluster, p), _caseSubtitle(cluster, p, _caseTitle(cluster, p))),
          pasta.exploitation_path || '')
      + _modelAnswer('Control failure',
          'Which preventive, detective, or response controls should have stopped or alerted on this activity?',
          pasta.control_failure || exploit || 'Control failure is not fully proven. Query DLP, PAM, egress, segmentation, identity analytics, EDR, and cloud audit coverage.',
          exploit)
      + _modelAnswer('Business impact',
          'How does the technical event translate into customer, regulatory, operational, financial, or board-level impact?',
          pasta.business_impact || damage || 'Impact ranges from operational exposure to regulated-data breach depending on data classification and destination ownership.',
          damage)
      + '</details>';
  }

  function _buildDiamondWorkbench(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var diamond = p.diamond_model || {};
    var infra = p.attacker_infrastructure || {};
    var rows = _rowsForCluster(cluster);
    var users = Array.from(new Set(rows.map(function (r) { return r.user || r.user_principal_name || r.account || r.actor; }).filter(Boolean))).slice(0, 8);
    var hosts = Array.from(new Set(rows.map(function (r) { return r.hostname || r.host || r.device_name || r.resource; }).filter(Boolean))).slice(0, 8);
    var ips = Array.from(new Set(rows.map(function (r) { return r.src_ip || r.source_ip || r.dst_ip || r.destination_ip || r.ip; }).filter(Boolean))).slice(0, 10);
    var capabilities = Array.isArray(diamond.capability) ? diamond.capability.join(', ') : diamond.capability;
    var victims = Array.isArray(diamond.victim) ? diamond.victim.join(', ') : diamond.victim;
    var infraText = _firstNonEmpty([diamond.infrastructure, infra.c2_ips, infra.ips, infra.domains, ips, hosts], 'Infrastructure is not fully classified yet.');
    return '<details class="bct-model-section" open data-model-section="diamond">'
      + '<summary>Diamond <span>adversary, capability, infrastructure, victim, pivots</span></summary>'
      + _modelAnswer('Adversary',
          'Who or what appears to be operating the activity, and what does the evidence prove versus infer?',
          diamond.adversary || 'Unknown actor or compromised account. Current evidence should not over-claim attribution without identity, infrastructure ownership, or campaign correlation.',
          diamond.adversary || '')
      + _modelAnswer('Capability',
          'What capabilities were shown, how mature are they, and what does that signify for repeatability or scale?',
          capabilities || 'Capability must be inferred from tools, commands, techniques, access level, data movement, and persistence indicators.',
          capabilities || '')
      + _modelAnswer('Infrastructure',
          'Which internal and external infrastructure was used or affected, and why does it matter?',
          infraText,
          infraText)
      + _modelAnswer('Victim',
          'Who is confirmed affected and who could be adjacent based on account groups, peer hosts, subnets, shares, or cloud roles?',
          victims || _firstNonEmpty([users, hosts], 'Victim scope requires user, host, group, subnet, and cloud-account expansion.'),
          victims || users.join(' ') + ' ' + hosts.join(' '))
      + _modelAnswer('Next hunts',
          'What should hunters pivot on next?',
          'Pivot same user/session across identity and cloud logs; same destination across proxy/DNS/cloud logs; same command/tool across hosts; same subnet/security group with unusual egress; adjacent shares and cloud roles for related access.',
          _rowsSummary(cluster))
      + '</details>';
  }

  function _buildThreatModelWorkbench(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var d = _dreadInfo(cluster);
    return [
      '<div class="br-threat-model bct-threat-model-workbench" data-testid="bct-threat-model-workbench">',
      '<div class="bct-model-head">',
      '<div><div class="bct-section-head">EVIDENCE-BACKED THREAT MODEL</div>',
      '<div class="bct-model-sub">Per-cluster DREAD, PASTA, and Diamond reasoning. Answers should cite rows and stay explicit about unknowns.</div></div>',
      '<button class="bct-btn bct-btn--primary" id="bct-threat-model-refresh" data-testid="bct-threat-model-refresh">Generate / refresh threat model</button>',
      '</div>',
      '<div class="bct-model-rail">',
      '<div><strong>Source</strong><span>' + _esc(d.provenance) + '</span></div>',
      '<div><strong>Evidence rows</strong><span>' + (cluster.row_refs || []).length + '</span></div>',
      '<div><strong>Last known</strong><span>' + _esc(p.generated_at || p.updated_at || 'current assessment state') + '</span></div>',
      '<div><strong>Decision trace</strong><span>Use cited rows and bitemporal state before broad remediation.</span></div>',
      '</div>',
      '<div class="bct-model-grid">',
      _buildDreadWorkbench(cluster),
      _buildPastaWorkbench(cluster),
      _buildDiamondWorkbench(cluster),
      '</div>',
      '</div>',
    ].join('');
  }

  function _firstEvidenceSentence(cluster, fallback) {
    var d = _dreadInfo(cluster);
    var damage = (d.frags && d.frags.damage) || '';
    var repro = (d.frags && d.frags.reproducibility) || '';
    function sentences(text) {
      return String(text || '').replace(/\s+/g, ' ').split(/(?<=[.!?])\s+/).map(function (s) { return s.trim(); }).filter(Boolean);
    }
    return [sentences(damage)[0], sentences(repro)[0]].filter(Boolean).join(' ') || fallback || '';
  }

  function _knownUnknownBox(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    var text = (d.parts.map(function (x) { return x.text; }).join(' ') + ' ' + JSON.stringify(p.observed_impact || {})).toLowerCase();
    var known = [];
    var unknown = [];
    if (/rclone/.test(text)) known.push('Tool: rclone file-sync activity');
    if (/cloud storage|external storage|object storage/.test(text)) known.push('Destination: external cloud storage indicated by evidence');
    if (/crown jewel|regulated data|critical data|protected data/.test(text)) known.push('Crown-jewel or protected data indicator present in evidence');
    if (/no dlp/.test(text) || /no pam/.test(text)) known.push('Control gaps: DLP/PAM coverage missing in evidence');
    if (/service account|privileged|finance|standard user/.test(text)) known.push('Affected roles: service account, privileged/IT, finance, standard users');
    if (!/pii|customer|payroll|secret|source code|credential dump/.test(text)) unknown.push('Exact data contents are unknown from current evidence');
    if (!/attacker-owned|external owner|malicious owner/.test(text)) unknown.push('External destination ownership is unknown from current evidence');
    if (!known.length) known.push('Evidence-confirmed facts are limited to the cited rows');
    return '<div class="bct-known-unknown"><div><strong>Known</strong><ul>' + known.map(function (x) { return '<li>' + _esc(x) + '</li>'; }).join('') + '</ul></div><div><strong>Unknown / not proven</strong><ul>' + unknown.map(function (x) { return '<li>' + _esc(x) + '</li>'; }).join('') + '</ul></div></div>';
  }

  function _buildCjEvidenceSeed(cluster) {
    var d = _dreadInfo(cluster);
    var text = d.parts.map(function (x) { return x.text; }).join(' ') + ' ' + JSON.stringify(((cluster || {}).tier1_prefill || {}).observed_impact || {});
    var names = [];
    ['crown jewel', 'regulated data', 'critical data', 'protected data'].forEach(function (needle) {
      if (text.toLowerCase().indexOf(needle.toLowerCase()) !== -1 && names.indexOf(needle) === -1) names.push(needle);
    });
    if (!names.length) return '';
    return [
      '<div class="bct-cj-panel">',
      '  <div class="bct-section-head" style="margin-bottom:8px;">CROWN JEWELS IN SCOPE <span style="font-size:10px;color:var(--text-muted);font-weight:400;margin-left:8px;">evidence-derived, registry resolving</span></div>',
      names.map(function (x) {
        return '<div class="bct-cj-entry"><div class="bct-cj-main"><span class="bct-cj-key">' + _esc(x) + '</span><span class="bct-cj-badge" style="color:#E0C446;border-color:#E0C446;">pending registry</span></div></div>';
      }).join(''),
      '</div>'
    ].join('');
  }

  function _buildSkeleton(cluster, assessmentId) {
    var p = cluster.tier1_prefill || {};
    var verdict = (cluster.verdict || cluster.final_verdict || 'UNCERTAIN').toUpperCase();
    var vc = VERDICT_COLOR[verdict] || '#888';
    var sev = (cluster.severity || 'info').toLowerCase();
    var sc = SEV_COLOR[sev] || '#888';
    var meter = p.confidence_meter || cluster.confidence_meter;
    var signOff = cluster.sign_off || {};
    var notes = cluster.analyst_notes || {};
    var xlinks = (p.cross_cluster_links || []).slice(0, 4);
    var caseTitle = _caseTitle(cluster, p);
    var caseSubtitle = _caseSubtitle(cluster, p, caseTitle);

    return [
      '<div class="bct-wrap" data-testid="bct-wrap">',

      // ── Back nav
      '<div class="bct-nav">',
      '  <a class="bct-back" href="/static/breach.html?assessment=' + encodeURIComponent(assessmentId) + '">← Back to Assessment</a>',
      '  <span class="bct-nav__cid">Threat Case Detail</span>',
      '</div>',

      // ── Header card
      '<div class="bct-header">',
      _renderGateBanner(cluster),
      '  <div class="bct-header__verdict" style="border-left-color:' + vc + '">',
      '    <span class="bct-header__verdict-pill" style="background:' + vc + '22;color:' + vc + '">' + _esc(_displayVerdict(verdict)) + '</span>' + _staleClusterBadge(cluster),
      '    <span class="bct-header__sev" style="color:' + sc + '">' + _esc(sev.toUpperCase()) + '</span>',
      '    <span class="bct-header__rows">' + (cluster.row_refs || []).length + ' rows</span>',
      meter ? '<span class="bct-header__conf">' + Math.round(meter.total) + '% confidence</span>' : '',
      _dreadScoreBadge(cluster),
      '  </div>',
      '  <div class="bct-header__title">' + _esc(caseTitle) + '</div>',
      caseSubtitle ? '<div class="bct-header__sub">' + _esc(caseSubtitle) + '</div>' : '',
      // what_happened is primary narrative — short_narrative is fallback
      (function() {
        var narrative = _firstEvidenceSentence(cluster, _caseNarrative(cluster, p, caseTitle, caseSubtitle));
        return narrative ? '<div class="bct-what-happened"><div class="bct-label">WHAT HAPPENED</div><div>' + _esc(narrative) + '</div></div>' : '';
      })(),
      _knownUnknownBox(cluster),
      '<details class="bct-technical-basis">',
      '<summary>Technical basis</summary>',
      p.root_cause ? '<div class="bct-header__root-cause"><span class="bct-label">Root cause:</span> ' + _esc(p.root_cause) + '</div>' : '',
      // WHY block removed — verdict_reasoning duplicates root_cause after prefill normalisation

      // ── Validation basis block
      '<div class="bct-validation-basis">',
      '  <div class="bct-label">VALIDATION BASIS</div>',
      '  <div class="bct-vb-row">',
      '    <span>Verdict: <strong>' + _esc(verdict) + '</strong></span>',
      meter ? '    <span>Confidence: <strong>' + Math.round(meter.total) + '%</strong></span>' : '',
      '    <span>Evidence rows: <strong>' + (cluster.row_refs || []).length + '</strong></span>',
      '    <span>Sources: <strong>' + _esc((cluster.source_sheets || []).join(', ') || '—') + '</strong></span>',
      p.model_used ? '    <span>Model: <strong>' + _esc(p.model_used) + '</strong></span>' : '',
      '  </div>',
      (p.observed_impact ? [
        '  <div class="bct-vb-impact">',
        p.observed_impact.identity ? '    <div><span class="bct-label">Identity:</span> ' + _esc(p.observed_impact.identity) + '</div>' : '',
        p.observed_impact.data ? '    <div><span class="bct-label">Data:</span> ' + _esc(p.observed_impact.data) + '</div>' : '',
        p.observed_impact.operational ? '    <div><span class="bct-label">Operational:</span> ' + _esc(p.observed_impact.operational) + '</div>' : '',
        '  </div>',
      ].join('') : ''),
      (function() {
        var mitre = _mitreForCluster(cluster, p);
        if (!Array.isArray(mitre) || !mitre.length) return '';
        var badges = mitre.slice(0, 8).map(function(t) {
          return '<span class="mitre-badge" style="display:inline-block;margin:2px 4px 2px 0;padding:2px 6px;border:1px solid var(--border-subtle);border-radius:6px;color:#9db7ff;font-size:11px;">' + _esc(t) + '</span>';
        }).join('');
        return '<div class="bct-mitre-row"><span class="bct-label">MITRE:</span> ' + badges + '</div>';
      })(),
      '</div>',
      '</details>',

      _buildThreatModelWorkbench(cluster),

      (function() {
        var chain = p.evidence_chain;
        if (!Array.isArray(chain) || !chain.length) return '';
        var items = chain.slice(0, 6).map(function(step, idx) {
          var refs = Array.isArray(step.row_refs) ? step.row_refs.join(', ') : '';
          return '<li class="evidence-step" style="margin:6px 0;">'
            + '<div><strong>Step ' + _esc(step.step || (idx + 1)) + ':</strong> ' + _esc(step.what || '') + '</div>'
            + (refs ? '<div style="color:var(--text-muted);font-size:10px;">Rows: ' + _esc(refs) + '</div>' : '')
            + (step.why_significant ? '<div style="color:var(--text-muted);font-size:10px;">' + _esc(step.why_significant) + '</div>' : '')
            + '</li>';
        }).join('');
        return '<div class="bct-section bct-evidence-chain evidence-chain">'
          + '<div class="bct-section-head">EVIDENCE CHAIN</div>'
          + '<ol style="margin:4px 0;padding-left:18px;font-size:11px;">' + items + '</ol>'
          + '</div>';
      })(),

      // ── Evidence gaps (before timeline)
      (function() {
        var gaps = p.evidence_gaps;
        if (!gaps || !gaps.length) return '';
        var items = gaps.slice(0, 4).map(function(g) {
          return '<li><strong>' + _esc(g.gap || '') + '</strong>'
            + (g.would_confirm ? ' <span style="color:#ffaa00;">→ would confirm: ' + _esc(g.would_confirm) + '</span>' : '')
            + (g.significance === 'high' ? ' <span style="color:#e05252;font-size:9px;">[HIGH]</span>' : '')
            + '</li>';
        }).join('');
        return '<div class="bct-section bct-evidence-gaps">'
          + '<div class="bct-section-head" style="color:#ffaa00;">EVIDENCE GAPS</div>'
          + '<ul style="margin:4px 0;padding-left:16px;font-size:11px;">' + items + '</ul>'
          + '</div>';
      })(),

      // Cross-cluster links
      xlinks.length ? _buildCrossLinks(xlinks) : '',
      // Repeat entity alert (filled async)
      '<div id="bct-repeat-alert"></div>',
      // Crown jewels review panel (filled async)
      '<div id="bct-cj-review">' + _buildCjEvidenceSeed(cluster) + '</div>',
      '</div>',

      // ── Persona tabs
      '<div class="bct-persona-tabs" id="bct-persona-tabs">',
      _buildPersonaTabBar(_activePersona),
      '</div>',

      // ── Persona content area
      '<div class="bct-persona-body" id="bct-persona-body" data-testid="bct-persona-body">',
      _buildPersonaSteps(_deterministicPersonaSteps(_activePersona, cluster), _activePersona, cluster, assessmentId, false),
      _buildPersonaGeneratePrompt(_activePersona, cluster, assessmentId),
      '</div>',

      // ── Timeline section (filled async by E9)
      '<div class="bct-section">',
      '  <div class="bct-section-head">ATTACK TIMELINE</div>',
      '  <div id="bct-timeline" data-testid="bct-timeline"><div class="bct-loading">Loading timeline…</div></div>',
      '</div>',

      // ── IOC export + Analyst notes
      '<div class="bct-tools-row">',
      '  <div class="bct-notes-wrap">',
      '    <div class="bct-section-head">ANALYST NOTES</div>',
      '    <textarea id="bct-notes-input" data-testid="bct-notes-input" class="bct-notes" placeholder="Add notes… (auto-saved)">' + _esc(notes.text || '') + '</textarea>',
      '    <span class="bct-notes-status" id="bct-notes-status">' + (notes.updated_at ? 'Last saved ' + _relativeTime(notes.updated_at) : '') + '</span>',
      '  </div>',
      '  <div class="bct-ioc-wrap">',
      '    <div class="bct-section-head">IOC EXPORT</div>',
      '    <button class="bct-btn" id="bct-ioc-btn" data-testid="bct-ioc-btn">⬇ Export IOCs (JSON)</button>',
      '    <div class="bct-ioc-summary" id="bct-ioc-summary"></div>',
      '  </div>',
      '</div>',

      // ── Sign-off row (A7)
      '<div class="bct-signoff" id="bct-signoff">',
      '  <div class="bct-section-head">ANALYST SIGN-OFF</div>',
      signOff.status === 'signed_off' ? _buildSignedOffBadge(signOff) : _buildSignOffButtons(),
      '  <button class="bct-btn bct-btn--secondary" id="bct-print-btn" onclick="window.print()">🖨 Print / Save PDF</button>',
      '</div>',

      '</div>', // .bct-wrap
    ].join('');
  }

  // ── Cross-cluster links ──────────────────────────────────────────────────────

  function _buildCrossLinks(links) {
    var parts = links.map(function (l) {
      return '<a class="bct-xlink" href="/static/breach.html?assessment=' + encodeURIComponent(_ctx.assessmentId) + '&cluster=' + encodeURIComponent(l.also_in_cluster_id) + '">'
        + _esc(l.entity) + ' → ' + _esc(l.also_in_incident_name || 'related threat case') + '</a>';
    });
    return '<div class="bct-xlinks">Also in: ' + parts.join(' · ') + '</div>';
  }

  // ── Persona tab bar ──────────────────────────────────────────────────────────

  function _buildPersonaTabBar(active) {
    return Object.keys(PERSONA_META).map(function (key) {
      var m = PERSONA_META[key];
      var cls = 'bct-ptab' + (key === active ? ' bct-ptab--active' : '');
      return '<button class="' + cls + '" data-persona="' + key + '">' + m.icon + ' ' + m.label + '</button>';
    }).join('');
  }

  // ── Persona tab content ──────────────────────────────────────────────────────

  function _loadPersonaTab(persona, cluster, assessmentId, forceLlm) {
    var body = document.getElementById('bct-persona-body');
    if (!body) return;
    body.innerHTML = '<div class="bct-loading">Loading ' + PERSONA_META[persona].label + ' steps…</div>';

    // Try tier2 cache endpoint — no LLM call (force=false means cache-only)
    var url = _apiBase() + '/api/v1/assessments/' + encodeURIComponent(assessmentId)
      + '/clusters/' + encodeURIComponent(cluster.cluster_id)
      + '/tier2' + (forceLlm ? '?force_refresh=true' : '');

    fetch(url, { headers: _authHdrs({ 'x-persona': persona }) })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        // Normalize: tier2 endpoint returns `steps`, persona endpoints return `persona_steps`
        var steps = data.persona_steps
          || data.steps
          || (data.data && (data.data.persona_steps || data.data.steps))
          || [];
        // Normalize each step to have a uniform shape
        steps = steps.map(function (s) {
          if (typeof s === 'string') return { title: s, subtasks: [] };
          return {
            title: s.title || s.label || s.action || s.name || 'Step',
            priority: s.priority || '',
            evidence_refs: s.evidence_refs || s.row_refs || [],
            instructions: s.instructions || '',
            why_flagged: s.why_flagged || '',
            evidence_pins: s.evidence_pins || {},
            subtasks: (s.subtasks || s.sub_tasks || []).map(function (sub) {
              if (typeof sub === 'string') return { label: sub };
              return sub;
            }),
          };
        });
        if (steps.length) {
          body.innerHTML = _buildPersonaSteps(steps, persona, cluster, assessmentId, false);
        } else {
          body.innerHTML = _buildPersonaSteps(_deterministicPersonaSteps(persona, cluster), persona, cluster, assessmentId, false)
            + _buildPersonaGeneratePrompt(persona, cluster, assessmentId);
        }
        _wireStepExpand(cluster, assessmentId);
        _wireFurtherTasksBtn(cluster, assessmentId);
      })
      .catch(function () {
        body.innerHTML = _buildPersonaSteps(_deterministicPersonaSteps(persona, cluster), persona, cluster, assessmentId, false)
          + _buildPersonaGeneratePrompt(persona, cluster, assessmentId);
      });
  }

  function _deterministicPersonaSteps(persona, cluster) {
    var refs = (cluster.row_refs || []).slice(0, 6);
    var baseRefs = refs.length ? refs : [];
    if (persona === 'threat_hunter') {
      return [
        { title: 'Hunt for matching file-sync activity across peer hosts', priority: 'P1', evidence_refs: baseRefs, subtasks: [{ label: 'Search endpoint and proxy logs for cloud-sync tools, external storage, and matching command signatures' }] },
        { title: 'Expand infrastructure scope around reused IPs and ASNs', priority: 'P2', evidence_refs: baseRefs, subtasks: [{ label: 'Pivot on destination IPs, DNS, ASN, JA3/JA4, and repeated egress timing' }] }
      ];
    }
    if (persona === 'forensics') {
      return [
        { title: 'Preserve endpoint process tree and command-line evidence', priority: 'P1', evidence_refs: baseRefs, subtasks: [{ label: 'Collect process lineage, binary hash, parent process, persistence artifacts, and relevant disk paths' }] },
        { title: 'Preserve data-platform query history and unload-stage evidence', priority: 'P1', evidence_refs: baseRefs, subtasks: [{ label: 'Export query text, actor, warehouse, database, stage, timestamp, and result metadata' }] }
      ];
    }
    return [
      { title: 'Confirm breach scope before containment', priority: 'P1', evidence_refs: baseRefs, subtasks: [{ label: 'Verify affected accounts, destinations, crown jewels, and row evidence are in scope' }] },
      { title: 'Coordinate bounded response actions', priority: 'P1', evidence_refs: baseRefs, subtasks: [{ label: 'Preserve evidence now; request approval before blocking egress or disabling identities' }] }
    ];
  }

  // ── 4-phase action bucketing ─────────────────────────────────────────────────

  var _PHASE_BUCKET_ORDER = ['CONTAIN', 'INVESTIGATE', 'PRESERVE', 'REPORT'];

  var _PHASE_BUCKET_KW = {
    CONTAIN:     ['isolat', 'disabl', 'block', 'revok', 'quarantin', 'contain', 'eradica'],
    INVESTIGATE: ['investigat', 'hunt', 'reconstruct', 'timeline', 'blast', 'confirm scope', 'confirm contain'],
    PRESERVE:    ['preserv', 'captur', 'snapshot', 'memory', 'volatile', 'chain of custody', 'forensic'],
    REPORT:      ['notif', 'report', 'sign-off', 'signoff', 'regulat', 'stakeholder', 'document', 'ciso', 'lesson', 'patch', 'harden', 'close']
  };

  function _bucketStep(step) {
    var t = (step.title || step.label || '').toLowerCase();
    for (var bi = 0; bi < _PHASE_BUCKET_ORDER.length; bi++) {
      var bucket = _PHASE_BUCKET_ORDER[bi];
      var kws = _PHASE_BUCKET_KW[bucket];
      for (var ki = 0; ki < kws.length; ki++) {
        if (t.indexOf(kws[ki]) !== -1) return bucket;
      }
    }
    return 'INVESTIGATE';
  }

  function _buildPersonaSteps(steps, persona, cluster, assessmentId, isLlmGenerated) {
    var m = PERSONA_META[persona] || PERSONA_META.soc_analyst;
    var qualityBadge = isLlmGenerated ? '' : '<span class="bct-badge bct-badge--fallback">Evidence-guided workflow</span>';
    var regenerateBtn = '<button class="bct-btn bct-btn--ghost" id="bct-regenerate-btn" data-persona="' + persona + '">↺ Regenerate with LLM</button>';

    // Group steps into 4 canonical IR buckets instead of rendering each step as a panel
    var _buckets = { CONTAIN: [], INVESTIGATE: [], PRESERVE: [], REPORT: [] };
    steps.forEach(function(step) { _buckets[_bucketStep(step)].push(step); });

    var _BKT_PRI   = { CONTAIN: 'P1', INVESTIGATE: 'P1', PRESERVE: 'P2', REPORT: 'P3' };
    var _BKT_COLOR = { CONTAIN: '#E54848', INVESTIGATE: '#E54848', PRESERVE: '#FF8A3C', REPORT: '#888' };

    var stepsHtml = _PHASE_BUCKET_ORDER.filter(function(b) {
      return _buckets[b].length > 0;
    }).map(function(bucket, bi) {
      var bucketSteps = _buckets[bucket];
      var bucketId    = 'bct-bucket-' + bi;
      var isExpanded  = !!_expandedSteps[bucketId];
      var pri         = _BKT_PRI[bucket];
      var priColor    = _BKT_COLOR[bucket];

      // Collect all unique row refs across steps in this bucket
      var allRefs = [];
      bucketSteps.forEach(function(s) {
        (s.evidence_refs || s.row_refs || []).forEach(function(r) {
          if (allRefs.indexOf(r) === -1) allRefs.push(r);
        });
      });

      // Render each original step as a labelled group of subtasks within the bucket
      var subtasksHtml = bucketSteps.map(function(step) {
        var derived = _deriveSubtasks(step);
        if (!derived.length) {
          derived = [{
            label: 'Review evidence rows and record a confirm/deny decision',
            tool_command: 'JanuSec evidence table: open rows ' + (allRefs.length ? allRefs.slice(0, 6).join(', ') : '<case_rows>'),
            expected_finding: 'Confirm whether row timestamps, entities, and source systems support this step.'
          }];
        }
        var innerHtml = derived.map(function(sub) {
          var label    = typeof sub === 'string' ? sub : (sub.label || '');
          var toolCmd  = typeof sub === 'object' ? (sub.tool_command || '') : '';
          var expected = typeof sub === 'object' ? (sub.expected_finding || '') : '';
          var combined = (label + ' ' + toolCmd).toLowerCase();
          var tier, tierStyle;
          if (/block|quarantin|isolat|revoke|reset.pass|disable|delete/.test(combined)) {
            tier = 'APPROVAL REQUIRED'; tierStyle = 'color:#ffaa00;border-left:3px solid #ffaa00;padding-left:6px;';
          } else if (/export|collect|captur|preserv|backup|snapshot|read.only|query|search|hunt|investigat/.test(combined)) {
            tier = 'SAFE TO RUN'; tierStyle = 'color:#52e07f;border-left:3px solid #52e07f;padding-left:6px;';
          } else if (/notif|contact|escalat|alert|page|call/.test(combined)) {
            tier = 'MANUAL REVIEW'; tierStyle = 'color:#90caf9;border-left:3px solid #90caf9;padding-left:6px;';
          } else {
            tier = ''; tierStyle = '';
          }
          return [
            '<div class="bct-subtask" style="' + tierStyle + 'margin-bottom:6px;">',
            tier ? '<span style="font-size:9px;opacity:.7;">[' + tier + ']</span><br>' : '',
            '<div class="bct-subtask__label">' + _esc(label) + '</div>',
            toolCmd  ? '<div class="bct-subtask__cmd" style="margin-top:2px;"><code style="font-size:10px;opacity:.8;">' + _esc(toolCmd) + '</code></div>' : '',
            expected ? '<div class="bct-subtask__expected" style="font-size:10px;color:var(--text-muted);">Expected: ' + _esc(expected) + '</div>' : '',
            '</div>',
          ].join('');
        }).join('');
        var stepTitle = step.title || step.label || '';
        return (stepTitle
          ? '<div style="font-size:10px;color:var(--text-muted);margin:6px 0 2px;font-weight:600;">' + _esc(stepTitle) + '</div>'
          : '') + innerHtml;
      }).join('');

      return [
        '<div class="bct-step" id="' + bucketId + '" data-expanded="' + isExpanded + '">',
        '  <div class="bct-step__header">',
        '    <span class="bct-step__title">' + _esc(bucket) + '</span>',
        '    <span class="bct-step__pri" style="color:' + priColor + '">' + _esc(pri) + '</span>',
        allRefs.length ? '<span class="bct-step__refs">rows: ' + allRefs.slice(0, 8).join(', ') + '</span>' : '',
        '    <button class="bct-step__expand bct-btn bct-btn--ghost" data-step="' + bucketId + '">' + (isExpanded ? '▲ Collapse' : '▼ Expand') + '</button>',
        '  </div>',
        isExpanded && subtasksHtml
          ? '<div class="bct-step__subtasks">' + subtasksHtml + '</div>'
          : '<div class="bct-step__subtasks" style="display:none">' + subtasksHtml + '</div>',
        '</div>',
      ].join('');
    }).join('');

    return [
      '<div class="bct-persona-header">',
      '  <span class="bct-persona-focus">' + m.focus + '</span>',
      qualityBadge,
      regenerateBtn,
      '</div>',
      '<div class="bct-steps" id="bct-steps-list">',
      stepsHtml,
      '</div>',
      '<div id="bct-further-tasks-area"></div>',
      '<div id="bct-followup-checks-area">' + _deriveFollowupChecks(_ctx ? _ctx.cluster : null) + '</div>',
    ].join('');
  }

  function _deriveFollowupChecks(cluster) {
    if (!cluster) return '';
    var p = cluster.tier1_prefill || {};
    var dn = p.dread_narrative || {};
    var frags = dn.fragments || {};
    var verdict = cluster.verdict || '';
    var checks = [];

    if (frags.discoverability && /\d+-day MTTD/.test(frags.discoverability)) {
      checks.push('Verify SIEM correlation rules now cover the activity pattern — MTTD was elevated at detection.');
    }
    if (frags.exploitability && /no dlp|no pam|no gate|unconstrained|without baseline/i.test(frags.exploitability)) {
      checks.push('Confirm control gap described in exploitability fragment has been remediated before closing the case.');
    }
    if (frags.damage && /exfil|copy into|unload|rclone|external storage|cloud storage/i.test(frags.damage)) {
      checks.push('Validate data-loss scope: request DLP/CASB logs for the exfiltration window and confirm no secondary staging.');
    }
    if ((cluster.affected_accounts || []).length > 2) {
      checks.push('Sweep all affected accounts (' + (cluster.affected_accounts || []).slice(0, 3).join(', ') + ') for persistent access (tokens, service accounts, OAuth grants).');
    }
    if (verdict === 'LIKELY_BREACH') {
      checks.push('Human review required — gather additional telemetry to upgrade or downgrade this verdict before regulatory clock starts.');
    }
    if (!checks.length) return '';

    return [
      '<div class="bct-followup-checks">',
      '<div class="bct-section-head" style="font-size:11px;margin-bottom:6px;">FOLLOW-UP CHECKS</div>',
      checks.map(function(c) {
        return '<div class="bct-followup-check">→ ' + _esc(c) + '</div>';
      }).join(''),
      '</div>',
    ].join('');
  }

  function _first(list) {
    return Array.isArray(list) && list.length ? String(list[0]) : '';
  }

  function _deriveSubtasks(step) {
    var pins = step.evidence_pins || {};
    var refs = step.evidence_refs || step.row_refs || [];
    var refText = refs.length ? ' rows ' + refs.slice(0, 4).join(', ') : '';
    var acct = _first(pins.accounts) || _first((_ctx.cluster || {}).shared_accounts);
    var host = _first(pins.hosts) || _first((_ctx.cluster || {}).shared_hosts);
    var ip = _first(pins.ips) || _first((_ctx.cluster || {}).shared_external_ips);
    var text = [step.title, step.instructions, step.why_flagged].join(' ').toLowerCase();
    var tasks = [];

    if (/okta|mfa|password|spray|legacy|imap|credential|session/.test(text) && acct) {
      tasks.push({
        label: 'Query Okta sign-in and MFA history for ' + acct + refText,
        tool_command: 'Okta System Log: actor.alternateId="' + acct + '" OR client.ipAddress="' + (ip || '<source_ip>') + '"',
        expected_finding: 'Confirm password spray, MFA fatigue, legacy authentication, or suspicious session reuse in the threat-case window.'
      });
    }
    if (/bec|mailbox|mail|forward|wire|finance|m365|imap/.test(text) && acct) {
      tasks.push({
        label: 'Run M365 message trace and mailbox audit for ' + acct,
        tool_command: 'M365: Search-UnifiedAuditLog -UserIds ' + acct + ' -Operations New-InboxRule,Set-Mailbox,MailItemsAccessed,Send',
        expected_finding: 'Confirm forwarding/BCC rule creation, mailbox access, sent BEC message, or absence of further payment emails.'
      });
    }
    if (/c2|beacon|dns|exfil|firewall|network|destination|proxy/.test(text)) {
      tasks.push({
        label: 'Hunt DNS/proxy/firewall egress for ' + (ip || 'the suspicious destination') + refText,
        tool_command: 'Sentinel KQL: CommonSecurityLog | where DestinationIP == "' + (ip || '<c2_ip>') + '" or RequestURL has_any ("update-cdn", "dns")',
        expected_finding: 'Confirm first seen, last seen, byte volume, beacon interval, and every internal host that contacted the destination.'
      });
    }
    if (/isolate|edr|host|process|schtask|powershell|persistence|defender|quarantine/.test(text) && (host || acct)) {
      tasks.push({
        label: 'Check Defender device/process evidence before containment',
        tool_command: 'Defender Advanced Hunting: DeviceProcessEvents | where DeviceName == "' + (host || '<host>') + '"',
        expected_finding: 'Confirm malicious parent process, persistence artifact, command line, and whether device isolation needs approval.'
      });
    }
    if (/block|c2|destination|firewall|dns/.test(text) && ip) {
      tasks.push({
        label: 'Prepare firewall/DNS block for ' + ip + ' after false-positive check',
        tool_command: 'Firewall/Proxy: search destination_ip=' + ip + ' and verify against allow-list/CDN ownership',
        expected_finding: 'Block only if destination is not approved SaaS/CDN and at least one affected host contacted it during the case window.'
      });
    }
    if (/confirm|scope|blast|timeline|sign.?off|report|notification/.test(text)) {
      tasks.push({
        label: 'Document confirm/deny decision with evidence row references',
        tool_command: 'JanuSec notes/sign-off: cite ' + (refs.length ? refs.slice(0, 6).join(', ') : 'supporting rows') + ' and mark Confirmed, Escalate, Dismiss, or Defer',
        expected_finding: 'A reviewer can see exactly which evidence confirmed the breach, which evidence stayed unresolved, and what telemetry was missing.'
      });
    }

    return tasks.slice(0, 3);
  }

  function _buildStep(step, stepId, isExpanded) {
    var subtasks = step.subtasks || step.sub_tasks || [];
    var refs = step.evidence_refs || step.row_refs || [];
    // Evidence-specific deterministic subtasks when the LLM has not generated them.
    if (!subtasks.length) {
      subtasks = _deriveSubtasks(step);
      if (!subtasks.length) {
        subtasks = [{
          label: 'Review evidence rows and record a confirm/deny decision',
          tool_command: 'JanuSec evidence table: open rows ' + (refs.length ? refs.slice(0, 6).join(', ') : '<case_rows>'),
          expected_finding: 'Confirm whether the row timestamps, entities, and source systems support this step.'
        }];
      }
    }
    var priority = step.priority || '';
    var priColor = priority === 'P1' ? '#E54848' : priority === 'P2' ? '#FF8A3C' : '#888';

    var subtasksHtml = subtasks.map(function (sub) {
      var label = typeof sub === 'string' ? sub : (sub.label || sub.title || sub);
      var toolCmd = typeof sub === 'object' ? (sub.tool_command || '') : '';
      var expected = typeof sub === 'object' ? (sub.expected_finding || '') : '';
      // Classify action tier by keywords in label/tool_command
      var combined = (label + ' ' + toolCmd).toLowerCase();
      var tier, tierStyle;
      if (/block|quarantine|isolat|revoke|reset.pass|disable.account|delete/.test(combined)) {
        tier = 'APPROVAL REQUIRED'; tierStyle = 'color:#ffaa00;border-left:3px solid #ffaa00;padding-left:6px;';
      } else if (/export|collect|capture|preserve|backup|snapshot|read.only|query|search|hunt|investigate/.test(combined)) {
        tier = 'SAFE TO RUN'; tierStyle = 'color:#52e07f;border-left:3px solid #52e07f;padding-left:6px;';
      } else if (/notify|contact|escalat|alert|page|call/.test(combined)) {
        tier = 'MANUAL REVIEW'; tierStyle = 'color:#90caf9;border-left:3px solid #90caf9;padding-left:6px;';
      } else {
        tier = ''; tierStyle = '';
      }
      return [
        '<div class="bct-subtask" style="' + tierStyle + 'margin-bottom:6px;">',
        tier ? '  <span style="font-size:9px;opacity:.7;">[' + tier + ']</span><br>' : '',
        '  <div class="bct-subtask__label">' + _esc(label) + '</div>',
        toolCmd ? '<div class="bct-subtask__cmd" style="margin-top:2px;"><code style="font-size:10px;opacity:.8;">' + _esc(toolCmd) + '</code></div>' : '',
        expected ? '<div class="bct-subtask__expected" style="font-size:10px;color:var(--text-muted);">Expected: ' + _esc(expected) + '</div>' : '',
        '</div>',
      ].join('');
    }).join('');

    return [
      '<div class="bct-step" id="' + stepId + '" data-expanded="' + isExpanded + '">',
      '  <div class="bct-step__header">',
      '    <span class="bct-step__title">' + _esc(step.title || step.label || 'Step') + '</span>',
      priority ? '<span class="bct-step__pri" style="color:' + priColor + '">' + _esc(priority) + '</span>' : '',
      refs.length ? '<span class="bct-step__refs">rows: ' + refs.join(', ') + '</span>' : '',
      '    <button class="bct-step__expand bct-btn bct-btn--ghost" data-step="' + stepId + '">' + (isExpanded ? '▲ Collapse' : '▼ Expand') + '</button>',
      '  </div>',
      isExpanded && subtasksHtml ? '<div class="bct-step__subtasks">' + subtasksHtml + '</div>' : '<div class="bct-step__subtasks" style="display:none">' + subtasksHtml + '</div>',
      '</div>',
    ].join('');
  }

  function _buildPersonaGeneratePrompt(persona, cluster, assessmentId) {
    var m = PERSONA_META[persona] || PERSONA_META.soc_analyst;
    return [
      '<div class="bct-generate-prompt">',
      '  <div class="bct-generate-prompt__text">No ' + m.label + ' steps generated yet.</div>',
      '  <button class="bct-btn bct-btn--primary" id="bct-gen-btn" data-persona="' + persona + '">',
      '    Generate ' + m.label + ' steps',
      '  </button>',
      '  <div class="bct-generate-prompt__note">Fires 1 LLM call (~8s). Cached after first run.</div>',
      '</div>',
    ].join('');
  }

  // ── Timeline (E9) ────────────────────────────────────────────────────────────

  function _loadTimeline(cluster, assessmentId) {
    var el = document.getElementById('bct-timeline');
    if (!el) return;

    _get('/api/v1/assessments/' + encodeURIComponent(assessmentId)
         + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/timeline')
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        if (!data.phases || !data.phases.length) {
          el.innerHTML = '<div class="bct-empty" data-testid="bct-timeline-empty">No timestamped rows found for this cluster.</div>';
          return;
        }
        el.innerHTML = _buildTimeline(data.phases);
      })
      .catch(function () {
        el.innerHTML = '<div class="bct-empty">Timeline unavailable — server not loaded yet.</div>';
      });
  }

  function _buildTimeline(phases) {
    return phases.map(function (pg) {
      var phaseColor = PHASE_COLOR[pg.phase] || '#888';
      var rowsHtml = pg.rows.map(function (row) {
        var sevColor = ({ critical: '#E54848', high: '#FF8A3C', medium: '#E0C446', low: '#3FA860' })[row.severity] || '#888';
        var ts = row.timestamp_raw ? String(row.timestamp_raw).slice(0, 16).replace('T', ' ') : '';
        var country = row.country || row.geo_country || row.src_country || '';
        var asn = row.asn || row.src_asn || row.as_org || '';
        var geoLabel = country && asn ? country + ' / ' + asn : (country || asn);
        var asnWarn = row._asn_reused ? ' title="ASN reused across phases — adversarial infrastructure"' : '';
        return [
          '<div class="bct-tl-row">',
          '  <div class="bct-tl-row__dot" style="background:' + sevColor + '"></div>',
          '  <div class="bct-tl-row__body">',
          '    <span class="bct-tl-row__desc">' + _esc(row.description) + '</span>',
          ts ? '<span class="bct-tl-row__ts">' + _esc(ts) + '</span>' : '',
          row.mitre_technique ? '<span class="bct-chip">' + _esc(row.mitre_technique) + '</span>' : '',
          row.source ? '<span class="bct-chip bct-chip--src">' + _esc(row.source) + '</span>' : '',
          row.user ? '<span class="bct-chip bct-chip--entity">' + _esc(row.user) + '</span>' : '',
          row.src_ip ? '<span class="bct-chip bct-chip--ip">' + _esc(row.src_ip) + '</span>' : '',
          row.hostname ? '<span class="bct-chip bct-chip--host">' + _esc(row.hostname) + '</span>' : '',
          geoLabel ? '<span class="bct-chip bct-chip--geo' + (row._asn_reused ? ' bct-chip--warn' : '') + '"' + asnWarn + '>' + _esc(geoLabel) + '</span>' : '',
          '  </div>',
          '</div>',
        ].join('');
      }).join('');
      return [
        '<div class="bct-tl-phase">',
        '  <div class="bct-tl-phase__label" style="border-left-color:' + phaseColor + ';color:' + phaseColor + '">' + _esc(pg.phase) + '</div>',
        '  <div class="bct-tl-rows">' + rowsHtml + '</div>',
        '</div>',
      ].join('');
    }).join('');
  }

  // ── Repeat entity alert (E12) ────────────────────────────────────────────────

  function _loadRepeatEntities(cluster, assessmentId) {
    _get('/api/v1/assessments/' + encodeURIComponent(assessmentId)
         + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/repeat-entities')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var el = document.getElementById('bct-repeat-alert');
        if (!el) return;
        if (data.match_count > 0) {
          var _BREACH_VERDICTS = ['CONFIRMED_BREACH', 'VALIDATED_BREACH', 'CONFIRMED_INTRUSION', 'LIKELY_BREACH'];
          var priorBreaches = data.matches.filter(function(m) {
            return _BREACH_VERDICTS.indexOf(m.past_verdict) !== -1;
          });
          var verdictLine = priorBreaches.length
            ? '<span class="bct-repeat-alert__verdict">' + priorBreaches.length +
              ' prior breach verdict(s): ' +
              priorBreaches.slice(0, 2).map(function(m) {
                return m.past_verdict + ' (' + m.shared_entities.slice(0, 2).join(', ') + ')';
              }).join('; ') + '</span>'
            : '';
          el.innerHTML = [
            '<div class="bct-repeat-alert' + (priorBreaches.length ? ' bct-repeat-alert--breach' : '') + '">',
            '  ⚠ <strong>' + data.match_count + ' past assessment(s)</strong> share entities with this cluster.',
            '  <span class="bct-repeat-alert__detail">Entities seen before: ' +
              data.matches.slice(0, 2).map(function (m) { return m.shared_entities.slice(0, 2).join(', '); }).join('; ') +
            '</span>',
            verdictLine,
            '</div>',
          ].join('');
        }
      })
      .catch(function () {});
  }

  // ── Crown jewels human gate panel ───────────────────────────────────────────

  var _CJ_TIER_OPTIONS = ['crown_jewel', 'tier_1', 'tier_2', 'tier_3', 'not_sensitive'];
  var _CJ_TIER_LABELS  = {
    crown_jewel:   'Crown Jewel',
    tier_1:        'Tier 1 — Critical',
    tier_2:        'Tier 2 — Internal',
    tier_3:        'Tier 3 — Low',
    not_sensitive: 'Not Sensitive',
  };
  var _CJ_BADGE_COLOR = {
    crown_jewel:    '#E54848',
    tier_1:         '#FF8A3C',
    tier_2:         '#E0C446',
    tier_3:         '#888',
    not_sensitive:  '#3FA860',
    'human-confirmed':  '#3FA860',
    'human-escalated':  '#E54848',
    'human-downgraded': '#90caf9',
    'pending-review':   '#888',
    'service_account':  '#FF8A3C',
    'privileged_user':  '#E54848',
    'standard_user':    '#5B8FD4',
    'unapproved_cloud': '#E54848',
  };

  function _cjTierColor(tier) {
    return _CJ_BADGE_COLOR[tier] || '#888';
  }

  function _loadCrownJewelsReview(cluster) {
    var el = document.getElementById('bct-cj-review');
    if (!el) return;

    var tenantId = _tenantId();
    // Collect identifiers to resolve
    var p = cluster.tier1_prefill || {};
    function _addToken(arr, value) {
      String(value || '').split(/[,\n;]/).forEach(function (part) {
        var s = part.trim().replace(/^assets?\s+/i, '').replace(/^accounts?\s+/i, '');
        if (s && arr.indexOf(s) === -1) arr.push(s);
      });
    }
    var extraAccounts = [];
    var extraAssets = [];
    var extraIps = [];
    var impact = p.observed_impact || {};
    _addToken(extraAccounts, impact.identity || '');
    _addToken(extraAssets, impact.data || '');
    _addToken(extraAssets, impact.operational || '');
    var d = _dreadInfo(cluster);
    d.parts.forEach(function (part) {
      var text = part.text || '';
      ['crown jewel', 'regulated data', 'critical data', 'protected data', 'external storage'].forEach(function (needle) {
        if (text.toLowerCase().indexOf(needle.toLowerCase()) !== -1) extraAssets.push(needle);
      });
    });
    _rowsForCluster(cluster).forEach(function (row) {
      ['user_principal_name', 'username', 'user', 'account', 'actor'].forEach(function (k) { _addToken(extraAccounts, row[k]); });
      ['database_name', 'warehouse_name', 'schema_name', 'hostname', 'host', 'device_name', 'object_name', 'file_path', 'path'].forEach(function (k) { _addToken(extraAssets, row[k]); });
      ['src_ip', 'source_ip', 'dst_ip', 'destination_ip', 'client_ip'].forEach(function (k) { _addToken(extraIps, row[k]); });
    });

    var accounts = (cluster.affected_accounts || cluster.shared_accounts || [])
      .concat(
        ((p.observed_impact || {}).identity || '')
          .split(',').map(function(s) { return s.trim(); }).filter(Boolean)
      )
      .concat(extraAccounts);
    var assets = (cluster.affected_assets || cluster.shared_assets || []).concat(extraAssets);
    var srcIps  = (cluster.shared_external_ips || []).concat(extraIps);

    // Deduplicate
    var uniqueAccounts = accounts.filter(function(v, i, a) { return v && a.indexOf(v) === i; }).slice(0, 8);
    var uniqueAssets   = assets.filter(function(v, i, a)   { return v && a.indexOf(v) === i; }).slice(0, 6);
    var uniqueIps      = srcIps.filter(function(v, i, a)   { return v && a.indexOf(v) === i; }).slice(0, 6);

    if (!uniqueAccounts.length && !uniqueAssets.length && !uniqueIps.length) return;

    function _renderCandidatePanel() {
      var candidates = uniqueAssets.concat(uniqueAccounts).slice(0, 10);
      if (!candidates.length) return;
      el.innerHTML = [
        '<div class="bct-cj-panel">',
        '  <div class="bct-section-head" style="margin-bottom:8px;">CROWN JEWELS IN SCOPE</div>',
        candidates.map(function (x) {
          return '<div class="bct-cj-entry"><div class="bct-cj-main"><span class="bct-cj-key">' + _esc(x) + '</span><span class="bct-cj-badge" style="color:#E0C446;border-color:#E0C446;">evidence-derived</span></div></div>';
        }).join(''),
        '</div>'
      ].join('');
    }

    // Fetch the full registry once, then do client-side lookups
    _get('/api/v1/config/tenant/' + encodeURIComponent(tenantId) + '/crown-jewels')
      .then(function(r) { return r.json(); })
      .then(function(cj) {
        var rows = [];
        var evidenceText = (
          JSON.stringify((cluster.tier1_prefill || {}).observed_impact || {}) + ' ' +
          _dreadInfo(cluster).parts.map(function (p) { return p.text; }).join(' ') + ' ' +
          _rowsForCluster(cluster).map(function (row) {
            return ['database_name', 'warehouse_name', 'schema_name', 'hostname', 'host', 'device_name', 'object_name', 'file_path', 'path', 'user', 'user_principal_name', 'account'].map(function (k) { return row[k] || ''; }).join(' ');
          }).join(' ')
        ).toLowerCase();
        ['assets', 'accounts', 'destinations', 'cloud_accounts'].forEach(function (section) {
          var obj = cj[section] || {};
          Object.keys(obj).forEach(function (key) {
            if (evidenceText.indexOf(String(key).toLowerCase()) === -1) return;
            if (section === 'accounts' && uniqueAccounts.indexOf(key) === -1) uniqueAccounts.push(key);
            if (section !== 'accounts' && uniqueAssets.indexOf(key) === -1) uniqueAssets.push(key);
          });
        });
        function _lookup(section, value) {
          var obj = cj[section] || {};
          if (obj[value]) return { key: value, entry: obj[value] };
          var vl = String(value || '').toLowerCase();
          for (var k in obj) {
            var kl = String(k).toLowerCase();
            if (kl === vl || (vl && vl.indexOf(kl) !== -1) || (kl && kl.indexOf(vl) !== -1)) return { key: k, entry: obj[k] };
          }
          return null;
        }

        uniqueAccounts.forEach(function(acct) {
          var hit = _lookup('accounts', acct);
          if (hit) rows.push({ key: hit.key, section: 'accounts', entry: hit.entry, label: acct });
        });
        uniqueAssets.forEach(function(asset) {
          var hit = _lookup('assets', asset);
          if (hit) rows.push({ key: hit.key, section: 'assets', entry: hit.entry, label: asset });
          var cloudHit = _lookup('cloud_accounts', asset);
          if (cloudHit) rows.push({ key: cloudHit.key, section: 'cloud_accounts', entry: cloudHit.entry, label: asset });
          var destHit = _lookup('destinations', asset);
          if (destHit) rows.push({ key: destHit.key, section: 'destinations', entry: destHit.entry, label: asset });
        });
        uniqueIps.forEach(function(ip) {
          // Check subnets
          var subnets = cj.subnets || {};
          for (var cidr in subnets) {
            if (_ipInSubnet(ip, cidr)) {
              rows.push({ key: cidr, section: 'subnets', entry: subnets[cidr], label: ip + ' (' + cidr + ')' });
              break;
            }
          }
        });

        if (!rows.length) {
          _renderCandidatePanel();
          return;
        }

        var rowsHtml = rows.map(function(item) {
          return _renderCjRow(item, tenantId);
        }).join('');

        el.innerHTML = [
          '<div class="bct-cj-panel">',
          '  <div class="bct-section-head" style="margin-bottom:8px;">',
          '    CROWN JEWELS IN SCOPE',
          '    <span style="font-size:10px;color:var(--text-muted);font-weight:400;margin-left:8px;">Review and gate each asset for accuracy</span>',
          '  </div>',
          rowsHtml,
          '</div>',
        ].join('');

        // Wire up review buttons
        el.querySelectorAll('.bct-cj-review-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var wrap = btn.closest('.bct-cj-entry');
            var form = wrap.querySelector('.bct-cj-form');
            if (form) form.style.display = form.style.display === 'none' ? 'block' : 'none';
          });
        });
        el.querySelectorAll('.bct-cj-submit').forEach(function(btn) {
          btn.addEventListener('click', function() {
            _submitCjReview(btn, tenantId);
          });
        });
        el.querySelectorAll('.bct-cj-clear').forEach(function(btn) {
          btn.addEventListener('click', function() {
            _clearCjReview(btn, tenantId, el, cluster);
          });
        });
      })
      .catch(function() { _renderCandidatePanel(); });
  }

  function _renderCjRow(item, tenantId) {
    var entry   = item.entry || {};
    var review  = entry._human_review || {};
    var effTier = entry._effective_tier || entry.tier || '';
    var badge   = entry._review_badge || 'pending-review';
    var badgeColor = _CJ_BADGE_COLOR[badge] || '#888';
    var tierColor  = _cjTierColor(effTier);
    var isReviewed = !!review.status;

    var metaParts = [];
    if (entry.label)              metaParts.push(entry.label);
    if (entry.provider)           metaParts.push(entry.provider.toUpperCase());
    if (entry.classification)     metaParts.push(entry.classification.replace(/_/g, ' '));
    if ((entry.notification_triggers || []).length)
      metaParts.push((entry.notification_triggers).map(function(t){return t.toUpperCase();}).join('+') + ' clock');
    if (review.reviewer)          metaParts.push('reviewed by ' + review.reviewer);
    if (review.reviewed_at)       metaParts.push(review.reviewed_at.slice(0, 10));

    var tierOptions = _CJ_TIER_OPTIONS.map(function(t) {
      return '<option value="' + t + '"' + (t === effTier ? ' selected' : '') + '>' + (_CJ_TIER_LABELS[t] || t) + '</option>';
    }).join('');

    return [
      '<div class="bct-cj-entry" data-section="' + _escAttr(item.section) + '" data-key="' + _escAttr(item.key) + '">',
      '  <div class="bct-cj-entry__row">',
      '    <span class="bct-cj-tier-pill" style="background:' + tierColor + '22;color:' + tierColor + '">' + _esc(effTier.replace(/_/g, ' ')) + '</span>',
      '    <span class="bct-cj-name">' + _esc(item.label) + '</span>',
      isReviewed ? '<span class="bct-cj-badge" style="color:' + badgeColor + '">[' + _esc(badge) + ']</span>' : '',
      review.reason ? '<span class="bct-cj-reason">' + _esc(review.reason) + '</span>' : '',
      '    <div class="bct-cj-actions">',
      '      <button class="bct-btn bct-btn--xs bct-cj-review-btn">' + (isReviewed ? '✎ Edit review' : '⚑ Gate / Review') + '</button>',
      isReviewed ? '<button class="bct-btn bct-btn--xs bct-btn--ghost bct-cj-clear">✕ Clear</button>' : '',
      '    </div>',
      '  </div>',
      metaParts.length ? '<div class="bct-cj-meta">' + _esc(metaParts.join(' · ')) + '</div>' : '',
      '  <div class="bct-cj-form" style="display:none;margin-top:8px;">',
      '    <select class="bct-cj-tier-select" style="font-size:11px;padding:3px 6px;background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:3px;">' + tierOptions + '</select>',
      '    <input class="bct-cj-reason-input" type="text" placeholder="Reason (required — stored in audit trail)" ',
      '      style="width:100%;margin-top:4px;font-size:11px;padding:3px 6px;background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:3px;" ',
      '      value="' + _escAttr(review.reason || '') + '">',
      '    <input class="bct-cj-reviewer-input" type="text" placeholder="Your name / email" ',
      '      style="width:100%;margin-top:4px;font-size:11px;padding:3px 6px;background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:3px;" ',
      '      value="' + _escAttr(review.reviewer || '') + '">',
      '    <button class="bct-btn bct-btn--primary bct-cj-submit" style="margin-top:6px;font-size:11px;">Save review</button>',
      '    <span class="bct-cj-msg" style="font-size:10px;margin-left:8px;"></span>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _submitCjReview(btn, tenantId) {
    var wrap       = btn.closest('.bct-cj-entry');
    var section    = wrap.dataset.section;
    var key        = wrap.dataset.key;
    var tier       = wrap.querySelector('.bct-cj-tier-select').value;
    var reason     = (wrap.querySelector('.bct-cj-reason-input').value || '').trim();
    var reviewer   = (wrap.querySelector('.bct-cj-reviewer-input').value || '').trim() || 'unknown';
    var msgEl      = wrap.querySelector('.bct-cj-msg');

    if (!reason) { if (msgEl) msgEl.textContent = 'Reason is required.'; return; }

    btn.disabled = true;
    btn.textContent = 'Saving…';
    _post(
      '/api/v1/config/tenant/' + encodeURIComponent(tenantId) +
      '/crown-jewels/' + encodeURIComponent(section) + '/' + encodeURIComponent(key) + '/review',
      { override_tier: tier, reason: reason, reviewer: reviewer }
    )
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.textContent = 'Saved';
      if (msgEl) {
        var color = data.review_status === 'escalated' ? '#E54848' : data.review_status === 'downgraded' ? '#90caf9' : '#3FA860';
        msgEl.style.color = color;
        msgEl.textContent = data.review_status + ' → ' + (data.effective_tier || tier).replace(/_/g, ' ');
      }
      // Refresh tier pill in-place
      var pill = wrap.querySelector('.bct-cj-tier-pill');
      if (pill) {
        var c = _cjTierColor(data.effective_tier || tier);
        pill.style.background = c + '22';
        pill.style.color = c;
        pill.textContent = (data.effective_tier || tier).replace(/_/g, ' ');
      }
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Save review';
      if (msgEl) { msgEl.style.color = '#E54848'; msgEl.textContent = 'Save failed — check server.'; }
    });
  }

  function _clearCjReview(btn, tenantId, panelEl, cluster) {
    var wrap    = btn.closest('.bct-cj-entry');
    var section = wrap.dataset.section;
    var key     = wrap.dataset.key;
    btn.disabled = true;
    fetch(
      '/api/v1/config/tenant/' + encodeURIComponent(tenantId) +
      '/crown-jewels/' + encodeURIComponent(section) + '/' + encodeURIComponent(key) + '/review',
      { method: 'DELETE' }
    ).then(function() {
      // Reload the panel
      _loadCrownJewelsReview(cluster);
    }).catch(function() { btn.disabled = false; });
  }

  // Lightweight client-side CIDR check (IPv4 only, for subnet display matching)
  function _ipInSubnet(ip, cidr) {
    try {
      var parts = cidr.split('/');
      var mask  = parseInt(parts[1], 10);
      var ipNum = _ipToNum(ip);
      var netNum = _ipToNum(parts[0]);
      var maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
      return (ipNum & maskNum) === (netNum & maskNum);
    } catch(_) { return false; }
  }
  function _ipToNum(ip) {
    return ip.split('.').reduce(function(acc, o) { return (acc << 8) + parseInt(o, 10); }, 0) >>> 0;
  }

  function _escAttr(s) {
    return String(s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── IOC export (E11) — client-side Blob ──────────────────────────────────────

  function _wireIocExport(cluster, allRows, assessmentId) {
    var btn = document.getElementById('bct-ioc-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = '⏳ Exporting…';
      _get('/api/v1/assessments/' + encodeURIComponent(assessmentId)
           + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/iocs')
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (iocs) {
          var blob = new Blob([JSON.stringify(iocs, null, 2)], { type: 'application/json' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = 'iocs_' + cluster.cluster_id + '.json';
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          var summary = document.getElementById('bct-ioc-summary');
          if (summary) {
            summary.textContent = (iocs.users || []).length + ' users · ' + (iocs.ips || []).length + ' IPs · ' + (iocs.hosts || []).length + ' hosts exported';
            summary.setAttribute('data-testid', 'bct-ioc-summary');
          }
          btn.textContent = '✓ Exported';
        })
        .catch(function () {
          btn.disabled = false;
          btn.textContent = '⬇ Export IOCs (JSON)';
          var summary = document.getElementById('bct-ioc-summary');
          if (summary) summary.textContent = 'Export failed — server unavailable.';
        });
    });
  }

  // ── Analyst notes (E10) — auto-save on blur ──────────────────────────────────

  function _wireThreatModelRefresh(cluster, assessmentId) {
    var btn = document.getElementById('bct-threat-model-refresh');
    if (!btn) return;
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = 'Generating...';
      _post('/api/v1/assessments/' + encodeURIComponent(assessmentId)
        + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/tier1-summary', {
          model: _selectedModel(),
          force: true,
        })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function (data) {
          if (data && data.tier1_prefill) {
            cluster.tier1_prefill = data.tier1_prefill;
            if (data.verdict) cluster.verdict = data.verdict;
            if (data.verdict_confidence != null) cluster.verdict_confidence = data.verdict_confidence;
          }
          BreachClusterTab.mount(_ctx.containerId, cluster, _ctx.allRows, assessmentId, _ctx.allClusters);
        })
        .catch(function () {
          btn.disabled = false;
          btn.textContent = 'Generate / refresh threat model';
          btn.title = 'Threat model generation failed. Check server logs and API key.';
        });
    });
  }

  function _wireNotes(cluster, assessmentId) {
    var textarea = document.getElementById('bct-notes-input');
    var status = document.getElementById('bct-notes-status');
    if (!textarea) return;

    var _saveTimer = null;
    textarea.addEventListener('input', function () {
      if (status) status.textContent = 'Unsaved…';
      clearTimeout(_saveTimer);
      _saveTimer = setTimeout(function () {
        _patch(
          '/api/v1/assessments/' + encodeURIComponent(assessmentId)
          + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/notes',
          { notes: textarea.value, analyst_id: '' }
        ).then(function (r) { return r.json(); })
         .then(function () {
           if (status) status.textContent = 'Saved ✓';
         })
         .catch(function () {
           if (status) status.textContent = 'Save failed';
         });
      }, 1200);
    });
  }

  // ── Sign-off (A7) ────────────────────────────────────────────────────────────

  function _buildSignOffButtons() {
    return [
      '<div class="bct-signoff__btns">',
      '  <button class="bct-signoff__btn bct-signoff__btn--confirm" data-action="confirmed" data-testid="bct-signoff-confirm">✓ Confirmed</button>',
      '  <button class="bct-signoff__btn bct-signoff__btn--escalate" data-action="escalate" data-testid="bct-signoff-escalate">↑ Escalate</button>',
      '  <button class="bct-signoff__btn bct-signoff__btn--dismiss" data-action="dismiss" data-testid="bct-signoff-dismiss">✗ Dismiss</button>',
      '  <button class="bct-signoff__btn bct-signoff__btn--defer" data-action="defer" data-testid="bct-signoff-defer">→ Defer</button>',
      '</div>',
    ].join('');
  }

  function _buildSignedOffBadge(signOff) {
    var action = signOff.status || 'signed_off';
    var ts = signOff.signed_off_at ? new Date(signOff.signed_off_at * 1000).toLocaleString() : '';
    return '<div class="bct-signoff__done">✓ Signed off: <strong>' + _esc(action) + '</strong>' + (ts ? ' · ' + ts : '') + (signOff.notes ? ' · "' + _esc(signOff.notes.slice(0, 80)) + '"' : '') + '</div>';
  }

  function _wireSignOff(cluster, assessmentId) {
    var el = document.getElementById('bct-signoff');
    if (!el) return;
    el.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-action]');
      if (!btn) return;
      var action = btn.dataset.action;
      var notes = '';
      var notesEl = document.getElementById('bct-notes-input');
      if (notesEl) notes = notesEl.value;

      btn.disabled = true;
      btn.textContent = '…';

      _post(
        '/api/v1/assessments/' + encodeURIComponent(assessmentId)
        + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/sign-off',
        { analyst_id: '', notes: notes, timeline_confirmed: true, action: action }
      ).then(function (r) {
         if (!r.ok) throw new Error('HTTP ' + r.status);
         return r.json();
       })
       .then(function (data) {
         var btnsEl = el.querySelector('.bct-signoff__btns');
         if (btnsEl) {
           btnsEl.innerHTML = '<div class="bct-signoff__done" data-testid="bct-signoff-done">✓ ' + _esc(action.toUpperCase()) + ' · ' + new Date().toLocaleTimeString() + '</div>';
         }
       })
       .catch(function () {
         btn.disabled = false;
         btn.textContent = '⚠ Retry';
       });
    });
  }

  // ── Persona tab wiring ───────────────────────────────────────────────────────

  function _wirePersonaTabs() {
    var bar = document.getElementById('bct-persona-tabs');
    if (!bar) return;
    bar.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-persona]');
      if (!btn) return;
      var persona = btn.dataset.persona;
      if (persona === _activePersona) return;
      _activePersona = persona;
      // Update tab bar active state
      bar.querySelectorAll('[data-persona]').forEach(function (b) {
        b.classList.toggle('bct-ptab--active', b.dataset.persona === persona);
      });
      _loadPersonaTab(persona, _ctx.cluster, _ctx.assessmentId, false);
    });
  }

  // ── Step expand wiring ───────────────────────────────────────────────────────

  function _wireStepExpand(cluster, assessmentId) {
    var body = document.getElementById('bct-persona-body');
    if (!body) return;

    // Regenerate button (E13)
    var regenBtn = document.getElementById('bct-regenerate-btn');
    if (regenBtn) {
      regenBtn.addEventListener('click', function () {
        var persona = regenBtn.dataset.persona || _activePersona;
        regenBtn.disabled = true;
        regenBtn.textContent = 'Generating…';
        _loadPersonaTab(persona, cluster, assessmentId, true);
      });
    }

    // Generate button (when no steps exist)
    var genBtn = document.getElementById('bct-gen-btn');
    if (genBtn) {
      genBtn.addEventListener('click', function () {
        var persona = genBtn.dataset.persona || _activePersona;
        genBtn.disabled = true;
        genBtn.textContent = 'Generating… (~8s)';
        _loadPersonaTab(persona, cluster, assessmentId, true);
      });
    }

    // Step expand/collapse
    body.addEventListener('click', function (e) {
      var expBtn = e.target.closest('[data-step]');
      if (!expBtn) return;
      var stepId = expBtn.dataset.step;
      var stepEl = document.getElementById(stepId);
      if (!stepEl) return;
      var isExpanded = stepEl.dataset.expanded === 'true';
      stepEl.dataset.expanded = isExpanded ? 'false' : 'true';
      _expandedSteps[stepId] = !isExpanded;
      var subtasksEl = stepEl.querySelector('.bct-step__subtasks');
      if (subtasksEl) subtasksEl.style.display = isExpanded ? 'none' : 'block';
      expBtn.textContent = isExpanded ? '▼ Expand' : '▲ Collapse';
      // Show further-tasks button when all steps expanded
      _checkFurtherTasksVisibility();
    });
  }

  function _checkFurtherTasksVisibility() {
    var steps = document.querySelectorAll('.bct-step');
    var allExpanded = steps.length > 0 && Array.from(steps).every(function (s) {
      return s.dataset.expanded === 'true';
    });
    var ftArea = document.getElementById('bct-further-tasks-area');
    if (!ftArea) return;
    if (allExpanded && !ftArea.dataset.loaded) {
      ftArea.innerHTML = [
        '<div class="bct-further-tasks-cta">',
        '  <span>All steps reviewed.</span>',
        '  <button class="bct-btn bct-btn--primary" id="bct-further-tasks-btn">+ Generate further investigation tasks</button>',
        '</div>',
      ].join('');
      _wireFurtherTasksBtn(_ctx.cluster, _ctx.assessmentId);
    }
  }

  function _wireFurtherTasksBtn(cluster, assessmentId) {
    var btn = document.getElementById('bct-further-tasks-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = 'Generating… (~8s)';

      // Gather completed evidence refs from expanded steps
      var completedRefs = [];
      var completedTitles = [];
      document.querySelectorAll('.bct-step').forEach(function (s) {
        if (s.dataset.expanded === 'true') {
          var titleEl = s.querySelector('.bct-step__title');
          if (titleEl) completedTitles.push(titleEl.textContent.trim());
          var refsEl = s.querySelector('.bct-step__refs');
          if (refsEl) {
            refsEl.textContent.replace(/\d+/g, function (n) {
              completedRefs.push(parseInt(n, 10));
              return n;
            });
          }
        }
      });

      _post(
        '/api/v1/assessments/' + encodeURIComponent(assessmentId)
        + '/clusters/' + encodeURIComponent(cluster.cluster_id) + '/further-tasks',
        { completed_evidence_refs: completedRefs, completed_task_titles: completedTitles, model: _selectedModel() }
      ).then(function (r) { return r.json(); })
       .then(function (data) {
         var area = document.getElementById('bct-further-tasks-area');
         if (!area) return;
         area.dataset.loaded = '1';
         if (!data.further_tasks || !data.further_tasks.length) {
           area.innerHTML = '<div class="bct-empty">No additional grounded tasks found.</div>';
           return;
         }
         area.innerHTML = [
           '<div class="bct-section-head" style="margin-top:16px">FURTHER INVESTIGATION</div>',
           '<div class="bct-steps">',
           data.further_tasks.map(function (task, i) {
             return _buildStep(task, 'bct-ft-step-' + i, false);
           }).join(''),
           '</div>',
         ].join('');
         // Wire expand for new further-task steps
         _wireStepExpand(cluster, assessmentId);
       })
       .catch(function () {
         btn.disabled = false;
         btn.textContent = '⚠ Retry';
       });
    });
  }

  // ── Utility ──────────────────────────────────────────────────────────────────

  function _relativeTime(unixTs) {
    var d = Math.floor(Date.now() / 1000 - unixTs);
    if (d < 60) return 'just now';
    if (d < 3600) return Math.floor(d / 60) + 'm ago';
    if (d < 86400) return Math.floor(d / 3600) + 'h ago';
    return Math.floor(d / 86400) + 'd ago';
  }

  // ── Post-mount wiring (called once) ─────────────────────────────────────────

  var _mounted = false;
  var _origMount = BreachClusterTab.mount;
  BreachClusterTab.mount = function (containerId, cluster, allRows, assessmentId, allClusters) {
    _origMount(containerId, cluster, allRows, assessmentId, allClusters);
    _wirePersonaTabs();
  };

  // ── Export ───────────────────────────────────────────────────────────────────

  global.BreachClusterTab = BreachClusterTab;

}(window));
