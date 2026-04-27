/* breach.js — JanuSec Breach Assessment front-end core
 *
 * Routing:
 *   breach.html                           → upload zone (no assessment)
 *   breach.html?assessment=a_XXXX         → home page (swimlane + cards)
 *   breach.html?cluster=C&assessment=A    → cluster detail tab
 *   breach.html?assessment=A&tab=evidence → evidence tab (reuses investigate.js)
 *   breach.html?assessment=A&tab=hopgraph → full HopGraph tab
 *   breach.html?assessment=A&tab=compliance → compliance tab (Phase B)
 *
 * LLM gate policy (NON-NEGOTIABLE):
 *   - Tier-1 cluster-1 fires ONCE automatically at page load (cached)
 *   - Exec summary fires ONCE at page load (cached)
 *   - Top threat cases hydrate automatically.
 *   - Additional threat cases hydrate only when the user clicks [Generate].
 *   - Nothing fires on hover, focus, polling, or tab-switch
 */
(function () {
  'use strict';

  // Auto-seed dev API key on localhost so progress polling works without manual settings config
  try {
    if (!localStorage.getItem('apiKey') && /localhost|127\.0\.0\.1/.test(window.location.hostname)) {
      localStorage.setItem('apiKey', 'devkey123');
    }
  } catch (_) {}

  // ── API helpers ─────────────────────────────────────────────────────────────

  function apiBase() { return window.JANUSEC_API_BASE || ''; }

  function authHeaders() {
    var k = '';
    try { k = localStorage.getItem('apiKey') || ''; } catch (_) {}
    var t = 'default';
    try { t = localStorage.getItem('tenantId') || 'default'; } catch (_) {}
    var h = { 'Content-Type': 'application/json' };
    if (k) h['x-api-key'] = k;
    h['x-tenant-id'] = t;
    return h;
  }

  function getSelectedModel() {
    try { return localStorage.getItem('selectedModel') || 'qwen3:14b'; } catch (_) { return 'qwen3:14b'; }
  }

  function apiFetch(path, opts) {
    return fetch(apiBase() + path, Object.assign({ headers: authHeaders() }, opts || {}));
  }

  function apiPost(path, body) {
    return apiFetch(path, {
      method: 'POST',
      body: JSON.stringify(body || {}),
    });
  }

  // ── URL state ───────────────────────────────────────────────────────────────

  var _params = new URLSearchParams(window.location.search);
  var AID   = _params.get('assessment') || '';
  var CID   = _params.get('cluster') || '';
  var TAB   = _params.get('tab') || '';

  // ── State ───────────────────────────────────────────────────────────────────

  var state = {
    assessment: null,
    clusters: [],
    rows: [],
    prefillStatus: {},   // cluster_id → 'pending' | 'done' | 'error'
    execSummary: null,
  };

  var _asyncRedirecting = {};
  var _asyncPollTimers = {};

  // ── Toast ───────────────────────────────────────────────────────────────────

  function toast(msg, durationMs) {
    var el = document.createElement('div');
    el.className = 'br-toast';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, durationMs || 2800);
  }

  // ── Main router ─────────────────────────────────────────────────────────────

  function init() {
    if (!AID) {
      renderUpload();
      return;
    }
    loadAssessment().then(function () {
      if (CID) {
        renderClusterTab();
      } else if (TAB === 'evidence') {
        renderEvidenceTab();
      } else if (TAB === 'hopgraph') {
        renderHopGraphTab();
      } else if (TAB === 'compliance') {
        renderComplianceTab();
      } else {
        renderHome();
      }
    });
  }

  // ── Assessment loader ────────────────────────────────────────────────────────

  function loadAssessment() {
    return apiFetch('/api/v1/assessments/' + encodeURIComponent(AID))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        state.assessment = data;
        // Prefer classified analysis_clusters; fall back to raw correlation_clusters.
        state.clusters = data.analysis_clusters || data.correlation_clusters || [];
        state.rawClusters = data.raw_correlation_clusters || data.correlation_clusters || [];
        state.threatCases = data.threat_cases || [];
        state.rows = data.normalized_rows || data.evidence_rows || data.rows || [];
      })
      .catch(function (err) {
        console.error('breach.js: loadAssessment failed', err);
      });
  }

  // ── Severity helpers ─────────────────────────────────────────────────────────

  var _VERDICT_CLASS = {
    'NO_VALIDATED_BREACH': 'benign',  'NO VALIDATED BREACH': 'benign',
    'VALIDATED_BREACH':    'confirmed', 'CONFIRMED_INTRUSION': 'confirmed',
    'CONFIRMED_BREACH':    'confirmed',
    'LIKELY_BREACH':       'likely',
    'LIKELY_COMPROMISE':   'likely',  'SUSPICIOUS_ACTIVITY': 'uncertain',
    'INSUFFICIENT_TELEMETRY': 'uncertain', 'BENIGN_EXPECTED': 'benign',
    'CONFIRMED': 'confirmed', 'LIKELY REAL': 'likely', 'LIKELY': 'likely',
    'UNCERTAIN': 'uncertain', 'BENIGN': 'benign',
    'INVESTIGATION_REQUIRED': 'uncertain',
    'ANALYSIS_INCOMPLETE': 'incomplete',
  };

  function verdictClass(v) {
    var vu = (v || '').toUpperCase();
    if (vu.indexOf('NO_VALIDATED_BREACH') !== -1 || vu.indexOf('NO VALIDATED BREACH') !== -1) return 'benign';
    for (var k in _VERDICT_CLASS) {
      if (vu.indexOf(k) !== -1) return _VERDICT_CLASS[k];
    }
    return 'uncertain';
  }

  function verdictIcon(v) {
    var vc = verdictClass(v);
    if (vc === 'confirmed') return '●';
    if (vc === 'likely') return '⚑';
    if (vc === 'uncertain') return '?';
    if (vc === 'benign') return '✓';
    return '';
  }

  function escHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _displayVerdict(v) {
    var raw = String(v || '').toUpperCase();
    if (raw === 'VALIDATED_BREACH' || raw === 'CONFIRMED_INTRUSION' || raw === 'CONFIRMED_BREACH') return 'CONFIRMED BREACH';
    if (raw === 'NO_VALIDATED_BREACH') return 'NO CONFIRMED BREACH';
    return raw.replace(/_/g, ' ') || 'UNCERTAIN';
  }

  function _dreadInfo(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var dn = p.dread_narrative || {};
    var frags = dn.fragments || {};
    var order = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'];
    var parts = [];
    order.forEach(function (key) {
      if (frags[key]) parts.push({ key: key, label: key.replace(/_/g, ' ').toUpperCase(), text: String(frags[key]) });
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
    } else if (p.what_happened || p.incident_name) {
      provenance = 'T1 LLM analysis';
    } else {
      provenance = 'Legacy fallback';
    }
    return {
      dn: dn,
      frags: frags,
      parts: parts,
      // hasStructured = true only when actual DREAD/PASTA/Diamond content exists.
      // Does NOT count raw T1 text (what_happened / incident_name) since those can
      // be deterministic fallback strings that carry no structured threat model.
      hasStructured: !!(dn.rendered || parts.length || hasPasta || hasDiamond),
      has: !!(dn.rendered || parts.length || p.what_happened || p.incident_name),
      hasPasta: hasPasta,
      hasDiamond: hasDiamond,
      hasT1: !!(p.what_happened || p.incident_name || p.evidence_chain),
      provenance: provenance
    };
  }

  function _rowChipsFromText(text, limit) {
    var found = [];
    String(text || '').replace(/\brows?\s+([0-9][0-9,\s+]*(?:\+\s*\d+\s+more)?)/ig, function (_, group) {
      var clean = String(group || '').replace(/\+\s*\d+\s*(?:more)?/ig, '');
      (clean.match(/\d+/g) || []).forEach(function (n) {
        if (found.indexOf(n) === -1 && found.length < (limit || 16)) found.push(n);
      });
      return _;
    });
    if (!found.length) return '';
    return '<div class="br-rowchips">Evidence refs: ' + found.map(function (n) {
      return '<a class="br-rowchip" href="/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=evidence&row=' + encodeURIComponent(n) + '">[' + escHtml(n) + ']</a>';
    }).join(' ') + '</div>';
  }

  function _renderWhyConfirmed(cluster) {
    var d = _dreadInfo(cluster);
    var _t1r = (cluster || {}).tier1_prefill || {};
    // Filter raw correlation text from what_happened before using it for pattern matching
    var _t1wh = _rawCorrelationText(_t1r.what_happened || '') ? '' : (_t1r.what_happened || '');
    var full = d.parts.map(function (p) { return p.text; }).join(' ').toLowerCase()
      + ' ' + JSON.stringify(_t1r.observed_impact || {}).toLowerCase()
      + ' ' + _t1wh.toLowerCase()
      + ' ' + JSON.stringify(_t1r.evidence_chain || []).toLowerCase()
      + ' ' + (_t1r.root_cause || '').toLowerCase()
      + ' ' + (_t1r.headline_subtitle || '').toLowerCase()
      // Cluster-level fields — always populated by the detection pipeline
      + ' ' + (cluster.lead_description || '').toLowerCase()
      + ' ' + (cluster.business_significance || '').toLowerCase()
      + ' ' + JSON.stringify(cluster.phases || []).toLowerCase()
      + ' ' + (cluster.shared_accounts || cluster.affected_accounts || []).join(' ').toLowerCase()
      + ' ' + (cluster.affected_assets || cluster.shared_hosts || []).join(' ').toLowerCase();
    var gates = [
      ['Data exfil', /exfil|copy into|unload|rclone|cloud sync|transferred data|cloud storage|s3.*get|putobject|download|data_exfil/.test(full)],
      ['Repeated activity', /recurred|distinct days|same command|reproduc|recurring|repeated|multiple.*event|persistent|multi.*phase|attack phase|8 phase/.test(full)],
      ['Affected users', /account|user|service_account|privileged|affected users|identity|credential|principal|pentest|svc_/.test(full)],
      ['Control gap', /no dlp|no pam|control gap|unconstrained|no inspection|no gate|unmonitored|bypass|privileged.*workload|daemonset|k8s.*privilege/.test(full)],
      ['Crown jewel', /crown jewel|regulated data|critical data|protected data|ndb|cps234|secret|encryption key|k8s|kubernetes|finance_wh|sfl_data|privileged workload|daemonset/.test(full)],
      ['Multi-source correlation', /cross-source|source types|multiple sources|correlation|multi.*source|okta|cloudtrail|azure/.test(full)
        || (cluster.confidence_meter && (cluster.confidence_meter.source_types_present || []).length > 1)]
    ];
    return '<div class="br-why-ladder">' + gates.map(function (g) {
      return '<span class="br-why-chip ' + (g[1] ? 'br-why-chip--ok' : 'br-why-chip--miss') + '">' + (g[1] ? '✓ ' : '? ') + escHtml(g[0]) + '</span>';
    }).join('') + '</div>';
  }

  function _sentenceList(text) {
    return String(text || '').replace(/\s+/g, ' ').split(/(?<=[.!?])\s+/).map(function (s) {
      return s.trim();
    }).filter(Boolean);
  }

  function _firstEvidenceSentence(cluster, fallback) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    var damage = (d.frags && d.frags.damage) || '';
    var repro = (d.frags && d.frags.reproducibility) || '';
    // Use T1 what_happened only when it's not raw correlation text
    var t1wh = (p.what_happened || '');
    var t1Sentence = (!_rawCorrelationText(t1wh)) ? (_sentenceList(t1wh)[0] || '') : '';
    var s1 = _sentenceList(damage)[0] || t1Sentence || fallback || '';
    var s2 = _sentenceList(repro)[0] || '';
    return [s1, s2].filter(Boolean).join(' ');
  }

  function _businessImpactSentence(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    var bits = [];
    if (d.dn && d.dn.sabsa_coda_draft) bits.push(d.dn.sabsa_coda_draft);
    // Only include exploitability fragment when its core text is NOT already
    // embedded in the sabsa_coda_draft (which always includes the control-gap hint)
    if (d.frags && d.frags.exploitability) {
      var explo = d.frags.exploitability;
      var exploCore = explo.replace(/^control gaps exploited:\s*/i, '').replace(/\.$/, '').toLowerCase();
      var alreadyCovered = bits.some(function(b) {
        return exploCore.length > 20 && b.toLowerCase().indexOf(exploCore.substring(0, 50)) !== -1;
      });
      if (!alreadyCovered) bits.push(explo);
    }
    if (!bits.length && p.observed_impact && p.observed_impact.data) bits.push('Data impact: ' + p.observed_impact.data);
    if (!bits.length && p.observed_impact && p.observed_impact.ops) bits.push('Operational impact: ' + p.observed_impact.ops);
    if (!bits.length && p.observed_impact && p.observed_impact.access) bits.push('Access impact: ' + p.observed_impact.access);
    if (!bits.length && p.pasta_summary && p.pasta_summary.business_impact) bits.push(p.pasta_summary.business_impact);
    // Use T1 what_happened only when it's not raw correlation text
    if (!bits.length && p.what_happened && !_rawCorrelationText(p.what_happened)) {
      bits.push(_sentenceList(p.what_happened)[0] || '');
    }
    // Cluster-level fallback: business_significance > lead_description
    if (!bits.length) {
      var biz = (cluster.business_significance || cluster.lead_description || '').trim();
      if (biz && !_rawCorrelationText(biz) && biz.length > 10) bits.push(biz);
    }
    return bits.filter(Boolean).join(' ');
  }

  function _knownUnknownBox(cluster) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    // Filter raw correlation text from what_happened before building text
    var _t1wh = _rawCorrelationText(p.what_happened || '') ? '' : (p.what_happened || '');
    var text = (d.parts.map(function (x) { return x.text; }).join(' ')
      + ' ' + JSON.stringify(p.observed_impact || {})
      + ' ' + _t1wh
      + ' ' + JSON.stringify(p.evidence_chain || [])
      + ' ' + (p.root_cause || '')
    ).toLowerCase();
    var known = [];
    var unknown = [];
    if (/rclone/.test(text)) known.push('Tool: rclone file-sync activity');
    if (/cloud storage|external storage|object storage/.test(text)) known.push('Destination: external cloud storage indicated by evidence');
    if (/crown jewel|regulated data|critical data|protected data/.test(text)) known.push('Crown-jewel or protected data indicator present in evidence');
    if (/no dlp/.test(text) || /no pam/.test(text)) known.push('Control gaps: DLP/PAM coverage missing in evidence');
    if (/service account|privileged|finance|standard user/.test(text)) known.push('Affected roles: service account, privileged/IT, finance, standard users');
    // T1 prefill enrichments — populate known list from structured T1 data
    if (!known.length && p.root_cause) known.push('Root cause: ' + p.root_cause);
    var _scope = p.affected_scope || {};
    var _scopeUsers = (_scope.users || _scope.accounts || []).filter(Boolean);
    if (!known.length && _scopeUsers.length) known.push('Compromised accounts: ' + _scopeUsers.slice(0, 3).join(', '));
    var _scopeHosts = (_scope.hosts || _scope.systems || []).filter(Boolean);
    if (_scopeHosts.length) known.push('Affected systems: ' + _scopeHosts.slice(0, 3).join(', '));
    // Evidence chain steps as confirmed facts — use first 2 meaningful steps
    if (!known.length && p.evidence_chain && p.evidence_chain.length) {
      p.evidence_chain.slice(0, 3).forEach(function(step) {
        var what = (step.what || step.event || step.description || step.action || '').trim();
        if (what && known.length < 3) known.push(what.length > 90 ? what.slice(0, 87) + '\u2026' : what);
      });
    }
    // Immediate actions as evidence of what was confirmed
    if (!known.length && p.immediate_actions && p.immediate_actions.length) {
      var ia = p.immediate_actions[0];
      var iaText = (typeof ia === 'string' ? ia : (ia.action || ia.step || '')).trim();
      if (iaText) known.push('Recommended: ' + (iaText.length > 80 ? iaText.slice(0, 77) + '\u2026' : iaText));
    }
    // Cluster-level data — always populated by the detection pipeline
    var clAccts = (cluster.shared_accounts || cluster.affected_accounts || []).filter(Boolean).slice(0, 3);
    if (clAccts.length && !known.some(function(k){ return /account|credential/i.test(k); })) {
      known.push('Compromised accounts: ' + clAccts.join(', '));
    }
    var clAssets = (cluster.affected_assets || cluster.shared_hosts || []).filter(Boolean).slice(0, 3);
    if (clAssets.length && !known.some(function(k){ return /system|host/i.test(k); })) {
      known.push('Affected systems: ' + clAssets.join(', '));
    }
    var clIps = (cluster.shared_external_ips || []).slice(0, 3);
    if (clIps.length) known.push('External infrastructure: ' + clIps.join(', '));
    var phases = (cluster.phases || []).map(function(ph) {
      return (ph.phase_role || ph.type || ph.name || '').replace(/_/g, ' ');
    }).filter(Boolean).slice(0, 5);
    if (phases.length) known.push('Attack phases confirmed: ' + phases.join(' \u2192 '));
    if (!/pii|customer|payroll|secret|source code|credential dump/.test(text)) unknown.push('Exact data contents and volume are unknown from current evidence');
    if (!/attacker-owned|external owner|malicious owner/.test(text)) unknown.push('External destination attribution and ownership is unconfirmed');
    if (!known.length) known.push('Evidence-confirmed facts are limited to the cited rows');
    return [
      '<div class="br-known-unknown">',
      '  <div><strong>Known</strong><ul>' + known.slice(0, 6).map(function (x) { return '<li>' + escHtml(x) + '</li>'; }).join('') + '</ul></div>',
      '  <div><strong>Unknown / not proven</strong><ul>' + unknown.slice(0, 4).map(function (x) { return '<li>' + escHtml(x) + '</li>'; }).join('') + '</ul></div>',
      '</div>'
    ].join('');
  }

  function _boundedActionsHtml(cluster) {
    var d = _dreadInfo(cluster);
    var _t1ba = (cluster || {}).tier1_prefill || {};
    // Filter raw correlation text before building the keyword-match text
    var _t1wh = _rawCorrelationText(_t1ba.what_happened || '') ? '' : (_t1ba.what_happened || '');
    var text = (d.parts.map(function (x) { return x.text; }).join(' ')
      + ' ' + _t1wh
      + ' ' + JSON.stringify(_t1ba.observed_impact || {})
      + ' ' + JSON.stringify(_t1ba.evidence_chain || [])
      // Cluster-level data for context branching
      + ' ' + JSON.stringify(cluster.phases || []).toLowerCase()
      + ' ' + (cluster.lead_description || '').toLowerCase()
      + ' ' + (cluster.business_significance || '').toLowerCase()
    ).toLowerCase();
    var safe, approval, manual;
    var isK8s = /kubernetes|k8s|daemonset|privileged.*workload|kubelet|container.*priv/.test(text);
    var isC2 = /c2[^a-z]|c2_comm|beacon|command.*control/.test(text);
    var isMultiPhase = /multi.*phase|multiphase|\d+\s+phase|attack phase/.test(text);
    var isExfil = /external storage|object storage|cloud|s3|exfil|transferred|data_exfil/.test(text);
    var isCred = /credential.*theft|lsass|mimikatz|token.*theft|mfa.*fatigue|session.*theft|password.*spray|credential_theft|session_theft/.test(text)
      || (cluster.phases || []).some(function(ph) { return /credential|session.*theft|mfa/.test((ph.phase_role || ph.type || ph.name || '').toLowerCase()); });
    var clAccts = (cluster.shared_accounts || cluster.affected_accounts || []).slice(0, 2);
    var acctList = clAccts.length ? clAccts.join(' and ') : 'affected accounts';
    var clIps = (cluster.shared_external_ips || []).slice(0, 3);
    var ipList = clIps.length ? clIps.join(', ') : 'identified C2 IPs';
    if (isCred) {
      safe = 'Revoke all active sessions and tokens for ' + acctList + ' immediately; collect endpoint memory dumps and auth logs before any changes';
      approval = 'Force password reset and MFA re-enrollment for ' + acctList + '; review and prune all delegated access after CISO sign-off';
      manual = 'CISO/Legal: assess whether credential access constitutes an NDB-reportable breach; confirm blast radius includes any downstream service accounts or API keys';
    } else if (isK8s) {
      safe = 'Isolate affected K8s namespaces; collect pod logs, kubelet audit events, and service account audit trails before any changes';
      approval = 'Revoke credentials for ' + acctList + '; rotate K8s service account tokens and RBAC bindings after sign-off';
      manual = isMultiPhase
        ? 'CISO/Legal: assess APRA CPS 234 72h notification window across all ' + ((cluster.phases || []).length || 'identified') + ' attack phases; confirm regulated-data exposure scope'
        : 'CISO/Legal: confirm whether regulated data was exposed via privileged K8s workload; assess NDB obligations';
    } else if (isC2) {
      safe = 'Preserve endpoint, DNS, and full-packet capture logs for identified C2 channels before firewall changes';
      approval = 'Block C2 destination IPs (' + ipList + ') at perimeter and DNS sinkholes after CISO approval';
      manual = 'CISO/Legal/Privacy: determine external attribution and reporting posture; assess NDB if data was staged';
    } else if (isExfil) {
      safe = 'Preserve endpoint, data-platform, and network egress logs before any remediation';
      approval = 'Block or restrict exfil destinations and revoke ' + acctList + ' credentials after approval';
      manual = 'CISO/Legal/Privacy: sign-off on breach notification posture and data-volume assessment';
    } else {
      safe = 'Preserve endpoint, data-platform, and network evidence before any remediation steps';
      approval = 'Contain affected destinations and revoke ' + acctList + ' credentials after sign-off';
      manual = 'CISO/Legal/Privacy: sign-off on reporting posture and scope confirmation';
    }
    return [
      '<div class="br-bounded-actions">',
      '  <div><span class="br-auto br-auto--safe">SAFE</span> ' + escHtml(safe) + '</div>',
      '  <div><span class="br-auto br-auto--approval">APPROVAL</span> ' + escHtml(approval) + '</div>',
      '  <div><span class="br-auto br-auto--manual">MANUAL</span> ' + escHtml(manual) + '</div>',
      '</div>'
    ].join('');
  }

  function _compactExecSummary(data, fallbackBody) {
    var fragments = data.dread_fragments || {};
    var p1 = _sentenceList(fragments.damage || data.executive_summary || fallbackBody).slice(0, 2).join(' ');
    var p2Parts = [];
    if (data.sabsa_coda_draft) p2Parts.push(data.sabsa_coda_draft);
    if (fragments.exploitability) p2Parts.push(_sentenceList(fragments.exploitability)[0]);
    if (data.scope && data.scope.ruled_out_rows) {
      p2Parts.push(data.scope.ruled_out_rows.toLocaleString() + ' authorized-security-test or benign rows were excluded from breach scope.');
    }
    var p2 = p2Parts.join(' ');
    return {
      p1: p1 || fallbackBody || '',
      p2: p2 || _sentenceList(data.executive_summary || fallbackBody).slice(2, 4).join(' ')
    };
  }

  function _dreadNarrativeText(cluster, fallback) {
    var d = _dreadInfo(cluster);
    var p = (cluster || {}).tier1_prefill || {};
    if (d.dn.rendered) return d.dn.rendered;
    if (d.parts.length) {
      var body = d.parts.map(function (x) { return x.label + ': ' + x.text; }).join('\n');
      if (d.dn.sabsa_coda_draft) body += '\nSABSA: ' + d.dn.sabsa_coda_draft;
      return body;
    }
    // PASTA fallback: stages 4 (threat profile), 5 (exploitation path), 7 (business impact)
    if (d.hasPasta) {
      var pasta = p.pasta_summary || {};
      var pastaParts = [];
      if (pasta.threat_profile) pastaParts.push('THREAT ACTOR: ' + pasta.threat_profile);
      if (pasta.exploitation_path) pastaParts.push('EXPLOITATION: ' + pasta.exploitation_path);
      if (pasta.business_impact) pastaParts.push('BUSINESS IMPACT: ' + pasta.business_impact);
      if (pastaParts.length) return pastaParts.join('\n');
    }
    // Diamond fallback: adversary, capability, victim
    if (d.hasDiamond) {
      var dm = p.diamond_model || {};
      var dmParts = [];
      if (dm.adversary) dmParts.push('ADVERSARY: ' + dm.adversary);
      if (dm.capability && dm.capability.length) dmParts.push('CAPABILITIES: ' + dm.capability.slice(0, 5).join(', '));
      var victims = (dm.victim_users || []).concat(dm.victim_data || []);
      if (victims.length) dmParts.push('VICTIM SCOPE: ' + victims.slice(0, 4).join(', '));
      if (dmParts.length) return dmParts.join('\n');
    }
    // T1 LLM prefill content — use only when it's not a raw correlation string
    if (p.what_happened && !_rawCorrelationText(p.what_happened)) return p.what_happened;
    return fallback || '';
  }

  // ── Upload view ──────────────────────────────────────────────────────────────

  function renderUpload() {
    updateTabBar(null);
    document.getElementById('br-content').innerHTML = [
      '<div class="br-upload" data-testid="br-upload">',
      '  <div class="br-upload__zone" id="br-drop-zone" data-testid="br-drop-zone">',
      '    <div class="br-upload__icon">⬆</div>',
      '    <div class="br-upload__title">Drop files to analyse</div>',
      '    <div class="br-upload__sub">.csv &nbsp;·&nbsp; .xlsx &nbsp;·&nbsp; .json &nbsp;·&nbsp; .log<br>Up to 3 files · 50 MB each</div>',
      '    <input type="file" id="br-file-input" data-testid="br-file-input" multiple accept=".csv,.xlsx,.json,.log" style="display:none">',
      '  </div>',
      '  <div id="br-recent"></div>',
      '</div>',
    ].join('');

    var zone = document.getElementById('br-drop-zone');
    var input = document.getElementById('br-file-input');

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('br-upload__zone--over'); });
    zone.addEventListener('dragleave', function () { zone.classList.remove('br-upload__zone--over'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('br-upload__zone--over');
      handleFiles(e.dataTransfer.files);
    });
    input.addEventListener('change', function () { handleFiles(input.files); });
  }

  function _readFileText(file) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function (e) { resolve(e.target.result); };
      fr.onerror = function () { reject(new Error('FileReader error')); };
      fr.readAsText(file);
    });
  }

  function _parseJsonRows(text, filename) {
    try {
      var data = JSON.parse(text.trim());
      var rows;
      if (Array.isArray(data)) {
        rows = data;
      } else if (data && typeof data === 'object') {
        // Try well-known single-array keys first
        rows = data.events || data.logs || data.records || data.data;
        if (!rows) {
          // Multi-section object (e.g. {aws_cloudtrail:[...], okta_system_log:[...]})
          // Flatten all top-level array values, skipping metadata objects
          rows = Object.values(data).reduce(function (acc, v) {
            if (Array.isArray(v)) return acc.concat(v);
            return acc;
          }, []);
        }
      }
      rows = (rows || []).filter(function (r) { return r && typeof r === 'object'; });
      return _sampleRowsForBreach(rows.map(function (r) { return Object.assign({ _source: filename }, r); }), MAX_ROWS_PER_FILE);
    } catch (_) { return []; }
  }

  // Per-file row cap for the SMALL/DEMO path (browser-side parsing).
  var MAX_ROWS_PER_FILE = 1200;

  // Above these thresholds we bypass browser parsing entirely and use the
  // async backend upload path (POST /api/v1/assessments/upload).
  var ASYNC_THRESHOLD_BYTES = 5 * 1024 * 1024;   // 5 MB total
  var ASYNC_THRESHOLD_FILES = 1;                   // always use async for multi-file, set to 99 to disable

  // Named-entity keyword list removed. Sampling is now neutral — severity
  // and volume signals only, no scenario-specific tokens.
  var _BREACH_KEEP_TERMS = [];

  function _scoreRowForBreach(row) {
    var score = 0;
    var sev = String(row.severity || row.severity_name || row.risk_level || row.alert_severity || '').toLowerCase();
    if (/critical|fatal|5/.test(sev)) score += 35;
    else if (/high|4/.test(sev)) score += 20;
    else if (/medium|3/.test(sev)) score += 8;
    if (row.alert_signature || row.detect_id || row.tactic || row.technique) score += 15;
    var bytes = Number(row.bytes_sent || row.orig_bytes || row.bytes || row.rows_produced || row.bytes_scanned || 0);
    if (bytes > 100000000) score += 20;
    if (bytes > 1000000000) score += 20;
    return score;
  }

  function _sampleRowsForBreach(rows, maxRows) {
    if (!Array.isArray(rows) || rows.length <= maxRows) return rows || [];
    var keep = new Map();
    var scored = rows.map(function (row, idx) { return { row: row, idx: idx, score: _scoreRowForBreach(row) }; });
    scored.sort(function (a, b) { return (b.score - a.score) || (a.idx - b.idx); });
    scored.slice(0, Math.floor(maxRows * 0.75)).forEach(function (item) { keep.set(item.idx, item.row); });
    var remaining = Math.max(1, maxRows - keep.size);
    var stride = Math.max(1, Math.floor(rows.length / remaining));
    for (var i = 0; i < rows.length && keep.size < maxRows; i += stride) keep.set(i, rows[i]);
    keep.set(0, rows[0]);
    keep.set(rows.length - 1, rows[rows.length - 1]);
    return Array.from(keep.entries())
      .sort(function (a, b) { return a[0] - b[0]; })
      .slice(0, maxRows)
      .map(function (entry) { return entry[1]; });
  }

  function _parseNdjsonRows(text, filename) {
    var rows = [];
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      try {
        var obj = JSON.parse(line);
        if (obj && typeof obj === 'object') rows.push(Object.assign({ _source: filename }, obj));
      } catch (_) {}
    }
    return _sampleRowsForBreach(rows, MAX_ROWS_PER_FILE);
  }

  function _splitCsvLine(line) {
    var out = [], cur = '', quoted = false;
    for (var i = 0; i < line.length; i++) {
      var ch = line[i];
      if (ch === '"') {
        if (quoted && line[i + 1] === '"') { cur += '"'; i++; }
        else quoted = !quoted;
      } else if (ch === ',' && !quoted) {
        out.push(cur); cur = '';
      } else {
        cur += ch;
      }
    }
    out.push(cur);
    return out;
  }

  function _parseCsvRows(text, filename) {
    var lines = text.split(/\r?\n/).filter(function (line) { return line.trim(); });
    if (lines.length < 2) return [];
    var headers = _splitCsvLine(lines[0]).map(function (h) { return h.trim(); });
    var rows = [];
    for (var i = 1; i < lines.length; i++) {
      var cells = _splitCsvLine(lines[i]);
      var obj = { _source: filename };
      headers.forEach(function (h, j) { obj[h || ('col_' + j)] = cells[j] !== undefined ? cells[j] : ''; });
      rows.push(obj);
    }
    return _sampleRowsForBreach(rows, MAX_ROWS_PER_FILE);
  }

  function handleFiles(files) {
    if (!files || !files.length) return;

    var fileArr = Array.from(files);
    var totalBytes = fileArr.reduce(function (s, f) { return s + (f.size || 0); }, 0);

    // Route to async backend upload for large datasets.
    // Above ASYNC_THRESHOLD_BYTES or when multiple files are dropped, the
    // browser sends raw file bytes and the server does all parsing.
    // This avoids main-thread freeze and the 5K-row JSON payload limit.
    var useAsync = totalBytes > ASYNC_THRESHOLD_BYTES || fileArr.length > ASYNC_THRESHOLD_FILES;
    if (useAsync) {
      return _handleFilesAsync(fileArr, totalBytes);
    }
    return _handleFilesSync(fileArr);
  }

  // ── Async backend upload (large files / multiple files) ──────────────────────

  function _handleFilesAsync(fileArr, totalBytes) {
    renderAsyncProgress(fileArr, totalBytes);

    var hdrs = authHeaders();
    delete hdrs['Content-Type'];
    var form = new FormData();
    fileArr.forEach(function (f) { form.append('files', f); });

    fetch(apiBase() + '/api/v1/assessments/upload', {
      method: 'POST',
      headers: hdrs,
      body: form,
    })
      .then(function (r) {
        if (!r.ok) return r.json().then(function (e) { throw new Error(e.detail || r.statusText); });
        return r.json();
      })
      .then(function (data) {
        var aid = data.assessment_id;
        if (!aid) { toast('Upload failed: ' + (data.detail || 'unknown')); return; }
        updateAsyncStatus('Uploaded — processing on server…', 5);
        _pollAsyncProgress(aid);
      })
      .catch(function (err) {
        _describeUploadFailure(err).then(function (msg) {
          toast('Upload error: ' + msg);
          document.getElementById('br-content').innerHTML = '<div class="br-processing"><div class="br-processing__title" style="color:#e74c3c">Upload failed: ' + _esc(msg) + '</div></div>';
        });
      });
  }

  function _describeUploadFailure(err) {
    var base = (err && err.message) || 'unknown error';
    var safeBase = base;
    try {
      var devLike = /localhost|127\.0\.0\.1/.test(window.location.hostname) ||
        localStorage.getItem('janusecShowDebugErrors') === '1';
      if (!devLike) return Promise.resolve(safeBase);
    } catch (_) {
      return Promise.resolve(safeBase);
    }
    return fetch(apiBase() + '/api/v1/debug/last-errors?limit=1', { headers: authHeaders() })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var item = d && d.errors && d.errors[0];
        if (!item) return safeBase;
        var typ = item.exception_type || item.error || 'backend_error';
        var detail = item.exception_str || item.path || '';
        return safeBase + ' (' + typ + (detail ? ': ' + String(detail).slice(0, 180) : '') + ')';
      })
      .catch(function () { return safeBase; });
  }

  function _pollAsyncProgress(aid) {
    // Prefer SSE for responsive updates, but always run JSON polling as the
    // authoritative watchdog. EventSource cannot send auth headers and some
    // proxies close streams early; polling must still complete the redirect.
    if (typeof EventSource !== 'undefined') {
      _connectSSE(aid);
    }
    _schedulePollJson(aid, 1200);
  }

  // Critical addition #5 — SSE progress
  function _connectSSE(aid) {
    var url = apiBase() + '/api/v1/assessments/' + encodeURIComponent(aid) + '/progress';
    var token = _getAuthToken();
    // EventSource doesn't support custom headers — append token as query param if needed
    var qs = [];
    if (token) qs.push('token=' + encodeURIComponent(token));
    try {
      var tenant = localStorage.getItem('tenantId') || 'default';
      if (tenant) qs.push('tenant_id=' + encodeURIComponent(tenant));
    } catch (_) {}
    if (qs.length) url += '?' + qs.join('&');

    var es = new EventSource(url);
    es.addEventListener('progress', function (e) {
      try {
        var d = JSON.parse(e.data);
        _applyProgressEvent(d, aid, es);
      } catch (_) {}
    });
    es.onerror = function () {
      es.close();
      // Fall back to polling on SSE error. Polling may already be running;
      // the scheduler deduplicates timers for this assessment id.
      _schedulePollJson(aid, 1000);
    };
  }

  function _schedulePollJson(aid, delayMs) {
    if (!aid || _asyncRedirecting[aid]) return;
    if (_asyncPollTimers[aid]) return;
    _asyncPollTimers[aid] = setTimeout(function () {
      delete _asyncPollTimers[aid];
      _pollJson(aid);
    }, delayMs || 0);
  }

  function _pollJson(aid) {
    if (!aid || _asyncRedirecting[aid]) return;
    var url = apiBase() + '/api/v1/assessments/' + encodeURIComponent(aid) + '/progress/poll';
    fetch(url, { headers: authHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        _applyProgressEvent(d, aid, null);
        if (!_asyncRedirecting[aid] && d.status !== 'ready' && d.status !== 'failed' && d.status !== 'cancelled') {
          _schedulePollJson(aid, 2000);
        }
      })
      .catch(function () {
        _schedulePollJson(aid, 3000);
      });
  }

  function _applyProgressEvent(d, aid, es) {
    if (!d || _asyncRedirecting[aid]) return;
    var pct = d.percent || 0;
    var label = d.label || d.stage || '';
    var status = d.status || '';
    var rows = d.row_count || 0;
    var clusters = d.cluster_count || 0;
    if (!label && status) label = status;

    updateAsyncStatus(label + (rows ? ' — ' + rows.toLocaleString() + ' rows' : ''), pct);
    if (clusters > 0) {
      updateAsyncDetail(clusters + ' cluster' + (clusters !== 1 ? 's' : '') + ' found');
    }

    if (status === 'ready') {
      if (es) es.close();
      _redirectToAssessment(aid);
    } else if (status === 'failed') {
      if (es) es.close();
      var errMsg = d.error || 'Assessment pipeline failed';
      toast('Assessment failed: ' + errMsg);
      document.getElementById('br-content').innerHTML =
        '<div class="br-processing"><div class="br-processing__title" style="color:#e74c3c">Failed: ' + _esc(errMsg) + '</div>' +
        '<p style="color:#888;font-size:0.85em;margin-top:8px">You can try uploading a smaller dataset or check server logs.</p></div>';
    } else if (status === 'cancelled') {
      if (es) es.close();
      toast(d.error || 'Assessment was cancelled');
      document.getElementById('br-content').innerHTML =
        '<div class="br-processing"><div class="br-processing__title" style="color:#e5c542">Cancelled</div></div>';
    } else if (d.terminal) {
      if (es) es.close();
      // A stream can terminate because of timeout/proxy behaviour while the job
      // is still running. Do not strand the page on "Queued 0%"; verify whether
      // the assessment exists, then continue polling if it is not ready yet.
      _verifyAssessmentReady(aid);
    }
  }

  function _redirectToAssessment(aid) {
    if (!aid || _asyncRedirecting[aid]) return;
    _asyncRedirecting[aid] = true;
    if (_asyncPollTimers[aid]) {
      clearTimeout(_asyncPollTimers[aid]);
      delete _asyncPollTimers[aid];
    }
    updateAsyncStatus('Assessment ready - redirecting...', 100);
    setTimeout(function () {
      window.location.href = '/static/breach.html?assessment=' + encodeURIComponent(aid);
    }, 500);
  }

  function _verifyAssessmentReady(aid) {
    if (!aid || _asyncRedirecting[aid]) return;
    apiFetch('/api/v1/assessments/' + encodeURIComponent(aid))
      .then(function (r) {
        if (r.ok) return r.json();
        throw new Error('not ready');
      })
      .then(function (data) {
        if (data && (data.assessment_id === aid || data.id === aid || data.status === 'ready')) {
          _redirectToAssessment(aid);
          return;
        }
        updateAsyncStatus('Still processing on server...', 90);
        _schedulePollJson(aid, 2000);
      })
      .catch(function () {
        updateAsyncStatus('Still processing on server...', 90);
        _schedulePollJson(aid, 2000);
      });
  }

  function _getAuthToken() {
    try {
      var h = authHeaders();
      return (h['Authorization'] || '').replace('Bearer ', '') || h['x-api-key'] || '';
    } catch (_) { return ''; }
  }

  function _esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ── Sync browser-side path (small / curated demos ≤ ASYNC_THRESHOLD_BYTES) ──

  function _handleFilesSync(fileArr) {
    renderProcessing();

    var jsonFiles   = fileArr.filter(function (f) { return /\.(json|jsonl)$/i.test(f.name); });
    var ndjsonFiles = fileArr.filter(function (f) { return /\.ndjson$/i.test(f.name); });
    var xlsxFiles   = fileArr.filter(function (f) { return /\.(xlsx|xlsm)$/i.test(f.name); });
    var csvFiles    = fileArr.filter(function (f) { return /\.csv$/i.test(f.name); });
    var serverFiles = fileArr.filter(function (f) { return !/\.(csv|json|jsonl|ndjson|xlsx|xlsm)$/i.test(f.name); });

    // XLSX enrichment workbooks: send to /upload/workbook_sheets to get all sheets with _sheet metadata
    var xlsxPromise = xlsxFiles.length ? (function () {
      var hdrs = authHeaders();
      delete hdrs['Content-Type'];
      var form = new FormData();
      xlsxFiles.forEach(function (f) { form.append('files', f); });
      return fetch(apiBase() + '/api/v1/upload/workbook_sheets', { method: 'POST', headers: hdrs, body: form })
        .then(function (r) { return r.json(); })
        .then(function (wb) {
          var allWbRows = [];
          (wb.results || []).forEach(function (res) {
            if (res.status === 'parsed' && Array.isArray(res.rows)) {
              allWbRows = allWbRows.concat(res.rows);
            }
          });
          return allWbRows;
        })
        .catch(function () { return []; });
    })() : Promise.resolve([]);

    var jsonPromise = Promise.all(
      jsonFiles.map(function (f) {
        return _readFileText(f).then(function (text) { return _parseJsonRows(text, f.name); });
      }).concat(
        ndjsonFiles.map(function (f) {
          return _readFileText(f).then(function (text) { return _parseNdjsonRows(text, f.name); });
        })
      ).concat(
        csvFiles.map(function (f) {
          return _readFileText(f).then(function (text) { return _parseCsvRows(text, f.name); });
        })
      )
    );

    var serverPromise = serverFiles.length ? (function () {
      var hdrs = authHeaders();
      delete hdrs['Content-Type'];
      var form = new FormData();
      serverFiles.forEach(function (f) { form.append('files', f); });
      return fetch(apiBase() + '/api/v1/upload/files', { method: 'POST', headers: hdrs, body: form })
        .then(function (r) { return r.json(); })
        .then(function (uploadData) {
          var fetches = (uploadData.results || [])
            .filter(function (r) { return r.status === 'processed' && r.analysis; })
            .map(function (r) {
              var analysis = r.analysis || {};
              if (analysis.pagination_session) {
                var sid = analysis.pagination_session;
                return fetch(apiBase() + '/api/v1/upload/tabular/page?session=' + encodeURIComponent(sid) + '&limit=' + MAX_ROWS_PER_FILE, { headers: authHeaders() })
                  .then(function (pr) { return pr.json(); })
                  .then(function (pd) {
                    var headers = pd.headers || [];
                    return (pd.rows || []).map(function (row) {
                      var obj = {};
                      headers.forEach(function (h, i) { obj[h] = row[i] !== undefined ? row[i] : ''; });
                      obj._source = r.filename || 'unknown';
                      return obj;
                    });
                  });
              }
              if (analysis.full_rows && Array.isArray(analysis.full_rows)) {
                return Promise.resolve(analysis.full_rows.map(function (row) {
                  return Object.assign({ _source: r.filename || 'unknown' }, row);
                }));
              }
              return Promise.resolve([]);
            });
          return Promise.all(fetches);
        });
    })() : Promise.resolve([]);

    Promise.all([jsonPromise, serverPromise, xlsxPromise])
      .then(function (results) {
        var jsonRows = [].concat.apply([], results[0]);
        var serverRows = [].concat.apply([], results[1]);
        var xlsxRows = results[2] || [];
        var allRows = jsonRows.concat(serverRows).concat(xlsxRows)
          .map(function (r, i) { return Object.assign({}, r, { row_index: i }); });
        if (!allRows.length) { toast('No rows extracted from uploaded files'); return; }
        return fetch(apiBase() + '/api/v1/csv/deep_analyze', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ rows: allRows, options: { auto_llm: false }, org: 'unknown' }),
        }).then(function (r) { return r.json(); });
      })
      .then(function (data) {
        if (!data) return;
        var aid = data.assessment_id;
        if (aid) {
          window.location.href = '/static/breach.html?assessment=' + encodeURIComponent(aid);
        } else {
          toast('Upload failed: ' + (data.detail || 'unknown error'));
        }
      })
      .catch(function (err) { toast('Upload error: ' + err.message); });
  }

  function renderProcessing() {
    document.getElementById('br-content').innerHTML = [
      '<div class="br-processing">',
      '  <div class="br-processing__title">Analysing files…</div>',
      '  <div class="br-processing__step br-processing__step--active" id="brs-norm">',
      '    <span>Normalising rows</span>',
      '    <div class="br-processing__bar"><div class="br-processing__bar-fill" style="width:0%" id="brs-norm-bar"></div></div>',
      '  </div>',
      '  <div class="br-processing__step" id="brs-corr">',
      '    <span>Correlation engine</span>',
      '    <div class="br-processing__bar"><div class="br-processing__bar-fill" style="width:0%" id="brs-corr-bar"></div></div>',
      '  </div>',
      '  <div class="br-processing__step" id="brs-t1">',
      '    <span>Tier-1 prefill (top cluster)</span>',
      '    <div class="br-processing__bar"><div class="br-processing__bar-fill" style="width:0%" id="brs-t1-bar"></div></div>',
      '  </div>',
      '</div>',
    ].join('');
    // Animate bars pseudo-progressively while we wait for the redirect
    _animateBar('brs-norm-bar', 8000);
  }

  // Critical addition #5 — async progress UI driven by SSE events
  function renderAsyncProgress(fileArr, totalBytes) {
    var sizeMB = (totalBytes / (1024 * 1024)).toFixed(1);
    var fileNames = fileArr.map(function (f) { return f.name; }).join(', ');
    document.getElementById('br-content').innerHTML = [
      '<div class="br-processing" id="br-async-progress">',
      '  <div class="br-processing__title" id="br-async-title">Uploading to server…</div>',
      '  <div style="color:#888;font-size:0.82em;margin-bottom:10px" id="br-async-detail">',
      '    ' + _esc(fileNames) + ' &nbsp;·&nbsp; ' + sizeMB + ' MB',
      '  </div>',
      '  <div class="br-processing__bar" style="margin-bottom:6px">',
      '    <div class="br-processing__bar-fill" id="br-async-bar" style="width:0%;transition:width 0.6s ease"></div>',
      '  </div>',
      '  <div style="color:#aaa;font-size:0.78em;margin-top:4px" id="br-async-pct">0%</div>',
      '  <div style="color:#888;font-size:0.75em;margin-top:12px">',
      '    Server-side parsing — no browser memory limit. Progress updates every ~2s.',
      '  </div>',
      '</div>',
    ].join('');
  }

  function updateAsyncStatus(label, percent) {
    var title = document.getElementById('br-async-title');
    var bar = document.getElementById('br-async-bar');
    var pctEl = document.getElementById('br-async-pct');
    if (title) title.textContent = label || 'Processing…';
    if (bar) bar.style.width = (percent || 0) + '%';
    if (pctEl) pctEl.textContent = (percent || 0) + '%';
  }

  function updateAsyncDetail(text) {
    var el = document.getElementById('br-async-detail');
    if (el) el.textContent = text;
  }

  function _animateBar(id, durationMs) {
    var el = document.getElementById(id);
    if (!el) return;
    var start = Date.now();
    (function tick() {
      var pct = Math.min(90, ((Date.now() - start) / durationMs) * 100);
      el.style.width = pct + '%';
      if (pct < 90) requestAnimationFrame(tick);
    })();
  }

  // ── Home view ─────────────────────────────────────────────────────────────────

  function _renderReingestBanner(a) {
    if (!a.requires_reingest && !a.fallback_used) return '';
    var diag = a.cluster_diagnostics || {};
    var staleRows = diag.stale_rows || 0;
    var msg = 'Telemetry was stored with an older normalizer — canonical pivot fields were missing, so typed clustering could not run.';
    if (staleRows) msg += ' ' + staleRows + ' stale rows detected.';
    return '<div class="reingest-banner" style="background:#7c2d2d;color:#fcd4d4;border-left:4px solid #ef4444;padding:10px 16px;margin-bottom:12px;border-radius:4px;font-size:13px;">'
      + '<strong>Re-ingest required:</strong> ' + escHtml(msg)
      + ' <a href="#" onclick="document.getElementById(\'upload-panel\').scrollIntoView({behavior:\'smooth\'});return false;" style="color:#fca5a5;text-decoration:underline;">Re-upload source files</a>'
      + '</div>';
  }

  function renderHome() {
    updateTabBar('breach');
    var a = state.assessment || {};

    // Prefer presentation-layer threat_cases for top cards when available.
    // Exclude ANALYSIS_INCOMPLETE cases from the ranked top pool — they are
    // shown as a banner/warning, not as evidence cards.
    var rawSource = (state.threatCases && state.threatCases.length > 0)
      ? state.threatCases
      : state.clusters;
    var topSource = rawSource.filter(function(c) {
      return (c.verdict || c.final_verdict || '').toUpperCase() !== 'ANALYSIS_INCOMPLETE';
    });
    var sorted = _rankClusters(topSource);
    // Always keep full cluster inventory available for context/audit sections.
    var allClusters = _rankClusters(state.clusters);

    var html = _renderReingestBanner(a);
    html += _renderMetaLine(a, allClusters);
    html += _renderBreachAnswerHero(sorted, a);
    html += _renderRootCauseNarrative(sorted[0], sorted);
    html += _renderExecSummaryShell(sorted, a);
    html += '<details class="br-analyst-detail" data-testid="br-analyst-detail"><summary class="br-section-head" style="cursor:pointer;">THREAT CASES — Analyst Detail ▸</summary>';
    html += _renderTopFindings(sorted);
    // Narrative context and additional findings use full cluster inventory.
    html += _renderNarrativeContext(allClusters);
    html += _renderAdditionalFindings(allClusters);
    html += '</details>';
    // Only count benign clusters not already shown in narrative context section
    var _shownBenignIds = new Set(allClusters.filter(function(c){
      return _vClass(c)==='benign' && ((c.row_refs||[]).length>0||c.case_type==='enrichment_guided');
    }).map(function(c){ return c.cluster_id; }));
    var _hiddenBenignCount = allClusters.filter(function(c){
      return _vClass(c)==='benign' && !_shownBenignIds.has(c.cluster_id);
    }).length;
    html += _renderCollapsed('BENIGN', _hiddenBenignCount);
    html += _renderCollapsed('ISOLATED', a.isolated_count || 0);
    html += _renderSwimlane(allClusters, a);
    html += _renderHopGraphMini(sorted[0]);

    document.getElementById('br-content').innerHTML = html;

    // Wire and hydrate the narrative/card UI before mounting optional visuals.
    // A D3 rendering issue should never block the analyst from seeing cases.
    _wireHomeEvents();
    _hydrateTopThreatCases(sorted, a);

    // Build the CEO summary from the current deterministic verdict/wording.
    _loadExecSummary(true);

    // Fix 6 — Auto-generate DREAD threat summary for CRITICAL secondary clusters
    // so the most dangerous cases (esp. data exfiltration) aren't lazy-loaded.
    var _AUTO_GEN_THRESHOLD = 50;
    sorted.forEach(function (c, idx) {
      if (idx === 0) return; // lead case handled by _hydrateTopThreatCases
      var di = _dreadInfo(c);
      if (di.hasStructured) return; // already has content
      var isCritical = (c.severity || '').toLowerCase() === 'critical'
        || (c.row_refs || []).length >= _AUTO_GEN_THRESHOLD;
      var isBreachVerdict = /CONFIRMED|VALIDATED/.test((c.verdict || c.final_verdict || '').toUpperCase());
      if (isCritical || isBreachVerdict) {
        window.setTimeout(function () {
          _fireDreadGenerate(c.cluster_id, function () {
            var resorted = _rankClusters(
              (state.threatCases && state.threatCases.length > 0) ? state.threatCases : state.clusters
            );
            _rerenderCard(c.cluster_id, resorted);
          });
        }, (idx + sorted.length) * 400); // stagger after primary prefill
      }
    });

    // A4: mount D3 visualisations now that containers exist in DOM
    _mountSwimlane(allClusters);
    _mountHopGraphMini(sorted[0] || null);
  }

  function _hydrateTopThreatCases(sorted, assessment) {
    var top = _selectTopThreatCases(sorted);
    top.forEach(function (c, idx) {
      // Never auto-fire LLM for ANALYSIS_INCOMPLETE — no typed evidence exists.
      var verdict = (c.verdict || c.final_verdict || '').toUpperCase();
      if (verdict === 'ANALYSIS_INCOMPLETE') return;
      var isConfirmed = _vClass(c) === 'confirmed';
      if (_prefillDone(c)) {
        _safeRenderCard(c, sorted, idx);
        return;
      }
      if (!isConfirmed) {
        // LIKELY_BREACH / LIKELY_COMPROMISE — render deterministic card immediately
        // with human-gate banner. Do NOT auto-fire LLM; analyst clicks Generate.
        _safeRenderCard(c, sorted, idx);
        return;
      }
      // CONFIRMED_BREACH / CONFIRMED_INTRUSION — auto-fire LLM prefill
      _renderCardLoading(c, idx);
      window.setTimeout(function () {
        _fireSinglePrefill(c.cluster_id, function () {
          var resorted = _rankClusters(
            (state.threatCases && state.threatCases.length > 0) ? state.threatCases : state.clusters
          );
          var hero = document.querySelector('[data-role="breach-answer-hero"]');
          if (hero) hero.outerHTML = _renderBreachAnswerHero(resorted, assessment);
          _loadExecSummary(true);
          _rerenderCard(c.cluster_id, resorted);
        });
      }, idx * 350);
    });

    // Also fire prefill for benign context clusters (shown in SECURITY CONTEXT section)
    // so their narrative/verdict_reasoning is populated. Fire after top cases with a delay.
    var contextClusters = sorted.filter(function (c) {
      return _vClass(c) === 'benign' && (c.row_refs || []).length > 0 && !_prefillDone(c);
    });
    contextClusters.forEach(function (c, idx) {
      window.setTimeout(function () {
        _fireSinglePrefill(c.cluster_id, function () {
          // Re-render the narrative context section in-place
          var el = document.getElementById('br-context-' + c.cluster_id);
          if (!el) return;
          var p = c.tier1_prefill || {};
          var sub = p.headline_subtitle || c.reason_summary || p.short_narrative || '';
          var narrative = p.verdict_reasoning || p.what_happened || c.business_significance || '';
          var _badRe = /command.and.control|c2 beacon|needs containment|attacker maintain/i;
          if (_badRe.test(narrative)) narrative = sub;
          var nameEl = el.querySelector('.br-finding__verdict');
          var subEl = el.querySelector('.br-finding__oneliner');
          var narEl = el.querySelector('.br-finding__meta');
          if (nameEl && p.incident_name) nameEl.textContent = '✓ ' + p.incident_name.toUpperCase();
          if (subEl && sub) subEl.textContent = sub;
          if (narEl && narrative) narEl.textContent = narrative;
        });
      }, (top.length + idx) * 350 + 800);
    });
  }

  function _renderMetaLine(a, sorted) {
    // Compute source count from row._source values when API doesn't provide it
    var sourceNames = new Set();
    state.rows.forEach(function (r) {
      var s = r._source || r.source || r.log_source || '';
      if (s) sourceNames.add(s);
    });
    var store = a.evidence_store || {};
    var sourceCount = a.source_count || (store.source_counts ? Object.keys(store.source_counts).length : 0) || (sourceNames.size > 0 ? sourceNames.size : '?');
    var rowCount = store.row_count || a.rows_processed || state.rows.length || 0;
    var uploadedCount = a.uploaded_row_count || a.total_rows_uploaded || 0;
    var FETCH_LIMIT = 2000;
    var atLimit = uploadedCount > rowCount;
    var coverageWarning = atLimit
      ? '<span style="color:#ffaa00;font-size:12px;" title="Upload may contain more rows than were analyzed"> ⚠ analyzed ' + rowCount + ' of ' + (uploadedCount > rowCount ? uploadedCount : '?') + ' uploaded rows (limit ' + FETCH_LIMIT + ')</span>'
      : '';
    return [
      '<div class="br-meta" data-testid="br-meta">',
      '  <strong>Assessment ' + escHtml(a.assessment_id || '') + '</strong>',
      '  &nbsp;·&nbsp; <span data-testid="br-source-count">' + sourceCount + '</span> sources',
      '  &nbsp;·&nbsp; <span data-testid="br-row-count">' + rowCount + '</span> rows analyzed',
      coverageWarning,
      '  &nbsp;·&nbsp; <span data-testid="br-cluster-count">' + sorted.length + '</span> threat cases',
      '  &nbsp;·&nbsp; ' + (a.isolated_count || 0) + ' isolated',
      '  <br>',
      '  Top threat cases hydrate automatically',
      '</div>',
    ].join('');
  }

  var _HERO_CONFIG = {
    VALIDATED_BREACH:      { label: 'CONFIRMED BREACH',       bg: '#3d0a0a', border: '#e05252', text: '#ff9090', icon: '🔴' },
    CONFIRMED_BREACH:      { label: 'CONFIRMED BREACH',       bg: '#3d0a0a', border: '#e05252', text: '#ff9090', icon: '🔴' },
    CONFIRMED_INTRUSION:   { label: 'CONFIRMED INTRUSION',    bg: '#3d1a00', border: '#ff7c3c', text: '#ffb090', icon: '🟠' },
    LIKELY_BREACH:         { label: 'LIKELY BREACH — REVIEW', bg: '#2a1500', border: '#ff8c00', text: '#ffb060', icon: '🟠' },
    LIKELY_COMPROMISE:     { label: 'LIKELY COMPROMISE',      bg: '#2a2000', border: '#e0c446', text: '#ffe090', icon: '🟡' },
    SUSPICIOUS_ACTIVITY:   { label: 'SUSPICIOUS ACTIVITY',    bg: '#1a2000', border: '#90ba55', text: '#c8e090', icon: '🟢' },
    INVESTIGATION_REQUIRED:{ label: 'INVESTIGATION REQUIRED', bg: '#1a1a2a', border: '#6090d0', text: '#90b0f0', icon: '🔵' },
    INSUFFICIENT_TELEMETRY:{ label: 'INSUFFICIENT TELEMETRY', bg: '#1a1a2a', border: '#6090d0', text: '#90b0f0', icon: '🔵' },
    BENIGN_EXPECTED:       { label: 'NO VALIDATED BREACH',    bg: '#0d1a0d', border: '#52e07f', text: '#90f0b0', icon: '✅' },
  };

  function _confidenceLabel(total, isBreachVerdict) {
    var highColor = isBreachVerdict ? '#ff4444' : '#4ade80';
    if (total >= 80) return { label: 'HIGH CONFIDENCE',       color: highColor };
    if (total >= 60) return { label: 'MEDIUM CONFIDENCE',     color: isBreachVerdict ? '#ff8c00' : '#facc15' };
    if (total >= 40) return { label: 'LOW CONFIDENCE',        color: '#fb923c' };
    return { label: 'INSUFFICIENT EVIDENCE', color: '#94a3b8' };
  }

  function _renderBreachAnswerHero(sorted, a) {
    // Determine top-level verdict from highest-ranked cluster
    var lead = sorted[0];
    var topVerdict = (lead && (lead.verdict || lead.final_verdict) || 'INSUFFICIENT_TELEMETRY').toUpperCase().replace(/ /g, '_');
    var cfg = _HERO_CONFIG[topVerdict] || _HERO_CONFIG.INSUFFICIENT_TELEMETRY;
    var p = (lead && lead.tier1_prefill) || {};
    var store = a.evidence_store || {};
    var rowCount = store.row_count || a.rows_processed || state.rows.length || 0;
    var srcCount = a.source_count || (store.source_counts ? Object.keys(store.source_counts).length : '?');

    var leadTitle = lead ? _displayIncidentName(lead) : '';
    var leadSubtitle = lead ? (p.headline_subtitle || _buildFallbackSummary(lead)) : '';
    if (_rawCorrelationText(leadSubtitle)) leadSubtitle = _friendlyThreatCaseSummary(lead, leadTitle);
    var narrative = lead ? _friendlyThreatCaseNarrative(lead, p, leadTitle, leadSubtitle) : '';
    var rootCause = lead ? _deriveRootCause(lead, p, leadTitle, leadSubtitle) : '';

    // Confidence from deterministic meter (always available, no LLM needed)
    var cm = (lead && (lead.confidence_meter || p.confidence_meter)) || {};
    var confTotal = (cm.total != null) ? cm.total : (lead && lead.verdict_confidence != null ? lead.verdict_confidence * 100 : null);
    var _isBreachVerdict = (topVerdict === 'VALIDATED_BREACH' || topVerdict === 'CONFIRMED_INTRUSION');
    var confInfo = (confTotal != null) ? _confidenceLabel(confTotal, _isBreachVerdict) : null;
    var srcPresent = (cm.source_types_present || []).join(' + ') || (srcCount + ' sources');

    // FP reduction stats: how many rows were explained vs remain as breach
    var breachRows = (lead && (lead.row_refs || []).length) || 0;
    var explainedRows = 0; var explainedLabel = '';
    sorted.forEach(function (c) {
      if (_vClass(c) === 'benign' && (c.row_refs || []).length > 0) {
        explainedRows += (c.row_refs || []).length;
        var n = (c.tier1_prefill && c.tier1_prefill.incident_name) || c.incident_name || 'authorized activity';
        if (!explainedLabel) explainedLabel = n;
      }
    });

    // Action urgency from lead cluster
    var urgency = lead && lead.gate_urgency;
    var isUrgent = urgency === 'URGENT' || urgency === 'HIGH';
    var urgencyBadge = (isUrgent && _vClass(lead) === 'confirmed')
      ? '<span style="background:#7f1d1d;color:#fca5a5;font-size:11px;font-weight:700;padding:3px 8px;border-radius:3px;letter-spacing:.5px;">IMMEDIATE RESPONSE REQUIRED</span>'
      : '';

    // Coverage disclosure
    var heroUploadedCount = a.uploaded_row_count || a.total_rows_uploaded || 0;
    var coverageNote = (heroUploadedCount > rowCount && rowCount > 0)
      ? ' ⚠ analyzed ' + rowCount + ' of ' + heroUploadedCount + ' rows'
      : '';

    var html = [
      '<div class="br-hero" style="background:' + cfg.bg + ';border:1px solid ' + cfg.border + ';border-radius:6px;padding:18px 20px;margin-bottom:16px;" data-testid="br-hero" data-role="breach-answer-hero">',
      '  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:8px;">',
      '    <div>',
      '      <div style="font-size:11px;opacity:.5;letter-spacing:.5px;margin-bottom:4px;">BREACH ASSESSMENT VERDICT</div>',
      '      <div class="br-hero__verdict" style="font-size:22px;font-weight:700;color:' + cfg.text + ';letter-spacing:.5px;" data-testid="breach-answer-verdict">' + cfg.icon + ' ' + cfg.label + '</div>',
      '    </div>',
      urgencyBadge ? '    <div style="padding-top:4px;">' + urgencyBadge + '</div>' : '',
      '  </div>',
    ].join('');

    // Confidence row
    if (confInfo) {
      var barW = Math.round(confTotal);
      html += [
        '<div style="margin-top:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">',
        '  <div style="flex:1;min-width:120px;max-width:220px;background:rgba(255,255,255,.1);border-radius:3px;height:6px;">',
        '    <div style="width:' + barW + '%;background:' + confInfo.color + ';height:6px;border-radius:3px;transition:width .4s;"></div>',
        '  </div>',
        '  <span style="color:' + confInfo.color + ';font-size:12px;font-weight:600;">' + confTotal + '/100 — ' + confInfo.label + '</span>',
        '  <span style="font-size:11px;opacity:.55;"> corroborated by ' + escHtml(srcPresent) + '</span>',
        '</div>',
      ].join('');
    }

    // Evidence vs FP stats row
    html += '<div style="margin-top:10px;display:flex;gap:20px;flex-wrap:wrap;font-size:12px;">';
    if (breachRows > 0) {
      html += '<span style="color:' + cfg.text + ';font-weight:600;">' + breachRows + ' breach rows confirmed</span>';
    }
    if (explainedRows > 0) {
      html += '<span style="color:#6ee7b7;">' + explainedRows.toLocaleString() + ' rows explained &amp; ruled out (' + escHtml(explainedLabel) + ')</span>';
    }
    if (rowCount > 0) {
      var unexplained = rowCount - breachRows - explainedRows;
      if (unexplained > 0) {
        html += '<span style="opacity:.5;">' + unexplained.toLocaleString() + ' rows — unclassified telemetry, not confirmed benign</span>';
      }
    }
    if (coverageNote) {
      html += '<span style="color:#ffaa00;">' + escHtml(coverageNote) + '</span>';
    }
    html += '</div>';

    if (narrative) html += '<div style="margin-top:10px;font-size:13px;line-height:1.6;opacity:.9;">' + escHtml(narrative) + '</div>';

    // Compliance controls — framework chips inline in hero
    html += _renderComplianceChips(lead);

    if (rootCause)  html += '<div style="margin-top:6px;font-size:12px;opacity:.65;"><strong>Root cause:</strong> ' + escHtml(rootCause) + '</div>';

    // Block 4.3: PASTA business impact — 1-sentence business consequence from pasta_summary
    var pastaImpact = (p.pasta_summary && p.pasta_summary.business_impact)
      ? String(p.pasta_summary.business_impact).trim()
      : '';
    if (pastaImpact && _vClass(lead) === 'confirmed') {
      html += '<div style="margin-top:8px;font-size:12px;padding:8px 12px;border-radius:4px;background:rgba(239,68,68,.07);border-left:3px solid rgba(239,68,68,.4);color:rgba(255,180,180,.85);">'
        + '<strong style="font-size:10px;letter-spacing:.05em;opacity:.7;">BUSINESS IMPACT</strong><br>'
        + escHtml(pastaImpact)
        + '</div>';
    }

    html += '</div>';
    return html;
  }

  // ── Root Cause Narrative: CEO-readable single paragraph ────────────────────
  function _renderRootCauseNarrative(lead, sorted) {
    if (!lead) return '';
    var p = lead.tier1_prefill || {};
    var dn = p.dread_narrative || {};
    var frags = dn.fragments || {};
    var whathappened = (p.what_happened || '').trim();
    var shortNarr = (p.short_narrative || '').trim();
    var rootCause = _deriveRootCause(lead, p, _displayIncidentName(lead), p.headline_subtitle || '');
    var evChain = p.evidence_chain || [];
    var impact = p.observed_impact || {};
    var actors = impact.identity || '';

    // Assemble timeline summary from evidence chain
    var chainSteps = [];
    (evChain || []).forEach(function (step) {
      var tactic = step.tactic || step.phase || '';
      var desc = step.description || step.detail || '';
      if (tactic && desc) chainSteps.push(tactic + ': ' + desc);
      else if (desc) chainSteps.push(desc);
    });
    var timelineStr = chainSteps.length > 0 ? chainSteps.slice(0, 6).join(' → ') : '';

    // Build the narrative
    var parts = [];

    // 1. What happened (prefer LLM-generated, then DREAD damage fragment, then fallback)
    var storySource = whathappened || (dn.rendered || '').split('\n')[0] || shortNarr || '';
    if (storySource && !_rawCorrelationText(storySource)) parts.push(storySource);

    // 2. Root cause
    if (rootCause) parts.push('Root cause: ' + rootCause);

    // 3. Timeline (condensed)
    if (timelineStr) parts.push('Attack progression: ' + timelineStr + '.');

    // 4. Affected actors
    if (actors && !/no named/i.test(actors)) parts.push('Affected accounts: ' + actors + '.');

    // 5. FP explanation
    var explained = 0;
    (sorted || []).forEach(function (c) {
      if (_vClass(c) === 'benign' && (c.row_refs || []).length > 0) explained += (c.row_refs || []).length;
    });
    if (explained > 0) {
      parts.push(explained.toLocaleString() + ' additional rows analysed and ruled out — not part of the breach.');
    }

    var fullText = parts.join(' ');
    if (!fullText) return '';

    return [
      '<div class="br-root-narrative" data-testid="br-root-narrative">',
      '  <div class="br-section-head" style="margin-bottom:8px;">ROOT CAUSE NARRATIVE</div>',
      '  <div style="font-size:14px;line-height:1.7;color:rgba(255,255,255,.88);">' + escHtml(fullText) + '</div>',
      '</div>',
    ].join('');
  }

  // ── Compliance Controls: framework chips ──────────────────────────────────
  function _renderComplianceChips(lead) {
    if (!lead) return '';
    var p = lead.tier1_prefill || {};
    var controls = p.compliance_controls || [];
    if (!controls.length) return '';

    var FRAMEWORK_COLORS = {
      'ISO 27001:2022': { bg: 'rgba(99,102,241,.15)', border: '#6366f1', text: '#a5b4fc' },
      'Essential Eight': { bg: 'rgba(34,197,94,.12)', border: '#22c55e', text: '#86efac' },
      'NIST CSF 2.0':   { bg: 'rgba(59,130,246,.12)', border: '#3b82f6', text: '#93c5fd' },
      'NDB Scheme':     { bg: 'rgba(239,68,68,.12)', border: '#ef4444', text: '#fca5a5' },
      'APRA CPS 234':   { bg: 'rgba(251,146,60,.12)', border: '#fb923c', text: '#fed7aa' },
    };

    var chips = controls.map(function (c) {
      var fc = FRAMEWORK_COLORS[c.framework] || { bg: 'rgba(148,163,184,.1)', border: '#64748b', text: '#94a3b8' };
      return '<span class="br-compliance-chip" style="'
        + 'background:' + fc.bg + ';border:1px solid ' + fc.border + ';color:' + fc.text + ';'
        + 'padding:3px 8px;border-radius:3px;font-size:11px;font-weight:600;white-space:nowrap;'
        + '" title="' + escHtml(c.framework + ' — ' + c.control_name) + '">'
        + escHtml(c.framework.replace('ISO 27001:2022', 'ISO').replace('Essential Eight', 'E8').replace('NIST CSF 2.0', 'NIST').replace('APRA CPS 234', 'APRA'))
        + ' ' + escHtml(c.control_id)
        + '</span>';
    });

    return [
      '<div class="br-compliance" data-testid="br-compliance-controls" style="margin-top:10px;">',
      '  <div style="font-size:10px;letter-spacing:.5px;opacity:.5;margin-bottom:4px;">CONTROLS BREACHED</div>',
      '  <div style="display:flex;flex-wrap:wrap;gap:4px;">' + chips.join('') + '</div>',
      '</div>',
    ].join('');
  }

  function _clientExecSummary(sorted, a) {
    var lead = sorted && sorted[0];
    var rowCount = (a.evidence_store && a.evidence_store.row_count) || a.rows_processed || state.rows.length || 0;
    if (!lead) {
      return {
        headline: 'No confirmed breach found',
        subline: 'No correlated threat cases were found in ' + rowCount.toLocaleString() + ' rows.',
        body: 'JanuSec analysed the supplied telemetry and did not identify a confirmed breach. All activity was accounted for by expected operational patterns.',
        provenance: 'Legacy fallback'
      };
    }
    var verdict = (lead.verdict || lead.final_verdict || 'UNCERTAIN').toUpperCase();
    var p = lead.tier1_prefill || {};
    var title = _displayIncidentName(lead);
    var breachRows = (lead.row_refs || []).length;

    // Collect FP-reduction stats: ruled-out rows and their explanation
    var explainedItems = [];
    sorted.forEach(function (c) {
      if (_vClass(c) === 'benign' && (c.row_refs || []).length > 0) {
        var n = (c.tier1_prefill && c.tier1_prefill.incident_name) || c.incident_name || 'authorized activity';
        explainedItems.push({ rows: (c.row_refs || []).length, name: n });
      }
    });
    var totalExplained = explainedItems.reduce(function (s, x) { return s + x.rows; }, 0);

    // Pull specifics from the lead cluster's prefill: actors, root cause
    var impact = p.observed_impact || {};
    var actors = impact.identity || '';
    var rootCause = p.root_cause || '';
    var cm = lead.confidence_meter || p.confidence_meter || {};
    var confTotal = cm.total != null ? cm.total : null;
    var _execIsBreachVerdict = (verdict === 'VALIDATED_BREACH' || verdict === 'CONFIRMED_INTRUSION');
    var confLabel = confTotal != null ? _confidenceLabel(confTotal, _execIsBreachVerdict).label : '';
    var urgency = lead.gate_urgency || '';
    var sev = (lead.severity || '').toUpperCase();

    // Compose headline and body
    var _isBreachClass = (verdict === 'VALIDATED_BREACH' || verdict === 'CONFIRMED_INTRUSION'
                         || verdict === 'CONFIRMED_BREACH' || verdict === 'LIKELY_BREACH');
    if (_isBreachClass) {
      var sublineStr = breachRows + ' correlated evidence rows · ' + (sev || 'CRITICAL') + ' severity';
      if (confLabel) sublineStr += ' · ' + confLabel;
      if (verdict === 'LIKELY_BREACH') sublineStr += ' · HUMAN REVIEW REQUIRED';

      // Prefer LLM-rendered narrative, then raw DREAD fragments, then flat paragraph
      var dn = p.dread_narrative || {};
      var frags = dn.fragments || {};
      var hasDread = !!(frags.damage || frags.affected_users || frags.discoverability);
      var bodyParts = [];
      var provenance = 'Legacy fallback';

      if (dn.rendered) {
        bodyParts.push(dn.rendered);
        provenance = 'LLM-rendered DREAD';
      } else if (hasDread) {
        // Order: damage → reproducibility → exploitability → affected_users → discoverability
        var _fragOrder = ['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'];
        _fragOrder.forEach(function(dim) {
          if (frags[dim]) bodyParts.push(frags[dim]);
        });
        if (dn.sabsa_coda_draft) bodyParts.push('\n\n' + dn.sabsa_coda_draft);
        provenance = 'Deterministic DREAD fragments';
      } else {
        // Try PASTA threat model before falling back to flat paragraph
        var dInfo = _dreadInfo(lead);
        if (dInfo.hasPasta) {
          var pasta = p.pasta_summary || {};
          if (pasta.threat_profile) bodyParts.push('Threat actor: ' + pasta.threat_profile);
          if (pasta.exploitation_path) bodyParts.push('Exploitation: ' + pasta.exploitation_path);
          if (pasta.business_impact) bodyParts.push('Business impact: ' + pasta.business_impact);
          provenance = 'PASTA threat model';
        } else if (dInfo.hasDiamond) {
          var dm = p.diamond_model || {};
          if (dm.adversary) bodyParts.push('Adversary: ' + dm.adversary);
          if (dm.capability && dm.capability.length) bodyParts.push('Capabilities: ' + dm.capability.slice(0, 5).join(', ') + '.');
          var dvictims = (dm.victim_users || []).concat(dm.victim_data || []);
          if (dvictims.length) bodyParts.push('Victim scope: ' + dvictims.slice(0, 4).join(', ') + '.');
          provenance = 'DIAMOND threat model';
        } else if (p.what_happened || p.root_cause) {
          // T1 LLM prefill has content — guard against raw correlation fallback strings
          var _wh = (p.what_happened || '');
          if (_wh && !_rawCorrelationText(_wh)) bodyParts.push(_wh);
          if (p.root_cause) bodyParts.push('Root cause: ' + p.root_cause);
          if (actors && actors.indexOf('No named') === -1) bodyParts.push('Affected accounts: ' + actors + '.');
          // If all T1 content was raw correlation text, fall through to deterministic
          if (!bodyParts.length) {
            bodyParts.push(
              'JanuSec confirmed a breach in the supplied telemetry. ' +
              (p.root_cause || lead.lead_description || 'Attacker activity was observed across multiple data sources.')
            );
            if (actors && actors.indexOf('No named') === -1) bodyParts.push('Affected accounts: ' + actors + '.');
          }
          provenance = 'T1 LLM analysis';
        } else {
          // Genuinely no threat model data of any kind
          bodyParts.push(
            'JanuSec confirmed a breach in the supplied telemetry. ' +
            (rootCause || 'Attacker activity was observed across multiple data sources.')
          );
          if (actors && actors.indexOf('No named') === -1) {
            bodyParts.push('Affected accounts: ' + actors + '.');
          }
          provenance = 'Deterministic';
        }
      }

      // Always append the ruled-out context regardless of narrative source
      if (totalExplained > 0) {
        var rulledOutStr = explainedItems.map(function (x) {
          return x.rows.toLocaleString() + ' rows (' + x.name + ')';
        }).join(', ');
        bodyParts.push(
          'The platform also analysed ' + totalExplained.toLocaleString() +
          ' additional rows and ruled them out: ' + rulledOutStr +
          '. These are NOT part of the breach and require no further investigation.'
        );
      }
      if (urgency === 'URGENT') {
        bodyParts.push('IMMEDIATE ACTION is required. Contain affected accounts and systems before further damage occurs.');
      }

      var headlineLabel = verdict === 'LIKELY_BREACH'
        ? 'Likely breach — human review required — '
        : 'Confirmed breach — ';
      return {
        headline: headlineLabel + (title || 'Unauthorised access with data exfiltration'),
        subline: sublineStr,
        body: bodyParts.join(' '),
        provenance: provenance
      };
    }

    // Non-breach verdicts
    var summary = _friendlyThreatCaseSummary(lead, title);
    var nonBreachBody = summary;
    if (totalExplained > 0) {
      nonBreachBody += ' Additionally, ' + totalExplained.toLocaleString() + ' rows were reviewed and ruled out — no further investigation of those cases is required.';
    }
    var _nbDreadInfo = lead ? _dreadInfo(lead) : { provenance: 'Legacy fallback' };
    return {
      headline: 'Highest finding: ' + verdict.replace(/_/g, ' ') + (title ? ' — ' + title : ''),
      subline: breachRows + ' evidence rows require analyst review before breach validation.',
      body: nonBreachBody,
      provenance: _nbDreadInfo.provenance
    };
  }

  function _renderExecSummaryShell(sorted, a) {
    var initial = _clientExecSummary(sorted || [], a || {});
    return [
      '<div class="br-section-head">EXECUTIVE SUMMARY</div>',
      '<div class="br-exec" id="br-exec-block" data-testid="br-exec-block">',
      '  <div class="br-exec__text" id="br-exec-det">',
      '    <div class="br-exec__headline">' + escHtml(initial.headline) + '</div>',
      '    <div class="br-exec__subline">' + escHtml(initial.subline) + '</div>',
      '    <div class="br-exec__source" id="br-exec-source">source: ' + escHtml(initial.provenance || 'Legacy fallback') + '</div>',
      '    <div class="br-exec__body">' + escHtml(initial.body) + '</div>',
      '    <div class="br-exec__refs" id="br-exec-refs"></div>',
      '    <div class="br-exec__warn" id="br-exec-warn"></div>',
      '  </div>',
      '  <div class="br-exec__color" id="br-exec-color"></div>',
      '  <div class="br-exec__footer">',
      '    <span class="br-exec__model" id="br-exec-model"></span>',
      '    <span class="br-exec__regen" id="br-exec-regen">[regenerate ↻]</span>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _selectTopThreatCases(sorted) {
    // Verdict-tier policy:
    //   confirmed (CONFIRMED_BREACH, CONFIRMED_INTRUSION) — all get top-card treatment
    //   likely    (LIKELY_BREACH, LIKELY_COMPROMISE)      — up to 3, shown with human gate
    //   uncertain / lower                                 — additional findings drawer
    var MIN_TOP_ROWS = 5;
    var confirmed = (sorted || []).filter(function (c) {
      return _vClass(c) === 'confirmed' && (c.row_refs || []).length >= MIN_TOP_ROWS;
    });
    var likely = (sorted || []).filter(function (c) {
      return _vClass(c) === 'likely' && (c.row_refs || []).length >= MIN_TOP_ROWS;
    }).slice(0, 3);
    var candidates = confirmed.concat(likely);
    if (!candidates.length) {
      // fallback: show any non-benign with evidence
      candidates = (sorted || []).filter(function (c) {
        return _vClass(c) !== 'benign' && (c.row_refs || []).length > 0;
      }).slice(0, 4);
    }
    return candidates;
  }

  function _renderTopFindings(sorted) {
    var nonBenign = _selectTopThreatCases(sorted);
    var html = '<div class="br-section-head">TOP THREAT CASES</div>';
    nonBenign.forEach(function (c, i) {
      html += '<div id="br-card-' + escHtml(c.cluster_id) + '" data-card-idx="' + i + '"></div>';
    });
    return html;
  }

  function _renderAdditionalFindings(sorted) {
    // Additional findings = uncertain-class only. Confirmed and likely go to top cards.
    var rest = sorted.filter(function (c) {
      return _vClass(c) !== 'benign'
          && _vClass(c) !== 'confirmed'
          && _vClass(c) !== 'likely'
          && (c.row_refs || []).length > 0;
    });
    if (!rest.length) return '';

    // Group by severity descending: critical > high > medium > low
    var _SEV_ORDER = ['critical', 'high', 'medium', 'low'];
    var groups = {};
    _SEV_ORDER.forEach(function (s) { groups[s] = []; });
    rest.forEach(function (c) {
      var s = (c.severity || 'low').toLowerCase();
      if (!groups[s]) groups[s] = [];
      groups[s].push(c);
    });

    function _findingRow(c) {
      var p = c.tier1_prefill || {};
      var title = _displayIncidentName(c);
      var heuristic = p.headline_subtitle || c.summary || c.cluster_label || _buildFallbackSummary(c);
      if (_rawCorrelationText(title)) title = _deriveIncidentName(c) || 'Threat Case';
      if (_rawCorrelationText(heuristic)) heuristic = _friendlyThreatCaseSummary(c, title);
      return [
        '<div class="br-finding" id="br-finding-' + escHtml(c.cluster_id) + '">',
        '  <div class="br-finding__main">',
        '    <div class="br-finding__verdict br-card__verdict--' + _vClass(c) + '">',
        '      ' + verdictIcon(c.verdict || c.final_verdict) + ' ' + escHtml((c.verdict || c.final_verdict || 'UNCERTAIN').toUpperCase()),
        '    </div>',
        '    <div class="br-finding__oneliner" id="br-fol-' + escHtml(c.cluster_id) + '">',
        '      ' + escHtml((title ? title + ' · ' : '') + heuristic),
        '    </div>',
        '    <div class="br-finding__meta">',
        '      ' + (c.row_refs || []).length + ' rows',
        '      &nbsp;·&nbsp; ' + escHtml((c.severity || 'low').toUpperCase()),
        '    </div>',
        '  </div>',
        '  <div class="br-finding__actions">',
        '    <button class="br-finding__gen" data-gen-cluster="' + escHtml(c.cluster_id) + '">',
        '      Generate summary',
        '    </button>',
        '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
        '      Open threat case ↗',
        '    </button>',
        '  </div>',
        '</div>',
      ].join('');
    }

    var bodyHtml = '';
    _SEV_ORDER.forEach(function (sev) {
      var group = groups[sev] || [];
      if (!group.length) return;
      var sevLabel = sev.toUpperCase();
      bodyHtml += '<div style="font-size:11px;font-weight:700;color:var(--text-muted);'
        + 'letter-spacing:.8px;padding:8px 0 4px;border-top:1px solid rgba(255,255,255,.06);">'
        + sevLabel + ' (' + group.length + ')</div>';
      group.forEach(function (c) { bodyHtml += _findingRow(c); });
    });

    // Collapsed by default — analysts open only when needed
    return [
      '<details class="br-additional-findings" style="margin-top:12px;">',
      '  <summary class="br-section-head" style="cursor:pointer;user-select:none;list-style:none;">',
      '    ADDITIONAL FINDINGS (' + rest.length + ' THREAT CASES)',
      '    <span style="font-size:11px;font-weight:400;color:var(--text-muted);margin-left:8px;">',
      '      ▶ expand by severity',
      '    </span>',
      '  </summary>',
      '  <div style="margin-top:8px;">' + bodyHtml + '</div>',
      '</details>',
    ].join('');
  }

  function _isSecurityTestCluster(c) {
    // Catch AUTHORIZED_SECURITY_TEST / pentest clusters that may have row_refs:[]
    // because the row count is tracked at assessment level, not cluster.row_refs.
    var name = ((c.tier1_prefill && c.tier1_prefill.incident_name) || c.incident_name || c.lead_description || c.cluster_label || '').toUpperCase();
    var verd = ((c.verdict || c.final_verdict) || '').toUpperCase();
    return verd === 'AUTHORIZED_SECURITY_TEST'
      || name.indexOf('AUTHORIZED') !== -1
      || name.indexOf('SECURITY TEST') !== -1
      || name.indexOf('PENTEST') !== -1
      || name.indexOf('RED TEAM') !== -1;
  }

  function _renderNarrativeContext(sorted) {
    // Include: enrichment_guided benign cases, benign clusters with evidence rows,
    // and authorized-security-test clusters (which may have empty row_refs but still
    // represent explained rows tracked at assessment level).
    var contextCases = sorted.filter(function (c) {
      if (!c) return false;
      if (_vClass(c) !== 'benign') return false;
      return c.case_type === 'enrichment_guided'
          || (c.row_refs || []).length > 0
          || _isSecurityTestCluster(c);
    });
    if (!contextCases.length) return '';
    var html = '<div class="br-section-head">SECURITY CONTEXT &amp; RULED-OUT CASES</div>';
    contextCases.forEach(function (c) {
      var p = c.tier1_prefill || {};
      var title = p.incident_name || c.incident_name || c.lead_description || 'Context case';
      var sub = p.headline_subtitle || c.reason_summary || p.short_narrative || '';
      // Build a plain-English paragraph explaining why this is benign
      var narrative = p.verdict_reasoning || p.what_happened || c.business_significance || '';
      // If verdict_reasoning looks like a malicious C2 statement, replace it with the short_narrative
      var _BAD_RE = /command.and.control|c2 beacon|needs containment|attacker maintain/i;
      if (_BAD_RE.test(narrative)) narrative = sub;
      if (!narrative && _vClass(c) === 'benign') {
        var _ck = c.cluster_kind || '';
        if (_ck === 'unclassified' || _ck === '') {
          narrative = 'No confirmed threat phase matched this component. ' +
            'The events remain unclassified — no malicious indicators were confirmed, ' +
            'but insufficient telemetry is available to fully characterise this activity. ' +
            'Additional log sources or investigation may be required.';
        } else {
          narrative = 'This activity cluster was reviewed and determined to be benign. ' +
            'No indicators of malicious intent, data loss, or unauthorised access were confirmed. ' +
            'The events are consistent with ' + (sub || 'expected operational activity') + '.';
        }
      }
      var rowCount = (c.row_refs || []).length;
      var isAuthorized = /authorized security test|pentest|penetration test|red team/i.test(title + ' ' + sub + ' ' + narrative);
      var authNarrative = isAuthorized
        ? '<div class="br-auth-explain"><strong>Why excluded:</strong> Activity matched approved security-test context in this assessment. '
          + '<strong>Rows explained:</strong> ' + rowCount.toLocaleString() + ' rows. '
          + '<strong>Residual check:</strong> confirm test window, source identities, and authorization record before final closure.</div>'
        : '';
      html += [
        '<div class="br-finding br-finding--context" id="br-context-' + escHtml(c.cluster_id) + '">',
        '  <div class="br-finding__main">',
        '    <div class="br-finding__verdict br-card__verdict--benign">✓ ' + escHtml(title.toUpperCase()) + '</div>',
        '    <div class="br-finding__oneliner">' + escHtml(sub) + '</div>',
        '    <div class="br-finding__meta" style="white-space:normal;line-height:1.5;">' + escHtml(narrative) + '</div>',
        authNarrative,
        '    <div class="br-finding__meta" style="opacity:.6;margin-top:4px;">' + rowCount + ' correlated rows reviewed</div>',
        '  </div>',
        '  <div class="br-finding__actions">',
        '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
        '      Review evidence ↗',
        '    </button>',
        '  </div>',
        '</div>',
      ].join('');
    });
    return html;
  }

  function _renderCollapsed(label, count) {
    if (!count) return '';
    var key = label.toLowerCase();
    return [
      '<div class="br-collapsed" data-collapsed-key="' + key + '" style="cursor:pointer;">',
      '  <span>' + escHtml(label) + ' — ' + count + ' threat case(s)</span>',
      '  <span class="br-collapsed__caret" id="br-caret-' + key + '">Expand ▼</span>',
      '</div>',
      '<div id="br-collapsed-body-' + key + '" style="display:none;border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;margin-bottom:8px;"></div>',
    ].join('');
  }

  // ── Card rendering ───────────────────────────────────────────────────────────

  var _ANALYST_NOTE = /^DAY\s*\d+\s*:/i;
  var _NOISE = /^(system|local service|network service|localhost|unknown|nt authority.*)$/i;
  var _BORING = /^correlated activity cluster$|^correlated incident$|^n\/a$|^unknown$/i;
  var _PLACEHOLDER_NAME = /^(unknown(?:[-_\s]*\d{4})?(?:[-_\s]*[a-z])?\s*breach|remaining telemetry did not form|no validated breach|correlated incident)$/i;

  function _heuristicValueText(value) {
    if (value == null) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
    try { return JSON.stringify(value); } catch (_) { return String(value); }
  }

  function _rowEvidenceText(row) {
    if (!row || typeof row !== 'object') return '';
    return [
      row._source, row.source, row.source_file,
      row.user, row.user_name, row.username, row.user_principal_name, row.account, row.actor,
      row.src_ip, row.source_ip, row.remote_address, row.dst_ip, row.destination_ip,
      row.hostname, row.host, row.device_name,
      row.process, row.process_name, row.event_simpleName, row.event_type, row.operationName,
      row.objectRef, row.notes, row.analyst_notes, row.description, row.dns_query, row.ja3, row.ja4,
    ].map(_heuristicValueText).join(' ');
  }

  function _clusterEvidenceText(cluster, p) {
    var parts = [
      cluster.incident_name,
      cluster.lead_description,
      cluster.reason_summary,
      cluster.business_significance,
      cluster.headline_subtitle,
      cluster.ioc_summary,
      cluster.attack_narrative,
      (cluster.top_mitre || []).join(' '),
      p && p.incident_name,
      p && p.headline_subtitle,
      p && p.short_narrative,
      p && p.what_happened,
      p && p.root_cause,
    ];
    (cluster.sample_rows || []).slice(0, 120).forEach(function (row) {
      parts.push(_rowEvidenceText(row));
    });
    var refs = new Set((cluster.row_refs || []).map(function (v) { return String(v); }));
    var added = 0;
    (state.rows || []).forEach(function (row) {
      if (added >= 160 || !row) return;
      var idx = row.row_index != null ? row.row_index : row.row_number;
      if (refs.has(String(idx))) {
        parts.push(_rowEvidenceText(row));
        added++;
      }
    });
    return parts.map(_heuristicValueText).join(' ').toLowerCase();
  }

  function _clusterHasEvidence(cluster, pattern) {
    cluster = cluster || {};
    var p = cluster.tier1_prefill || {};
    var head = [
      cluster.incident_name,
      cluster.lead_description,
      cluster.reason_summary,
      cluster.business_significance,
      cluster.headline_subtitle,
      cluster.ioc_summary,
      cluster.attack_narrative,
      p.incident_name,
      p.headline_subtitle,
      p.short_narrative,
      p.what_happened,
      p.root_cause,
      _heuristicValueText(p.observed_impact),
    ].map(_heuristicValueText).join(' ');
    pattern.lastIndex = 0;
    if (pattern.test(head)) return true;
    var rows = cluster.sample_rows || [];
    for (var i = 0; i < rows.length; i++) {
      pattern.lastIndex = 0;
      if (pattern.test(_rowEvidenceText(rows[i]))) return true;
    }
    var refs = new Set((cluster.row_refs || []).map(function (v) { return String(v); }));
    for (var j = 0; j < (state.rows || []).length; j++) {
      var row = state.rows[j];
      if (!row) continue;
      var idx = row.row_index != null ? row.row_index : row.row_number;
      if (!refs.has(String(idx))) continue;
      pattern.lastIndex = 0;
      if (pattern.test(_rowEvidenceText(row))) return true;
    }
    return false;
  }

  function _isPlaceholderIncidentName(name) {
    var n = String(name || '').trim();
    if (!n) return true;
    return _BORING.test(n) || _PLACEHOLDER_NAME.test(n) || /unknown[-_\s]+\d{4}[-_\s]+[a-z]\s+breach/i.test(n);
  }

  function _deriveIncidentName(cluster) {
    // Regex-label chain removed. Incident name must come from LLM Tier-1
    // prefill (backend). If prefill is absent the backend returns a neutral
    // placeholder which the UI displays verbatim — no client-side guessing.
    return '';
  }

  function _displayIncidentName(cluster) {
    var p = (cluster || {}).tier1_prefill || {};
    var candidates = [p.incident_name, (cluster || {}).incident_name];
    for (var i = 0; i < candidates.length; i++) {
      var name = String(candidates[i] || '').trim();
      if (name && !_isPlaceholderIncidentName(name)) return name;
    }
    return _deriveIncidentName(cluster || {}) || _buildFallbackTitle(cluster || {});
  }

  function _deriveRootCause(cluster, p, title, subtitle) {
    p = p || {};
    var explicit = String(p.root_cause || '').trim();
    var boring = /correlated evidence|investigation threshold|exceeded.*threshold|threshold.*exceeded|no specific|additional.*logs/i;
    if (explicit && !boring.test(explicit)) return explicit;
    var text = _clusterEvidenceText(cluster || {}, p) + ' ' + String(title || '') + ' ' + String(subtitle || '');
    if (/bec|wire|bcc|mailbox|finance officer/.test(text)) {
      return 'Compromised finance mailbox or identity used for business email compromise activity.';
    }
    if (/mfa fatigue|legacy imap|session token|password spray/.test(text)) {
      return 'Identity compromise via MFA fatigue or legacy authentication allowed attacker access.';
    }
    return '';
  }

  function _buildFallbackTitle(cluster) {
    var derived = _deriveIncidentName(cluster);
    if (derived) return derived;
    // Prefer clean pre-computed fields; skip analyst-notes style text
    var desc = cluster.reason_summary || cluster.summary || '';
    var ld = cluster.lead_description || '';
    if (ld && !_ANALYST_NOTE.test(ld) && !_BORING.test(ld.trim()) && !_rawCorrelationText(ld) && ld.length <= 80) desc = ld;
    if (desc && !_BORING.test(desc.trim()) && !_rawCorrelationText(desc) && desc.length > 4) return desc.length > 80 ? desc.slice(0, 77) + '…' : desc;

    // Heuristic: severity label · real users · MITRE · N events
    var sev = (cluster.severity || '').toLowerCase();
    var sevLabel = { critical: 'Critical', high: 'High-severity', medium: 'Suspicious', low: 'Low-severity' }[sev] || 'Suspicious';

    var allAccts = cluster.shared_accounts || cluster.affected_accounts || [];
    var realAccts = allAccts.filter(function (a) {
      return a && !_NOISE.test(a) && a.indexOf('$') === -1;
    }).slice(0, 2);
    if (!realAccts.length && allAccts.length) realAccts = allAccts.slice(0, 1);

    var mitre = (cluster.top_mitre || []).slice(0, 2);
    var rowCount = (cluster.row_refs || []).length;

    var parts = [sevLabel + ' activity'];
    if (realAccts.length) parts.push(realAccts.join(', '));
    if (mitre.length) parts.push(mitre.join(' + '));
    parts.push(rowCount + ' events');
    return parts.join(' · ');
  }

  function _buildFallbackSummary(cluster) {
    var allAccts = (cluster.shared_accounts || cluster.affected_accounts || []);
    var realAccts = allAccts.filter(function (a) {
      return a && !_NOISE.test(a) && a.indexOf('$') === -1;
    }).slice(0, 3);
    if (!realAccts.length && allAccts.length) realAccts = allAccts.slice(0, 1);
    var hosts = (cluster.shared_hosts || cluster.affected_assets || []).slice(0, 2);
    var ips = (cluster.shared_external_ips || []).slice(0, 2);
    var mitre = (cluster.top_mitre || []).slice(0, 3);
    var ld = cluster.lead_description || '';
    var desc = (!_ANALYST_NOTE.test(ld) && ld.length <= 120) ? ld : (cluster.reason_summary || '');
    var entities = realAccts.concat(hosts).concat(ips).filter(Boolean);
    var parts = [];
    if (entities.length) parts.push(entities.join(', '));
    if (mitre.length) parts.push('Techniques: ' + mitre.join(', '));
    if (desc && desc.length > 4) parts.push(desc);
    return parts.join(' · ') || ((cluster.row_refs || []).length + ' correlated events');
  }

  function _rawCorrelationText(s) {
    return /shared attacker|shared identity|same network|same host sequence|same ATT&CK|identity compromise or shared actor|external infrastructure appears|\d+\s+phase\(s\)\s+·|\d+\s+telemetry source\(s\)|^multi-phase intrusion\s+·/i.test(String(s || ''));
  }

  function _friendlyThreatCaseSummary(cluster, title) {
    var text = [
      title,
      cluster.lead_description,
      cluster.reason_summary,
      cluster.business_significance,
      (cluster.top_mitre || []).join(' '),
      _clusterEvidenceText(cluster || {}, (cluster || {}).tier1_prefill || {})
    ].join(' ').toLowerCase();
    var rows = (cluster.row_refs || []).length;
    if (/bec|mailbox|wire|finance/.test(text)) {
      return rows + ' evidence rows connect identity compromise, mailbox activity, and payment-risk evidence.';
    }
    if (/dns|c2|beacon|command/.test(text)) {
      return rows + ' evidence rows show command-and-control activity requiring containment and egress review.';
    }
    if (/npm|supply|github|token|secret/.test(text)) {
      return rows + ' evidence rows show developer or supply-chain activity requiring token and repository review.';
    }
    if (/password|mfa|legacy|okta|identity/.test(text)) {
      return rows + ' evidence rows show identity compromise indicators requiring session and MFA review.';
    }
    return rows + ' correlated evidence rows require analyst review before closure.';
  }

  // ── Context strip: IDENTITY / SYSTEMS / C2 INFRA / SOURCES ─────────────
  function _renderContextStrip(cluster, p) {
    var accts    = (cluster.shared_accounts || cluster.affected_accounts || []).filter(Boolean).slice(0, 4);
    var assets   = (cluster.affected_assets || cluster.shared_hosts || []).filter(Boolean).slice(0, 4);
    var ips      = (cluster.shared_external_ips || []).slice(0, 4);
    var cm       = cluster.confidence_meter || p.confidence_meter || {};
    var srcs     = (cm.source_types_present || []).slice(0, 6);
    var srcCount = typeof cluster.source_count === 'number' ? cluster.source_count : srcs.length;
    if (!accts.length && !assets.length && !ips.length && !srcs.length) return '';

    // Detect identity providers from account names, source list, and observed_impact
    var probeText = accts.concat(srcs).join(' ').toLowerCase()
      + ' ' + (cluster.lead_description || '').toLowerCase()
      + ' ' + ((p.observed_impact && p.observed_impact.identity) ? p.observed_impact.identity : '').toLowerCase();
    var providers = [];
    if (/\bokta\b/.test(probeText)) providers.push('Okta');
    if (/entra|azure.?ad|azuread|\.onmicrosoft\.com/.test(probeText)) providers.push('Entra ID');
    if (/sailpoint/.test(probeText)) providers.push('SailPoint');
    if (/\bping\b/.test(probeText)) providers.push('PingIdentity');
    if (/jumpcloud/.test(probeText)) providers.push('JumpCloud');

    var rows = [];
    if (accts.length) {
      var providerTag = providers.length
        ? ' <span class="br-ctx__provider">via ' + escHtml(providers.slice(0, 2).join(' · ')) + '</span>'
        : '';
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">IDENTITY</span>'
        + '<span class="br-ctx__val">' + escHtml(accts.join(' · ')) + providerTag + '</span>'
        + '</div>'
      );
    }
    if (assets.length) {
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">SYSTEMS</span>'
        + '<span class="br-ctx__val">' + escHtml(assets.join(' · ')) + '</span>'
        + '</div>'
      );
    }
    if (ips.length) {
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">C2 INFRA</span>'
        + '<span class="br-ctx__val">' + escHtml(ips.join(' · ')) + '</span>'
        + '</div>'
      );
    }
    if (srcs.length) {
      var cntSuffix = srcCount > 0
        ? ' <span class="br-ctx__count">(' + srcCount + ' stream' + (srcCount !== 1 ? 's' : '') + ')</span>'
        : '';
      rows.push(
        '<div class="br-ctx__row">'
        + '<span class="br-ctx__label">SOURCES</span>'
        + '<span class="br-ctx__val">' + escHtml(srcs.join(' · ')) + cntSuffix + '</span>'
        + '</div>'
      );
    }
    return rows.length ? '<div class="br-context-strip">' + rows.join('') + '</div>' : '';
  }

  // ── Threat narrative (DREAD · PASTA · Diamond) ───────────────────────────
  function _renderThreatModelSummary(cluster, p, dreadInfo) {
    var frags    = dreadInfo.frags || {};
    var ds       = p.dread_score  || {};
    var riskTier = (ds.risk_tier  || '').toLowerCase();

    function _block(icon, label, sub, text) {
      return '<div class="br-tm__block">'
        + '<div class="br-tm__block-head">'
        + '<span class="br-tm__block-icon">' + icon + '</span>'
        + '<span class="br-tm__block-label">' + escHtml(label) + '</span>'
        + '<span class="br-tm__block-sub">' + escHtml(sub) + '</span>'
        + '</div>'
        + '<div class="br-tm__block-text">' + escHtml(String(text)) + '</div>'
        + '</div>';
    }

    // ── DREAD ── evidence narrative fragments first; numeric detail strings as fallback
    var DREAD_DIMS = [
      { fk: 'damage',          dk: 'damage_detail',          icon: '\uD83D\uDCA5', label: 'DAMAGE',          sub: 'What broke, what\u2019s at risk, and how far it spread (blast radius)' },
      { fk: 'reproducibility', dk: 'reproducibility_detail', icon: '\uD83D\uDD01', label: 'REPRODUCIBILITY', sub: 'Why this can happen again right now and what\u2019s still exposed' },
      { fk: 'exploitability',  dk: 'exploitability_detail',  icon: '\u26A1',        label: 'EXPLOITABILITY',  sub: 'The attack vector, control gap exploited, and why people should care' },
      { fk: 'affected_users',  dk: 'affected_users_detail',  icon: '\uD83D\uDC64', label: 'AFFECTED USERS',  sub: 'Who was hit, their access level, and any privilege abuse or lateral movement' },
      { fk: 'discoverability', dk: 'discoverability_detail', icon: '\uD83D\uDD0D', label: 'DISCOVERABILITY', sub: 'What was visible, what was misconfigured, and mean time to detect' }
    ];
    var dreadBlocks = DREAD_DIMS
      .map(function(dim) { return { dim: dim, text: frags[dim.fk] || ds[dim.dk] || '' }; })
      .filter(function(d) { return d.text; })
      .map(function(d) { return _block(d.dim.icon, d.dim.label, d.dim.sub, d.text); });

    // ── PASTA ── plain-language attack narrative
    var pasta = p.pasta_summary || {};
    var PASTA_DIMS = [
      { key: 'objective',         icon: '\uD83C\uDFAF', label: 'OBJECTIVE',       sub: 'What the attacker was trying to achieve' },
      { key: 'threat_profile',    icon: '\uD83D\uDD75\uFE0F', label: 'THREAT ACTOR',    sub: 'Who or what was behind this and their motivation' },
      { key: 'exploitation_path', icon: '\uD83D\uDD13', label: 'HOW THEY GOT IN', sub: 'The exploitation path and control gaps used' },
      { key: 'business_impact',   icon: '\uD83D\uDCCB', label: 'BUSINESS IMPACT', sub: 'What this means for operations and compliance' }
    ];
    var pastaBlocks = PASTA_DIMS
      .filter(function(dim) { return pasta[dim.key]; })
      .map(function(dim)  { return _block(dim.icon, dim.label, dim.sub, pasta[dim.key]); });

    // ── Diamond ── adversary / capability / infrastructure / victim
    var dm = p.diamond_model || {};
    var diamondItems = [];
    if (dm.adversary) {
      diamondItems.push(_block('\uD83C\uDFAF', 'WHO ATTACKED',         'Threat actor attribution and any proxy identity used', dm.adversary));
    }
    if (dm.capability && dm.capability.length) {
      diamondItems.push(_block('\u2699\uFE0F',  'WHAT THEY USED',       'Attack capability, tooling, and technique chain', dm.capability.join(' \u2192 ')));
    }
    var infra = dm.infrastructure || dm.c2_infrastructure || [];
    if (infra.length) {
      var infraText = Array.isArray(infra) ? infra.join(', ') : String(infra);
      diamondItems.push(_block('\uD83C\uDFD7\uFE0F', 'THEIR INFRASTRUCTURE', 'External C2, staging, or exfil infrastructure identified', infraText));
    }
    var victims = (dm.victim_users || []).concat(dm.victim_data || []).filter(Boolean);
    if (victims.length) {
      // Use typed sub-buckets when the backend has separated humans / machines / data
      var hasTyped = (dm.victim_humans && dm.victim_humans.length)
                  || (dm.victim_machines && dm.victim_machines.length);
      if (hasTyped) {
        var typedLines = [];
        if (dm.victim_humans && dm.victim_humans.length) {
          typedLines.push('\uD83D\uDC64 Human accounts: ' + dm.victim_humans.join(', '));
        }
        if (dm.victim_machines && dm.victim_machines.length) {
          typedLines.push('\uD83E\uDD16 Machine/service identities: ' + dm.victim_machines.join(', '));
        }
        if (dm.victim_data && dm.victim_data.length) {
          typedLines.push('\uD83D\uDCBE Data assets: ' + dm.victim_data.join(', '));
        }
        diamondItems.push(_block('\uD83C\uDFAF', 'WHO WAS HIT', 'Victim accounts, service identities, and data assets impacted', typedLines.join(' \u00b7 ')));
      } else {
        // Legacy flat render (older assessments without typed buckets)
        diamondItems.push(_block('\uD83C\uDFAF', 'WHO WAS HIT', 'Victim accounts, systems, and data impacted', victims.join(', ')));
      }
    }

    var hasContent = dreadBlocks.length || pastaBlocks.length || diamondItems.length;
    if (!hasContent) {
      // Embed the generate button directly — don't tell users to look "below" for a
      // button that may be hidden by the dreadInfo.has guard.
      var _cid = escHtml(cluster.cluster_id || '');
      return '<div class="br-threat-model br-threat-model--empty">'
        + '<span class="br-tm__block-icon">\uD83E\uDDE0</span>'
        + '<div style="flex:1">'
        + '<div class="br-tm__empty-title">Threat narrative not yet generated</div>'
        + '<div class="br-tm__hint">Structured DREAD \u00b7 PASTA \u00b7 Diamond analysis will be built from evidence rows by the multi-agent reasoning engine.</div>'
        + '<div style="margin-top:8px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        + '<button class="br-finding__gen br-finding__gen--dread" data-gen-dread="' + _cid + '"'
        + ' title="Runs: Sequence-aware \u00b7 Adversarial reasoning \u00b7 CorrectiveRAG \u00b7 TemporalRAG">'
        + '\uD83E\uDDE0 Generate Threat Summary'
        + '</button>'
        + '<span class="br-tm__reasoning-tags">Sequence-aware \u00b7 Adversarial \u00b7 CorrectiveRAG \u00b7 TemporalRAG</span>'
        + '</div>'
        + '</div>'
        + '</div>';
    }

    var tierBadge = riskTier
      ? ' <span class="br-tm__tier br-tm__tier--' + escHtml(riskTier) + '">' + escHtml(riskTier.toUpperCase()) + ' RISK</span>'
      : '';

    var sections = [];
    if (dreadBlocks.length) {
      sections.push(
        '<div class="br-tm__section">'
        + '<div class="br-tm__section-heading">DREAD \u2014 Evidence-grounded assessment' + tierBadge + '</div>'
        + dreadBlocks.join('')
        + '</div>'
      );
    }
    if (pastaBlocks.length) {
      sections.push(
        '<div class="br-tm__section">'
        + '<div class="br-tm__section-heading">PASTA \u2014 How the attack unfolded (plain language)</div>'
        + pastaBlocks.join('')
        + '</div>'
      );
    }
    if (diamondItems.length) {
      sections.push(
        '<div class="br-tm__section">'
        + '<div class="br-tm__section-heading">\u25CA Diamond \u2014 Who did what, to whom, and how</div>'
        + diamondItems.join('')
        + '</div>'
      );
    }

    return '<div class="br-threat-model">'
      + '<div class="br-tm__heading">Threat narrative <span>DREAD \u00b7 PASTA \u00b7 DIAMOND</span></div>'
      + sections.join('')
      + '</div>';
  }

  function _friendlyThreatCaseNarrative(cluster, p, title, subtitle) {
    var narrative = (p.what_happened || '').trim() || (p.short_narrative || '').trim();
    var text = [
      title, subtitle, narrative,
      _clusterEvidenceText(cluster || {}, p || {})
    ].join(' ').toLowerCase();
    if (narrative && !_rawCorrelationText(narrative) && !_isPlaceholderIncidentName(narrative)) return narrative;
    if (/bec|mailbox|wire|finance/i.test(title + ' ' + subtitle)) {
      return 'JanuSec linked identity access, mailbox activity, and payment-risk evidence into a business email compromise threat case.';
    }
    if (/dns|c2|beacon|command/i.test(title + ' ' + subtitle)) {
      return 'JanuSec linked repeated network egress and endpoint evidence into a command-and-control threat case.';
    }
    if (/npm|supply|github|token|secret/i.test(title + ' ' + subtitle)) {
      return 'JanuSec linked developer activity, token exposure, and repository evidence into a supply-chain threat case.';
    }
    return subtitle || narrative || cluster.lead_description || cluster.reason_summary || '';
  }

  function _renderCard(cluster, allSorted, idx) {
    var el = document.getElementById('br-card-' + cluster.cluster_id);
    if (!el) return;
    var p = cluster.tier1_prefill || {};
    var verdict = cluster.verdict || cluster.final_verdict || 'UNCERTAIN';
    var vc = verdictClass(verdict);
    var meter = p.confidence_meter || cluster.confidence_meter;
    var xlinks = (p.cross_cluster_links || []).slice(0, 3);
    var _topTotal = _selectTopThreatCases(allSorted).length;
    var rankLabel = idx === 0 ? 'LEAD 1/' + _topTotal : (idx + 1) + '/' + _topTotal;
    // Deterministic fallback values when LLM hasn't run
    var cardTitle = _displayIncidentName(cluster);
    var cardSubtitle = p.headline_subtitle || cluster.business_significance || _buildFallbackSummary(cluster);
    if (_rawCorrelationText(cardSubtitle)) cardSubtitle = _friendlyThreatCaseSummary(cluster, cardTitle);

    var fullNarrative = _dreadNarrativeText(cluster, _friendlyThreatCaseNarrative(cluster, p, cardTitle, cardSubtitle));
    var narrative = _firstEvidenceSentence(cluster, fullNarrative);
    var dreadInfo = _dreadInfo(cluster);
    var rootCauseText = _deriveRootCause(cluster, p, cardTitle, cardSubtitle);
    var rootCause = rootCauseText ? '<div style="font-size:13px;color:#90caf9;margin-top:4px;"><strong>Root cause:</strong> ' + escHtml(rootCauseText) + '</div>' : '';

    var html = [
      '<div class="br-card br-card--lead" data-verdict="' + vc.toUpperCase() + '" data-testid="br-card-' + escHtml(cluster.cluster_id) + '">',
      '  <div class="br-card__rank">' + escHtml(rankLabel) + '</div>',
      _renderGateBanner(cluster),
      '  <div class="br-card__verdict br-card__verdict--' + vc + '">',
      '    ' + verdictIcon(verdict) + ' ' + escHtml(_displayVerdict(verdict)),
      '  </div>',
      '  <div class="br-card__title">' + escHtml(cardTitle) + '</div>',
      '  <div class="br-card__subtitle">' + escHtml(cardSubtitle) + '</div>',
      meter ? _renderMeter(meter) : '',
      '  <div class="br-card__evidence-title">What happened <span>source: ' + escHtml(dreadInfo.provenance) + '</span></div>',
      '  <div class="br-card__narrative">' + escHtml(narrative) + '</div>',
      _renderContextStrip(cluster, p),
      _renderWhyConfirmed(cluster),
      _renderThreatModelSummary(cluster, p, dreadInfo),
      '<div class="br-card__evidence-title">Business consequence'
      + ' <button class="br-regen-btn" data-gen-dread="' + escHtml(cluster.cluster_id) + '"'
      + ' title="Re-run multi-agent reasoning to generate SABSA business consequence">\u21BB Regenerate</button>'
      + '</div>',
      '<div class="br-card__sabsa">' + escHtml(_businessImpactSentence(cluster) || 'Business impact not yet assessed — click Regenerate to build from evidence.') + '</div>',
      '<div class="br-card__evidence-title">Bounded next actions'
      + ' <button class="br-regen-btn" data-gen-dread="' + escHtml(cluster.cluster_id) + '"'
      + ' title="Re-run multi-agent reasoning to generate scenario-specific actions">\u21BB Regenerate</button>'
      + '</div>',
      _boundedActionsHtml(cluster),
      '  <div class="br-card__meta">',
      '    <span>' + (cluster.row_refs || []).length + ' rows</span>',
      '    <span>' + escHtml((cluster.severity || 'low').toUpperCase()) + '</span>',
      // Fix 4 — split confidence chip with explainer tooltip
      (meter
        ? '    <span class="br-conf-chip" title="Severity is based on evidence volume '
          + 'and attack-phase count. Narrative confidence reflects chain completeness '
          + 'and cross-source corroboration. Lower confidence = evidence gap, not false positive.">'
          + Math.round(meter.total) + '% confidence'
          + '<span class="br-conf-chip__icon">ⓘ</span>'
          + '</span>'
        : ''),
      p.model_used ? '    <span title="Model used">model: ' + escHtml(p.model_used) + '</span>' : '',
      '  </div>',
      _renderQualityWarning(p._quality),
      _renderJargonWarning(p._quality_flags),
      // Fix 5 — attack timeline is always visible; detail section collapses separately
      _renderEvidenceChain(p.evidence_chain),
      '<details class="br-drilldown br-card__technical"><summary>Expand technical detail</summary>',
      rootCause,
      _knownUnknownBox(cluster),
      p.verdict_reasoning ? '<div class="br-card__verdict-reasoning"><span style="color:var(--text-muted);font-size:13px;">WHY:</span> ' + escHtml(p.verdict_reasoning) + '</div>' : '',
      _rowChipsFromText(fullNarrative, 12),
      _renderEvidenceGaps(p.evidence_gaps),
      '</details>',
      '  <div class="br-card__actions">',
      // LIKELY_BREACH / LIKELY_COMPROMISE without prefill — show Generate button prominently
      (vc === 'likely' && !_prefillDone(cluster))
        ? '    <button class="br-finding__gen" style="font-weight:700;" data-gen-cluster="' + escHtml(cluster.cluster_id) + '">'
          + '      ⚑ Generate narrative — human review required'
          + '    </button>'
        : '    <button class="br-card__open" onclick="window.location.href=\'/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=evidence\'">'
          + '      Show evidence rows'
          + '    </button>',
      // DREAD generate — only show in actions bar when structured content IS present
      // (so analyst can re-generate/improve it). When absent, the button is embedded
      // inline in the _renderThreatModelSummary empty state above.
      dreadInfo.hasStructured
        ? '    <button class="br-finding__gen br-finding__gen--dread" data-gen-dread="' + escHtml(cluster.cluster_id) + '"'
          + ' title="Re-run: Sequence-aware \u00b7 Adversarial \u00b7 CorrectiveRAG \u00b7 TemporalRAG">'
          + '      \uD83E\uDDE0 Regenerate Threat Summary'
          + '    </button>'
        : '',
      '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(cluster.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
      '      Open threat case ↗',
      '    </button>',
      '  </div>',
      xlinks.length ? _renderCrossLinks(xlinks) : '',
      '</div>',
    ].join('');

    el.innerHTML = html;
  }

  function _renderCardLoading(cluster, idx) {
    var el = document.getElementById('br-card-' + cluster.cluster_id);
    if (!el) return;
    var verdict = cluster.verdict || cluster.final_verdict || 'UNCERTAIN';
    var vc = verdictClass(verdict);
    var cardTitle = _displayIncidentName(cluster);
    var cardSubtitle = cluster.business_significance || _buildFallbackSummary(cluster);
    if (_rawCorrelationText(cardSubtitle)) cardSubtitle = _friendlyThreatCaseSummary(cluster, cardTitle);

    el.innerHTML = [
      '<div class="br-card br-card--lead" data-verdict="' + vc.toUpperCase() + '" data-testid="br-card-' + escHtml(cluster.cluster_id) + '">',
      '  <div class="br-card__rank">' + (idx + 1) + '/3</div>',
      '  <div class="br-card__verdict br-card__verdict--' + vc + '">',
      '    ' + verdictIcon(verdict) + ' ' + escHtml(verdict.toUpperCase()),
      '  </div>',
      '  <div class="br-card__title">' + escHtml(cardTitle) + '</div>',
      '  <div class="br-card__subtitle">' + escHtml(cardSubtitle) + '</div>',
      '  <div class="br-card__await">',
      '    <div class="br-card__await-dot"></div>',
      '    Preparing threat case summary with ' + escHtml(getSelectedModel()) + '...',
      '  </div>',
      '  <div class="br-card__meta">',
      '    <span>' + (cluster.row_refs || []).length + ' rows</span>',
      '    <span>' + escHtml((cluster.severity || 'low').toUpperCase()) + '</span>',
      '  </div>',
      '  <div style="text-align:right;margin-top:8px">',
      '    <button class="br-card__open" onclick="window.open(\'/static/breach.html?cluster=' + encodeURIComponent(cluster.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '\', \'_blank\')">',
      '      Open threat case ↗',
      '    </button>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _renderMeter(meter) {
    var segs = meter.segments || {};
    function pct(v) {
      var n = Number(v);
      return isFinite(n) && n > 0 ? n : 0;
    }
    var total = pct(meter.total);
    if (total > 0 && total <= 1) total = total * 100;
    var source = pct(segs.source_diversity);
    var quality = pct(segs.evidence_quality);
    var corrobor = pct(segs.corroboration);
    var pattern = pct(segs.pattern_match);
    if ((source + quality + corrobor + pattern) <= 0 && total > 0) {
      source = Math.min(100, total);
    }
    return [
      '<div class="br-meter" title="Confidence: ' + Math.round(total) + '/100">',
      '  <div class="br-meter__seg br-meter__seg--source"   style="width:' + source + '%"></div>',
      '  <div class="br-meter__seg br-meter__seg--quality"  style="width:' + quality + '%"></div>',
      '  <div class="br-meter__seg br-meter__seg--corrobor" style="width:' + corrobor + '%"></div>',
      '  <div class="br-meter__seg br-meter__seg--pattern"  style="width:' + pattern + '%"></div>',
      '</div>',
    ].join('');
  }

  var _GATE_STYLE = {
    URGENT: 'background:#7b1a1a;color:#ffd6d6;border-left:4px solid #ff4444;',
    HIGH:   'background:#5a3a00;color:#ffe0a0;border-left:4px solid #ffaa00;',
    NORMAL: 'background:#2a3a1a;color:#c8e6c9;border-left:4px solid #66bb6a;',
    LOW:    'background:#1a2a3a;color:#b3cde0;border-left:4px solid #4a90d9;',
  };
  var _GATE_LABEL = {
    URGENT: 'URGENT — Human sign-off required before any action',
    HIGH:   'HIGH — Senior analyst review required',
    NORMAL: 'Pending human review',
    LOW:    'Auto-triaged — verify if escalating',
  };

  function _renderGateBanner(cluster) {
    if (!cluster.human_validation_required) return '';
    var urgency = (cluster.gate_urgency || 'NORMAL').toUpperCase();
    var style = _GATE_STYLE[urgency] || _GATE_STYLE.NORMAL;
    var label = _GATE_LABEL[urgency] || _GATE_LABEL.NORMAL;
    var status = cluster.playbook_status ? ' · ' + escHtml(cluster.playbook_status) : '';
    return '<div style="padding:6px 10px;margin-bottom:8px;font-size:11px;font-weight:600;border-radius:3px;' + style + '">'
      + escHtml(label) + status
      + '</div>';
  }

  function _renderEvidenceChain(chain) {
    if (!chain || !chain.length) return '';
    var rows = chain.slice(0, 5).map(function (step, i) {
      var refs = (step.row_refs || []).join(', ');
      var refsHtml = refs ? '<span style="opacity:.5;font-size:11px;"> [rows ' + escHtml(refs) + ']</span>' : '';
      return '<li style="margin-bottom:4px;">'
        + '<span style="color:var(--text-muted);font-size:11px;margin-right:4px;">' + (i + 1) + '.</span>'
        + '<strong>' + escHtml(step.what || '') + '</strong>'
        + refsHtml
        + (step.why_significant ? '<div style="font-size:12px;opacity:.7;margin-top:1px;">' + escHtml(step.why_significant) + '</div>' : '')
        + '</li>';
    }).join('');
    return '<div class="br-card__section-head" style="font-size:12px;color:var(--text-muted);margin-top:10px;margin-bottom:4px;">ATTACK TIMELINE</div>'
      + '<ol style="margin:0;padding-left:14px;font-size:13px;">' + rows + '</ol>';
  }

  function _renderEvidenceGaps(gaps) {
    if (!gaps || !gaps.length) return '';
    var items = gaps.slice(0, 3).map(function (g) {
      return '<li style="margin-bottom:3px;">'
        + escHtml(g.gap || '')
        + (g.would_confirm ? '<span style="color:#ffaa00;font-size:11px;"> → ' + escHtml(g.would_confirm) + '</span>' : '')
        + '</li>';
    }).join('');
    return '<div class="br-card__section-head" style="font-size:12px;color:#ffaa00;margin-top:10px;margin-bottom:4px;">EVIDENCE GAPS</div>'
      + '<ul style="margin:0;padding-left:14px;font-size:12px;opacity:.85;">' + items + '</ul>';
  }

  function _renderImmediateActions(actions, fallbackTopActions) {
    // Prefer new structured immediate_actions, fall back to top_actions strings
    if (actions && actions.length) {
      var items = actions.slice(0, 4).map(function (a) {
        var subtasks = (a.subtasks || []).slice(0, 2).map(function (s) {
          return '<li style="opacity:.7;font-size:11px;">' + escHtml(s.label || '') + '</li>';
        }).join('');
        return '<li style="margin-bottom:5px;">'
          + '<span style="font-size:11px;color:var(--text-muted);">[' + escHtml(a.persona || 'analyst') + ']</span> '
          + '<strong>' + escHtml(a.title || '') + '</strong>'
          + (subtasks ? '<ul style="margin:2px 0 0 10px;padding:0;">' + subtasks + '</ul>' : '')
          + '</li>';
      }).join('');
      return items;
    }
    var fallback = (fallbackTopActions || []).slice(0, 4);
    if (!fallback.length) {
      fallback = ['Validate the evidence chain, contain affected identities or workloads, and preserve source logs before closure.'];
    }
    return fallback.map(function (a) {
      if (a && typeof a === 'object') {
        var label = a.title || a.action || a.label || 'Review evidence';
        var detail = a.rationale || a.tool || '';
        return '<li><strong>' + escHtml(label) + '</strong>'
          + (detail ? '<div style="opacity:.7;font-size:11px;">' + escHtml(detail) + '</div>' : '')
          + '</li>';
      }
      return '<li>' + escHtml(a) + '</li>';
    }).join('');
  }

  function _renderQualityWarning(quality) {
    if (!quality || quality.passed !== false) return '';
    return [
      '<div style="font-size:12px;color:var(--medium);margin-bottom:6px;">',
      '  ⚠ Quality gate flagged: ' + escHtml((quality.flagged_tokens || []).join(', ')),
      '  &nbsp;— verify entities manually',
      '</div>',
    ].join('');
  }

  function _renderJargonWarning(qualityFlags) {
    if (!qualityFlags || !qualityFlags.length) return '';
    var hasJargon = qualityFlags.some(function (f) { return f.indexOf('jargon') !== -1; });
    if (!hasJargon) return '';
    return '<div style="font-size:12px;padding:4px 8px;margin-bottom:6px;background:rgba(255,170,0,0.08);border-left:3px solid #ffaa00;color:#ffaa00;">'
      + '⚠ Summary contains technical terms — review before sharing with executives'
      + '</div>';
  }

  function _renderCrossLinks(links) {
    var parts = links.map(function (l) {
      return '<span class="br-card__xlink" onclick="_openCluster(\'' + escHtml(l.also_in_cluster_id) + '\')">'
        + escHtml(l.entity) + ' → ' + escHtml(l.also_in_incident_name || l.also_in_cluster_id)
        + '</span>';
    });
    return '<div class="br-card__xlinks">Also in: ' + parts.join(' &nbsp;·&nbsp; ') + '</div>';
  }

  function _renderMitreBadges(techniques, evidenceMap) {
    // E7: show row count tooltip per technique if mitre_evidence_map is present
    var techs = (techniques || []).slice(0, 4);
    return techs.map(function (t) {
      var refs = evidenceMap && evidenceMap[t];
      var title = refs && refs.length
        ? 'title="Supported by rows: ' + refs.join(', ') + '"'
        : '';
      var badge = refs && refs.length
        ? '<sup style="font-size:10px;opacity:.7;"> ×' + refs.length + '</sup>'
        : '';
      return '<span class="br-card__mitre-chip" ' + title + '>' + escHtml(t) + badge + '</span>';
    }).join('');
  }

  // ── Event wiring ─────────────────────────────────────────────────────────────

  function _wireHomeEvents() {
    // Per-threat-case generate buttons (T1 narrative)
    document.getElementById('br-content').addEventListener('click', function (e) {
      // T1 narrative generate
      var btn2 = e.target.closest('[data-gen-cluster]');
      if (btn2) {
        var cid = btn2.getAttribute('data-gen-cluster');
        btn2.disabled = true;
        btn2.textContent = 'Generating…';
        _fireSinglePrefill(cid, function () {
          var fol = document.getElementById('br-fol-' + cid);
          var cluster = _findCluster(cid);
          if (fol && cluster) {
            var p = cluster.tier1_prefill || {};
            fol.textContent = p.incident_name
              ? (p.headline_subtitle || p.incident_name)
              : fol.textContent;
          }
          btn2.textContent = 'Done ✓';
        });
      }
      // DREAD + PASTA + Diamond structured analysis generate / regenerate
      var btnDread = e.target.closest('[data-gen-dread]');
      if (btnDread) {
        var dcid = btnDread.getAttribute('data-gen-dread');
        btnDread.disabled = true;
        var _isRegen = btnDread.classList.contains('br-regen-btn');
        btnDread.textContent = _isRegen ? '↻ …' : '\uD83E\uDDE0 Generating…';
        _fireDreadGenerate(dcid, function () {
          var resorted = _rankClusters(
            (state.threatCases && state.threatCases.length > 0) ? state.threatCases : state.clusters
          );
          _rerenderCard(dcid, resorted);
          _loadExecSummary(true);
        });
      }
    });

    // Exec summary regenerate
    var regen = document.getElementById('br-exec-regen');
    if (regen) regen.addEventListener('click', function () {
      regen.textContent = '[regenerating…]';
      regen.style.opacity = '0.5';
      regen.style.pointerEvents = 'none';
      _loadExecSummary(true, function () {
        regen.textContent = '[regenerate ↻]';
        regen.style.opacity = '';
        regen.style.pointerEvents = '';
      });
    });

    // Collapsed section expand (BENIGN / ISOLATED)
    document.getElementById('br-content').addEventListener('click', function (e) {
      var collapsed = e.target.closest('[data-collapsed-key]');
      if (!collapsed) return;
      var key = collapsed.getAttribute('data-collapsed-key');
      var body = document.getElementById('br-collapsed-body-' + key);
      var caret = document.getElementById('br-caret-' + key);
      if (!body) return;
      var isOpen = body.style.display !== 'none';
      if (isOpen) {
        body.style.display = 'none';
        if (caret) caret.textContent = 'Expand ▼';
      } else {
        if (!body.innerHTML) {
          var matchClass = key === 'benign' ? 'benign' : null;
          var shown = _rankClusters(state.clusters).filter(function (c) {
            if (matchClass) return _vClass(c) === matchClass && (c.row_refs || []).length > 0;
            return true;
          });
          body.innerHTML = shown.length ? shown.map(function (c) {
            var p2 = c.tier1_prefill || {};
      var t = _displayIncidentName(c);
            var s = p2.headline_subtitle || _buildFallbackSummary(c);
            return '<div style="padding:8px 14px;border-bottom:1px solid var(--border);font-size:13px;display:flex;gap:12px;align-items:baseline;">'
              + '<span style="opacity:.5;font-size:12px;min-width:30px;">' + (c.row_refs || []).length + ' rows</span>'
              + '<span><strong>' + escHtml(t) + '</strong>'
              + (s ? ' <span style="opacity:.65;">· ' + escHtml(s) + '</span>' : '') + '</span>'
              + '<a style="margin-left:auto;font-size:12px;color:var(--text-muted);white-space:nowrap;" href="/static/breach.html?cluster='
              + encodeURIComponent(c.cluster_id) + '&assessment=' + encodeURIComponent(AID) + '">Open ↗</a>'
              + '</div>';
          }).join('')
            : '<div style="padding:10px 14px;color:var(--text-muted);font-size:12px;">No cases.</div>';
        }
        body.style.display = 'block';
        if (caret) caret.textContent = 'Collapse ▲';
      }
    });
  }

  // ── LLM calls ────────────────────────────────────────────────────────────────

  function _loadExecSummary(regenerate, done) {
    apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/executive-summary',
      { regenerate: !!regenerate, model: getSelectedModel() })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        var det = document.getElementById('br-exec-det');
        var col = document.getElementById('br-exec-color');
        var model = document.getElementById('br-exec-model');
        if (det) {
          if (data.headline || data.subline || data.executive_summary) {
            // Geo travel alert banner — uses human-readable from_label/to_label
            var travelHtml = '';
            var impossible = data.geo_impossible_travel || [];
            var suspicious = data.geo_suspicious_travel || [];
            var plausible = data.geo_plausible_travel || [];
            if (impossible.length) {
              var f = impossible[0];
              var fromLbl = f.from_label || f.from_country || '?';
              var toLbl   = f.to_label   || f.to_country   || '?';
              travelHtml = '<div style="margin-top:10px;padding:10px 12px;border-radius:4px;background:rgba(239,68,68,.10);border-left:3px solid #ef4444;font-size:13px;color:#fca5a5;">'
                + '<strong>⚠ Impossible travel — credential compromise likely</strong><br>'
                + '<strong>' + escHtml(f.user || '') + '</strong>'
                + ' logged in from <strong>' + escHtml(fromLbl) + '</strong>'
                + (f.from_ts ? ' at ' + escHtml(String(f.from_ts).slice(0, 16).replace('T', ' ')) : '')
                + ', then from <strong>' + escHtml(toLbl) + '</strong>'
                + (f.to_ts ? ' at ' + escHtml(String(f.to_ts).slice(0, 16).replace('T', ' ')) : '')
                + (f.hours_between != null ? ' — only <strong>' + f.hours_between + 'h</strong> apart' : '')
                + (f.min_flight_hours ? ' (minimum flight time: ' + f.min_flight_hours + 'h)' : '')
                + '.'
                + '</div>';
            } else if (suspicious.length) {
              var f = suspicious[0];
              var fromLbl = f.from_label || f.from_country || '?';
              var toLbl   = f.to_label   || f.to_country   || '?';
              travelHtml = '<div style="margin-top:10px;padding:10px 12px;border-radius:4px;background:rgba(249,115,22,.10);border-left:3px solid #f97316;font-size:13px;color:#fdba74;">'
                + '<strong>⚠ Suspicious travel — high velocity between locations</strong><br>'
                + '<strong>' + escHtml(f.user || '') + '</strong>'
                + ' accessed from <strong>' + escHtml(fromLbl) + '</strong>'
                + ' then <strong>' + escHtml(toLbl) + '</strong>'
                + (f.hours_between != null ? ' (' + f.hours_between + 'h apart)' : '')
                + '. Verify user location before closing.'
                + '</div>';
            } else if (plausible.length) {
              var f = plausible[0];
              var fromLbl = f.from_label || f.from_country || '?';
              var toLbl   = f.to_label   || f.to_country   || '?';
              travelHtml = '<div style="margin-top:10px;padding:10px 12px;border-radius:4px;background:rgba(250,204,21,.08);border-left:3px solid #facc15;font-size:13px;color:#fde68a;">'
                + '<strong>✈ Overseas access — consistent with business travel</strong><br>'
                + '<strong>' + escHtml(f.user || '') + '</strong>'
                + ' logged in from <strong>' + escHtml(toLbl) + '</strong>'
                + (f.hours_between != null ? ', ' + f.hours_between + 'h after their login from ' + escHtml(fromLbl) : '')
                + (f.min_flight_hours ? '. A direct flight takes approximately ' + f.min_flight_hours + 'h — geographically consistent.' : '. Travel is geographically plausible.')
                + ' Verify with HR or travel calendar before escalating.'
                + '</div>';
            }

            // IAM playbook actions — shown as numbered steps
            var iamPlaybook = data.iam_playbook || [];
            var iamHtml = '';
            if (iamPlaybook.length) {
              var stepItems = iamPlaybook.map(function (p, i) {
                return '<li style="margin-bottom:3px;">' + escHtml(p) + '</li>';
              }).join('');
              iamHtml = '<div style="margin-top:10px;padding:8px 12px;background:rgba(255,255,255,.03);border-radius:4px;font-size:13px;">'
                + '<div style="font-size:11px;font-weight:700;letter-spacing:.06em;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">IAM Response Playbook</div>'
                + '<ol style="margin:0;padding-left:16px;color:var(--text-secondary);">' + stepItems + '</ol>'
                + '</div>';
            }

            det.innerHTML = [
              data.headline ? '<div class="br-exec__headline">' + escHtml(data.headline) + '</div>' : '',
              data.subline ? '<div class="br-exec__subline">' + escHtml(data.subline) + '</div>' : '',
              '<div class="br-exec__source">source: ' + escHtml(data.narrative_source || data.narrative_provenance || 'legacy') + (data.from_cache ? ' (cached)' : '') + '</div>',
              (function () {
                var compact = _compactExecSummary(data, data.executive_summary || '');
                return '<div class="br-exec__body"><p>' + escHtml(compact.p1) + '</p><p>' + escHtml(compact.p2) + '</p></div>';
              })(),
              (data.evidence_refs && data.evidence_refs.length)
                ? '<details class="br-drilldown"><summary>Show evidence basis</summary>'
                  + '<div class="br-exec__refs">Evidence refs: ' + data.evidence_refs.slice(0, 18).map(function (n) {
                      return '<a class="br-rowchip" href="/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=evidence&row=' + encodeURIComponent(n) + '">[' + escHtml(n) + ']</a>';
                    }).join(' ') + '</div>'
                  + (data.executive_summary ? '<div class="br-drilldown__body">' + escHtml(data.executive_summary) + '</div>' : '')
                  + '</details>'
                : '',
              data.render_warning ? '<div class="br-exec__warn">' + escHtml(data.render_warning) + '</div>' : '',
              travelHtml,
              iamHtml,
            ].join('');
          } else {
            det.textContent = data.deterministic || '';
          }
          det.removeAttribute('style');
        }
        if (col) col.textContent = '';
        if (model && data.model_used) model.textContent = 'model: ' + data.model_used;
        if (done) done();
      })
      .catch(function (err) {
        console.warn('breach.js: exec summary failed', err);
        var det = document.getElementById('br-exec-det');
        if (det) det.innerHTML = '<span style="color:var(--text-muted);font-size:11px">Executive summary unavailable — server loading.</span>';
        if (done) done();
      });
  }

  function _fireDreadGenerate(cid, cb) {
    // Force re-run T1 prefill to regenerate what_happened, evidence_chain, root_cause,
    // and any DREAD/PASTA/Diamond fragments that can be deterministically built.
    // The card will re-render using the updated T1 content once complete.
    _fireSinglePrefill(cid, cb, true);
  }

  function _fireSinglePrefill(cid, cb, force) {
    apiPost('/api/v1/assessments/' + encodeURIComponent(AID) + '/clusters/' + encodeURIComponent(cid) + '/tier1-summary', { model: getSelectedModel(), force: !!force })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        var cluster = _findCluster(cid);
        if (cluster && data.tier1_prefill) {
          cluster.tier1_prefill = data.tier1_prefill;
          if (data.verdict) cluster.verdict = data.verdict;
          if (data.verdict_rationale) cluster.verdict_rationale = data.verdict_rationale;
          if (data.verdict_confidence != null) cluster.verdict_confidence = data.verdict_confidence;
          if (data.human_validation_required != null) cluster.human_validation_required = data.human_validation_required;
          if (data.gate_urgency) cluster.gate_urgency = data.gate_urgency;
          if (data.playbook_status) cluster.playbook_status = data.playbook_status;
        }
        if (cb) cb(data);
      })
      .catch(function (err) {
        console.warn('breach.js: tier1-summary failed for', cid, err);
        if (cb) cb({});
      });
  }

  function _rerenderCard(cid, sorted) {
    var cluster = _findCluster(cid);
    if (!cluster) return;
    var idx = sorted.findIndex(function (c) { return c.cluster_id === cid; });
    if (idx < 0 || idx > 2) return;
    _safeRenderCard(cluster, sorted, idx);
  }

  function _safeRenderCard(cluster, sorted, idx) {
    try {
      _renderCard(cluster, sorted, idx);
    } catch (err) {
      console.warn('breach.js: card render failed for', cluster && cluster.cluster_id, err);
      try { _renderCardLoading(cluster, idx); } catch (_) {}
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  function _findCluster(cid) {
    return state.clusters.find(function (c) { return c.cluster_id === cid; }) || null;
  }

  function _prefillDone(cluster) {
    var p = cluster && cluster.tier1_prefill;
    return !!(p && p.incident_name && !p._error && !p._fallback_generated);
  }

  var _VERDICT_RANK = {
    'VALIDATED_BREACH': 6, 'CONFIRMED_INTRUSION': 5,
    'LIKELY_COMPROMISE': 4, 'SUSPICIOUS_ACTIVITY': 3,
    'INSUFFICIENT_TELEMETRY': 2, 'BENIGN_EXPECTED': 1,
    'CONFIRMED': 5, 'LIKELY REAL': 4, 'LIKELY': 4, 'UNCERTAIN': 3, 'BENIGN': 1
  };
  var _SEV_RANK = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };

  function _rankClusters(clusters) {
    return clusters.slice().sort(function (a, b) {
      var va = _verdictRank(a), vb = _verdictRank(b);
      if (va !== vb) return vb - va;
      var sa = _SEV_RANK[String(a.severity || '').toLowerCase()] || 0;
      var sb = _SEV_RANK[String(b.severity || '').toLowerCase()] || 0;
      if (sa !== sb) return sb - sa;
      return ((b.row_refs || []).length) - ((a.row_refs || []).length);
    });
  }

  function _verdictRank(c) {
    var v = ((c.verdict || c.final_verdict) || '').toUpperCase();
    if (v.indexOf('NO_VALIDATED_BREACH') !== -1 || v.indexOf('NO VALIDATED BREACH') !== -1) return 1;
    for (var k in _VERDICT_RANK) {
      if (v.indexOf(k) !== -1) return _VERDICT_RANK[k];
    }
    return 2;
  }

  function _vClass(c) {
    return verdictClass(c.verdict || c.final_verdict || 'UNCERTAIN');
  }

  function _countBenign(sorted) {
    return sorted.filter(function (c) {
      return _vClass(c) === 'benign' && (c.row_refs || []).length > 0;
    }).length;
  }

  window._openCluster = function (cid) {
    window.open('/static/breach.html?cluster=' + encodeURIComponent(cid) + '&assessment=' + encodeURIComponent(AID), '_blank');
  };

  // ── Tab stubs (wired in A4-A6) ───────────────────────────────────────────────

  function renderClusterTab() {
    updateTabBar('cluster');
    var clusters = state.clusters;
    var cluster = clusters.find(function (c) { return c.cluster_id === CID; });
    if (!cluster) {
      document.getElementById('br-content').innerHTML =
        '<div style="padding:32px;color:var(--text-muted)">Cluster ' + escHtml(CID) + ' not found in assessment.</div>';
      return;
    }

    // Provide a mount point then call A6 renderer
    document.getElementById('br-content').innerHTML = '<div id="bct-mount"></div>';

    if (typeof BreachClusterTab !== 'undefined') {
      BreachClusterTab.mount('bct-mount', cluster, state.rows, AID, clusters);
    } else {
      document.getElementById('bct-mount').innerHTML =
        '<div style="padding:32px;color:var(--text-muted)">breach_cluster_tab.js not loaded.</div>';
    }
  }

  // ── Evidence tab ─────────────────────────────────────────────────────────────

  var _evState = { sort: 'triage_score', asc: false, cluster: '', sev: '', search: '', expanded: {} };

  function _evSevColor(sev) {
    return { critical: 'var(--danger)', high: 'var(--warn)', medium: 'var(--accent)', low: 'var(--safe)' }[(sev||'').toLowerCase()] || 'var(--text-muted)';
  }

  function _evClusterColor(cid) {
    if (!cid) return 'var(--text-muted)';
    var colors = ['var(--accent)','var(--safe)','var(--warn)','var(--danger)','#a78bfa','#22d3ee','#fb923c','#f472b6'];
    var h = 0; for (var i=0; i<cid.length; i++) h = (h*31 + cid.charCodeAt(i)) & 0xffff;
    return colors[h % colors.length];
  }

  function _evShortTs(ts) {
    if (!ts) return '—';
    var d = new Date(ts);
    if (isNaN(d)) return ts.slice(0,10);
    return (d.getMonth()+1).toString().padStart(2,'0') + '-' + d.getDate().toString().padStart(2,'0') +
      ' ' + d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
  }

  function _evFilterRows(rows) {
    var s = _evState;
    return rows.filter(function(r) {
      if (s.cluster && r.correlation_cluster_id !== s.cluster) return false;
      if (s.sev && (r.severity||'').toLowerCase() !== s.sev) return false;
      if (s.search) {
        var needle = s.search.toLowerCase();
        var haystack = [
          r.user_principal_name, r.userPrincipalName, r.user, r.actor,
          r.accounts && r.accounts[0], r.entity,
          r.source_ip, r.src_ip, r.ips && r.ips[0],
          r.event_type, r.description, r.action, r.event_simpleName,
          r.analyst_notes, r.mitre_technique, r.mitre && r.mitre[0],
          r.correlation_cluster_id, r.source_platform, r._source,
        ].join(' ').toLowerCase();
        if (haystack.indexOf(needle) === -1) return false;
      }
      return true;
    }).sort(function(a, b) {
      var av = a[s.sort], bv = b[s.sort];
      // Numeric sort for score/triage fields
      if (s.sort === 'triage_score' || s.sort === 'risk_score') {
        av = parseFloat(av) || 0; bv = parseFloat(bv) || 0;
      } else {
        av = av || ''; bv = bv || '';
      }
      if (av < bv) return s.asc ? -1 : 1;
      if (av > bv) return s.asc ?  1 : -1;
      return 0;
    });
  }

  function _evRenderTable(rows, clusters) {
    var clusterSev = {};
    clusters.forEach(function(c) { clusterSev[c.cluster_id] = c.severity; });

    var clusterIds = [];
    clusters.forEach(function(c) { clusterIds.push(c.cluster_id); });

    var filtered = _evFilterRows(rows);
    var s = _evState;

    function sortHdr(col, label) {
      var arrow = s.sort === col ? (s.asc ? ' ▲' : ' ▼') : '';
      return '<th class="br-ev__th br-ev__th--sort" data-evsort="' + col + '">' + label + arrow + '</th>';
    }

    var clusterOpts = '<option value="">All clusters</option>' +
      clusterIds.map(function(id) {
        return '<option value="' + escHtml(id) + '"' + (s.cluster===id?' selected':'') + '>' + escHtml(id) + '</option>';
      }).join('');

    var sevOpts = '<option value="">All severities</option>' +
      ['critical','high','medium','low'].map(function(sv) {
        return '<option value="' + sv + '"' + (s.sev===sv?' selected':'') + '>' + sv + '</option>';
      }).join('');

    var rowsHtml = filtered.map(function(r) {
      var cid = r.correlation_cluster_id || '';
      var sev = (r.severity || '').toLowerCase();
      var notes = r.analyst_notes || r.description || '';
      var isOpen = !!_evState.expanded[r.row_index];
      var mitre = r.mitre_technique || (r.mitre && r.mitre[0]) || '';

      var evTs = r.timestamp_utc || r.timestamp || r['@timestamp'] || r.ts || '';
      var evType = r.event_type || r.description || (r.event && r.event.type) || r.action || r.operationName || r.event_simpleName || '';
      var evUser = (r.accounts && r.accounts[0]) || r.user_principal_name || r.userPrincipalName || r.user || r.actor || r.entity || '';
      var evIp = r.source_ip || r.src_ip || r.LocalAddressIP4 || r.sourceIPAddress || (r.ips && r.ips[0]) || '';
      return [
        '<tr class="br-ev__row' + (isOpen?' br-ev__row--open':'') + '" data-evrow="' + r.row_index + '">',
        '  <td class="br-ev__td br-ev__td--ts">' + escHtml(_evShortTs(evTs)) + '</td>',
        '  <td class="br-ev__td br-ev__td--src">' + escHtml(r.source_platform || r._source || '') + '</td>',
        '  <td class="br-ev__td br-ev__td--evt">' + escHtml(evType.replace(/_/g,' ').slice(0,40)) + '</td>',
        '  <td class="br-ev__td br-ev__td--user">' + escHtml(evUser.slice(0,30)) + '</td>',
        '  <td class="br-ev__td br-ev__td--ip">' + escHtml(evIp) + '</td>',
        '  <td class="br-ev__td">',
        cid ? '<span class="br-ev__cluster" style="border-color:' + _evClusterColor(cid) + ';color:' + _evClusterColor(cid) + '">' + escHtml(cid) + '</span>' : '<span class="br-ev__cluster br-ev__cluster--none">—</span>',
        '  </td>',
        '  <td class="br-ev__td">',
        sev ? '<span class="br-ev__sev" style="color:' + _evSevColor(sev) + '">' + sev.toUpperCase() + '</span>' : '',
        '  </td>',
        '  <td class="br-ev__td br-ev__td--mitre">' + (mitre ? '<span class="br-ev__mitre">' + escHtml(mitre) + '</span>' : '') + '</td>',
        '  <td class="br-ev__td br-ev__td--score">' + (r.risk_score != null ? r.risk_score : (r.triage_score != null ? r.triage_score.toFixed(1) : '')) + '</td>',
        '  <td class="br-ev__td br-ev__td--expand">' + (notes ? '<button class="br-ev__toggle" data-evtoggle="' + r.row_index + '">' + (isOpen ? '▲' : '▼') + '</button>' : '') + '</td>',
        '</tr>',
        isOpen && notes ? [
          '<tr class="br-ev__detail" data-evdetail="' + r.row_index + '">',
          '  <td colspan="10" class="br-ev__detail-td">',
          '    <div class="br-ev__notes">' + escHtml(notes) + '</div>',
          '  </td>',
          '</tr>',
        ].join('') : '',
      ].join('');
    }).join('');

    return [
      '<div class="br-ev">',
      '  <div class="br-ev__controls">',
      '    <select class="br-ev__filter" id="br-ev-cluster">' + clusterOpts + '</select>',
      '    <select class="br-ev__filter" id="br-ev-sev">' + sevOpts + '</select>',
      '    <input class="br-ev__search" id="br-ev-search" type="text" placeholder="Search user, IP, event, MITRE…" value="' + escHtml(s.search) + '">',
      '    <span class="br-ev__count">' + filtered.length + ' / ' + rows.length + ' rows</span>',
      '  </div>',
      '  <div class="br-ev__scroll">',
      '  <table class="br-ev__table">',
      '    <thead><tr>',
      sortHdr('timestamp', 'Time'),
      sortHdr('source_platform', 'Source'),
      sortHdr('description', 'Event'),
      sortHdr('accounts', 'User'),
      sortHdr('src_ip', 'Src IP'),
      '    <th class="br-ev__th">Cluster</th>',
      sortHdr('severity', 'Sev'),
      '    <th class="br-ev__th">MITRE</th>',
      sortHdr('risk_score', 'Score'),
      '    <th class="br-ev__th"></th>',
      '    </tr></thead>',
      '    <tbody id="br-ev-tbody">' + (rowsHtml || '<tr><td colspan="10" style="padding:24px;color:var(--text-muted);text-align:center">No rows match filters</td></tr>') + '</tbody>',
      '  </table>',
      '  </div>',
      '</div>',
    ].join('');
  }

  function _evWireEvents(rows, clusters) {
    var el = document.getElementById('br-content');

    el.querySelector('#br-ev-cluster').addEventListener('change', function() {
      _evState.cluster = this.value; _evRerender(rows, clusters);
    });
    el.querySelector('#br-ev-sev').addEventListener('change', function() {
      _evState.sev = this.value; _evRerender(rows, clusters);
    });
    var searchEl = el.querySelector('#br-ev-search');
    var debounce;
    searchEl.addEventListener('input', function() {
      clearTimeout(debounce);
      var v = this.value;
      debounce = setTimeout(function() { _evState.search = v; _evRerender(rows, clusters); }, 200);
    });

    el.addEventListener('click', function(e) {
      var th = e.target.closest('[data-evsort]');
      if (th) {
        var col = th.dataset.evsort;
        if (_evState.sort === col) _evState.asc = !_evState.asc;
        else { _evState.sort = col; _evState.asc = true; }
        _evRerender(rows, clusters);
        return;
      }
      var btn = e.target.closest('[data-evtoggle]');
      if (btn) {
        var idx = btn.dataset.evtoggle;
        _evState.expanded[idx] = !_evState.expanded[idx];
        _evRerender(rows, clusters);
      }
    });
  }

  function _evRerender(rows, clusters) {
    document.getElementById('br-content').innerHTML = _evRenderTable(rows, clusters);
    _evWireEvents(rows, clusters);
  }

  function renderEvidenceTab() {
    var rows = state.rows || [];
    var clusters = state.clusters || [];
    var el = document.getElementById('br-content');
    if (!rows.length) {
      el.innerHTML = '<div style="padding:32px;color:var(--text-muted)">No evidence rows loaded.</div>';
      return;
    }
    _evState.cluster = ''; _evState.sev = ''; _evState.search = ''; _evState.expanded = {};
    el.innerHTML = _evRenderTable(rows, clusters);
    _evWireEvents(rows, clusters);
  }

  function renderHopGraphTab() {
    var el = document.getElementById('br-content');
    el.innerHTML = [
      '<div style="padding:16px 0 8px;color:var(--text-muted);font-size:13px;">Full assessment HopGraph</div>',
      '<div id="br-hopgraph-full" style="min-height:500px;"></div>',
    ].join('');
    if (typeof BreachHopGraph !== 'undefined' && state.clusters && state.clusters.length) {
      BreachHopGraph.render('br-hopgraph-full', state.clusters[0], state.rows, AID);
    }
  }

  function renderComplianceTab() {
    document.getElementById('br-content').innerHTML =
      '<div style="padding:32px;color:var(--text-muted)">Compliance & Architecture — Phase B</div>';
  }

  // ── Swimlane — container div only; BreachSwimlane.render() called after insert ─

  function _renderSwimlane(sorted, assessment) {
    return [
      '<div class="br-section-head">PARALLEL ATTACK CHAINS</div>',
      '<div class="br-swimlane" id="br-swimlane-container">',
      '</div>',
    ].join('');
  }

  function _mountSwimlane(sorted) {
    var el = document.getElementById('br-swimlane-container');
    try {
      if (typeof BreachSwimlane !== 'undefined') {
        BreachSwimlane.render('br-swimlane-container', sorted, state.rows, AID);
      } else if (el) {
        el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px;">Swimlane unavailable (D3 not loaded).</div>';
      }
    } catch (err) {
      console.warn('breach.js: swimlane render failed', err);
      if (el) el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:12px;">Swimlane unavailable for this dataset.</div>';
    }
  }

  // ── HopGraph mini — container div; BreachHopGraph.render() called after insert ─

  function _renderHopGraphMini(leadCluster) {
    var cid = (leadCluster || {}).cluster_id || '';
    return [
      '<div class="br-section-head">HOPGRAPH</div>',
      '<div class="br-hopgraph">',
      '  <div class="br-hopgraph__header">',
      '    Threat case scope: <strong>' + escHtml(((leadCluster || {}).tier1_prefill || {}).incident_name || _buildFallbackTitle(leadCluster || {})) + '</strong>',
      '    &nbsp;<a style="color:var(--text-muted);font-size:13px;" href="/static/breach.html?assessment=' + encodeURIComponent(AID) + '&tab=hopgraph">Expand ▶</a>',
      '  </div>',
      '  <div id="br-hopgraph-mini"></div>',
      '</div>',
    ].join('');
  }

  function _mountHopGraphMini(leadCluster) {
    if (!leadCluster) return;
    var el = document.getElementById('br-hopgraph-mini');
    try {
      if (typeof BreachHopGraph !== 'undefined') {
        BreachHopGraph.render('br-hopgraph-mini', leadCluster, state.rows, AID);
      } else if (el) {
        el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:8px;">HopGraph unavailable (D3 not loaded).</div>';
      }
    } catch (err) {
      console.warn('breach.js: hopgraph render failed', err);
      if (el) el.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:8px;">HopGraph unavailable for this dataset.</div>';
    }
  }

  // ── Tab bar ───────────────────────────────────────────────────────────────────

  function updateTabBar(activeTab) {
    var bar = document.getElementById('br-tabbar');
    if (!bar) return;
    var base = AID ? '?assessment=' + encodeURIComponent(AID) : '';
    var curModel = getSelectedModel();
    var modelOpts = ['qwen3:14b', 'qwen2.5:14b', 'qwen3.6:27b', 'qwen3:30b'].map(function (m) {
      return '<option value="' + m + '"' + (m === curModel ? ' selected' : '') + '>' + m + '</option>';
    }).join('');
    bar.innerHTML = [
      _tab('breach',     'BREACH ASSESSMENT',      base,                     activeTab),
      _tab('compliance', 'Compliance & Arch',        base + '&tab=compliance', activeTab),
      _tab('evidence',   'Evidence',                 base + '&tab=evidence',   activeTab),
      _tab('hopgraph',   'HopGraph',                 base + '&tab=hopgraph',   activeTab),
      '<div class="br-tabs__spacer"></div>',
      '<select class="br-model-select" id="br-model-select" title="LLM model for this session"><option disabled style="font-size:10px;color:#888">— model —</option>' + modelOpts + '</select>',
      '<a class="br-tab br-tab--secondary" href="/static/investigate.html' + base + '">Advanced Console →</a>',
    ].join('');
    var sel = document.getElementById('br-model-select');
    if (sel) {
      sel.addEventListener('change', function () {
        try { localStorage.setItem('selectedModel', sel.value); } catch (_) {}
      });
    }
  }

  function _tab(key, label, href, active) {
    var cls = 'br-tab' + (key === active ? ' br-tab--active' : '');
    return '<a class="' + cls + '" href="/static/breach.html' + href + '">' + label + '</a>';
  }

  // ── Boot ──────────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
