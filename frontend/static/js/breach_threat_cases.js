/* breach_threat_cases.js — Threat case card rendering module
 *
 * Extracted from breach.js to reduce its size and improve testability.
 * Exposes window.BreachThreatCases with pure rendering functions.
 *
 * Load BEFORE breach.js. breach.js delegates to these when available,
 * falling back to its own implementations if this file is not loaded.
 *
 * Dependencies: none (self-contained — escHtml and verdict helpers are local copies).
 */
(function (global) {
  'use strict';

  // ── Local utility copies (duplicated to avoid tight coupling to breach.js) ──

  function _esc(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  var _VERDICT_CLASS_MAP = {
    'NO_VALIDATED_BREACH': 'benign', 'NO VALIDATED BREACH': 'benign',
    'VALIDATED_BREACH':    'confirmed', 'CONFIRMED_INTRUSION': 'confirmed',
    'CONFIRMED_BREACH':    'confirmed',
    'LIKELY_BREACH':       'likely',
    'LIKELY_COMPROMISE':   'likely', 'SUSPICIOUS_ACTIVITY': 'uncertain',
    'INSUFFICIENT_TELEMETRY': 'uncertain', 'BENIGN_EXPECTED': 'benign',
    'CONFIRMED':           'confirmed', 'LIKELY REAL': 'likely', 'LIKELY': 'likely',
    'UNCERTAIN':           'uncertain', 'BENIGN': 'benign',
    'INVESTIGATION_REQUIRED': 'uncertain',
    'ANALYSIS_INCOMPLETE': 'incomplete',
  };

  function _vClass(cluster) {
    var v = ((cluster.verdict || cluster.final_verdict || '')).toUpperCase();
    if (v.indexOf('NO_VALIDATED_BREACH') !== -1 || v.indexOf('NO VALIDATED BREACH') !== -1) return 'benign';
    for (var k in _VERDICT_CLASS_MAP) {
      if (v.indexOf(k) !== -1) return _VERDICT_CLASS_MAP[k];
    }
    return 'uncertain';
  }

  // ── Confidence meter ─────────────────────────────────────────────────────────

  function renderMeter(meter) {
    if (!meter) return '';
    var segs = meter.segments || {};
    function pct(v) { var n = Number(v); return isFinite(n) && n > 0 ? n : 0; }
    var total    = pct(meter.total);
    if (total > 0 && total <= 1) total = total * 100;
    var source   = pct(segs.source_diversity);
    var quality  = pct(segs.evidence_quality);
    var corrobor = pct(segs.corroboration);
    var pattern  = pct(segs.pattern_match);
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

  // ── Human-gate banner ────────────────────────────────────────────────────────

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

  function renderGateBanner(cluster) {
    if (!cluster.human_validation_required) return '';
    var urgency = (cluster.gate_urgency || 'NORMAL').toUpperCase();
    var style   = _GATE_STYLE[urgency] || _GATE_STYLE.NORMAL;
    var label   = _GATE_LABEL[urgency] || _GATE_LABEL.NORMAL;
    var status  = cluster.playbook_status ? ' · ' + _esc(cluster.playbook_status) : '';
    return '<div style="padding:6px 10px;margin-bottom:8px;font-size:11px;font-weight:600;border-radius:3px;' + style + '">'
      + _esc(label) + status + '</div>';
  }

  // ── Evidence chain (ATTACK TIMELINE) ────────────────────────────────────────

  function renderEvidenceChain(chain) {
    if (!chain || !chain.length) return '';
    var rows = chain.slice(0, 5).map(function (step, i) {
      var refs     = (step.row_refs || []).join(', ');
      var refsHtml = refs ? '<span style="opacity:.5;font-size:11px;"> [rows ' + _esc(refs) + ']</span>' : '';
      return '<li style="margin-bottom:4px;">'
        + '<span style="color:var(--text-muted);font-size:11px;margin-right:4px;">' + (i + 1) + '.</span>'
        + '<strong>' + _esc(step.what || '') + '</strong>'
        + refsHtml
        + (step.why_significant ? '<div style="font-size:12px;opacity:.7;margin-top:1px;">' + _esc(step.why_significant) + '</div>' : '')
        + '</li>';
    }).join('');
    return '<div class="br-card__section-head" style="font-size:12px;color:var(--text-muted);margin-top:10px;margin-bottom:4px;">ATTACK TIMELINE</div>'
      + '<ol style="margin:0;padding-left:14px;font-size:13px;">' + rows + '</ol>';
  }

  // ── Evidence gaps ────────────────────────────────────────────────────────────

  function renderEvidenceGaps(gaps) {
    if (!gaps || !gaps.length) return '';
    var items = gaps.slice(0, 3).map(function (g) {
      return '<li style="margin-bottom:3px;">'
        + _esc(g.gap || '')
        + (g.would_confirm ? '<span style="color:#ffaa00;font-size:11px;"> → ' + _esc(g.would_confirm) + '</span>' : '')
        + '</li>';
    }).join('');
    return '<div class="br-card__section-head" style="font-size:12px;color:#ffaa00;margin-top:10px;margin-bottom:4px;">EVIDENCE GAPS</div>'
      + '<ul style="margin:0;padding-left:14px;font-size:12px;opacity:.85;">' + items + '</ul>';
  }

  // ── Immediate / bounded actions ──────────────────────────────────────────────

  function renderImmediateActions(actions, fallbackTopActions) {
    if (actions && actions.length) {
      return actions.slice(0, 4).map(function (a) {
        var subtasks = (a.subtasks || []).slice(0, 2).map(function (s) {
          return '<li style="opacity:.7;font-size:11px;">' + _esc(s.label || '') + '</li>';
        }).join('');
        return '<li style="margin-bottom:5px;">'
          + '<span style="font-size:11px;color:var(--text-muted);">[' + _esc(a.persona || 'analyst') + ']</span> '
          + '<strong>' + _esc(a.title || '') + '</strong>'
          + (subtasks ? '<ul style="margin:2px 0 0 10px;padding:0;">' + subtasks + '</ul>' : '')
          + '</li>';
      }).join('');
    }
    var fallback = (fallbackTopActions || []).slice(0, 4);
    if (!fallback.length) {
      fallback = ['Validate the evidence chain, contain affected identities or workloads, and preserve source logs before closure.'];
    }
    return fallback.map(function (a) {
      if (a && typeof a === 'object') {
        var label  = a.title || a.action || a.label || 'Review evidence';
        var detail = a.rationale || a.tool || '';
        return '<li><strong>' + _esc(label) + '</strong>'
          + (detail ? '<div style="opacity:.7;font-size:11px;">' + _esc(detail) + '</div>' : '')
          + '</li>';
      }
      return '<li>' + _esc(a) + '</li>';
    }).join('');
  }

  // ── Quality / jargon warnings ────────────────────────────────────────────────

  function renderQualityWarning(quality) {
    if (!quality || quality.passed !== false) return '';
    return [
      '<div style="font-size:12px;color:var(--medium);margin-bottom:6px;">',
      '  ⚠ Quality gate flagged: ' + _esc((quality.flagged_tokens || []).join(', ')),
      '  &nbsp;— verify entities manually',
      '</div>',
    ].join('');
  }

  function renderJargonWarning(qualityFlags) {
    if (!qualityFlags || !qualityFlags.length) return '';
    var hasJargon = qualityFlags.some(function (f) { return f.indexOf('jargon') !== -1; });
    if (!hasJargon) return '';
    return '<div style="font-size:12px;padding:4px 8px;margin-bottom:6px;background:rgba(255,170,0,0.08);border-left:3px solid #ffaa00;color:#ffaa00;">'
      + '⚠ Summary contains technical terms — review before sharing with executives'
      + '</div>';
  }

  // ── Cross-cluster entity links ───────────────────────────────────────────────

  function renderCrossLinks(links) {
    var parts = links.map(function (l) {
      return '<span class="br-card__xlink" onclick="_openCluster(\'' + _esc(l.also_in_cluster_id) + '\')">'
        + _esc(l.entity) + ' → ' + _esc(l.also_in_incident_name || l.also_in_cluster_id)
        + '</span>';
    });
    return '<div class="br-card__xlinks">Also in: ' + parts.join(' &nbsp;·&nbsp; ') + '</div>';
  }

  // ── MITRE badges ─────────────────────────────────────────────────────────────

  function renderMitreBadges(techniques, evidenceMap) {
    var techs = (techniques || []).slice(0, 4);
    return techs.map(function (t) {
      var refs  = evidenceMap && evidenceMap[t];
      var title = refs && refs.length ? 'title="Supported by rows: ' + refs.join(', ') + '"' : '';
      var badge = refs && refs.length ? '<sup style="font-size:10px;opacity:.7;"> ×' + refs.length + '</sup>' : '';
      return '<span class="br-card__mitre-chip" ' + title + '>' + _esc(t) + badge + '</span>';
    }).join('');
  }

  // ── Top threat case selection ────────────────────────────────────────────────

  function selectTopThreatCases(sorted) {
    var MIN_TOP_ROWS = 5;
    var confirmed = (sorted || []).filter(function (c) {
      return _vClass(c) === 'confirmed' && (c.row_refs || []).length >= MIN_TOP_ROWS;
    });
    var likely = (sorted || []).filter(function (c) {
      return _vClass(c) === 'likely' && (c.row_refs || []).length >= MIN_TOP_ROWS;
    }).slice(0, 3);
    var candidates = confirmed.concat(likely);
    if (!candidates.length) {
      candidates = (sorted || []).filter(function (c) {
        return _vClass(c) !== 'benign' && (c.row_refs || []).length > 0;
      }).slice(0, 4);
    }
    return candidates;
  }

  function renderTopFindings(sorted) {
    var nonBenign = selectTopThreatCases(sorted);
    var html = '<div class="br-section-head">TOP THREAT CASES</div>';
    nonBenign.forEach(function (c, i) {
      html += '<div id="br-card-' + _esc(c.cluster_id) + '" data-card-idx="' + i + '"></div>';
    });
    return html;
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  global.BreachThreatCases = {
    renderMeter:            renderMeter,
    renderGateBanner:       renderGateBanner,
    renderEvidenceChain:    renderEvidenceChain,
    renderEvidenceGaps:     renderEvidenceGaps,
    renderImmediateActions: renderImmediateActions,
    renderQualityWarning:   renderQualityWarning,
    renderJargonWarning:    renderJargonWarning,
    renderCrossLinks:       renderCrossLinks,
    renderMitreBadges:      renderMitreBadges,
    selectTopThreatCases:   selectTopThreatCases,
    renderTopFindings:      renderTopFindings,
  };

})(window);
