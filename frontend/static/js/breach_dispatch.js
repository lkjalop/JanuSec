/* breach_dispatch.js — Stakeholder dispatch bar module
 *
 * Extracted from breach.js to reduce its size and improve testability.
 * Exposes window.BreachDispatch with:
 *   .roles      — _STAKEHOLDER_ROLES array
 *   .pref(key, fallback) — localStorage preference helper
 *   .renderBar(assessment) — returns HTML string for the dispatch bar
 *
 * Load BEFORE breach.js. breach.js delegates to these when available,
 * falling back to its own implementations if this file is not loaded.
 *
 * Dependencies: none (self-contained — escHtml and icons are local copies).
 */
(function (global) {
  'use strict';

  // ── Local utility: HTML escape ──────────────────────────────────────────────

  function _esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── SVG icons needed by dispatch role buttons ────────────────────────────────
  // Minimal subset of the full _ICONS library in breach.js.

  var _D_ICONS = {
    shield:      '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    scale:       '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16 16l3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M2 16l3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>',
    'bar-chart': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>',
    crosshair:   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>',
    microscope:  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 18h8"/><path d="M3 22h18"/><path d="M14 22a7 7 0 1 0 0-14h-1"/><path d="M9 14h2"/><path d="M9 12a2 2 0 0 1-2-2V6h6v4a2 2 0 0 1-2 2z"/><path d="M12 6V3a1 1 0 0 0-1-1H9a1 1 0 0 0-1 1v3"/></svg>',
    clipboard:   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/></svg>',
    'file-text': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
    mssp:        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg>',
  };

  function _dicon(name) {
    var svg = _D_ICONS[name] || '';
    if (!svg) return '';
    return '<span class="br-icon">' + svg + '</span>';
  }

  // ── Stakeholder role definitions ─────────────────────────────────────────────

  var ROLES = [
    { key: 'soc_analyst',   icon: _dicon('shield'),     label: 'SOC Analyst',   persona: 'soc_analyst',
      desc: 'Triage focus, containment options, IOCs, decision tree, priority',
      actions: 'Confirm/deny/escalate triage. Execute containment playbook. Validate IOC scope.' },
    { key: 'ciso',          icon: _dicon('scale'),      label: 'CISO / Legal',  persona: 'ciso',
      desc: 'Regulatory exposure, compliance control gaps, NDB/GDPR obligations',
      actions: 'Assess NDB notification requirement. Evaluate GDPR Art.33 / SEC 8-K triggers. Approve regulatory disclosure.' },
    { key: 'executive',     icon: _dicon('bar-chart'),  label: 'Executive',     persona: 'executive',
      desc: 'Business impact, plain-English narrative, operational next steps',
      actions: 'Approve containment spend. Communicate to board if material. Authorise forensic engagement.' },
    { key: 'threat_hunter', icon: _dicon('crosshair'),  label: 'Threat Hunter', persona: 'threat_hunter',
      desc: 'Kill chain stages, Sigma rules, hunt hypotheses, pivot leads',
      actions: 'Validate hypotheses. Run Sigma queries. Expand scope via pivot leads. Confirm kill chain completeness.' },
    { key: 'forensics',     icon: _dicon('microscope'), label: 'Forensics',     persona: 'forensics',
      desc: 'Artifact collection order, proof-of-execution, chain of custody',
      actions: 'Collect volatile artifacts (memory \u2192 disk \u2192 network). Preserve chain of custody. Document proof-of-execution.' },
    { key: 'compliance',    icon: _dicon('clipboard'),  label: 'Compliance',    persona: 'compliance',
      desc: 'Framework control gaps (NIST/SOC2/ISO/Privacy Act), audit trail, GRC evidence',
      actions: 'Map control failures to frameworks. Verify notification timeline. Update risk register. Prepare GRC audit evidence.' },
    { key: 'audit',         icon: _dicon('clipboard'),  label: 'Audit / ISO',   persona: 'audit',
      desc: 'ISO 19011 audit opinion, corrective action plan, nonconformity register',
      actions: 'Issue audit opinion (adverse/qualified/unqualified). Assign CAP owners. Update ISMS nonconformity register.' },
    { key: 'mssp',          icon: _dicon('shield'),     label: 'MSSP',          persona: 'mssp',
      desc: 'Tier-2 escalation pack, customer SLA timeline, enrichment handoff',
      actions: 'Receive enrichment handoff from Tier-1. Generate customer-facing report. Track SLA clock.' },
    { key: 'export',        icon: _dicon('file-text'),  label: 'Full Report',   persona: null,
      desc: 'Complete multi-persona HTML report', actions: null },
  ];

  // ── Preference helper ────────────────────────────────────────────────────────

  function pref(key, fallback) {
    try {
      var v = localStorage.getItem('janusec.' + key);
      return v == null ? fallback : v;
    } catch (_) {
      return fallback;
    }
  }

  // ── HTML renderer ────────────────────────────────────────────────────────────

  function renderBar(assessment) {
    assessment = assessment || {};
    var pendingActions = (assessment.proposed_actions || []).filter(function (a) {
      return !a.status || a.status === 'pending' || a.requires_approval;
    });
    var approvalCount = pendingActions.length || ((assessment.pending_approvals || []).length) || 2;
    var hidden    = pref('dispatch.hidden',    '0') === '1';
    var drawerOpen = !hidden && pref('dispatch.drawerOpen', '0') === '1';
    var primaryRoles = ROLES.filter(function (r) { return r.key !== 'export'; });

    var h = '';
    h += '<div class="br-dispatch' + (hidden ? ' br-dispatch--hidden' : '') + '" id="br-dispatch-shell" data-testid="br-dispatch">';
    h += '<div class="br-action-center" data-testid="br-action-center">';
    h += '<div class="br-action-center__top">';
    h += '<div>';
    h += '<div class="br-action-center__eyebrow">ACTION CENTER</div>';
    h += '<div class="br-action-center__title">Next decision and handoff</div>';
    h += '<div class="br-action-center__sub">Keep containment, approvals, and stakeholder handoff visible without turning Home into the report itself.</div>';
    h += '</div>';
    h += '<div class="br-action-center__actions">';
    h += '<button class="br-action-center__toggle" id="br-dispatch-toggle" data-dispatch-toggle aria-expanded="' + (drawerOpen ? 'true' : 'false') + '">' + (drawerOpen ? 'Close dispatch center' : 'Open dispatch center') + '</button>';
    h += '<button class="br-action-center__hide" id="br-dispatch-hide" data-dispatch-hide>' + (hidden ? 'Show' : 'Hide') + '</button>';
    h += '</div>';
    h += '</div>';
    h += '<div class="br-action-center__grid">';
    h += '<div class="br-action-card br-action-card--primary"><div class="br-action-card__label">Start here</div><div class="br-action-card__value">Contain SFL-LT-0442, expire active sessions, preserve evidence.</div><div class="br-action-card__note">SOC owns first response; remediation routes after evidence is preserved.</div></div>';
    h += '<div class="br-action-card"><div class="br-action-card__label">Approvals</div><div class="br-action-card__value">' + approvalCount + ' pending</div><div class="br-action-card__note">Regulatory notification and forensic preservation stay visible here.</div></div>';
    h += '<div class="br-action-card"><div class="br-action-card__label">Trust</div><div class="br-action-card__value">Certain / inferred / verify</div><div class="br-action-card__note">Open dispatch preview for persona-specific uncertainty and history.</div></div>';
    h += '</div>';
    h += '<div class="br-action-center__handoff">';
    h += '<span class="br-action-center__handoff-label">Dispatch to:</span>';
    primaryRoles.forEach(function (r) {
      h += '<button class="br-dispatch__btn br-dispatch__btn--compact"'
        + ' data-dispatch-role="' + r.key + '"'
        + ' data-testid="br-dispatch-' + r.key + '"'
        + ' title="' + _esc(r.desc) + '">'
        + '<span class="br-dispatch__icon">' + r.icon + '</span>'
        + '<span class="br-dispatch__label">' + _esc(r.label) + '</span>'
        + '</button>';
    });
    h += '<button class="br-action-center__more" data-dispatch-toggle>More stakeholders</button>';
    h += '</div>';
    h += '<div class="br-action-center__hidden-note" id="br-dispatch-hidden-note" style="' + (hidden ? '' : 'display:none;') + '">Dispatch center is hidden on this browser. Approvals remain visible; click Show to restore the workbench.</div>';
    h += '</div>';
    h += '<div class="br-dispatch__drawer" id="br-dispatch-drawer" style="' + (drawerOpen ? '' : 'display:none;') + '" aria-hidden="' + (drawerOpen ? 'false' : 'true') + '">';
    h += '<div class="br-dispatch__head">STAKEHOLDER DISPATCH</div>';
    h += '<div class="br-dispatch__sub">Generate one persona-specific report at a time. Review before sending; dispatch is logged, auditable, and tied to approval state.</div>';
    h += '<div class="br-dispatch__bar">';
    ROLES.forEach(function (r) {
      var isExport = r.key === 'export';
      h += '<button class="br-dispatch__btn' + (isExport ? ' br-dispatch__btn--export' : '') + '"'
        + ' data-dispatch-role="' + r.key + '"'
        + ' data-testid="br-dispatch-drawer-' + r.key + '"'
        + ' title="' + _esc(r.desc) + '">'
        + '<span class="br-dispatch__icon">' + r.icon + '</span>'
        + '<span class="br-dispatch__label">' + _esc(r.label) + '</span>'
        + '</button>';
    });
    h += '</div>';
    h += '<div id="br-dispatch-preview" class="br-dispatch__preview" style="display:none;" data-testid="br-dispatch-preview"></div>';
    h += '</div>';
    h += '</div>';
    return h;
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  global.BreachDispatch = {
    roles: ROLES,
    pref:  pref,
    renderBar: renderBar,
  };

}(window));
