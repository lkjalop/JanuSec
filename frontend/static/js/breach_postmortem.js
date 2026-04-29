/**
 * Postmortem Renderer
 * ===================
 *
 * Renders the 7-section postmortem inside the Postmortem tab. Handles:
 *   - Initial assemble call (or fetch existing)
 *   - Per-section auto/computed view
 *   - Override editor (PATCH /sections/{id})
 *   - Signoff (POST /sections/{id}/sign-off)
 *   - ITSM push (POST /push-itsm) with dry-run preview
 *   - Regulator form pre-fill (POST /regulator-form)
 *   - Data-quality issue surfacing (the "0 failed controls" bug guard)
 *
 * USAGE
 * -----
 * Loaded via breach_postmortem_tab.js. Exposes:
 *   window.JanusecPostmortem.render(rootElement, assessmentId, clusterId)
 *
 * BACKEND ROUTES CALLED
 * ---------------------
 *   POST  /api/v1/postmortem/{aid}/clusters/{cid}/assemble
 *   GET   /api/v1/postmortem/{aid}/clusters/{cid}
 *   PATCH /api/v1/postmortem/{aid}/clusters/{cid}/sections/{sid}
 *   POST  /api/v1/postmortem/{aid}/clusters/{cid}/sections/{sid}/sign-off
 *   POST  /api/v1/postmortem/{aid}/clusters/{cid}/push-itsm
 *   POST  /api/v1/postmortem/{aid}/clusters/{cid}/regulator-form
 *
 * SECTIONS
 * --------
 *   s1_incident_lifecycle      FULL
 *   s2_threat_reconstruction   STUB (rendered with 'Available in v2' badge)
 *   s3_control_failures        FULL
 *   s4_sabsa_architecture      STUB
 *   s5_risk_register_delta     STUB
 *   s6_regulatory_clocks       FULL
 *   s7_corrective_actions      FULL
 */

(function () {
  'use strict';

  const SECTION_TITLES = {
    s1_incident_lifecycle:    '1. Incident Lifecycle (ISO 27035)',
    s2_threat_reconstruction: '2. Threat Reconstruction (MITRE + STRIDE)',
    s3_control_failures:      '3. Control Failures by Framework',
    s4_sabsa_architecture:    '4. SABSA Architecture & Policy Implications',
    s5_risk_register_delta:   '5. Risk Register Delta',
    s6_regulatory_clocks:     '6. Regulatory Notification Clocks',
    s7_corrective_actions:    '7. Corrective Actions',
  };

  // ── Public entry point ────────────────────────────────────────────────────

  async function render(rootEl, assessmentId, clusterId) {
    if (!rootEl) return;

    // Try GET first; if 404, call assemble.
    let pm = await fetchPostmortem(assessmentId, clusterId);
    if (!pm) {
      const result = await assemblePostmortem(assessmentId, clusterId, false);
      pm = result && result.postmortem;
    }
    if (!pm) {
      rootEl.innerHTML = '<div class="postmortem-error">Could not load or assemble postmortem.</div>';
      return;
    }

    drawShell(rootEl, assessmentId, clusterId, pm);
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  function _authHeaders(extra) {
    var k = ''; var t = 'default';
    try { k = localStorage.getItem('apiKey') || ''; } catch (_) {}
    try { t = localStorage.getItem('tenantId') || 'default'; } catch (_) {}
    var h = Object.assign({ 'Content-Type': 'application/json', 'x-tenant-id': t }, extra || {});
    if (k) h['x-api-key'] = k;
    return h;
  }

  async function fetchPostmortem(aid, cid) {
    const url = `/api/v1/postmortem/${encodeURIComponent(aid)}/clusters/${encodeURIComponent(cid)}`;
    try {
      const r = await fetch(url, { credentials: 'same-origin', headers: _authHeaders() });
      if (!r.ok) return null;
      const data = await r.json();
      return data && data.postmortem;
    } catch (e) {
      console.warn('fetchPostmortem failed', e);
      return null;
    }
  }

  async function assemblePostmortem(aid, cid, regenerate) {
    const url = `/api/v1/postmortem/${encodeURIComponent(aid)}/clusters/${encodeURIComponent(cid)}/assemble`;
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: _authHeaders(),
      body: JSON.stringify({ regenerate: !!regenerate }),
    });
    if (!r.ok) {
      console.error('assemble failed', r.status, await r.text().catch(() => ''));
      return null;
    }
    return r.json();
  }

  async function patchSection(aid, cid, sid, payload) {
    const url = `/api/v1/postmortem/${encodeURIComponent(aid)}/clusters/${encodeURIComponent(cid)}/sections/${encodeURIComponent(sid)}`;
    const r = await fetch(url, {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: _authHeaders(),
      body: JSON.stringify(payload),
    });
    return r.ok ? r.json() : null;
  }

  async function signOffSection(aid, cid, sid, actor, notes) {
    const url = `/api/v1/postmortem/${encodeURIComponent(aid)}/clusters/${encodeURIComponent(cid)}/sections/${encodeURIComponent(sid)}/sign-off`;
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: _authHeaders(),
      body: JSON.stringify({ actor: actor, notes: notes || null }),
    });
    return r.ok ? r.json() : null;
  }

  async function pushItsm(aid, cid, target, dryRun) {
    const url = `/api/v1/postmortem/${encodeURIComponent(aid)}/clusters/${encodeURIComponent(cid)}/push-itsm`;
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: _authHeaders(),
      body: JSON.stringify({ target: target, dry_run: !!dryRun }),
    });
    return r.ok ? r.json() : { success: false, error: 'http_' + r.status };
  }

  async function prefillRegulator(aid, cid, regulator, ransomwareMeta) {
    const url = `/api/v1/postmortem/${encodeURIComponent(aid)}/clusters/${encodeURIComponent(cid)}/regulator-form`;
    const body = { regulator: regulator };
    if (ransomwareMeta) {
      body.ransomware_payment_made = true;
      body.ransomware_payment_meta = ransomwareMeta;
    }
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: _authHeaders(),
      body: JSON.stringify(body),
    });
    return r.ok ? r.json() : null;
  }

  // ── DOM rendering ─────────────────────────────────────────────────────────

  function drawShell(rootEl, aid, cid, pm) {
    rootEl.innerHTML = '';
    rootEl.appendChild(buildHeader(aid, cid, pm));
    rootEl.appendChild(buildDataQualityBanner(pm));
    rootEl.appendChild(buildVerdictBlock(pm));
    rootEl.appendChild(buildToolbar(aid, cid, pm));
    rootEl.appendChild(buildSectionList(aid, cid, pm));
    rootEl.appendChild(buildProvenanceFooter(pm));
  }

  function buildHeader(aid, cid, pm) {
    const div = document.createElement('div');
    div.className = 'postmortem-header';
    const verdict = (pm.verdict && pm.verdict.platform_verdict) || '?';
    const conf = ((pm.verdict && pm.verdict.confidence) || 0).toFixed(2);
    div.innerHTML = `
      <h2>JanuSec Postmortem</h2>
      <div class="pm-meta">
        <span><strong>${escapeHtml(pm.postmortem_id || '?')}</strong></span>
        <span>cluster: <code>${escapeHtml(pm.cluster_id || '?')}</code></span>
        <span>verdict: <strong class="pm-verdict-${verdictClass(verdict)}">${escapeHtml(verdict)}</strong> (${escapeHtml(conf)})</span>
        <span>tx: ${escapeHtml(pm.transaction_time || '?')}</span>
      </div>
    `;
    return div;
  }

  function buildDataQualityBanner(pm) {
    const dq = pm.data_quality || {};
    const issues = dq.issues || [];
    const div = document.createElement('div');
    if (!issues.length) {
      div.style.display = 'none';
      return div;
    }
    const errors = issues.filter(i => i.severity === 'error');
    const warnings = issues.filter(i => i.severity === 'warning');
    div.className = 'postmortem-dq-banner ' + (errors.length ? 'error' : 'warning');
    div.innerHTML = `
      <h4>Data Quality Issues (${errors.length} error${errors.length === 1 ? '' : 's'}, ${warnings.length} warning${warnings.length === 1 ? '' : 's'})</h4>
      <ul>
        ${issues.map(i => `<li><strong>[${escapeHtml(i.severity)}]</strong> <code>${escapeHtml(i.code)}</code>: ${escapeHtml(i.message)}${
          i.blast_radius && i.blast_radius.length ? ` <em>(affects: ${i.blast_radius.map(escapeHtml).join(', ')})</em>` : ''
        }</li>`).join('')}
      </ul>
    `;
    return div;
  }

  function buildVerdictBlock(pm) {
    const v = pm.verdict || {};
    const div = document.createElement('div');
    div.className = 'postmortem-verdict-block';
    div.innerHTML = `
      <table class="pm-verdict-table">
        <tr><th>Platform verdict</th><td>${escapeHtml(v.platform_verdict || '?')}</td></tr>
        <tr><th>Confidence</th><td>${escapeHtml(String((v.confidence || 0).toFixed(3)))}</td></tr>
        <tr><th>Materiality</th><td>${escapeHtml(v.materiality_assessment || '?')}</td></tr>
        <tr><th>Materiality rationale</th><td>${escapeHtml(v.materiality_rationale || '')}</td></tr>
        <tr><th>Notification status</th><td>${escapeHtml(v.notification_status || '?')}</td></tr>
        <tr><th>Kill chain stage</th><td>${escapeHtml(v.kill_chain_stage || '?')}</td></tr>
      </table>
    `;
    return div;
  }

  function buildToolbar(aid, cid, pm) {
    const div = document.createElement('div');
    div.className = 'postmortem-toolbar';
    div.innerHTML = `
      <button class="btn btn-secondary" data-action="regenerate">Regenerate</button>
      <span class="pm-toolbar-spacer"></span>
      <span class="pm-toolbar-group">
        <strong>Push to ITSM:</strong>
        <button class="btn btn-secondary" data-action="push-jira-dry">Preview Jira</button>
        <button class="btn btn-primary" data-action="push-jira">Push to Jira</button>
        <button class="btn btn-secondary" data-action="push-confluence">Push to Confluence</button>
      </span>
      <span class="pm-toolbar-spacer"></span>
      <span class="pm-toolbar-group">
        <strong>Regulator pre-fill:</strong>
        <button class="btn btn-secondary" data-action="prefill-au_ndb">NDB</button>
        <button class="btn btn-secondary" data-action="prefill-au_apra_cps234">APRA</button>
        <button class="btn btn-secondary" data-action="prefill-au_soci">SOCI</button>
        <button class="btn btn-secondary" data-action="prefill-au_cyber_security_act">CSA Ransomware</button>
      </span>
    `;
    div.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const action = btn.dataset.action;
      btn.disabled = true;
      try {
        if (action === 'regenerate') {
          const ok = confirm('Regenerate the postmortem? Auto-content will be rebuilt; your overrides are preserved but signoff is cleared.');
          if (!ok) return;
          const r = await assemblePostmortem(aid, cid, true);
          if (r && r.postmortem) {
            const root = document.getElementById('postmortem-tab-panel');
            drawShell(root, aid, cid, r.postmortem);
          }
        } else if (action === 'push-jira-dry') {
          const r = await pushItsm(aid, cid, 'jira', true);
          showModal('Jira preview', `<pre>${escapeHtml(JSON.stringify(r, null, 2))}</pre>`);
        } else if (action === 'push-jira') {
          const r = await pushItsm(aid, cid, 'jira', false);
          showModal('Jira push result', `<pre>${escapeHtml(JSON.stringify(r, null, 2))}</pre>`);
        } else if (action === 'push-confluence') {
          const r = await pushItsm(aid, cid, 'confluence', false);
          showModal('Confluence push result', `<pre>${escapeHtml(JSON.stringify(r, null, 2))}</pre>`);
        } else if (action.startsWith('prefill-')) {
          const reg = action.replace('prefill-', '');
          let ransomwareMeta = null;
          if (reg === 'au_cyber_security_act') {
            const made = confirm('Was a ransomware payment actually made or arranged?');
            if (made) {
              const amount = prompt('Payment amount (numeric, no currency symbol):');
              ransomwareMeta = { payment_amount: amount, date_payment_made: new Date().toISOString() };
            }
          }
          const r = await prefillRegulator(aid, cid, reg, ransomwareMeta);
          if (r) showRegulatorPrefill(r.prefill);
        }
      } finally {
        btn.disabled = false;
      }
    });
    return div;
  }

  function buildSectionList(aid, cid, pm) {
    const wrap = document.createElement('div');
    wrap.className = 'postmortem-sections';
    (pm.sections || []).forEach(sec => {
      wrap.appendChild(buildSection(aid, cid, pm, sec));
    });
    return wrap;
  }

  function buildSection(aid, cid, pm, sec) {
    const sid = sec.section_id;
    const isStub = sec.v1_status === 'STUB';
    const signed = !!sec.signoff;

    const wrap = document.createElement('section');
    wrap.className = 'postmortem-section ' +
      (signed ? 'is-signed' : '') +
      (isStub ? ' is-stub' : '');

    const hdr = document.createElement('div');
    hdr.className = 'pm-section-header';
    hdr.innerHTML = `
      <h3>${escapeHtml(SECTION_TITLES[sid] || sid)}</h3>
      <span class="pm-section-badges">
        ${isStub ? '<span class="pm-badge stub">Available in v2</span>' : ''}
        ${signed ? `<span class="pm-badge signed">Signed by ${escapeHtml(sec.signoff.signed_by)} at ${escapeHtml(sec.signoff.signed_at)}</span>` : ''}
        ${(sec.overrides && sec.overrides.length) ? `<span class="pm-badge overrides">${sec.overrides.length} override${sec.overrides.length === 1 ? '' : 's'}</span>` : ''}
      </span>
    `;
    wrap.appendChild(hdr);

    if (sec.build_error) {
      const err = document.createElement('div');
      err.className = 'pm-section-error';
      err.innerHTML = `<strong>Section build failed:</strong> ${escapeHtml(sec.build_error.exception_class)}: ${escapeHtml(sec.build_error.message)}`;
      wrap.appendChild(err);
      return wrap;
    }

    // Body — render the computed view (auto + overrides applied).
    const computed = applyOverrides(sec.auto_output, sec.overrides || []);
    const body = document.createElement('div');
    body.className = 'pm-section-body';
    body.appendChild(renderSectionBody(sid, computed, sec));
    wrap.appendChild(body);

    // Footer: edit / signoff actions (skip for stubs).
    if (!isStub) {
      const ftr = document.createElement('div');
      ftr.className = 'pm-section-footer';
      ftr.innerHTML = `
        <button class="btn btn-link" data-pm-edit="${escapeHtml(sid)}">Add override</button>
        ${signed
          ? `<button class="btn btn-link" data-pm-revoke="${escapeHtml(sid)}" disabled title="Revoke not yet supported in v1">Revoke signoff</button>`
          : `<button class="btn btn-primary" data-pm-signoff="${escapeHtml(sid)}">Sign off</button>`
        }
      `;
      ftr.addEventListener('click', async (e) => {
        const editBtn = e.target.closest('button[data-pm-edit]');
        const signBtn = e.target.closest('button[data-pm-signoff]');
        if (editBtn) {
          openOverrideDialog(aid, cid, sid, sec, () => render(document.getElementById('postmortem-tab-panel'), aid, cid));
        } else if (signBtn) {
          const actor = prompt('Sign-off actor (your email or username):');
          if (!actor) return;
          const notes = prompt('Sign-off notes (optional):') || '';
          const r = await signOffSection(aid, cid, sid, actor, notes);
          if (r) render(document.getElementById('postmortem-tab-panel'), aid, cid);
        }
      });
      wrap.appendChild(ftr);
    }

    return wrap;
  }

  // Section body rendering — distinct rendering per section so the user sees
  // a structured table not a JSON dump for the FULL sections.

  function renderSectionBody(sid, computed, sec) {
    if (!computed) {
      const div = document.createElement('div');
      div.className = 'pm-section-empty';
      div.textContent = 'No content. (Stub or build error.)';
      return div;
    }
    if (sid === 's1_incident_lifecycle') return renderS1(computed);
    if (sid === 's3_control_failures') return renderS3(computed);
    if (sid === 's6_regulatory_clocks') return renderS6(computed);
    if (sid === 's7_corrective_actions') return renderS7(computed);
    // Stubs and others: pretty-print JSON.
    const pre = document.createElement('pre');
    pre.className = 'pm-json-dump';
    pre.textContent = JSON.stringify(computed, null, 2);
    return pre;
  }

  function renderS1(d) {
    const div = document.createElement('div');
    const detect = d.detect || {};
    const tl = d.timeline || [];
    div.innerHTML = `
      <h4>Detect</h4>
      <table class="pm-table">
        <tr><th>Method</th><td>${escapeHtml(detect.method || '?')}</td></tr>
        <tr><th>Reference</th><td>${escapeHtml(detect.reference || '?')}</td></tr>
        <tr><th>Detected at</th><td>${escapeHtml(detect.detected_at || '?')}</td></tr>
        <tr><th>First evidence at</th><td>${escapeHtml(detect.first_evidence_at || '?')}</td></tr>
        <tr><th>Detection lag</th><td>${escapeHtml(detect.detection_lag_human || '?')}</td></tr>
        <tr><th>Discovery channel</th><td>${escapeHtml(detect.discovery_channel || '?')}</td></tr>
      </table>
      <h4>Timeline</h4>
      <table class="pm-table pm-timeline-table">
        <thead><tr><th>Time</th><th>Phase</th><th>Event</th><th>Refs</th><th>Technique</th></tr></thead>
        <tbody>
          ${tl.map(e => `<tr>
            <td>${escapeHtml(e.ts || '')}</td>
            <td>${escapeHtml(e.phase || '')}</td>
            <td>${escapeHtml(e.event || '')}</td>
            <td>${(e.evidence_refs || []).map(escapeHtml).join(', ')}</td>
            <td>${escapeHtml(e.mitre_technique || '')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
      <p><em>Contain / eradicate / recover / post-incident review fields start empty. Add via "Add override".</em></p>
    `;
    return div;
  }

  function renderS3(d) {
    const div = document.createElement('div');
    const summary = d.summary || {};
    const flat = d.flat_list || [];
    const asks = d.auditor_asks || [];
    div.innerHTML = `
      <h4>Summary</h4>
      <table class="pm-table">
        <tr><th>Failed control count</th><td>${summary.failed_control_count || 0}</td></tr>
        <tr><th>Critical control count</th><td>${summary.critical_control_count || 0}</td></tr>
        <tr><th>Frameworks with failures</th><td>${(summary.frameworks_with_failures || []).map(escapeHtml).join(', ') || 'none'}</td></tr>
        <tr><th>Evidence link count</th><td>${summary.evidence_link_count || 0}</td></tr>
      </table>
      <h4>Failed Controls</h4>
      <table class="pm-table">
        <thead><tr><th>Severity</th><th>Framework</th><th>Control</th><th>Type</th><th>Triggers</th><th>Refs</th></tr></thead>
        <tbody>
          ${flat.map(f => `<tr>
            <td><span class="pm-sev pm-sev-${escapeHtml(f.severity || 'low')}">${escapeHtml(f.severity || '?')}</span></td>
            <td>${escapeHtml(f.framework || '')}</td>
            <td><strong>${escapeHtml(f.control_id || '')}</strong> ${escapeHtml(f.control_name || '')}</td>
            <td>${escapeHtml(f.failure_type || '')}</td>
            <td>${(f.triggered_by || []).map(escapeHtml).join(', ')}</td>
            <td>${(f.evidence_refs || []).slice(0, 5).map(escapeHtml).join(', ')}${f.evidence_refs && f.evidence_refs.length > 5 ? '…' : ''}</td>
          </tr>`).join('')}
        </tbody>
      </table>
      <h4>Auditor Asks</h4>
      <ul>${asks.map(a => `<li>${escapeHtml(a)}</li>`).join('')}</ul>
    `;
    return div;
  }

  function renderS6(d) {
    const div = document.createElement('div');
    const summary = d.summary || {};
    const triggers = d.triggers || [];
    div.innerHTML = `
      <div class="pm-callout">${escapeHtml(d.human_submit_only_notice || '')}</div>
      <h4>Summary</h4>
      <table class="pm-table">
        <tr><th>Trigger count</th><td>${summary.trigger_count || 0}</td></tr>
        <tr><th>Tightest deadline</th><td>${escapeHtml(summary.tightest_deadline || 'n/a')} (${escapeHtml(summary.tightest_trigger_id || '?')})</td></tr>
        <tr><th>Hours remaining</th><td>${escapeHtml(String(summary.tightest_hours_left || 'n/a'))}</td></tr>
        <tr><th>Any overdue</th><td>${summary.any_overdue ? 'YES — escalate' : 'no'}</td></tr>
      </table>
      <h4>Triggers</h4>
      <table class="pm-table">
        <thead><tr><th>Regulator</th><th>Clock</th><th>Starts from</th><th>Deadline</th><th>Hours left</th><th>Status</th><th>Form</th></tr></thead>
        <tbody>
          ${triggers.map(t => `<tr class="${t.overdue ? 'pm-row-overdue' : ''}">
            <td>${escapeHtml(t.regulator || '')} (${escapeHtml(t.jurisdiction || '')})</td>
            <td>${escapeHtml(t.clock_human || '')}</td>
            <td>${escapeHtml(t.starts_from || '')}</td>
            <td>${escapeHtml(t.deadline || '')}</td>
            <td>${escapeHtml(String(t.hours_remaining || ''))}</td>
            <td>${escapeHtml(t.submission_status || '')}</td>
            <td><code>${escapeHtml(t.form_module || '')}</code></td>
          </tr>`).join('')}
        </tbody>
      </table>
    `;
    return div;
  }

  function renderS7(d) {
    const div = document.createElement('div');
    const actions = d.actions || [];
    const ownership = d.ownership_summary || {};
    div.innerHTML = `
      <h4>Ownership Summary</h4>
      <table class="pm-table">
        <thead><tr><th>Owner role</th><th>Action count</th></tr></thead>
        <tbody>
          ${Object.keys(ownership).sort().map(k =>
            `<tr><td>${escapeHtml(k)}</td><td>${ownership[k]}</td></tr>`
          ).join('')}
        </tbody>
      </table>
      <h4>Corrective Actions</h4>
      <table class="pm-table">
        <thead><tr><th>Pri</th><th>Title</th><th>Owner role</th><th>Due (days)</th><th>Triggered by</th><th>Frameworks</th></tr></thead>
        <tbody>
          ${actions.map(a => `<tr>
            <td><span class="pm-pri pm-pri-${escapeHtml(a.priority || 'P3')}">${escapeHtml(a.priority || '?')}</span></td>
            <td><strong>${escapeHtml(a.title || '')}</strong><br/><small>${escapeHtml(a.description || '')}</small></td>
            <td>${escapeHtml(a.owner_role || '')}</td>
            <td>${escapeHtml(String(a.due_days || ''))}</td>
            <td><code>${escapeHtml(a.triggered_by_failure || '')}</code></td>
            <td>${(a.framework_refs || []).map(escapeHtml).join(', ')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    `;
    return div;
  }

  function buildProvenanceFooter(pm) {
    const ev = pm.evidence_provenance || {};
    const div = document.createElement('div');
    div.className = 'postmortem-provenance-footer';
    div.innerHTML = `
      <hr/>
      <small>
        Evidence rows: ${escapeHtml(String(ev.row_count || 0))}.
        Hash: <code>${escapeHtml(ev.evidence_content_hash || '?')}</code>.
        Framework version: <code>${escapeHtml(pm.framework_version || '?')}</code>.
      </small>
    `;
    return div;
  }

  // ── Override dialog ───────────────────────────────────────────────────────

  function openOverrideDialog(aid, cid, sid, sec, onApplied) {
    const fieldPath = prompt('Field path to override (e.g. "post_incident_review.root_cause" or "timeline[0].event"):');
    if (!fieldPath) return;
    const newValue = prompt('New value (will be parsed as JSON; wrap strings in quotes):');
    if (newValue === null) return;
    const reason = prompt('Reason for override (mandatory):');
    if (!reason) return;
    const actor = prompt('Your email or username:');
    if (!actor) return;

    let parsed;
    try { parsed = JSON.parse(newValue); }
    catch (e) { parsed = newValue; }  // tolerate raw strings

    patchSection(aid, cid, sid, {
      actor: actor,
      field_path: fieldPath,
      new_value: parsed,
      reason: reason,
      operation: 'replace',
    }).then(r => { if (r) onApplied(); });
  }

  // ── Modal + regulator prefill display ─────────────────────────────────────

  function showModal(title, htmlBody) {
    const overlay = document.createElement('div');
    overlay.className = 'pm-modal-overlay';
    overlay.innerHTML = `
      <div class="pm-modal">
        <div class="pm-modal-header">
          <h3>${escapeHtml(title)}</h3>
          <button class="pm-modal-close">&times;</button>
        </div>
        <div class="pm-modal-body">${htmlBody}</div>
      </div>
    `;
    overlay.addEventListener('click', e => {
      if (e.target === overlay || e.target.classList.contains('pm-modal-close')) {
        overlay.remove();
      }
    });
    document.body.appendChild(overlay);
  }

  function showRegulatorPrefill(prefill) {
    if (!prefill) {
      showModal('Regulator pre-fill', '<p>(no payload returned)</p>');
      return;
    }
    if (prefill.applicable === false) {
      showModal('Regulator pre-fill — not applicable', `
        <p><strong>${escapeHtml(prefill.regulator || '?')}</strong> is not applicable to this incident.</p>
        <p>${escapeHtml(prefill.applicability_rationale || '')}</p>
      `);
      return;
    }
    const fields = prefill.fields || {};
    const checklist = prefill.human_review_checklist || [];
    const missing = prefill.missing_required_fields || [];
    showModal(`Regulator pre-fill — ${prefill.regulator}`, `
      <div class="pm-callout"><strong>Human review required.</strong> JanuSec never auto-submits.</div>
      <p><strong>Submission method:</strong> ${escapeHtml(prefill.submission_method || '?')}</p>
      <p><strong>Clock:</strong> ${escapeHtml(prefill.clock_human || prefill.clock_human_significant || '?')}</p>
      ${missing.length ? `<div class="pm-callout pm-callout-warn"><strong>Missing required fields:</strong> ${missing.map(escapeHtml).join(', ')}</div>` : ''}
      <h4>Fields</h4>
      <pre class="pm-json-dump">${escapeHtml(JSON.stringify(fields, null, 2))}</pre>
      <h4>Human Review Checklist</h4>
      <ul>${checklist.map(c => `<li>${escapeHtml(c)}</li>`).join('')}</ul>
      <p><a href="${escapeHtml(prefill.submission_endpoint || '#')}" target="_blank" rel="noopener">Open regulator portal in new tab →</a></p>
      <p><button class="btn btn-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(JSON.stringify(fields, null, 2)).replace(/"/g, '&quot;')})">Copy fields JSON</button></p>
    `);
  }

  // ── Override application (mirrors src/postmortem/human_edits.py) ──────────

  function applyOverrides(autoOutput, overrides) {
    if (!autoOutput) return autoOutput;
    let out = JSON.parse(JSON.stringify(autoOutput));
    (overrides || []).forEach(ov => {
      try { applyOne(out, ov); } catch (e) { console.warn('override apply failed', e); }
    });
    return out;
  }

  function applyOne(target, ov) {
    const op = (ov.operation || 'replace').toLowerCase();
    const parts = splitPath(ov.field_path || '');
    if (!parts.length) return;
    let parent = target;
    for (let i = 0; i < parts.length - 1; i++) {
      parent = stepInto(parent, parts[i]);
      if (parent == null) return;
    }
    const final = parts[parts.length - 1];
    if (op === 'delete') deleteAt(parent, final);
    else if (op === 'add') addAt(parent, final, ov.new_value);
    else replaceAt(parent, final, ov.new_value);
  }

  function splitPath(path) {
    const out = [];
    path.split('.').forEach(raw => {
      const m = raw.match(/^([^\[]+)\[(\d+)\]$/);
      if (m) out.push([m[1], parseInt(m[2], 10)]);
      else out.push([raw, null]);
    });
    return out;
  }
  function stepInto(c, seg) {
    const [k, idx] = seg;
    if (!c || typeof c !== 'object') return null;
    let nxt = c[k];
    if (idx != null) {
      if (!Array.isArray(nxt) || idx >= nxt.length) return null;
      return nxt[idx];
    }
    return nxt;
  }
  function replaceAt(p, seg, v) {
    const [k, idx] = seg;
    if (!p || typeof p !== 'object') return;
    if (idx == null) p[k] = v;
    else if (Array.isArray(p[k]) && idx < p[k].length) p[k][idx] = v;
  }
  function addAt(p, seg, v) {
    const [k] = seg;
    if (!p || typeof p !== 'object') return;
    if (Array.isArray(p[k])) p[k].push(v);
    else p[k] = [v];
  }
  function deleteAt(p, seg) {
    const [k, idx] = seg;
    if (!p || typeof p !== 'object') return;
    if (idx == null) delete p[k];
    else if (Array.isArray(p[k]) && idx < p[k].length) p[k].splice(idx, 1);
  }

  // ── Misc ──────────────────────────────────────────────────────────────────

  function verdictClass(v) {
    v = (v || '').toUpperCase();
    if (v.includes('VALIDATED') || v.includes('CONFIRMED')) return 'breach';
    if (v.includes('SUSPECTED')) return 'suspected';
    if (v.includes('FALSE')) return 'fp';
    return 'unknown';
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  // ── Public export ─────────────────────────────────────────────────────────

  window.JanusecPostmortem = window.JanusecPostmortem || {};
  window.JanusecPostmortem.render = render;
})();
