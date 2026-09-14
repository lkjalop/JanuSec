(() => {
  "use strict";
  const state = {
    model: null,
    assessmentId: new URLSearchParams(location.search).get("assessment"),
    selectedCaseId: null,
    tab: "claims",
    selected: null,
    providers: [],
    partitions: [],
    uploadFiles: [],
    activeUploadId: null,
    activeModelJobId: null,
    actionFilter: "all",
  };
  const $ = (id) => document.getElementById(id);
  const apiKey = () => localStorage.getItem("apiKey") || "devkey123";
  const accessToken = () => localStorage.getItem("accessToken") || "";
  const tenant = () => localStorage.getItem("tenantId") || "default";
  const headers = (extra = {}) => ({
    ...(accessToken()
      ? { Authorization: `Bearer ${accessToken()}` }
      : { "x-api-key": apiKey() }),
    "x-tenant-id": tenant(),
    ...extra,
  });
  const esc = (value) =>
    String(value ?? "").replace(
      /[&<>'"]/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          "'": "&#39;",
          '"': "&quot;",
        })[c],
    );
  const toast = (message) => {
    $("toast").textContent = message;
    $("toast").classList.add("show");
    setTimeout(() => $("toast").classList.remove("show"), 2800);
  };
  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: headers(options.headers || {}),
    });
    if (!response.ok)
      throw new Error(`${response.status} ${await response.text()}`);
    return response.json();
  }
  function show(name) {
    document.body.dataset.view = name;
    ["inboxView", "newView", "caseView"].forEach((id) =>
      $(id).classList.toggle("hidden", id !== name),
    );
    document
      .querySelectorAll("[data-view]")
      .forEach((el) =>
        el.classList.toggle(
          "active",
          el.dataset.view === (name === "newView" ? "new" : "cases"),
        ),
      );
  }
  function openNewAssessment() {
    clearUploadFiles();
    state.assessmentId = null;
    state.selectedCaseId = null;
    history.replaceState({}, "", location.pathname);
    show("newView");
    $("tenantLabel").textContent = `${tenant()} / NEW RUN`;
    $("caseTitle").textContent = "New breach assessment";
    $("caseMeta").textContent =
      "Capture related evidence, validate the inputs, then follow one assessment through the shared DAG.";
    $("uploadTenant").textContent = tenant();
  }
  async function loadProviders() {
    try {
      const data = await api("/api/v1/model-providers");
      state.providers = data.providers || [];
      const options = [
        '<option value="deterministic|janusec-rules|false">Deterministic only</option>',
      ];
      state.providers
        .filter((p) => p.available && p.provider !== "deterministic")
        .forEach((p) =>
          (p.models || []).forEach((model) =>
            options.push(
              `<option value="${esc(p.provider)}|${esc(model)}|${p.external_data_transfer ? "true" : "false"}">${esc(p.provider)} / ${esc(model)} · ${esc(p.location)}</option>`,
            ),
          ),
        );
      $("modelSelector").innerHTML = options.join("");
    } catch (error) {
      $("modelSelector").title = `Discovery failed: ${error.message}`;
    }
  }
  async function loadInbox() {
    show("inboxView");
    $("caseTitle").textContent = "Case workspace";
    $("caseMeta").textContent = "Select an assessment to inspect its evidence.";
    try {
      const data = await api("/api/v1/assessments/?limit=50");
      $("apiState").textContent = "API connected";
      document.querySelector(".status-dot").style.background = "var(--cyan)";
      $("caseList").innerHTML =
        (data.jobs || [])
          .map(
            (job) =>
              `<article class="case-row" tabindex="0" data-id="${esc(job.assessment_id)}"><strong>${esc(job.assessment_id)}</strong><span class="pill">${esc(job.status)}</span><span>${esc(job.stage || "—")}</span><span>${Number(job.row_count || 0).toLocaleString()} rows</span><span>${new Date((job.created_at || 0) * 1000).toLocaleString()}</span></article>`,
          )
          .join("") || '<p class="empty">No assessments for this tenant.</p>';
      document.querySelectorAll(".case-row").forEach((row) => {
        const open = () => openCase(row.dataset.id);
        row.onclick = open;
        row.onkeydown = (e) => {
          if (e.key === "Enter") open();
        };
      });
    } catch (error) {
      $("caseList").innerHTML =
        `<p class="empty">Unable to load cases: ${esc(error.message)}</p>`;
      $("apiState").textContent = "API unavailable";
    }
  }
  function scopeQuery() {
    const params = new URLSearchParams();
    if (state.selectedCaseId) params.set('case_id', state.selectedCaseId);
    if ($('knownAt').value) params.set('as_known_at', new Date($('knownAt').value).toISOString());
    return params.size ? `?${params}` : '';
  }
  async function loadPartition(caseId) {
    state.selectedCaseId = caseId || null;
    const suffix = scopeQuery();
    history.replaceState({}, "", `?assessment=${encodeURIComponent(state.assessmentId)}${suffix ? "&" + suffix.slice(1) : ""}`);
    state.model = await api(
      `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/case-view${suffix}`,
    );
    renderCase();
  }
  async function openCase(id) {
    const incoming = new URLSearchParams(location.search);
    const restoring = incoming.get('assessment') === id;
    const requestedCase = restoring ? incoming.get('case_id') : null;
    const requestedTime = restoring ? incoming.get('as_known_at') : null;
    if (requestedTime && !Number.isNaN(Date.parse(requestedTime))) {
      const date = new Date(requestedTime);
      $('knownAt').value = new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0,23);
    } else if (!restoring) $('knownAt').value = '';
    state.assessmentId = id;
    show("caseView");
    $("caseTitle").textContent = id;
    $("caseMeta").textContent = "Loading authoritative case projection…";
    try {
      const cases = await api(
        `/api/v1/assessments/${encodeURIComponent(id)}/cases${$('knownAt').value ? '?as_known_at=' + encodeURIComponent(new Date($('knownAt').value).toISOString()) : ''}`,
      ).catch(() => ({ cases: [] }));
      state.partitions = (cases.cases || []).filter(
        (item) => item.status !== "background",
      );
      if ($('knownAt').value && requestedCase && !state.partitions.some(item => item.case_id === requestedCase)) {
        state.partitions.push({case_id: requestedCase, title: 'Historical evidence scope', verdict: 'Unrecorded'});
      }
      const preferredCase = requestedCase || cases.selected_case_id;
      state.selectedCaseId =
        preferredCase &&
        state.partitions.some((item) => item.case_id === preferredCase)
          ? preferredCase
          : (state.partitions[0] || {}).case_id || null;
      $("casePartitionLabel").classList.toggle(
        "hidden",
        !state.partitions.length,
      );
      $("casePartitionSelector").innerHTML = state.partitions
        .map(
          (item) =>
            `<option value="${esc(item.case_id)}">${esc(item.title || item.case_id)} · ${esc(item.verdict)}</option>`,
        )
        .join("");
      $("casePartitionSelector").value = state.selectedCaseId || "";
      await loadPartition(state.selectedCaseId);
    } catch (error) {
      toast(`Could not load case: ${error.message}`);
      loadInbox();
    }
  }
  const compact = (title, subtitle, status = "") =>
    `<div class="compact-row"><strong>${esc(title)}${status ? ` <span class="status-tag">${esc(status)}</span>` : ""}</strong><small>${esc(subtitle)}</small></div>`;
  function renderCase() {
    const m = state.model,
      c = m.case,
      p = m.posture,
      summary = m.breach_summary || {};
    $("tenantLabel").textContent = `${c.tenant_id} / CASE`;
    $("caseTitle").textContent = c.id;
    const incomplete = (m.claims || []).some(claim => claim.status === 'ANALYSIS_INCOMPLETE') || c.verdict === 'ANALYSIS_INCOMPLETE';
    $("caseMeta").textContent =
      `${c.percent}% processed | ${incomplete ? 'Analysis incomplete: review required' : c.stage} | ${m.schema_version}`;
    if ((m.report_context || {}).as_known_at) {
      const receipt = (m.report_context || {}).historical_receipt;
      $('caseMeta').textContent += receipt ? ` | Recorded view: ${receipt.recorded_at}` : ' | Historical evidence only';
      // Current partition titles/verdicts must not appear beside a historical view.
      $('casePartitionSelector').innerHTML = `<option value="${esc(state.selectedCaseId || '')}">${esc(state.selectedCaseId || 'Assessment')} · Historical scope</option>`;
    } else {
      $('casePartitionSelector').innerHTML = state.partitions.map(item => `<option value="${esc(item.case_id)}">${esc(item.title || item.case_id)} · ${esc(item.verdict)}</option>`).join('');
      $('casePartitionSelector').value = state.selectedCaseId || '';
    }
    $("breachSummary").innerHTML =
      `<p class="eyebrow">WHAT HAPPENED · ${esc(summary.status || "provisional")}</p><h2>${esc(summary.headline || "Breach summary unavailable")}</h2><p>${esc(summary.what_happened || "The current evidence does not support a defensible narrative yet.")}</p><footer>${(summary.supporting_evidence_ids || []).length} cited records · ${(summary.coverage_gaps || []).length} known gaps</footer>`;
    $("posture").innerHTML = Object.entries(p)
      .map(([key, value]) => {
        const shown =
          (key === "evidence_completeness" || key === "evidence_confidence") &&
          typeof value === "number"
            ? `${Math.round(value * 100)}%`
            : (value ?? "not measured");
        return `<div class="posture-card"><span>${esc(key === "evidence_completeness" ? "evidence reference availability" : key.replaceAll("_", " "))}</span><strong>${esc(shown)}</strong></div>`;
      })
      .join("");
    const gaps = m.coverage_gaps || [];
    $("gapBanner").classList.toggle("hidden", !gaps.length);
    $("gapBanner").textContent = gaps.length
      ? `Coverage gaps (${gaps.length}): ${gaps.map((g) => (typeof g === "object" ? g.gap || JSON.stringify(g) : g)).join(" · ")}`
      : "";
    const plannedActions = (m.action_plan || {}).actions || [];
    const decisions = m.immediate_decisions || [];
    $("immediateDecisions").innerHTML =
      plannedActions
        .filter((item) => item.horizon === "now")
        .slice(0, 3)
        .map((d) =>
          compact(
            `${d.priority} · ${d.title}`,
            `${d.owner_role} · due ${d.due_within} · ${d.recommendation_status}`,
          ),
        )
        .join("") || decisions.slice(0, 3).map((d) =>
          compact(`${d.priority} · ${d.decision}`, `${d.rationale || "Awaiting analyst review"} · ${d.approval_status}`),
        ).join("") || '<p class="empty">No evidence-backed immediate actions.</p>';
    const milestones = (m.attack_story || {}).milestones || [],
      summaryMilestones = milestones.slice(0, 8);
    $("attackStory").innerHTML =
      summaryMilestones
        .map(
          (item, i) =>
            `<div class="milestone" tabindex="0" data-milestone="${i}"><span class="eyebrow">${esc(item.phase)}</span><strong>${esc(item.title)}</strong><small>${esc(item.occurred_at || "time not established")}</small><small>${esc(item.status)} · ${(item.evidence_ids || []).length} evidence</small></div>`,
        )
        .join("") +
        (milestones.length > summaryMilestones.length
          ? `<p class="empty">Showing ${summaryMilestones.length} of ${milestones.length} observed milestones. Open Detailed timeline for event-level drill-down.</p>`
          : "") ||
      '<p class="empty">No backend-authored milestones. JanusSec will not invent a causal story.</p>';
    document.querySelectorAll("[data-milestone]").forEach((el) => {
      const open = () =>
        selectItem(
          "attack milestone",
          milestones[Number(el.dataset.milestone)],
          el,
        );
      el.onclick = open;
      el.onkeydown = (e) => {
        if (e.key === "Enter") open();
      };
    });
    $("businessImpact").innerHTML =
      (m.business_impact || [])
        .slice(0, 5)
        .map((s) =>
          compact(s.name, s.impact || "Impact not established", s.status),
        )
        .join("") ||
      '<p class="empty">No asset-to-business-service mapping supplied.</p>';
    $("containment").innerHTML =
      (m.containment || [])
        .slice(0, 5)
        .map((item) =>
          compact(
            item.object || item.name || item.action || "Containment item",
            item.verification || "Verification evidence required",
            item.status || "unknown",
          ),
        )
        .join("") ||
      '<p class="empty">Containment state has not been verified.</p>';
    $("controlImpact").innerHTML =
      (m.control_impacts || [])
        .slice(0, 5)
        .map((item) =>
          compact(
            `${item.control_id} · ${item.title}`,
            item.assertion_status,
            item.reviewer_status,
          ),
        )
        .join("") || '<p class="empty">No candidate control impacts.</p>';
    $("claimCount").textContent = String(m.claims.length);
    $("claimList").innerHTML =
      m.claims
        .map(
          (claim, i) =>
            `<div class="item" data-claim="${i}"><strong>${esc(claim.title)}</strong><small>${esc(claim.type)} · ${claim.confidence == null ? "unscored" : Math.round(claim.confidence * 100) + "%"} · ${esc(claim.status)}</small></div>`,
        )
        .join("") ||
      '<div class="item empty">No claims have been produced.</div>';
    document
      .querySelectorAll("[data-claim]")
      .forEach(
        (el) =>
          (el.onclick = () =>
            selectItem("claim", m.claims[Number(el.dataset.claim)], el)),
      );
    renderAssurance(m);
    $("apiState").textContent = "API connected";
    renderStage();
  }
  function renderAssurance(m) {
    const context = m.report_context || {},
      truth = context.infrastructure_truth || {},
      receipts = context.evidence_pack_receipts || [];
    const acceptance = context.acceptance_truth || {};
    const metrics = acceptance.evaluation || {};
    const quality = context.quality_metrics || {};
    const short = (value) =>
      value ? String(value).slice(0, 14) + "…" : "not available";
    const proof = (label, value, status, detail) =>
      `<div class="proof-item ${esc(status)}"><span>${esc(label)}</span><strong title="${esc(value || "")}">${esc(short(value))}</strong><small>${esc(detail)}</small></div>`;
    $("assuranceProof").innerHTML =
      proof(
        "GRAPH PROJECTION",
        context.graph_receipt_hash,
        context.graph_projection_status === "current" ? "current" : "warning",
        context.graph_projection_status || "unrecorded",
      ) +
      proof(
        "EVIDENCE PACK",
        receipts.length ? receipts[receipts.length - 1].content_hash : null,
        receipts.length ? "current" : "warning",
        receipts.length
          ? `${receipts.length} immutable receipt(s)`
          : "not compiled for this case",
      ) +
      proof(
        "IAM / TOPOLOGY",
        truth.iam?.receipt_hash || truth.topology?.receipt_hash,
        truth.iam?.status === "verified" &&
          truth.topology?.status === "verified"
          ? "current"
          : "warning",
        `${truth.iam?.status || "missing"} / ${truth.topology?.status || "missing"}`,
      ) +
      proof(
        "BUSINESS MAPPING",
        truth.cmdb?.receipt_hash,
        truth.cmdb?.status === "verified" ? "current" : "blocked",
        truth.cmdb?.status === "verified"
          ? "asset → service verified"
          : "impact unavailable",
      ) +
      proof(
        "DATA CLASSIFICATION",
        truth.data_classification?.receipt_hash,
        truth.data_classification?.status === "verified" ? "current" : "blocked",
        truth.data_classification?.status === "verified"
          ? "signed affected-data scope"
          : "regulatory conclusions unavailable",
      ) +
      proof(
        "REGULATORY SCOPE",
        truth.regulatory_applicability?.receipt_hash,
        truth.regulatory_applicability?.status === "verified" ? "current" : "blocked",
        truth.regulatory_applicability?.status === "verified"
          ? "signed applicability profile"
          : "legal/privacy review required",
      ) +
      (acceptance.scenario
        ? proof("MUST DETECT", metrics.must_detect, metrics.must_detect === 1 ? "current" : "blocked", `${acceptance.scenario} acceptance truth`) +
          proof("MUST SEPARATE", metrics.must_separate, metrics.must_separate == null || metrics.must_separate === 1 ? "current" : "blocked", metrics.must_separate == null ? "not applicable" : "role-aware partitions") +
          proof("MUST SUPPRESS", metrics.must_suppress, metrics.must_suppress === 1 ? "current" : "blocked", "false-confirmed and false-suspected") +
          proof("ROLE ATTRIBUTION", metrics.role_attribution, metrics.role_attribution === 1 ? "current" : "blocked", "actor / victim / target")
        : "") +
      (Object.keys(quality).length
        ? proof("ATTRIBUTION", quality.attribution_quality, quality.attribution_quality >= 0.75 ? "current" : "blocked", "model-run quality") +
          proof("EVIDENCE RECALL", quality.evidence_recall, quality.evidence_recall >= 0.6 ? "current" : "blocked", "cited eligible evidence") +
          proof("CONTRADICTIONS", quality.contradictions_discovered ?? quality.contradiction_count, "current", "found and surfaced") +
          proof("CALIBRATION", quality.calibration_brier ?? quality.brier_score ?? quality.calibration, (quality.calibration_brier ?? quality.brier_score) == null || (quality.calibration_brier ?? quality.brier_score) <= 0.2 ? "current" : "warning", quality.acceptance_truth_status === "labelled" ? "labelled Brier score" : "proxy until independent truth is attached") +
          proof("NODES TO INSPECT", quality.analyst_nodes_to_inspect ?? quality.nodes_to_inspect, "current", quality.actual_analyst_trace ? "measured analyst workload" : "citation-set proxy")
        : "");
  }
  function inspectorValue(kind, item) {
    if (kind !== "immutable Evidence Pack" || !item) return item;
    const correction = item.corrective_acceptance || {};
    return {
      schema_version: item.schema_version,
      pack_id: item.pack_id,
      content_hash: item.content_hash,
      case_id: item.case_id,
      question_id: item.question_id,
      query: item.query,
      evidence_counts: {
        case_evidence: (item.case_evidence || []).length,
        retrieved_context: (item.retrieved_context || []).length,
        contradictions: (item.contradictions || []).length,
        coverage_gaps: (item.coverage_gaps || []).length,
        excluded_candidates: (item.excluded_candidates || []).length,
      },
      graph_projection_id: item.graph_projection_id,
      graph_receipt_hash: item.graph_receipt_hash,
      ledger_head_hash: item.ledger_head_hash,
      corrective_acceptance: {
        outcome: correction.outcome,
        changed_evidence_set: Boolean(correction.changed_evidence_set),
        initial_evidence_count: (correction.initial_evidence_ids || []).length,
        corrected_evidence_count: (correction.corrected_evidence_ids || [])
          .length,
        added_evidence_count: (correction.added_evidence_ids || []).length,
        removed_evidence_count: (correction.removed_evidence_ids || []).length,
        truth_set_attached: Boolean(correction.truth_set_attached),
        initial_metrics: correction.initial_metrics,
        corrected_metrics: correction.corrected_metrics,
        abstention_reason: correction.abstention_reason,
      },
      verification: item.verification,
      retrieval_trace: item.retrieval_trace,
      coverage_gaps: item.coverage_gaps,
    };
  }
  function selectItem(kind, item, element) {
    state.selected = { kind, item };
    document
      .querySelectorAll(".item.selected,.milestone.selected")
      .forEach((el) => el.classList.remove("selected"));
    if (element) element.classList.add("selected");
    $("inspectorContent").innerHTML =
      `<p class="eyebrow">${esc(kind)}</p><pre>${esc(JSON.stringify(inspectorValue(kind, item), null, 2))}</pre>`;
  }
  function renderStage() {
    const m = state.model;
    if (!m) return;
    const tab = state.tab;
    $("stageTitle").textContent = {
      claims: "Evidence",
      graph: "Typed graph",
      timeline: "Bitemporal timeline",
      retrieval: "Retrieval trace",
      actions: "Action plan and verification",
    }[tab];
    if (tab === "claims") {
      const rows = m.evidence.rows || [];
      $("resultCount").textContent = `${rows.length} / ${m.evidence.total}`;
      $("stageContent").innerHTML =
        `<table class="evidence-table"><thead><tr><th>Time</th><th>Source</th><th>Summary</th><th>Severity</th></tr></thead><tbody>${rows.map((row, i) => `<tr class="item" data-evidence="${i}"><td>${esc(row.occurred_at || "unknown")}</td><td>${esc(row.source)}</td><td>${esc(row.summary)}</td><td>${esc(row.severity)}</td></tr>`).join("")}</tbody></table>`;
      document
        .querySelectorAll("[data-evidence]")
        .forEach(
          (el) =>
            (el.onclick = () =>
              selectItem("evidence", rows[Number(el.dataset.evidence)], el)),
        );
    } else if (tab === "graph") {
      const g = m.graph;
      $("resultCount").textContent =
        `${g.nodes.length} nodes · ${g.edges.length} edges`;
      $("stageContent").innerHTML =
        `<div class="item"><strong>Edge policy</strong><small>${esc(g.edge_policy)}. No co-occurrence edges are invented in the browser.</small></div>${g.nodes.map((n, i) => `<div class="item" data-node="${i}"><strong>${esc(n.label)}</strong><small>${esc(n.kind)} · ${esc(n.id)}</small></div>`).join("")}`;
      document
        .querySelectorAll("[data-node]")
        .forEach(
          (el) =>
            (el.onclick = () =>
              selectItem("graph node", g.nodes[Number(el.dataset.node)], el)),
        );
    } else if (tab === "timeline") {
      $("resultCount").textContent = String(m.timeline.length);
      $("stageContent").innerHTML =
        m.timeline
          .map(
            (event, i) =>
              `<div class="item" data-event="${i}"><strong>${esc(event.occurred_at)}</strong><small>${esc(event.source)} · ${esc(event.label)}</small></div>`,
          )
          .join("") ||
        '<div class="item empty">No valid-time events available.</div>';
      document
        .querySelectorAll("[data-event]")
        .forEach(
          (el) =>
            (el.onclick = () =>
              selectItem(
                "timeline event",
                m.timeline[Number(el.dataset.event)],
                el,
              )),
        );
    } else if (tab === "retrieval") {
      const receipts = (m.report_context || {}).evidence_pack_receipts || [];
      $("resultCount").textContent = `${receipts.length} pack(s)`;
      $("stageContent").innerHTML =
        `<div class="item"><strong>Retrieval order</strong><small>Exact identifiers → bitemporal SQL → bounded causal traversal → lexical → dense documents → corrective verification</small></div><button id="compilePackButton">${receipts.length ? "Compile another question pack" : "Compile Evidence Pack"}</button><div class="receipt-list">${receipts.map((r) => `<div class="receipt-row"><strong>${esc(r.pack_id)}</strong><small>${esc(r.question_id || "case question")} · ${esc(r.corrective_outcome || "not evaluated")}</small><small>+${Number(r.added_evidence_count || 0)} corrective evidence · ${r.truth_set_attached ? "labelled recall measured" : "no evidence-ID truth set"} · graph ${esc((r.graph_projection_id || "unbound").slice(0, 18))}</small></div>`).join("") || '<p class="empty">No case-scoped Evidence Pack exists yet. Compile one before relying on retrieval or model narration.</p>'}</div><pre>${esc(JSON.stringify(m.retrieval_trace || [], null, 2))}</pre>`;
      $("compilePackButton").onclick = compileEvidencePack;
    } else {
      renderActionPlan();
    }
  }
  function renderActionPlan() {
    const plan = state.model.action_plan || { actions: [], decisions_required: [] };
    const actions = plan.actions || [];
    const filters = [
      ["all", "All"], ["now", "Now"], ["24_hours", "24 hours"],
      ["7_days", "7 days"], ["30_90_days", "30–90 days"],
    ];
    const shown = state.actionFilter === "all"
      ? actions
      : actions.filter((item) => item.horizon === state.actionFilter);
    $("resultCount").textContent = `${shown.length} of ${actions.length} actions`;
    const actionCards = shown.map((item, index) => {
      const proof = item.required_closure_evidence || [];
      const frameworks = (item.framework_trace || [])
        .map((entry) => `${entry.framework} ${entry.control_id}`)
        .join(" · ");
      return `<article class="action-card item" data-action-index="${index}">
        <header><span class="action-priority ${esc(item.priority)}">${esc(item.priority)} · ${esc(item.due_within)}</span><span>${esc(item.status)}</span></header>
        <h3>${esc(item.title)}</h3><p>${esc(item.exact_action)}</p>
        <dl><div><dt>Why</dt><dd>${esc(item.why)}</dd></div><div><dt>Owner / approval</dt><dd>${esc(item.owner_role)} / ${esc(item.accountable_approver_role)}</dd></div><div><dt>Evidence</dt><dd>${esc((item.supporting_evidence_ids || []).join(", ") || "None — suggested investigation only")}</dd></div><div><dt>Verify</dt><dd>${esc(item.verification_procedure)}</dd></div></dl>
        <div class="closure-proof"><strong>Required closure proof</strong>${proof.map((value) => `<span>□ ${esc(value)}</span>`).join("")}</div>
        ${item.control_consequence ? `<p class="control-consequence"><strong>Control consequence:</strong> ${esc(item.control_consequence)}</p>` : ""}
        ${frameworks ? `<small>Traceability only until GRC review: ${esc(frameworks)}</small>` : ""}
        <div class="workflow-actions">${workflowButtons(item)}</div>
      </article>`;
    }).join("");
    const decisions = (plan.decisions_required || []).map((item) =>
      `<article class="decision-card"><span class="action-priority ${esc(item.priority)}">DECISION · ${esc(item.due_within)}</span><h3>${esc(item.question)}</h3><p>${esc(item.status)}</p><small>Owner: ${esc(item.owner_role)}</small><div class="closure-proof">${(item.required_information || []).map((value) => `<span>□ ${esc(value)}</span>`).join("")}</div></article>`,
    ).join("");
    $("stageContent").innerHTML =
      `<div class="action-boundary"><strong>Human authorization boundary</strong><span>${esc(plan.governance_boundary || "Models may propose; authenticated humans approve execution and closure.")}</span><small>Plan receipt ${esc(plan.content_hash || "not recorded")}</small></div>
       <div class="action-filters">${filters.map(([value, label]) => `<button class="secondary ${state.actionFilter === value ? "active" : ""}" data-action-filter="${value}">${label}</button>`).join("")}</div>
       ${decisions ? `<section class="decision-grid"><h3>Decisions required</h3>${decisions}</section>` : ""}
       <section class="action-list">${actionCards || '<p class="empty">No actions in this time horizon.</p>'}</section>`;
    document.querySelectorAll("[data-action-filter]").forEach((button) => {
      button.onclick = () => { state.actionFilter = button.dataset.actionFilter; renderActionPlan(); };
    });
    document.querySelectorAll("[data-action-index]").forEach((element) => {
      element.onclick = () => selectItem("action plan item", shown[Number(element.dataset.actionIndex)], element);
    });
    document.querySelectorAll("[data-action-transition]").forEach((button) => {
      button.onclick = (event) => {
        event.stopPropagation();
        transitionAction(button.dataset.actionId, button.dataset.actionTransition);
      };
    });
  }
  function workflowButtons(item) {
    const status = item.status === "pending" || item.status === "unassigned" ? "proposed" : item.status;
    const transitions = {
      proposed: [["assign", "Assign"]], open: [["assign", "Assign"]], reopened: [["assign", "Reassign"]],
      assigned: [["approve", "Approve"], ["reject", "Reject"]],
      approved: [["implementing", "Start implementation"], ["reject", "Reject"]],
      implementing: [["implemented", "Record implementation"], ["reject", "Reject"]],
      implemented: [["verification_pending", "Request verification"], ["reopen", "Reopen"]],
      verification_pending: [["verified", "Verify independently"], ["reject", "Reject"]],
      verified: [["closed", "Close"], ["reopen", "Reopen"]],
      closed: [["reopen", "Reopen"]], rejected: [["reopen", "Reopen"]],
    };
    return (transitions[status] || []).map(([next, label]) =>
      `<button class="secondary" data-action-transition="${next}" data-action-id="${esc(item.id)}">${label}</button>`,
    ).join("");
  }
  const receiptIds = (value) => String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
  async function transitionAction(actionId, nextStatus) {
    const item = ((state.model.action_plan || {}).actions || []).find((candidate) => candidate.id === actionId);
    if (!item || !state.assessmentId || !state.selectedCaseId) return;
    const payload = {
      finding_id: item.finding_id || item.id,
      event_type: nextStatus,
      status: nextStatus === "assign" ? "assigned" : nextStatus === "reject" ? "rejected" : nextStatus === "reopen" ? "reopened" : nextStatus,
      supporting_evidence_ids: item.supporting_evidence_ids || [],
      before_evidence_ids: item.before_evidence_ids || [],
      after_evidence_ids: item.after_evidence_ids || [],
      verification_evidence_ids: item.verification_evidence_ids || [],
    };
    if (nextStatus === "assign") {
      payload.control_owner = prompt("Assign to authenticated control owner or team", item.owner_role || "") || item.owner_role;
      payload.due_at = prompt("Due date/time (ISO 8601)", item.due_at || "") || null;
    }
    if (nextStatus === "implemented") {
      payload.before_evidence_ids = receiptIds(prompt("Before-state receipt IDs (comma separated)", (item.before_evidence_ids || []).join(",")));
      payload.after_evidence_ids = receiptIds(prompt("After-state provider receipt IDs (comma separated)", (item.after_evidence_ids || []).join(",")));
    }
    if (["verification_pending", "verified", "closed"].includes(payload.status) && !payload.after_evidence_ids.length) {
      payload.after_evidence_ids = receiptIds(prompt("After-state provider receipt IDs (comma separated)", ""));
    }
    if (["verified", "closed"].includes(payload.status) && !payload.verification_evidence_ids.length) {
      payload.verification_evidence_ids = receiptIds(prompt("Independent verification receipt IDs (comma separated)", payload.after_evidence_ids.join(",")));
    }
    if (["rejected", "reopened"].includes(payload.status)) payload.notes = prompt("Reason", "") || "";
    try {
      await api(`/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/cases/${encodeURIComponent(state.selectedCaseId)}/grc/events`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
      });
      await loadPartition(state.selectedCaseId);
      state.tab = "actions";
      renderStage();
      toast(`Action ${payload.status} receipt persisted.`);
    } catch (error) {
      toast(`Action transition failed: ${error.message}`);
    }
  }
  async function compileEvidencePack() {
    if (!state.assessmentId || !state.selectedCaseId)
      return toast("Select an investigation first.");
    const button = $("compilePackButton");
    if (button) {
      button.disabled = true;
      button.textContent = "Compiling…";
    }
    try {
      const roles = state.model.entity_roles || state.model.roles || [];
      const identifiers = roles
        .map((item) => item.entity || item.entity_id)
        .filter(Boolean);
      const pack = await api(
        `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/cases/${encodeURIComponent(state.selectedCaseId)}/evidence-pack`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            query:
              (state.model.breach_summary || {}).headline ||
              "breach reconstruction contradictions denied actions and alternative attribution",
            identifiers,
            as_known_at: new URLSearchParams(scopeQuery()).get('as_known_at'),
            limit: 200,
            max_hops: 3,
          }),
        },
      );
      await loadPartition(state.selectedCaseId);
      state.model.retrieval_trace = pack.retrieval_trace || [];
      state.tab = "retrieval";
      renderStage();
      selectItem("immutable Evidence Pack", pack);
      toast(
        pack.corrective_acceptance?.outcome === "improved"
          ? "Corrective retrieval improved evidence recall."
          : `Evidence Pack saved: ${pack.corrective_acceptance?.outcome || "verification recorded"}`,
      );
    } catch (error) {
      toast(`Evidence Pack failed: ${error.message}`);
      if (button) {
        button.disabled = false;
        button.textContent = "Compile Evidence Pack";
      }
    }
  }
  const allowedUploadExtensions = new Set([
    "csv",
    "json",
    "jsonl",
    "ndjson",
    "xlsx",
    "xlsm",
  ]);
  const formatBytes = (value) => {
    const bytes = Number(value || 0);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };
  function fileFamily(name) {
    const value = name.toLowerCase();
    const rules = [
      ["Cloud / identity", /cloud|aws|azure|gcp|alibaba|aliyun|iam|okta|entra/],
      ["Email", /mail|email|exchange|gmail|m365/],
      ["Endpoint", /endpoint|sysmon|edr|crowdstrike|process|ebpf|tetragon/],
      ["Network", /network|zeek|suricata|firewall|flow|dns|pcap/],
      ["Management plane", /nutanix|vmware|vcenter|hpe|oneview|ilo/],
    ];
    return (rules.find(([, pattern]) => pattern.test(value)) || [
      "Telemetry",
    ])[0];
  }
  function validateFile(file) {
    const ext = (file.name.split(".").pop() || "").toLowerCase();
    if (!allowedUploadExtensions.has(ext)) return "Unsupported format";
    if (!file.size) return "Empty file";
    return "";
  }
  function renderUploadFiles() {
    const rows = state.uploadFiles.map((file) => {
      const error = validateFile(file);
      return `<div class="file-row${error ? " invalid" : ""}"><div><strong>${esc(file.name)}</strong><small>${esc(fileFamily(file.name))}</small></div><span class="file-size">${formatBytes(file.size)}</span><span class="file-state">${error ? esc(error) : "Ready to capture"}</span></div>`;
    });
    $("uploadPreflight").innerHTML =
      rows.join("") ||
      '<div class="empty-upload"><strong>No files selected</strong><span>Add two or more telemetry domains when possible; filenames and content are inspected after capture.</span></div>';
    const valid = state.uploadFiles.filter((file) => !validateFile(file));
    const invalid = state.uploadFiles.length - valid.length;
    const total = valid.reduce((sum, file) => sum + file.size, 0);
    $("fileSummary").textContent = valid.length
      ? `${valid.length} accepted · ${formatBytes(total)}${invalid ? ` · ${invalid} requires attention` : ""}`
      : "Nothing will be uploaded until you start the assessment.";
    $("startAssessmentButton").disabled =
      !valid.length ||
      invalid > 0 ||
      valid.length > 20 ||
      total > 500 * 1024 * 1024;
    $("clearFilesButton").classList.toggle("hidden", !state.uploadFiles.length);
  }
  function selectUploadFiles(files, { append = true } = {}) {
    const next = append ? [...state.uploadFiles] : [];
    for (const file of [...files]) {
      const duplicate = next.some(
        (item) =>
          item.name === file.name &&
          item.size === file.size &&
          item.lastModified === file.lastModified,
      );
      if (!duplicate) next.push(file);
    }
    state.uploadFiles = next.slice(0, 21);
    renderUploadFiles();
  }
  function clearUploadFiles() {
    $("fileInput").value = "";
    state.uploadFiles = [];
    renderUploadFiles();
    $("uploadProgress").classList.add("hidden");
    state.activeUploadId = null;
  }
  async function upload(event) {
    event.preventDefault();
    const files = state.uploadFiles.filter((file) => !validateFile(file));
    if (!files.length)
      return toast("Choose at least one supported telemetry file.");
    const form = new FormData();
    files.forEach((file) => form.append("files", file));
    $("startAssessmentButton").disabled = true;
    $("uploadProgress").classList.remove("hidden");
    $("progressText").textContent = "Capturing immutable inputs · 0%";
    try {
      const result = await api("/api/v1/assessments/upload", {
        method: "POST",
        body: form,
      });
      state.assessmentId = result.assessment_id;
      state.activeUploadId = result.assessment_id;
      $("assessmentRunId").textContent =
        `Run ${result.assessment_id} · ${result.file_count || files.length} files queued`;
      poll(result.assessment_id);
    } catch (error) {
      $("startAssessmentButton").disabled = false;
      toast(`Upload failed: ${error.message}`);
    }
  }
  function renderPipelineStage(stage, status) {
    const order = ["upload", "parsing", "normalizing", "reasoning", "ready"];
    const aliases = {
      capture: "upload",
      capturing: "upload",
      parse: "parsing",
      normalization: "normalizing",
      clustering: "reasoning",
      episodes: "reasoning",
      projection: "reasoning",
    };
    const current = aliases[stage] || stage;
    const index = Math.max(0, order.indexOf(current));
    document.querySelectorAll("#pipelineSteps li").forEach((item, i) => {
      item.classList.toggle("complete", i < index || status === "ready");
      item.classList.toggle("active", i === index && status !== "ready");
    });
  }
  async function poll(id) {
    try {
      const p = await api(
        `/api/v1/assessments/${encodeURIComponent(id)}/progress/poll`,
      );
      $("progressBar").style.width = `${p.percent || 0}%`;
      $("progressText").textContent =
        `${p.label || p.stage} · ${p.percent || 0}%`;
      renderPipelineStage(p.stage, p.status);
      if (p.status === "ready") {
        state.activeUploadId = null;
        $("cancelAssessmentButton").classList.add("hidden");
        toast("Assessment ready. Opening the case workspace.");
        openCase(id);
        return;
      }
      if (["failed", "cancelled"].includes(p.status)) {
        state.activeUploadId = null;
        $("cancelAssessmentButton").classList.add("hidden");
        $("startAssessmentButton").disabled = false;
        toast(p.error || p.status);
        return;
      }
      setTimeout(() => poll(id), 1200);
    } catch (error) {
      toast(error.message);
    }
  }
  async function cancelUpload() {
    if (!state.activeUploadId) return;
    try {
      await api(
        `/api/v1/assessments/${encodeURIComponent(state.activeUploadId)}/cancel`,
        { method: "POST" },
      );
      toast("Cancellation requested. Captured evidence remains auditable.");
    } catch (error) {
      toast(`Could not cancel: ${error.message}`);
    }
  }
  async function runSelectedModel() {
    if ($('knownAt').value && !state.activeModelJobId) return toast('Historical model execution requires a versioned derivation. Clear the time filter to run against current evidence.');
    if (!state.assessmentId) return toast("Open a case first.");
    if (state.activeModelJobId) {
      try {
        await api(
          `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/model-jobs/${encodeURIComponent(state.activeModelJobId)}`,
          { method: "DELETE" },
        );
        toast("Model cancellation recorded. Partial receipts remain auditable.");
      } catch (error) {
        toast(`Could not cancel model: ${error.message}`);
      }
      return;
    }
    const [provider, model, external] = $("modelSelector").value.split("|");
    const caseId = $("casePartitionSelector").value || null;
    if (state.partitions.length > 1 && !caseId)
      return toast("Select an investigation before running a model.");
    const externalAllowed =
      external === "true"
        ? confirm(
            "This sends the compact selected case projection to an external model. Continue?",
          )
        : false;
    if (external === "true" && !externalAllowed) return;
    $("runModelButton").disabled = true;
    $("runModelButton").textContent = "Queueing…";
    try {
      const job = await api(
        `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/model-jobs`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            provider,
            model,
            case_id: caseId,
            mode: externalAllowed
              ? "paid_allowed"
              : provider === "deterministic"
                ? "deterministic_only"
                : "manual",
            external_allowed: externalAllowed,
            hard_budget_seconds: 300,
          }),
        },
      );
      state.activeModelJobId = job.job_id;
      $("runModelButton").disabled = false;
      $("runModelButton").textContent = "Cancel model";
      toast(`Queued ${provider}/${model}. Ingestion remains available.`);
      pollModelJob(job.job_id);
    } catch (error) {
      toast(error.message);
      $("runModelButton").disabled = false;
      $("runModelButton").textContent = "Run model";
    }
  }

  async function pollModelJob(jobId) {
    if (state.activeModelJobId !== jobId) return;
    try {
      const job = await api(
        `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/model-jobs/${encodeURIComponent(jobId)}`,
      );
      const labels = {
        queued: "Queued",
        running: "Reasoning",
        correcting: "Correcting",
        escalating: "Escalating",
        cancelled: "Cancelled",
        budget_exhausted: "Budget exhausted",
        failed: "Failed",
        completed: "Completed",
      };
      $("runModelButton").title = `${labels[job.status] || job.status} · ${(job.partial_run_receipts || []).length} immutable state receipt(s)`;
      if (!job.terminal) {
        $("runModelButton").textContent = `Cancel · ${labels[job.status] || job.status}`;
        setTimeout(() => pollModelJob(jobId), 1200);
        return;
      }
      state.activeModelJobId = null;
      $("runModelButton").textContent = "Run model";
      $("runModelButton").title = "";
      if (job.status === "completed") {
        const runId = job.details?.run_id;
        const listed = await api(
          `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/model-runs`,
        );
        const run = (listed.runs || []).find((item) => item.run_id === runId);
        if (run) selectItem("immutable model run", run);
        await loadPartition(state.selectedCaseId);
        toast(`Model completed as ${runId || "an immutable run"}.`);
      } else {
        selectItem("model job receipts", job);
        toast(`Model ${labels[job.status] || job.status}. Partial receipts preserved.`);
      }
    } catch (error) {
      state.activeModelJobId = null;
      $("runModelButton").textContent = "Run model";
      toast(`Model status failed: ${error.message}`);
    }
  }
  async function compareModels() {
    if (!state.assessmentId) return toast("Open a case first.");
    try {
      const listed = await api(
        `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/model-runs`,
      );
      const ids = (listed.runs || []).slice(-2).map((run) => run.run_id);
      if (ids.length < 2) return toast("Run at least two models first.");
      const result = await api(
        `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/model-runs/compare`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ run_ids: ids }),
        },
      );
      selectItem("model comparison", result);
      toast("Comparison opened in the inspector.");
    } catch (error) {
      toast(error.message);
    }
  }
  async function exportGrc() {
    if (!state.assessmentId) return toast("Open a case first.");
    try {
      const response = await fetch(
        `/api/v1/assessments/${encodeURIComponent(state.assessmentId)}/grc-action-pack${scopeQuery()}`,
        { headers: headers() },
      );
      if (!response.ok) throw new Error(await response.text());
      const blob = new Blob([await response.text()], { type: "text/html" });
      window.open(URL.createObjectURL(blob), "_blank", "noopener");
    } catch (error) {
      toast(error.message);
    }
  }
  document.querySelectorAll("[data-view]").forEach((el) => {
    if (el.tagName === "BUTTON")
      el.onclick = () =>
        el.dataset.view === "new" ? openNewAssessment() : loadInbox();
  });
  document.querySelectorAll("[data-tab]").forEach(
    (el) =>
      (el.onclick = () => {
        state.tab = el.dataset.tab;
        document
          .querySelectorAll("[data-tab]")
          .forEach((tab) =>
            tab.setAttribute("aria-selected", String(tab === el)),
          );
        renderStage();
      }),
  );
  $("casePartitionSelector").onchange = () =>
    loadPartition($("casePartitionSelector").value).catch((error) =>
      toast(`Could not switch investigation: ${error.message}`),
    );
  $("knownAt").onchange = () => state.assessmentId && loadPartition(state.selectedCaseId).catch(error => toast(error.message));
  $("newButton").onclick = openNewAssessment;
  $("refreshButton").onclick = () =>
    state.assessmentId ? loadPartition(state.selectedCaseId).catch(error => toast(error.message)) : loadInbox();
  $("runModelButton").onclick = runSelectedModel;
  $("compareModelsButton").onclick = compareModels;
  $("exportGrcButton").onclick = exportGrc;
  $("uploadForm").onsubmit = upload;
  $("fileInput").onchange = () => selectUploadFiles($("fileInput").files);
  $("clearFilesButton").onclick = clearUploadFiles;
  $("cancelAssessmentButton").onclick = cancelUpload;
  const dropZone = $("dropZone");
  let dragDepth = 0;
  ["dragenter", "dragover"].forEach((type) =>
    dropZone.addEventListener(type, (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (type === "dragenter") dragDepth += 1;
      dropZone.classList.add("drag-active");
      if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
    }),
  );
  dropZone.addEventListener("dragleave", (event) => {
    event.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) dropZone.classList.remove("drag-active");
  });
  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    event.stopPropagation();
    dragDepth = 0;
    dropZone.classList.remove("drag-active");
    selectUploadFiles(event.dataTransfer.files);
  });
  dropZone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      $("fileInput").click();
    }
  });
  loadProviders();
  state.assessmentId ? openCase(state.assessmentId) : loadInbox();
})();
