// Extracted metrics logic (Phase 1)
(function(){
    let _lastMultiDomainConfigFetch = 0;
    const RANSOMWARE_BLUEPRINT = {
        pipeline: {
            title: 'Pipeline & Telemetry Enrichment',
            desc: 'Wire detections into ingestion, scoring, and incident generation fabrics so Tier 1 can see high-confidence factors immediately.',
            items: [
                'Instrument entropy scoring on file writes per host/time bucket; persist baseline/variance to HopGraph session payloads.',
                'Detect VSS tamper (shadow copy deletes, vssadmin invocations, WMI volume shadow ops) and emit dedicated factor nodes.',
                'Track rapid file modification rates with sliding windows; feed anomalies into /api/v1/decisions/recent via _merge_decision_meta.',
                'Combine entropy + VSS + high-rate writes into a composite ransomware_confidence metric surfaced in dependency_status and scoring config.',
                'Push missing detections into /api/v1/graph/session/build mapping stats so analysts can see canonical field coverage gaps.'
            ]
        },
        tier1: {
            title: 'Tier 1 LLM Summary Hooks',
            desc: 'Provide concise cues so Tier 1 assistants highlight blast radius and next actions within 90 seconds.',
            items: [
                'Surface "entropy surge + VSS tamper" as a pre-built chip with host/user/process context.',
                'Auto-suggest Tier 1 narrative: Potential ransomware sequence detected; confirm if SMB shares show similar entropy uplift.',
                'Flag whether isolation already triggered; if not, prompt containment or escalation to Tier 2 for quarantine.',
                'Call out dependency health state so Tier 1 trusts HopGraph correlation context.'
            ]
        },
        tier2: {
            title: 'Tier 2 LLM Deep Dive',
            desc: 'Give investigation copilots enough structure to link nodes, propose hypotheses, and request additional telemetry.',
            items: [
                'Expose entropy buckets, VSS command lineage, and file-hash clusters via mapping_semantics contributions.',
                'Recommend reconstruction plan: pivot to SMB logs for share-level modification rate, request EDR timeline for PID reuse.',
                'Highlight replayed HopGraph factors or queued batches so Tier 2 knows if results lag behind real time.',
                'Attach POST /api/v1/incidents/{id}/recommendations/act payload template for quarantine guidance.'
            ]
        },
        report: {
            title: 'Report Generator Anchors',
            desc: 'Pre-seed /api/v1/report/ingestion narrative sections so exports reflect ransomware-specific evidence.',
            items: [
                'Add Advanced Ransomware Factors section summarizing entropy deltas, VSS tamper attempts, and impacted hosts.',
                'Include remediation readiness checklist (network isolation, VSS restore validation, endpoint patch posture).',
                'Document optional agent hooks (hash dedupe, EDR integration) as backlog vs. done to show maturity.',
                'Feed domain diversity + mapping semantics scores into Scoring Config so leadership sees weighting decisions.'
            ]
        },
        hopgraph: {
            title: 'HopGraph Attack Reconstruction',
            desc: 'Ensure graph sessions clearly depict ransomware stages and weave in EWMA smoothing for volatility handling.',
            items: [
                'Auto-tag sequences with ransom_stage (initial access, encryption prep, detonation) inside session builds.',
                'Store entropy/VSS metrics as node attributes so adaptive EWMA can lower alpha during volatile bursts.',
                'Link file-hash dedupe results to infected hosts and propagate to recommendation_catalog for hardening.',
                'Record replay history + queued_factor_batches so analysts know if nodes were replayed during degraded mode.'
            ]
        },
        missing: {
            title: 'Related Missing Logs / Evidence Requests',
            desc: 'Prompt analysts to request additional telemetry when coverage gaps appear.',
            items: [
                'Windows Security logs (4663, 4732) for file permission changes tied to suspected hosts.',
                'EDR or Sysmon operational logs for process ancestry and command-line capture of vssadmin/wmic usage.',
                'NAS / SMB audit trails for rapid file rename/delete operations on shared drives.',
                'Backup controller telemetry (Veeam, Rubrik, Cohesity) for failed or cancelled jobs matching incident timeline.',
                'Identity provider risk signals (Azure AD risky sign-ins, Okta anomaly events) for lateral movement context.'
            ]
        },
        enhancements: {
            title: 'Optional Enhancements & Automations',
            desc: 'Future hooks that raise fidelity and shorten response cycles.',
            items: [
                'Endpoint agent hooks for hash-level deduplication and sandbox triage results piped into mapping stats.',
                'EDR integration for auto-quarantine when composite ransomware factor exceeds threshold with confidence > 0.82.',
                'Shadow copy recreation validation using TEST_HELPERS to simulate VSS tamper for regression coverage.',
                'Expose SCORING_WEIGHTS_JSON overrides through admin scoring UI for quick tuning of ransomware weights.'
            ]
        }
    };
    const RANSOMWARE_NARRATIVE = [
        'Advanced ransomware detection initiative couples entropy scoring, VSS tamper monitoring, and rapid file-modification analytics to raise HopGraph confidence across Tier 1/2 flows.',
        '',
        'Pipeline impact: entropy/VSS telemetry is persisted in graph sessions, merged into /decisions metadata, and surfaced inside Multi-Domain Health + Scoring Config panels.',
        'Tier cues: Tier 1 summaries highlight entropy surge + shadow-copy tamper with containment prompts, while Tier 2 assistants receive reconstruction prompts, replay history, and recommendation_act payloads.',
        'Reporting: /api/v1/report/ingestion gains an Advanced Ransomware Factors section with remediation readiness checklists and backlog callouts.',
        'HopGraph/Attack reconstruction: EWMA smoothing adapts via volatility-aware alpha to keep ransomware stages legible.',
        'Evidence gaps: automatically list missing logs (Windows Security, Sysmon, NAS audit, backup controllers, IdP risk) so analysts can request additional data before finalizing incidents.',
        'Optional: integrate endpoint agent hooks for hash dedupe and direct EDR quarantine triggers when composite ransomware confidence exceeds defined thresholds.'
    ].join('\n');
    let _ransomwareStageKey = 'pipeline';
    let _ransomwarePanelReady = false;
    let _ransomwareLivePrompts = '';

    function ensureRansomwarePanel(){
        const panel = document.getElementById('ransomwareInsightsPanel');
        if(!panel){
            return false;
        }
        if(!_ransomwarePanelReady){
            const buttons = panel.querySelectorAll('.ransomware-stage-btn');
            buttons.forEach(btn => {
                btn.addEventListener('click', ()=>{
                    buttons.forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    const stage = btn.getAttribute('data-stage') || 'pipeline';
                    renderRansomwareStage(stage);
                });
            });
            renderRansomwareStage(_ransomwareStageKey);
            const copyBtn = document.getElementById('ransomwareCopyStage');
            if(copyBtn && !copyBtn._wired){
                copyBtn._wired = true;
                copyBtn.addEventListener('click', ()=>{
                    const stage = copyBtn.getAttribute('data-stage') || _ransomwareStageKey;
                    const text = getRansomwareStageText(stage);
                    try{ navigator.clipboard.writeText(text); }catch(_){ }
                });
            }
            const copyNarrativeBtn = document.getElementById('ransomwareCopyNarrative');
            if(copyNarrativeBtn && !copyNarrativeBtn._wired){
                copyNarrativeBtn._wired = true;
                copyNarrativeBtn.addEventListener('click', ()=>{
                    const text = buildRansomwareReportNarrative(_ransomwareLivePrompts);
                    try{ navigator.clipboard.writeText(text); }catch(_){ }
                });
            }
            const promptsEl = document.getElementById('ransomwareTierPrompts');
            if(promptsEl){
                promptsEl.textContent = RANSOMWARE_NARRATIVE;
                _ransomwareLivePrompts = RANSOMWARE_NARRATIVE;
            }
            _ransomwarePanelReady = true;
        }
        return true;
    }

    function renderRansomwareStage(stageKey){
        _ransomwareStageKey = stageKey in RANSOMWARE_BLUEPRINT ? stageKey : 'pipeline';
        const data = RANSOMWARE_BLUEPRINT[_ransomwareStageKey];
        const body = document.getElementById('ransomwareStageBody');
        if(body){
            const listHtml = data.items.map(item => `<li>${item}</li>`).join('');
            body.innerHTML = `<div class="ransom-stage-title">${data.title}</div>
                <div class="ransom-stage-desc">${data.desc}</div>
                <ul>${listHtml}</ul>`;
        }
        const copyBtn = document.getElementById('ransomwareCopyStage');
        if(copyBtn){
            copyBtn.setAttribute('data-stage', _ransomwareStageKey);
        }
    }

    function getRansomwareStageText(stageKey){
        const key = stageKey in RANSOMWARE_BLUEPRINT ? stageKey : 'pipeline';
        const data = RANSOMWARE_BLUEPRINT[key];
        return `${data.title}\n${data.desc}\n${data.items.map(item => `- ${item}`).join('\n')}`;
    }

    function buildRansomwareReportNarrative(livePrompts){
        const live = (livePrompts && livePrompts.trim()) ? livePrompts.trim() : 'No live telemetry yet.';
        return `${RANSOMWARE_NARRATIVE}\n\nLive context (${new Date().toISOString()}):\n${live}`;
    }

    function gatherRansomwareFactors(decision){
        const values = [];
        const pushVal = (item) => {
            if(!item) return;
            if(Array.isArray(item)){
                item.forEach(pushVal);
                return;
            }
            if(typeof item === 'string'){
                values.push(item);
                return;
            }
            if(typeof item === 'object'){
                ['id','name','label','title','factor','description'].forEach(key=>{
                    if(item[key]) pushVal(item[key]);
                });
            }
        };
        pushVal(decision && decision.factors);
        pushVal(decision && decision.top_factors);
        pushVal(decision && decision.summary && decision.summary.factors);
        pushVal(decision && decision.graph_summary && decision.graph_summary.factors);
        return values;
    }

    function extractRansomwareEntities(decision, fields){
        const set = new Set();
        const addVal = (val) => {
            if(!val) return;
            if(Array.isArray(val)){
                val.forEach(addVal);
                return;
            }
            if(typeof val === 'string'){
                const trimmed = val.trim();
                if(trimmed) set.add(trimmed);
                return;
            }
            if(typeof val === 'object'){
                ['host','hostname','user','name','principal','account'].forEach(key=>{
                    if(val[key]) addVal(val[key]);
                });
            }
        };
        const containers = [decision, decision && decision.entities, decision && decision.hopgraph_context, decision && decision.mapping];
        containers.forEach(container => {
            if(!container) return;
            fields.forEach(field => addVal(container[field]));
        });
        return Array.from(set);
    }

    function describeEntityList(list, fallback){
        if(!Array.isArray(list) || !list.length) return fallback || 'n/a';
        if(list.length === 1) return list[0];
        if(list.length === 2) return `${list[0]} & ${list[1]}`;
        return `${list[0]}, ${list[1]} +${list.length - 2} more`;
    }

    function pickMetricValue(decision, keys){
        const sources = [
            decision,
            decision && decision.metrics,
            decision && decision.summary,
            decision && decision.graph_summary,
            decision && decision.stats,
            decision && decision.hopgraph_context && (decision.hopgraph_context.summary || decision.hopgraph_context),
            decision && decision.pipeline_meta,
            decision && decision.analysis
        ];
        for(const source of sources){
            if(!source) continue;
            for(const key of keys){
                if(source[key] !== undefined && source[key] !== null){
                    const num = Number(source[key]);
                    if(!Number.isNaN(num)) return num;
                }
            }
        }
        return null;
    }

    function applyRansomwareSignals(decision){
        if(!ensureRansomwarePanel()) return;
        const signalsEl = document.getElementById('ransomwareSignals');
        const telemetryEl = document.getElementById('ransomwareTelemetryStatus');
        const missingEl = document.getElementById('ransomwareMissingLogs');
        const promptsEl = document.getElementById('ransomwareTierPrompts');
        const esc = window._htmlEsc || (s => String(s ?? ''));
        if(!decision){
            if(signalsEl) signalsEl.innerHTML = '<li>No decisions available.</li>';
            if(telemetryEl) telemetryEl.textContent = 'Telemetry pending.';
            if(missingEl) missingEl.innerHTML = '<li>No gaps detected.</li>';
            if(promptsEl) promptsEl.textContent = RANSOMWARE_NARRATIVE;
            _ransomwareLivePrompts = RANSOMWARE_NARRATIVE;
            return;
        }
        const factorStrings = gatherRansomwareFactors(decision).map(str => String(str || '').toLowerCase());
        const blob = JSON.stringify(decision || {}).toLowerCase();
        const hosts = extractRansomwareEntities(decision, ['hosts','hostnames','host','hostname']);
        const users = extractRansomwareEntities(decision, ['users','user','username','principal','account']);
        const processes = extractRansomwareEntities(decision, ['process','processes','image','exe']);
        const hostLabel = describeEntityList(hosts, 'impacted hosts');
        const signals = [];
        const entropyScore = pickMetricValue(decision, ['entropy_score','file_entropy_score','entropy','entropy_delta']);
        const entropyDelta = pickMetricValue(decision, ['entropy_delta','entropy_change']);
        if(entropyScore !== null){
            const deltaTxt = entropyDelta !== null ? ` (Δ ${entropyDelta.toFixed(2)})` : '';
            signals.push(`Entropy score ${entropyScore.toFixed(2)}${deltaTxt} observed on ${hostLabel}.`);
        } else if(factorStrings.some(f => f.includes('entropy')) || blob.includes('entropy')){
            signals.push('Entropy anomaly factor surfaced in decision metadata.');
        }
        const vssEvents = pickMetricValue(decision, ['vss_tamper_count','shadow_copy_deletes','shadow_copy_events','vss_events']);
        if(vssEvents !== null){
            signals.push(`Shadow copy tamper count ${vssEvents} tied to ${hostLabel}.`);
        } else if(factorStrings.some(f => f.includes('vss')) || blob.includes('shadow copy')){
            signals.push('Possible VSS tamper detected via command-line telemetry.');
        }
        const modRate = pickMetricValue(decision, ['file_mod_rate','rapid_file_mod_rate','modification_rate','write_rate']);
        if(modRate !== null){
            signals.push(`Rapid file modification rate ${modRate.toFixed(2)} files/sec.`);
        } else if(factorStrings.some(f => f.includes('rapid file'))){
            signals.push('Rapid file modification factor emitted by pipeline.');
        }
        if(factorStrings.some(f => f.includes('dedupe')) || blob.includes('hash dedupe')){
            signals.push('Endpoint hash dedupe surfaced repeated ransomware payload artifacts.');
        }
        const hopCtx = decision.hopgraph_context || {};
        const chainId = hopCtx.chain_id || hopCtx.session_id || hopCtx.id || 'HopGraph chain';
        if(hopCtx && hopCtx.edges){
            const edgeCount = Array.isArray(hopCtx.edges) ? hopCtx.edges.length : (hopCtx.edge_count || null);
            if(edgeCount){
                signals.push(`HopGraph ${chainId} tracks ${edgeCount} edges through ransomware stages.`);
            }
        }
        if(!signals.length){
            signals.push('No ransomware-specific signals reported in the latest decision.');
        }
        if(signalsEl){
            signalsEl.innerHTML = signals.map(item => `<li>${esc(item)}</li>`).join('');
        }
        const ransomwareConfidence = pickMetricValue(decision, ['ransomware_confidence','ransomware_score','composite_ransomware']);
        const telemetryParts = [];
        if(ransomwareConfidence !== null){
            telemetryParts.push(`Composite confidence ${ransomwareConfidence.toFixed(2)}`);
        }
        const dep = decision.dependency_status || {};
        const hopStatus = dep.hopgraph || {};
        if(typeof hopStatus.seconds_since_ok === 'number'){
            telemetryParts.push(`HopGraph healthy ${formatDuration(hopStatus.seconds_since_ok)} ago`);
        }
        if(typeof hopStatus.health_last_ok_ts === 'number' && typeof hopStatus.seconds_since_ok !== 'number'){
            telemetryParts.push(`HopGraph last OK @ ${new Date(hopStatus.health_last_ok_ts * 1000).toLocaleTimeString()}`);
        }
        if(dep.queued_factor_batches){
            telemetryParts.push(`${dep.queued_factor_batches} factor batches queued`);
        }
        if(telemetryEl){
            telemetryEl.textContent = telemetryParts.length ? telemetryParts.join(' · ') : 'Awaiting entropy/VSS instrumentation – follow blueprint to wire pipeline signals.';
        }
        let missingItems = [];
        if(Array.isArray(dep.missing_logs) && dep.missing_logs.length){
            missingItems = dep.missing_logs.map(entry => {
                if(typeof entry === 'string') return entry;
                if(entry && typeof entry === 'object'){
                    const src = entry.source || entry.label || 'log source';
                    const reason = entry.reason || entry.details || 'missing';
                    return `${src}: ${reason}`;
                }
                return String(entry);
            });
        } else {
            const hostSuffix = hosts.length ? ` for ${hostLabel}` : '';
            missingItems = [
                `Windows Security events 4663/4732${hostSuffix} to validate file permission tamper.`,
                `Sysmon / EDR logs capturing vssadmin or wmic usage${hostSuffix}.`,
                `NAS / SMB audit logs highlighting rename/delete bursts on shared drives.`,
                `Backup controller telemetry (Veeam/Rubrik/Cohesity) around the incident window.`,
                `IdP risky sign-in feeds to track lateral ransomware operators impacting ${describeEntityList(users, 'key identities')}.`
            ];
        }
        if(missingEl){
            missingEl.innerHTML = missingItems.map(item => `<li>${esc(item)}</li>`).join('');
        }
        const promptChunks = [];
        promptChunks.push(`Tier 1: Call out entropy surge + VSS tamper on ${hostLabel}; confirm containment and request SMB confirmation.`);
        promptChunks.push(`Tier 2: Re-run HopGraph ${chainId} with EWMA context and request SMB/backup logs before reconstruction.`);
        promptChunks.push(`Report: Document Advanced Ransomware Factors with confidence ${(ransomwareConfidence !== null ? ransomwareConfidence.toFixed(2) : (decision.confidence ?? 'n/a'))} and remediation readiness.`);
        if(dep.queued_factor_batches){
            promptChunks.push(`HopGraph Health: ${dep.queued_factor_batches} queued batches pending replay – mention in Multi-Domain Health banner.`);
        } else {
            promptChunks.push('HopGraph Health: No queued batches; include adaptive EWMA notes in report.');
        }
        const promptText = promptChunks.join('\n');
        if(promptsEl){
            promptsEl.textContent = promptText;
        }
        _ransomwareLivePrompts = promptText;
    }

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', ensureRansomwarePanel);
    } else {
        ensureRansomwarePanel();
    }
    async function updateMetrics(){
        try{
            // Minimal safe implementation: call dashboard/metrics and update header counts
            const fetcher = window.safeFetch || fetch;
            const r = await fetcher('/api/v1/dashboard/metrics', { headers: authHeaders() });
            if (!r.ok) throw new Error('metrics_fetch_failed');
            const j = await r.json();
            const critical = j.critical_count ?? j.critical ?? 0;
            const high = j.high_count ?? j.high ?? 0;
            const medium = j.medium_count ?? j.medium ?? 0;
            const last = j.last_update || new Date().toISOString();
            const elC = document.getElementById('criticalCount'); if (elC) elC.textContent = critical;
            const elH = document.getElementById('highCount'); if (elH) elH.textContent = high;
            const elM = document.getElementById('mediumCount'); if (elM) elM.textContent = medium;
            const elL = document.getElementById('lastUpdate'); if (elL) elL.textContent = last;

            // Derive artifact & threat counts if available
            const artifacts = j.artifacts_total ?? j.artifacts ?? j.total_artifacts ?? null;
            if (artifacts !== null) {
                const aEl = document.getElementById('artifactsCount'); if (aEl) aEl.textContent = artifacts;
            }
            // Threat count could be sum of critical+high+medium if not explicit
            const threatsRaw = j.active_threats ?? j.threats ?? j.active ?? null;
            let threatsVal = threatsRaw;
            if (threatsVal === null || threatsVal === undefined) {
                const maybe = critical + high + medium;
                if (maybe > 0) threatsVal = maybe; else threatsVal = 0;
            }
            const tEl = document.getElementById('threatCount'); if (tEl) tEl.textContent = threatsVal;

            // Temporal EWMA sparkline: track a short history of temporal_avg_score for visualization
            try{
                const temporalAvg = (j.temporal_avg_score ?? j.temporal_avg ?? j.temporal) || 0;
                window._temporalSpark = window._temporalSpark || { data: [], maxLen: 40 };
                const s = window._temporalSpark;
                s.data.push(Number(temporalAvg) || 0);
                if(s.data.length > s.maxLen) s.data.splice(0, s.data.length - s.maxLen);
                drawTemporalSparkline(s.data);
            }catch(_err){ /* ignore spark errors */ }

            // Secondary status call for reconciliation (optional)
            try {
                const sr = await fetcher('/api/v1/dashboard/status', { headers: authHeaders() });
                if (sr.ok) {
                    const sj = await sr.json();
                    // Prefer explicit totals if present
                    if (sj.artifacts_total && document.getElementById('artifactsCount')) {
                        document.getElementById('artifactsCount').textContent = sj.artifacts_total;
                    }
                    if (sj.active_threats && document.getElementById('threatCount')) {
                        document.getElementById('threatCount').textContent = sj.active_threats;
                    }
                    // Update severity counts if different
                    if (typeof sj.critical === 'number' && sj.critical !== critical) { const el = document.getElementById('criticalCount'); if (el) el.textContent = sj.critical; }
                    if (typeof sj.high === 'number' && sj.high !== high) { const el = document.getElementById('highCount'); if (el) el.textContent = sj.high; }
                    if (typeof sj.medium === 'number' && sj.medium !== medium) { const el = document.getElementById('mediumCount'); if (el) el.textContent = sj.medium; }
                }
            } catch (_err) { /* ignore reconciliation errors */ }

            try{
                await updateMultiDomainHealth();
            }catch(_){}
            try{
                await updateMissingLogPanel();
            }catch(_){}
            try{
                await updateTier1SummaryCard();
            }catch(_){}
            try{
                await updateRiskRoiCard(j);
            }catch(_){}
        }catch(_err){
            // noop fallback
            console.warn('updateMetrics fallback', _err && _err.message);
        }
    }

    async function updateMultiDomainHealth(){
        const panel = document.getElementById('multiDomainHealthPanel');
        if(!panel) return;
        try{
            const fetcher = window.safeFetch || fetch;
            const resp = await fetcher('/api/v1/correlation/multi-domain/status', { headers: authHeaders() });
            if(!resp.ok){
                panel.style.display = 'none';
                return;
            }
            const stats = await resp.json();
            panel.style.display = 'block';
            const ttlEl = document.getElementById('multiDomainTtlValue');
            const entEl = document.getElementById('multiDomainEntityCount');
            const totalEl = document.getElementById('multiDomainChainTotal');
            const latestEl = document.getElementById('multiDomainLatestSummary');
            const listEl = document.getElementById('multiDomainRecentList');
            if(ttlEl){
                const ttlParts = [];
                ttlParts.push(`Configured ${formatDuration(stats.ttl_seconds)}`);
                if(typeof stats.latest_chain_ttl_remaining === 'number'){
                    ttlParts.push(`Latest ${formatDuration(stats.latest_chain_ttl_remaining)} remaining`);
                }
                if(typeof stats.next_cleanup_in === 'number'){
                    ttlParts.push(`Cleanup in ${formatDuration(stats.next_cleanup_in)}`);
                }
                ttlEl.textContent = ttlParts.join(' · ');
            }
            if(entEl) entEl.textContent = String(stats.tracked_entities ?? stats.remaining_entities ?? '--');
            if(totalEl) totalEl.textContent = String(stats.total_emitted ?? '--');
            const recent = Array.isArray(stats.recent_chains) ? stats.recent_chains : [];
            if(latestEl){
                if(recent.length){
                    const latest = recent[recent.length - 1];
                    const doms = (latest.domains || []).join(', ') || 'unknown domains';
                    const expires = typeof latest.expires_at === 'number' ? ` · expires in ${formatDuration(Math.max(0, latest.expires_at - Date.now()/1000))}` : '';
                    latestEl.textContent = `Last chain ${latest.chain_id || '-'} touched ${doms} @ ${new Date((latest.generated_at||Date.now())*1000).toLocaleTimeString()}${expires}`;
                } else {
                    latestEl.textContent = 'No recent chains.';
                }
            }
            if(listEl){
                if(recent.length){
                    const html = recent.map(item => {
                        const recs = (item.recommendations || []).slice(0,3).map(r => `<li>${r}</li>`).join('');
                        const domains = (item.domains || []).join(', ') || 'unknown';
                        return `<div style="margin-bottom:6px;"><div style="font-weight:600;">${item.chain_id || 'chain'}</div><div style="font-size:11px; color:var(--text-muted);">Domains: ${domains} | Confidence ${(item.confidence ?? 0).toFixed(2)}</div><ul style="margin:4px 0 0 18px;">${recs || '<li>No recommendations</li>'}</ul></div>`;
                    }).join('');
                    listEl.innerHTML = html;
                } else {
                    listEl.textContent = 'No multi-domain sessions captured yet.';
                }
            }
            renderMultiDomainDependencyBanner(stats);
            try { await updateMultiDomainAdminMeta(); } catch(_){}
            try { await updateScoringTransparency(); } catch(_){}
            if (applyMultiDomainConfig) {
                try { applyMultiDomainConfig(stats); } catch(_err){}
            }
            try { await updateFactorTelemetry(); } catch(_){}
            try { await updateFactorCalibration(); } catch(_){}
        }catch(_err){
            panel.style.display = 'none';
        }
    }

    function renderTicketSummary(ticket){
        if(!ticket) return '';
        const esc = window._htmlEsc || ((s)=>String(s ?? ''));
        const providers = ticket.providers || (ticket.result && ticket.result.providers);
        if(!Array.isArray(providers) || !providers.length){
            const status = ticket.status || (ticket.result && ticket.result.status);
            if(!status) return '';
            return `<div class="small">SOAR ticket ${esc(ticket.action || 'ticket.create')}: ${esc(status)}</div>`;
        }
        const pills = providers.map(entry => {
            const state = entry.error || (entry.result && (entry.result.status || entry.result.code)) || 'sent';
            const colors = entry.error ? 'background:#3b1c11;color:#ffb38c;border-color:#8f3d2a;' : 'background:#17391d;color:#9ee6a4;border-color:#2f6c3a;';
            return `<span class="pill" style="margin-right:4px;${colors}">${esc(entry.provider || 'provider')}: ${esc(state)}</span>`;
        }).join('');
        return `<div class="small">SOAR tickets ${esc(ticket.action || 'ticket.create')}: ${pills}</div>`;
    }

    async function updateTier1SummaryCard(){
        const card = document.getElementById('tier1SummaryCard');
        if(!card) return;
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/decisions/recent?limit=1', { headers: authHeaders() });
            if(!resp.ok){ return; }
            const payload = await resp.json().catch(()=>({}));
            const d = (payload.decisions || payload.rows || payload.events || [])[0] || {};
            const verdictEl = document.getElementById('tier1Verdict');
            const confEl = document.getElementById('tier1Confidence');
            const dreadEl = document.getElementById('tier1Dread');
            const kcEl = document.getElementById('tier1KillChain');
            const stepsEl = document.getElementById('tier1NextSteps');
            const openExplain = document.getElementById('tier1OpenExplain');
            const createIncidentBtn = document.getElementById('tier1CreateIncident');
            const verdict = d.verdict || d.status || '–';
            const conf = (d.confidence!=null)? Number(d.confidence).toFixed(2) : '–';
            if(verdictEl) verdictEl.textContent = `Verdict: ${verdict}`;
            if(confEl) confEl.textContent = `Confidence: ${conf}`;
            // DREAD if present; otherwise show n/a
            const dread = d.dread_score!=null ? Number(d.dread_score).toFixed(2) : (d.dread || 'n/a');
            if(dreadEl) dreadEl.textContent = `DREAD: ${dread}`;
            // Kill-chain context from hopgraph_context
            let kcTxt = 'n/a';
            try{
                const hc = d.hopgraph_context || {};
                const cid = hc.chain_id || hc.session_id || hc.id;
                const edges = Array.isArray(hc.edges) ? hc.edges.length : (hc.edge_count || null);
                kcTxt = cid ? `Chain ${cid}${edges!=null? ` • ${edges} edges`:''}` : 'n/a';
            }catch(_){ }
            if(kcEl) kcEl.textContent = `Kill-chain: ${kcTxt}`;
            // Recommendations
            try{
                const recs = Array.isArray(d.recommendation_catalog) ? d.recommendation_catalog
                             : (Array.isArray(d.recommendation_actions)? d.recommendation_actions.map(a=>a.action) : []);
                const top = (recs||[]).slice(0,3);
                if(stepsEl){
                    stepsEl.innerHTML = top.length ? top.map(x=>`<li>${window._htmlEsc? _htmlEsc(String(x)) : String(x)}</li>`).join('') : '<li style="opacity:.6;">No recommendations available.</li>';
                }
            }catch(_){ if(stepsEl) stepsEl.innerHTML = '<li style="opacity:.6;">No recommendations available.</li>'; }
            // Explain link and incident button
            try{
                const hc = d.hopgraph_context || {};
                const sid = hc.session_id || hc.id || null;
                if(openExplain){
                    openExplain.href = sid ? ('/static/graph_explain.html?session_id='+encodeURIComponent(sid)) : '#';
                    openExplain.style.pointerEvents = sid? 'auto' : 'none';
                    openExplain.style.opacity = sid? '1' : '.6';
                }
            }catch(_){ }
            if(createIncidentBtn && typeof window.createIncidentFromRecent === 'function'){
                if(!createIncidentBtn._wired){
                    createIncidentBtn._wired = true;
                    createIncidentBtn.addEventListener('click', ()=>{
                        try{ window.createIncidentFromRecent(); }catch(_){ }
                    });
                }
            }
            // Recon coverage chip
            try{
                const chip = document.getElementById('chipRecon');
                if(chip){
                    const mitreList = Array.isArray(d.mitre) ? d.mitre
                        : (Array.isArray(d.mapping?.mitre) ? d.mapping.mitre
                        : (Array.isArray(d.techniques) ? d.techniques : []));
                    const reconTags = (mitreList || []).filter(t => /^T159[0-9]/.test(String(t)));
                    chip.textContent = reconTags.length ? `Recon: ${reconTags.slice(0,4).join(', ')}` : 'Recon: n/a';
                }
            }catch(_){ }
            try{
                applyRansomwareSignals(d);
            }catch(_){ }
        }catch(_err){ /* ignore */ }
    }

    async function updateRiskRoiCard(metricsPayload){
        const card = document.getElementById('riskRoiCard');
        if(!card) return;
        // Detection accuracy from dashboard metrics
        try{
            const accEl = document.getElementById('reportDetectionAccuracy');
            const rate = metricsPayload && (metricsPayload.portscan_accuracy ?? metricsPayload.detection_rate);
            if(accEl){ accEl.textContent = (rate!=null ? (Number(rate).toFixed(2)+'%') : '–'); }
        }catch(_){ }
        // FP rate, window TP/FP from factor telemetry
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/admin/factors/telemetry', { headers: authHeaders() });
            if(resp.ok){
                const tel = await resp.json().catch(()=>({}));
                const counts = tel.window_counts || {};
                const tp = Number(counts.tp || 0);
                const fp = Number(counts.fp || 0);
                const total = tp + fp;
                const fpRate = total>0 ? ((fp/total)*100).toFixed(2)+'%' : '–';
                const fpEl = document.getElementById('reportFpRate'); if(fpEl) fpEl.textContent = fpRate;
            }
        }catch(_){ }
        // MTTD / MTTR from dashboard status if available
        try{
            const sr = await (window.safeFetch || fetch)('/api/v1/dashboard/status', { headers: authHeaders() });
            if(sr.ok){
                const sj = await sr.json().catch(()=>({}));
                const mttd = sj.mttd_seconds ?? sj.mttd;
                const mttr = sj.mttr_seconds ?? sj.mttr;
                const mttdEl = document.getElementById('reportMttd'); if(mttdEl) mttdEl.textContent = (typeof mttd==='number' ? formatDuration(mttd) : '–');
                const mttrEl = document.getElementById('reportMttr'); if(mttrEl) mttrEl.textContent = (typeof mttr==='number' ? formatDuration(mttr) : '–');
            }
        }catch(_){ }
        // Tier 1 coverage from IAM connector status
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/iam/connectors/status?include_health=1', { headers: authHeaders() });
            if(resp.ok){
                const payload = await resp.json().catch(()=>({}));
                const list = Array.isArray(payload.connectors) ? payload.connectors : [];
                const total = list.length;
                const healthy = list.filter(c => c && c.health && !c.health.missing_log).length;
                const pct = total>0 ? Math.round((healthy/total)*100) : null;
                const covEl = document.getElementById('reportCoverage'); if(covEl) covEl.textContent = `Tier 1 coverage: ${pct!=null? pct+'%' : '–'} (${healthy}/${total})`;
                // Simple cost avoidance note (placeholder): lower MTTD implies reduced dwell
                const caEl = document.getElementById('reportCostAvoidance'); if(caEl){ caEl.textContent = (pct!=null ? `Cost avoidance (est.): coverage ${pct}% reduces dwell time risk` : 'Cost avoidance: –'); }
            }
        }catch(_){ }
    }

    async function updateMissingLogPanel(){
        const panel = document.getElementById('missingLogPanel');
        if(!panel) return;
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/iam/connectors/status?include_health=1', { headers: authHeaders() });
            if(!resp.ok){
                panel.style.display = 'none';
                return;
            }
            const payload = await resp.json().catch(()=>({}));
            const alerts = Array.isArray(payload.missing_alerts) ? payload.missing_alerts : [];
            const summaryEl = document.getElementById('missingLogSummary');
            const listEl = document.getElementById('missingLogList');
            if(!alerts.length){
                panel.style.display = 'none';
                if(summaryEl) summaryEl.textContent = 'All IAM connectors healthy.';
                if(listEl) listEl.textContent = 'No heartbeat violations.';
                return;
            }
            panel.style.display = 'block';
            if(summaryEl){
                summaryEl.textContent = `${alerts.length} connector${alerts.length>1?'s':''} idle beyond TTL`;
            }
            if(listEl){
                listEl.innerHTML = alerts.map(alert => {
                    const idle = typeof alert.seconds_since_event === 'number' ? formatDuration(alert.seconds_since_event) : 'unknown';
                    const ttl = typeof alert.ttl_seconds === 'number' ? formatDuration(alert.ttl_seconds) : 'n/a';
                    const recs = (alert.recommendations || []).map(rec => `<li>${rec}</li>`).join('');
                    return `<div style="margin-bottom:6px;">
                        <div style="font-weight:600;">${alert.label || alert.connector}</div>
                        <div class="small">Idle ${idle} • TTL ${ttl}</div>
                        <ul style="margin:4px 0 0 1.2rem;">${recs || '<li>Investigate ingestion worker</li>'}</ul>
                        ${renderTicketSummary(alert.auto_ticket)}
                    </div>`;
                }).join('');
            }
        }catch(_err){
            panel.style.display = 'none';
        }
    }

    function renderMultiDomainDependencyBanner(stats){
        const banner = document.getElementById('multiDomainDependencyBanner');
        if(!banner) return;
        const dep = (stats && stats.dependency_status) || null;
        if(!dep){
            banner.style.display = 'none';
            banner.textContent = '';
            return;
        }
        const warnings = [];
        const hop = dep.hopgraph || {};
        const redis = dep.redis || {};
        if(hop.available === false){
            warnings.push(`HopGraph unavailable${hop.reason ? ' ('+hop.reason+')' : ''}`);
        } else if(hop.stale){
            warnings.push('HopGraph snapshots stale');
        }
        if(redis.available === false){
            warnings.push(`Redis unavailable${redis.reason ? ' ('+redis.reason+')' : ''}`);
        }
        if(dep.queued_factor_batches){
            warnings.push(`Queued factor batches awaiting replay: ${dep.queued_factor_batches}`);
        }
        const formatTs = (ts) => {
            if(typeof ts !== 'number') return 'n/a';
            try{
                return new Date(ts * 1000).toLocaleTimeString();
            }catch(_){
                return 'n/a';
            }
        };
        if(warnings.length === 0){
            banner.style.display = 'none';
            banner.textContent = '';
            return;
        }
        warnings.push(`Last healthy HopGraph: ${formatTs(hop.last_ok_ts || hop.health_last_ok_ts)}`);
        warnings.push(`Last healthy Redis: ${formatTs(redis.last_ok_ts || redis.health_last_ok_ts)}`);
        const replayHistory = Array.isArray(dep.replay_history) ? dep.replay_history : [];
        if(replayHistory.length){
            const lastReplay = replayHistory[replayHistory.length - 1];
            const count = lastReplay && lastReplay.batch_count ? lastReplay.batch_count : replayHistory.length;
            warnings.push(`Last replay flushed ${count} batches at ${formatTs(lastReplay && lastReplay.timestamp)}`);
        } else if(dep.last_replay_ts){
            warnings.push(`Last replay observed at ${formatTs(dep.last_replay_ts)}`);
        }
        banner.innerHTML = warnings.map(text => `<div>${text}</div>`).join('');
        banner.style.display = 'block';
    }

    async function updateMultiDomainAdminMeta(force = false){
        const metaEl = document.getElementById('multiDomainConfigMeta');
        const depMetaEl = document.getElementById('multiDomainDependencyMeta');
        if(!metaEl && !depMetaEl){
            return;
        }
        const now = Date.now();
        if(!force && (now - _lastMultiDomainConfigFetch) < 30000){
            return;
        }
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/correlation/multi-domain/config', { headers: authHeaders() });
            if(!resp.ok){
                return;
            }
            const payload = await resp.json().catch(()=>({}));
            _lastMultiDomainConfigFetch = now;
            if(metaEl){
                const parts = [];
                if(typeof payload.ttl_seconds === 'number'){
                    parts.push(`Chain TTL ${formatDuration(payload.ttl_seconds)}`);
                }
                if(typeof payload.cleanup_interval_seconds === 'number'){
                    parts.push(`Cleanup ${formatDuration(payload.cleanup_interval_seconds)}`);
                }
                const depCfg = payload.dependency_config || {};
                if(typeof depCfg.session_ttl_seconds === 'number'){
                    parts.push(`Session TTL ${formatDuration(depCfg.session_ttl_seconds)}`);
                }
                if(typeof depCfg.session_cleanup_interval_seconds === 'number'){
                    parts.push(`Session cleanup ${formatDuration(depCfg.session_cleanup_interval_seconds)}`);
                }
                if(parts.length){
                    metaEl.textContent = parts.join(' • ');
                } else {
                    metaEl.textContent = 'No configuration overrides detected.';
                }
            }
            if(depMetaEl){
                const depCfg = payload.dependency_config || {};
                const lines = [];
                if(typeof depCfg.dependency_health_cache_ttl_seconds === 'number'){
                    lines.push(`Health cache TTL ${formatDuration(depCfg.dependency_health_cache_ttl_seconds)}`);
                }
                if(depCfg.hopgraph_health_endpoint){
                    lines.push(`HopGraph probe: ${_htmlEsc(depCfg.hopgraph_health_endpoint)}`);
                }
                if(depCfg.redis_health_endpoint){
                    lines.push(`Redis probe: ${_htmlEsc(depCfg.redis_health_endpoint)}`);
                }
                const depStatus = payload.dependency_status || {};
                const hop = depStatus.hopgraph || {};
                const redis = depStatus.redis || {};
                const fmtTs = (ts) => {
                    if(typeof ts !== 'number') return 'n/a';
                    try{ return new Date(ts * 1000).toLocaleTimeString(); }catch(_err){ return 'n/a'; }
                };
                if(hop.last_ok_ts || hop.health_last_ok_ts){
                    lines.push(`HopGraph healthy: ${fmtTs(hop.last_ok_ts || hop.health_last_ok_ts)}`);
                }
                if(redis.last_ok_ts || redis.health_last_ok_ts){
                    lines.push(`Redis healthy: ${fmtTs(redis.last_ok_ts || redis.health_last_ok_ts)}`);
                }
                if(typeof depStatus.queued_factor_batches === 'number' && depStatus.queued_factor_batches > 0){
                    lines.push(`Queued factor batches: ${depStatus.queued_factor_batches}`);
                }
                const replayHistory = Array.isArray(depStatus.replay_history) ? depStatus.replay_history : [];
                if(replayHistory.length){
                    const last = replayHistory[replayHistory.length - 1];
                    const count = last && last.batch_count ? last.batch_count : replayHistory.length;
                    lines.push(`Last replay flushed ${count} batches at ${fmtTs(last && last.timestamp)}`);
                } else if(depStatus.last_replay_ts){
                    lines.push(`Last replay observed at ${fmtTs(depStatus.last_replay_ts)}`);
                }
                depMetaEl.innerHTML = lines.length ? lines.map(line => `<div>${line}</div>`).join('') : '';
            }
            if (applyMultiDomainConfig) {
                try { applyMultiDomainConfig(payload); } catch(_err){}
            }
        }catch(_err){
            // ignore
        }
    }

    const applyMultiDomainConfig = (() => {
        const ttlInput = document.getElementById('multiDomainTtlInput');
        const cleanupInput = document.getElementById('multiDomainCleanupInput');
        const saveBtn = document.getElementById('multiDomainConfigSave');
        const statusEl = document.getElementById('multiDomainConfigStatus');
        if(saveBtn){
            saveBtn.addEventListener('click', async () => {
                const payload = {};
                if(ttlInput && ttlInput.value){
                    payload.ttl_seconds = Number(ttlInput.value);
                }
                if(cleanupInput && cleanupInput.value){
                    payload.cleanup_interval_seconds = Number(cleanupInput.value);
                }
                statusEl && (statusEl.textContent = 'Updating…');
                try{
                    const resp = await (window.safeFetch || fetch)('/api/v1/correlation/multi-domain/config', {
                        method:'POST',
                        headers:{ 'Content-Type':'application/json', ...authHeaders() },
                        body: JSON.stringify(payload)
                    });
                    const data = await resp.json().catch(()=>({}));
                    if(!resp.ok){
                        throw new Error((data && (data.detail || data.error)) || resp.statusText);
                    }
                    if(statusEl){
                        statusEl.textContent = 'Updated multi-domain settings';
                    }
                    if(data && data.stats){
                        applyMultiDomainConfig && applyMultiDomainConfig(data.stats);
                    }
                    try{ await updateMultiDomainAdminMeta(true); }catch(_err){}
                }catch(err){
                    if(statusEl){
                        statusEl.textContent = `Update failed: ${(err && err.message) || err}`;
                    }
                }
            });
        }
        return (stats) => {
            if(ttlInput && typeof stats.ttl_seconds === 'number' && document.activeElement !== ttlInput){
                ttlInput.value = Math.round(stats.ttl_seconds);
            }
            if(cleanupInput && typeof stats.cleanup_interval_seconds === 'number' && document.activeElement !== cleanupInput){
                cleanupInput.value = Math.round(stats.cleanup_interval_seconds);
            }
        };
    })();

    async function updateFactorTelemetry(){
        const panel = document.getElementById('factorTelemetryPanel');
        if(!panel) return;
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/admin/factors/telemetry', { headers: authHeaders() });
            if(!resp.ok){
                panel.style.display = 'none';
                return;
            }
            const payload = await resp.json().catch(()=>({}));
            const tel = payload.telemetry || {};
            panel.style.display = 'block';
            const precEl = document.getElementById('factorTelemetryPrecision');
            const supEl = document.getElementById('factorTelemetrySuppressed');
            const metaEl = document.getElementById('factorTelemetryMeta');
            const fpEl = document.getElementById('factorTelemetryTopFp');
            const ctxEl = document.getElementById('factorTelemetryContext');
            if(precEl){
                const precision = tel.window_precision !== undefined ? Number(tel.window_precision).toFixed(3) : 'n/a';
                precEl.textContent = precision;
            }
            if(supEl){
                const count = Array.isArray(tel.suppressed) ? tel.suppressed.length : (tel.suppressed || []).length || 0;
                supEl.textContent = String(count);
            }
            if(metaEl){
                const ts = tel.timestamp ? new Date(tel.timestamp * 1000).toLocaleString() : 'n/a';
                metaEl.textContent = `Snapshot ${ts} • Window TP ${tel.window_counts?.tp||0} / FP ${tel.window_counts?.fp||0}`;
            }
            if(fpEl){
                const rows = Array.isArray(tel.factor_rankings) ? tel.factor_rankings.slice(0,8) : [];
                fpEl.innerHTML = rows.length
                    ? rows.map(row => `<div>${_htmlEsc(row.factor || 'factor')}: FP ${(row.fp_ratio ?? 0).toFixed(2)} (${row.fp || 0}/${row.observations || 0})</div>`).join('')
                    : 'No factor FP stats.';
            }
            if(ctxEl){
                const ctx = tel.context_multipliers || {};
                const entries = Object.keys(ctx).slice(0,10).map(key => `<div>${_htmlEsc(key)}: ${Number(ctx[key]).toFixed(2)}</div>`);
                ctxEl.innerHTML = entries.length ? entries.join('') : 'No context multipliers.';
            }
        }catch(_err){
            panel.style.display = 'none';
        }
    }

    async function updateFactorCalibration(){
        const panel = document.getElementById('factorCalibrationPanel');
        if(!panel) return;
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/admin/factors/calibration', { headers: authHeaders() });
            if(!resp.ok){
                panel.style.display = 'none';
                return;
            }
            const payload = await resp.json().catch(()=>({}));
            panel.style.display = 'block';
            const pathEl = document.getElementById('calibrationPathLabel');
            if(pathEl){
                pathEl.textContent = payload.path || '(not configured)';
            }
            const ctx = payload.context_multipliers || {};
            const ctxEl = document.getElementById('calibrationContextList');
            if(ctxEl){
                const keys = Object.keys(ctx);
                if(keys.length){
                    const rows = keys.sort().map(key => `<span class="pill">${key}: ${(Number(ctx[key]).toFixed ? Number(ctx[key]).toFixed(2) : ctx[key])}</span>`);
                    ctxEl.innerHTML = rows.join(' ');
                } else {
                    ctxEl.textContent = 'No context multipliers defined.';
                }
            }
        }catch(_err){
            panel.style.display = 'none';
        }
    }

    async function updateScoringTransparency(){
        const host = document.getElementById('multiDomainScoringConfig');
        if(!host) return;
        try{
            const resp = await (window.safeFetch || fetch)('/api/v1/decisions/recent?limit=1', { headers: authHeaders() });
            if(!resp.ok){ host.textContent = 'No recent decision.'; return; }
            const payload = await resp.json().catch(()=>({}));
            const d = (payload.decisions || payload.rows || payload.events || [])[0] || {};
            const sc = d.scoring_config || {};
            const blob = {
                ewma_alpha: sc.ewma_alpha ?? null,
                adaptive_ewma: sc.adaptive_ewma ?? null,
                weights: sc.weights ?? {}
            };
            host.textContent = JSON.stringify(blob, null, 2);
        }catch(_){ host.textContent = 'Scoring config unavailable.'; }
    }

    function formatDuration(seconds){
        if(typeof seconds !== 'number' || Number.isNaN(seconds)){
            return '--';
        }
        if(seconds < 60){
            return `${Math.round(seconds)} s`;
        }
        if(seconds < 3600){
            return `${Math.round(seconds/60)} m`;
        }
        return `${(seconds/3600).toFixed(1)} h`;
    }

    // Simple canvas sparkline renderer (temporal avg)
    function drawTemporalSparkline(values){
        try{
            // Always create canvas element so tests can observe it even if values are empty
            if(!values) values = [];
            let card = document.getElementById('temporalMetricCard');
            if(!card) return;
            let canvas = card.querySelector('canvas.temporal-spark');
            if(!canvas){
                canvas = document.createElement('canvas');
                canvas.className = 'temporal-spark';
                canvas.width = 220; canvas.height = 28;
                canvas.style.width = '220px'; canvas.style.height = '28px';
                canvas.style.display = 'block'; canvas.style.marginTop = '6px';
                const label = document.createElement('div'); label.style.fontSize='11px'; label.style.color='var(--text-muted)'; label.textContent='Temporal EWMA';
                card.appendChild(label);
                card.appendChild(canvas);
            }
            const ctx = canvas.getContext('2d');
            const w = canvas.width; const h = canvas.height; ctx.clearRect(0,0,w,h);
            const maxv = Math.max(...values, 0.001); const minv = Math.min(...values, 0);
            const range = Math.max(0.0001, maxv - minv);
            ctx.lineWidth = 2; ctx.strokeStyle = 'rgba(74,99,231,0.9)'; ctx.beginPath();
            for(let i=0;i<values.length;i++){
                const x = Math.floor((i/(values.length-1||1))*(w-2))+1;
                const norm = (values[i]-minv)/range;
                const y = Math.floor(h - 2 - (norm*(h-4)));
                if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
            }
            ctx.stroke();
            // draw current dot
            const last = values[values.length-1]; const lx = Math.floor(((values.length-1)/(values.length-1||1))*(w-2))+1; const lnorm = (last-minv)/range; const ly = Math.floor(h - 2 - (lnorm*(h-4)));
            ctx.fillStyle = 'rgba(74,99,231,1)'; ctx.beginPath(); ctx.arc(lx, ly, 3, 0, Math.PI*2); ctx.fill();
            // mark canvas as drawn for deterministic tests
            try{ canvas.dataset.drawn = '1'; canvas.setAttribute('data-drawn','1'); window.__temporalDrawn = true; window.dispatchEvent(new Event('temporal-drawn')); }catch(_err){}
        }catch(_err){ console.warn('spark draw failed', _err); }
    }

    // Single scheduler: call once on DOMContentLoaded and every 30s
    // Subscribe to stream messages for live updates if available
    function initCalibrationControls(){
        const btn = document.getElementById('calibrationReloadBtn');
        if(!btn) return;
        btn.addEventListener('click', async ()=>{
            const statusEl = document.getElementById('calibrationStatus');
            const pathInput = document.getElementById('calibrationPathInput');
            const overridesInput = document.getElementById('calibrationOverridesInput');
            let path = pathInput && pathInput.value ? pathInput.value.trim() : '';
            let overrides = overridesInput && overridesInput.value ? overridesInput.value.trim() : '';
            let config = null;
            if(overrides){
                try{
                    config = JSON.parse(overrides);
                }catch(err){
                    if(statusEl) statusEl.textContent = 'Invalid JSON overrides';
                    return;
                }
            }
            const body = {};
            if(path){
                body.path = path;
            }
            if(config){
                body.config = config;
            }
            if(!body.path && !body.config){
                if(statusEl) statusEl.textContent = 'Provide a path or JSON overrides.';
                return;
            }
            if(statusEl) statusEl.textContent = 'Applying...';
            try{
                const resp = await (window.safeFetch || fetch)('/api/v1/admin/factors/calibration/reload', {
                    method: 'POST',
                    headers: Object.assign({'Content-Type':'application/json'}, authHeaders()),
                    body: JSON.stringify(body),
                });
                const data = await resp.json().catch(()=>({}));
                if(!resp.ok){
                    if(statusEl) statusEl.textContent = data.detail || 'Calibration update failed';
                    return;
                }
                if(statusEl) statusEl.textContent = 'Calibration applied';
                try{ overridesInput.value = ''; }catch(_){}
                await updateFactorCalibration();
                await updateFactorTelemetry();
            }catch(err){
                if(statusEl) statusEl.textContent = (err && err.message) ? err.message : 'Calibration error';
            }
        });
    }

    const startPollingAndSubscribe = ()=>{
        try{ updateMetrics(); }catch(_err){}
        setInterval(()=>{ try{ updateMetrics(); }catch(_err){} }, 30000);
        // subscribe to low-level stream messages and trigger update on relevant events
        if(window.streamSubscribe){
            window.streamSubscribe('message', (ev)=>{
                try{
                    const data = JSON.parse(ev.data);
                    // If the message looks like a metrics/dashboard update, refresh small parts
                    if(data.type && (data.type.includes('dashboard') || data.type.includes('metrics') || data.source==='dashboard')){
                        try{ updateMetrics(); }catch(_e){}
                    }
                }catch(_e){ }
            });
        }
        // If heavy charts present, lazy-load the chart lib
        try{
            const chartHolder = document.getElementById('metricsChart');
            try{
                const flagEnabled = window.featureFlags && typeof window.featureFlags.isEnabled === 'function' ? window.featureFlags.isEnabled('demo_lazy_chart') : false;
                if(chartHolder && window.lazyLoadScript && flagEnabled){
                    window.lazyLoadScript('/static/js/vendor/charting.bundle.js').then(()=>{ window.dispatchEvent(new Event('charts-loaded')); }).catch(()=>{});
                }
            }catch(_){ }
        }catch(_e){}
        initCalibrationControls();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startPollingAndSubscribe);
    } else { startPollingAndSubscribe(); }

    window.updateMetrics = updateMetrics;
})();
