# 14. Frontend Artifact Intelligence Console Specification

Status: Draft (Initial Comprehensive Spec)
Owner: Platform / Artifact Intelligence Team
Last Updated: 2025-09-23
Related Docs: `01-architecture-overview.md`, `08-playbook-dsl-spec.md`, `09-nlp-intent-spec.md`, `10-calibration-and-replay.md`, `13-extensibility-and-future-ml.md`

---
## 1. Purpose & Scope
Provide a single, explainable, executive-friendly and analyst-powerful web UI for the Artifact Intelligence sidecar: ingest artifact inventories (executables, scripts, macros, downloads), synthesize risk, map MITRE/STRIDE/CVE signals, surface business impact, show clusters, prevalence, rarity, and allow human feedback + distribution (Slack / future email digest). This document is **source-of-truth** for initial UI scaffolding (React or similar) and LLM (Opus 4.1) code generation prompts.

Non‑Goals (Phase 1): AuthN/O multi-tenant portal, deep RBAC, full behavioral sandbox integration, websocket push (polling acceptable initially).

---
## 2. User Personas (Plain Language)
| Persona | Objectives | Key Needs |
|---------|------------|-----------|
| SOC Analyst | Rapid triage | Clear factors, override, propagation visibility |
| Security Manager / Exec | Posture snapshot | Business summary, top risks, recommended actions |
| Threat Researcher | Pattern discovery | Clusters, similarity, technique coverage deltas |
| Sales Engineer / Demo | Fast narrative | Upload → instant summary & visuals |
| Non-Technical Stakeholder | Avoid panic | Simple color-coded risk + plain explanations |

---
## 3. Core Objectives
1. **Fast Upload → Insight Loop** (< 10s small dataset)
2. **Explainability** (factor breakdown, MITRE/STRIDE mapping, business framing)
3. **Actionability** (recommended actions, Slack notifications)
4. **Stability & Trust** (prevalence calibration, risk delta transparency)
5. **Low Cognitive Load** (progressive disclosure, plain-language glossary)

---
## 4. Information Architecture
Left collapsible nav (Rail) → Main Content (tab or view) → Right Context Drawer (artifact details). Mobile: rail becomes overlay; drawer becomes bottom sheet.

**Nav Sections (First Iteration)**
1. Ingest & Analysis
   - Upload Artifacts
   - Recent Batches
   - Offline Runner (future)
2. Intelligence
   - Current Report
   - Clusters & Similarity
   - MITRE / STRIDE Coverage
   - Prevalence & Rarity
3. Business & Governance
   - Executive Summary
   - Risk Trends (future)
   - Feedback Overrides
   - Calibration Tests
4. Integration
   - Slack Webhook
   - API Keys / HMAC
5. Settings & Help
   - Thresholds (view-only init)
   - File Format Guide
   - About / Version

---
## 5. Visual Layout Wireframe (ASCII)
```
+----------------------------------------------------------------------------------------------------------------+
| Logo / Brand | Upload New Batch (Primary)                            | Batch Selector | Search Artifacts | User |
+---------LEFT RAIL (280px)----------------------+--------------------------------------------+--------------------+
| [⬆ Upload]                                     | EXECUTIVE SUMMARY VIEW (Default)                                |
| Ingest & Analysis                              | Overall Posture: Elevated (2 high-risk artifacts)               |
|  - Upload                                      | Top Concerns: powerscan.exe, macro_payload.dotm                 |
|  - Recent Batches                              | Propagation: Yes (2 artifacts across >3 hosts)                  |
| Intelligence                                   | Emerging Techniques: T1059, T1105                              |
|  - Current Report                              | Business Impact: Potential lateral discovery tooling            |
|  - Clusters                                    | Recommended Actions: Contain hosts; review macro; block macros  |
|  - Coverage                                    | Confidence: High | Generated: 2025-09-23 14:02 UTC              |
|  - Prevalence                                  | [View Artifacts] [Download JSON] [Download Markdown] [Share]    |
| Business & Governance                          | --------------------------------------------------------------  |
|  - Executive Summary                           | RIGHT DRAWER (Artifact) (toggle)                                |
|  - Overrides                                   | Name: powerscan.exe | Risk: 87 (MALICIOUS)                     |
|  - Calibration Tests                           | Hosts: 4 | Cluster: #12 | Rarity: Rare                         |
| Integration                                    | Factors (Accordion): Unsigned, Multi-Host Spread, Rare          |
|  - Slack Webhook                               | MITRE: T1059, T1105 | Reputation: Pending VT                   |
|  - API / HMAC                                  | Override: [Dropdown] Rationale [textarea] (Submit)              |
| Settings & Help                                |                                                              |
|  - File Formats                                |                                                              |
|  - About                                       |                                                              |
+------------------------------------------------+---------------------------------------------------------------+
```

---
## 6. Theme & Branding
Dark-first (credible + calm; avoids neon). Light mode deferred.

| Token | Value | Usage |
|-------|-------|-------|
| `bg.base` | `#0D1117` | App background |
| `bg.surface` | `#162030` | Panels / cards |
| `accent.primary` | `#345DFF` | Primary buttons, links |
| `accent.primary.focus` | `#4C82FF` | Focus ring |
| `text.primary` | `#E6ECF3` | Main text |
| `text.muted` | `#8894A6` | Secondary labels |
| `accent.warning` | `#D9A441` | Suspicious / caution factors |
| `accent.danger` | `#FF4D4F` | Malicious / destructive |
| `accent.success` | `#2DBF7A` | Confirmations |
| `border.default` | `#1F2733` | Dividers |
| `badge.low` | `#2B4C99` | Low risk badge bg |
| `badge.suspicious` | `#B9821F` | Suspicious badge bg |
| `badge.high` | `#D76622` | High risk badge bg |
| `badge.malicious` | `#C82333` | Malicious badge bg |
| `shadow.elevate` | rgba(0,0,0,0.4) 0 4px 16px | Drawer floating |

Typography: Inter (regular, medium, semibold). Monospace: JetBrains Mono (hashes, IDs). Line-height body 1.45.

Motion: 120–160ms ease-in-out for transitions; no bounce; skeletons > spinners for loading states.

---
## 7. Component Inventory
Foundational: `AppShell`, `NavRail`, `TopBar`, `ContextDrawer`, `RouteTabs`, `SkeletonLoader`.
Interactive Core: `UploadWizard`, `BatchStatusCard`, `ArtifactTable`, `ArtifactRow`, `RiskBadge`, `CoverageMatrix`, `ClusterGraph`, `PrevalenceTimeline`, `FactorsAccordion`, `BusinessImpactPanel`, `SlackWebhookForm`, `OverrideForm`, `CalibrationRunner`, `NotificationToast`, `JSONDownloadButton`, `MarkdownDownloadButton`.
Assistive: `InlineHelp`, `SchemaGuideModal`, `EmptyState`, `GuardrailDialog`, `AccessibilityAnnouncer`.

---
## 8. Routes (Conceptual)
| Path | View | Notes |
|------|------|-------|
| `/` | Redirect → `/executive` | Landing summary |
| `/upload` | Upload wizard | Multi-step ingestion |
| `/batches/:batchId` | Batch report | Query param fallback `?batch_id=` |
| `/artifacts/:id` | Deep link (opens drawer) | Use router state |
| `/clusters` | Cluster & similarity | Lazy load graph |
| `/coverage` | MITRE/STRIDE matrix | Heatmap |
| `/prevalence` | Rarity & trend | Charts |
| `/executive` | Business summary | Non-technical |
| `/overrides` | Feedback list | Audit trail |
| `/calibration` | Prevalence tests | Synthetic driver |
| `/integration/slack` | Slack config | Test button |
| `/settings/file-formats` | File schema | Upload guidance |
| `/settings/about` | Version & build info | Git commit hash |

---
## 9. Data Model (Frontend Representation)
```ts
// Simplified interfaces (TypeScript)
export interface ArtifactSummary {
  id: string;
  artifact_name: string;
  artifact_type: string; // EXECUTABLE|SCRIPT|MACRO|DOWNLOAD|LIBRARY|SERVICE
  risk_score: number; // 0-100
  verdict: 'BENIGN' | 'LOW' | 'SUSPICIOUS' | 'HIGH' | 'MALICIOUS';
  rarity: 'COMMON' | 'RARE' | 'EMERGING' | null;
  hosts: number; // distinct host count
  cluster_id?: string;
  flags: string[]; // e.g., ["unsigned","macro","multi_host"]
}

export interface ArtifactDetail extends ArtifactSummary {
  factors: FactorContribution[];
  mitre: string[];          // technique IDs
  stride: string[];         // STRIDE categories
  cve_hints: string[];      // optional
  reputation?: ReputationInfo;
  prevalence?: PrevalenceInfo;
  timeline?: ArtifactEvent[];
  override?: OverrideRecord;
}

export interface FactorContribution {
  category: string;      // STATIC|SCRIPT|MACRO|ORIGIN|PERSISTENCE|RELATIONAL|TEMPORAL|REPUTATION|RARITY
  score_delta: number;   // numeric weight contribution
  label: string;         // human readable
  notes?: string[];      // list of raw signals
}

export interface BatchReport {
  batch_id: string;
  status: 'QUEUED' | 'PROCESSING' | 'ENRICHING' | 'COMPLETE' | 'ERROR';
  generated_at?: string;
  artifacts: ArtifactSummary[];
  top_risks: string[]; // artifact IDs sorted by risk
  mitre_coverage: string[];
  mitre_delta?: string[]; // new since previous batch
  stride_coverage: string[];
  business_impact?: BusinessImpactSummary; // only if risk present
  narrative?: string; // textual summary
}
```

---
## 10. API Contracts (Representative)
(Align with existing backend; adapt path prefix as needed.)

| Endpoint | Method | Purpose | Request | Response (200) |
|----------|--------|---------|---------|----------------|
| `/api/artifacts/batch_analyze` | POST | Submit batch | `{ artifacts: ArtifactInput[], options? }` | `{ batch_id }` |
| `/api/artifacts/report/latest` | GET | Latest or batch-specific | `?batch_id=` (optional) | `BatchReport` |
| `/api/artifacts/feedback` | POST | Override | `{ artifact_id, override_verdict, rationale }` | `{ status:'ok' }` |
| `/api/artifacts/clusters` | GET | Cluster list | `limit?` | `{ clusters:[{id,size,top_names[]}] }` |
| `/api/artifacts/artifact/:id` | GET | Detail | — | `ArtifactDetail` |
| `/api/integration/slack` | POST | Configure webhook | `{ webhook_url, triggers[] }` | `{ saved:true }` |
| `/api/integration/slack/test` | POST | Send test | — | `{ delivered:true }` |
| `/api/artifacts/calibrate_prevalence` | POST | Calibration run | `{ batches, synthetic }` | `{ sequence: CalibrationPoint[] }` |

Example Upload JSON Body (converted from CSV client-side):
```json
{
  "artifacts": [
    {
      "artifact_name": "winword.exe",
      "path": "C:/Program Files/Microsoft Office/winword.exe",
      "artifact_type": "EXECUTABLE",
      "hash_sha256": "abc123...",
      "host_id": "HR-LAPTOP-22",
      "signed": true
    }
  ],
  "options": { "include_business_summary": true }
}
```

---
## 11. Upload & Ingestion UX Flow
**Steps:**
1. Select / Drag Files (CSV, XLSX, JSONL, ZIP) → client size check.
2. Parse & Preview (first 30 rows; detect delimiter, headers, encoding fallback → show warnings).
3. Column Mapping (auto map → allow manual override): required `artifact_name` + (`path` OR `hash_sha256`).
4. Validation Summary (skipped rows log, anomalies: missing name/hash, unknown encoding, oversized row count > threshold).
5. Submit (POST) → show progress bar with phases: `Queued → Factors → Clustering → Reputation → Post-VT → Complete`.
6. Completion CTA: View Executive Summary or Artifact Table.

File Acceptance Rules:
- Max file size per upload: 25 MB (configurable).
- Row soft cap: 50k (warn) / Hard cap: 100k (reject).
- XLSX: first sheet selected by default (dropdown for others if >1).
- ZIP: flatten any contained CSV/XLSX/JSONL; merge sequentially; log each file.
- Security: never render raw HTML; escape preview cells.

Client-Side Enhancements (optional later):
- Hash calculation (SHA-256) if `hash_sha256` missing and file includes binary (future).

---
## 12. Risk & Verdict Presentation
Risk Score 0–100 → Buckets:
| Bucket | Range | Color | Label Tone |
|--------|-------|-------|------------|
| BENIGN | 0–19 | Muted neutral | "Benign" |
| LOW | 20–44 | Soft blue | "Low" |
| SUSPICIOUS | 45–64 | Amber | "Suspicious" |
| HIGH | 65–79 | Orange-Red | "High" |
| MALICIOUS | 80–100 | Red | "Malicious" |

Dual Encoding: color + text always; ARIA label: `Risk: High (72)`.

Tooltips should describe elevating factors succinctly (“Raised by unsigned + macro + network beacon pattern”).

---
## 13. Factor Explainability
Factors Accordion: one section per category with table:
| Factor Signal | Weight Δ | Rationale |
|---------------|----------|-----------|
| `unsigned_executable` | `+18` | "Binary missing trusted signature" |
| `multi_host_spread` | `+15` | "Observed on 4 distinct hosts" |
| `rare_prevalence` | `+10` | "First appearance in monitored environment" |

Show cumulative subtotal vs final risk (indicate any LLM refinement delta with capped ±). Provide toggle: “Show Raw JSON”.

---
## 14. Clusters & Similarity
Display clusters sorted by size or risk-weighted centroid.
Node Visual Simplification (MVP): list grouping with representative artifact, count, top technique tags.
Future: force graph with emphasis on colored risk halos.

Cluster Item Card:
- Cluster ID (#12)
- Size (e.g., 7 artifacts)
- Representative Name
- Avg Risk Score / Highest Risk
- Techniques (chips)
- CTA: “View Members” → filtered artifact table state.

---
## 15. MITRE / STRIDE Coverage View
Matrix of Tactics (columns) vs Observed Techniques (rows collapsed or chips). Delta highlight for newly added techniques since previous completed batch: highlight border glow (blue) and `NEW` badge.

Provide export option (CSV of technique IDs + counts). Clear disclaimers: “Mappings are heuristic hints, not confirmed adversary activity.”

---
## 16. Prevalence & Rarity Views
Charts:
- Bar: Artifact counts by type (EXECUTABLE, SCRIPT, etc.)
- Rarity Breakdown: Rare vs Emerging vs Common counts.
- Timeline (if historical batches stored): stacked area of new vs recurring artifacts.

Rarity Definitions (display inline):
- **Rare**: First time seen across all persisted history.
- **Emerging**: Seen in ≤2 prior batches with low host spread.
- **Common**: Prevalence stabilized beyond threshold.

---
## 17. Executive Summary Panel
Non-technical text sections:
1. Posture Headline (e.g., “Elevated: 2 high-risk files need review today”).
2. Top 3 Concerns (Plain bullet; one line each).
3. Business Impact Narrative (from backend summarizer).
4. Emerging Techniques (human phrased: “Script-based execution (T1059)”).
5. Propagation / Lateral Movement note (if >N hosts).
6. Recommended Immediate Actions (3 bullet max; action verbs).
7. Confidence / Ambiguity Statement.
8. Timestamp + Batch ID.

CTA Buttons: `View Artifact Table`, `Download Executive Markdown`, `Share to Slack` (if webhook configured), `Copy Summary`.

---
## 18. Overrides & Feedback
Overrides Table Columns: Artifact | Original Verdict | Override | Analyst | Timestamp | Rationale (truncate → expand).

Override Drawer Form:
- New verdict (dropdown; cannot escalate from MALICIOUS → BENIGN without confirmation dialog).
- Rationale (textarea, required if downgrading risk ≥ 2 buckets).
- Submit → optimistic UI + toast “Override saved.”
- History panel (diff list) under current form.

---
## 19. Slack Integration UX
Panel Fields:
- Webhook URL (masked; eye toggle; stored server-side encrypted)
- Triggers (checkboxes): `High-Risk Artifact`, `New Rare Artifact`, `Cluster Propagation`, `Daily Digest`
- Test Delivery Button (returns toast + entry in log)
- Delivery Log Table: Time | Event | Status (✅ / ❌) | Artifact Ref

Error Patterns & Guidance:
- 410 Gone → “Webhook invalidated; recreate via Slack apps portal.”
- 429 → show cooldown ephemeral banner.

Example Slack Alert JSON (for doc transparency):
```json
{
  "text": ":rotating_light: Artifact Risk Alert",
  "blocks": [
    {"type":"section","text":{"type":"mrkdwn","text":"*powerscan.exe* (Cluster #12)\nScore: 87 MALICIOUS | Hosts: 4 | Rare: Yes\nMITRE: T1059, T1105"}},
    {"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Open Console"},"url":"https://console.example/artifacts/powerscan"}]}
  ]
}
```

---
## 20. Calibration Tests
Calibration Runner UI:
- Inputs: Number of synthetic batches (default 5), Variation seed (optional)
- Run Button → spinner + progress
- Output: Line chart (batch index vs rare factor count); stability metric (std deviation / mean ratio)
- Badge: Stable (< 0.3) / Noisy (>= 0.3)
- Export JSON results.

---
## 21. Accessibility & Inclusivity
Checklist:
- ARIA roles on nav (`role="navigation"`), tables (`aria-rowcount`), dialogs (focus trap + `aria-modal="true"`).
- Keyboard: Tab sequence logical; `Esc` closes drawer.
- Color Contrast: All text contrast ≥ 4.5:1; risk colors accompanied by textual label.
- Reduced Motion: Respect `prefers-reduced-motion`; disable transition animations.
- Screen Reader Live Region: Announce batch completion & new high-risk count.
- Tooltips dismissable / accessible via keyboard (trigger element `aria-describedby`).

---
## 22. Glossary (Surface in Help)
| Term | Plain Explanation |
|------|-------------------|
| Artifact | A file, document, script, or executable analyzed. |
| Cluster | Group of similar artifacts (content/behavior). |
| Prevalence | How often an artifact appears historically. |
| Rarity | First-time or seldom-seen artifact classification. |
| Propagation | Same artifact observed across multiple hosts. |
| Coverage | Possible attacker technique hints captured. |
| Override | Analyst adjustment to automated verdict. |

---
## 23. Error & Edge State Patterns
| Scenario | UI Response |
|----------|-------------|
| No batches yet | Empty state card: “Upload a CSV/XLSX to begin.” Sample download link. |
| Upload parse error | Banner: “Could not parse file (encoding ISO-8859-1). Try saving as UTF‑8.” |
| Partial ingestion | Info toast + downloadable skip log. |
| Slack failure | Inline error row + retry icon. |
| Reputation pending | Grey badge “Reputation: Pending (VT queue)” |
| Override conflict | Modal: “Verdict changed since you opened. Refresh?” |

---
## 24. Security & Privacy Messaging
Visible in Settings > File Formats:
- “We store only metadata, not original binary content.”
- “Avoid embedding PII; host aliases preferred.”
- “Webhook and API secrets are encrypted at rest.”
- “Uploads scanned for malicious embedded scripts in textual cells.”
- “Rate limiting: 1 batch / 30s per tenant (configurable).”

---
## 25. Initial MVP Scope vs Phase 2
| Feature | MVP | Phase 2 |
|---------|-----|---------|
| Upload CSV/XLSX/JSONL | Yes | ZIP w/ multi-file merge |
| Batch Report | Yes | Historical diff compare |
| Executive Summary | Yes | Email digest scheduling |
| Artifact Detail Drawer | Yes | Timeline animations |
| Slack High-Risk Alert | Yes | Daily digest + interactive buttons |
| Clusters (list) | Yes | Force-directed visualization |
| Coverage Matrix | Yes | Technique trend diff chart |
| Prevalence View | Basic | Historical multi-batch charts |
| Overrides | Yes | RBAC approval workflow |
| Calibration | Basic | Auto scheduled nightly run |
| Theming | Dark | Light theme + contrast toggle |
| WebSockets | No (poll) | Yes |

---
## 26. Suggested Tech Stack
- Build: Vite + React (or Next.js if SSR desired later)
- UI Primitives: Radix UI (accessible) + custom theming tokens.
- State: Zustand (simple & lightweight) or Redux Toolkit if needed.
- Table: TanStack Table (virtualization for >5k rows)
- Charts: Visx or Recharts
- Forms: React Hook Form + Zod schema validation
- HTTP: Fetch + lightweight wrapper (retry w/ exponential backoff)
- Testing: Vitest + Testing Library; Storybook for components (optional)

---
## 27. State Management Plan
Global Store Slices:
- `batches`: current batch ID, status map
- `artifacts`: dictionary keyed by ID (normalized)
- `filters`: search query, risk range, cluster filter
- `ui`: drawer open, active tab, theme mode
- `integration`: slack config state
- `overrides`: pending + applied overrides

Derived Selectors:
- `selectTopRisks(batchId)`
- `selectArtifactsByCluster(clusterId)`
- `selectFilteredArtifacts()`

---
## 28. Polling & Performance Strategy
- Poll interval: start 2s; backoff to 5s; stop when status=COMPLETE or ERROR.
- Stagger large artifact table rendering (virtual rows).
- Lazy load heavy panels (Clusters Graph, Coverage Matrix) via dynamic import.
- Cache last N batch reports in memory & persist to `localStorage` for quick reload.

---
## 29. Example React Component Stubs
```tsx
// src/components/RiskBadge.tsx
import React from 'react';

const colorForVerdict: Record<string,string> = {
  BENIGN: 'var(--badge-benign-bg, #2B3746)',
  LOW: 'var(--badge-low-bg, #2B4C99)',
  SUSPICIOUS: 'var(--badge-suspicious-bg, #B9821F)',
  HIGH: 'var(--badge-high-bg, #D76622)',
  MALICIOUS: 'var(--badge-malicious-bg, #C82333)'
};

export const RiskBadge: React.FC<{verdict:string; score:number}> = ({ verdict, score }) => (
  <span
    role="status"
    aria-label={`Risk: ${verdict} (${score})`}
    style={{
      background: colorForVerdict[verdict] || '#2B3746',
      color: '#E6ECF3',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 500,
      letterSpacing: 0.25
    }}
  >{verdict} ({score})</span>
);
```

```tsx
// src/hooks/useBatchPolling.ts
import { useEffect, useRef } from 'react';
import { useStore } from '../state/store';

export function useBatchPolling(batchId?: string) {
  const fetchReport = useStore(s => s.fetchReport);
  const status = useStore(s => s.batches[batchId||'']?.status);
  const timer = useRef<number|undefined>();

  useEffect(() => {
    if (!batchId) return;
    if (status === 'COMPLETE' || status === 'ERROR') return;

    const interval = status === 'PROCESSING' ? 2000 : 4000;
    timer.current = window.setTimeout(() => fetchReport(batchId), interval);
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, [batchId, status, fetchReport]);
}
```

---
## 30. File Format Guide (Display Summary)
**Accepted:** `.csv`, `.xlsx`, `.jsonl`, `.zip` (containing previous). Future: `.ndjson.gz`.

**Required Columns:**
- `artifact_name`
- `path` OR `hash_sha256`

**Optional Columns:** `artifact_type`, `host_id`, `user`, `signed`, `size_bytes`, `download_url`, `first_seen`, `cluster_hint`

**Inference Rules:** extension `.ps1|.vbs|.js` → SCRIPT; macros flagged via internal parser; Download path pattern `/Users/*/Downloads/` → DOWNLOAD.

---
## 31. Security Considerations (Frontend)
- Sanitize all user-facing strings (avoid innerHTML; use text content only).
- Mask webhook URL after save (show last 6 chars).
- Prevent oversized JSON logging (truncate to safe length in dev tools panel).
- Implement CSRF token if cookies introduced (not in MVP if pure token header auth).

---
## 32. Telemetry (Optional Future)
- Time to first summary render
- Artifact table filter usage frequency
- Override frequency distribution
- Slack alert click-through (tracked via special redirect URL)

---
## 33. Copywriting Guidelines
Tone: Calm, direct, supportive.
Patterns:
- Use present tense (“Appears on 4 hosts”).
- Avoid fear (“Critical breach”) → prefer factual (“Observed on finance server; review recommended”).
- Provide action before reasoning when urgent (“Contain hosts; lateral spread likely.”)

---
## 34. LLM Integration (Optional Panels)
If LLM refinement narrative appears:
- Display info badge: “Supplemental narrative generated under ambiguity gating; capped influence.”
- Offer toggle: Show / Hide LLM Narrative.

---
## 35. Internationalization (Future)
Design copy keys now (e.g., `ui.upload.cta`, `risk.badge.high`). English default; structure ready for locale map.

---
## 36. Open Questions / Deferred Decisions
| Topic | Decision Needed By | Notes |
|-------|--------------------|-------|
| Auth model | Post-MVP | Token vs OIDC |
| Batch retention UI | Phase 2 | Currently latest only |
| Email digest scheduling | Phase 2 | Cron vs external job |
| Light theme | Phase 2 | Demand-based |
| WebSocket push | Phase 2 | Replace polling for scale |

---
## 37. Implementation Order (Recommended Sprint Plan)
1. Shell + NavRail + Theme tokens
2. UploadWizard (CSV only) + Mock API
3. BatchReport fetch + Polling Hook
4. ArtifactTable + Drawer (static factors)
5. Executive Summary + Download (Markdown)
6. Slack Webhook Form + Test Delivery
7. Coverage Matrix + MITRE Delta highlighting
8. Cluster list + filter integration
9. Prevalence basic charts
10. Overrides persistence + UI
11. Calibration runner placeholder
12. Accessibility audit pass

---
## 38. Sample Markdown Report Export Structure
```
# Artifact Intelligence Executive Summary (Batch BATCH-2025-09-23-001)
Generated: 2025-09-23T14:02:00Z

## Posture
Elevated: 2 high-risk artifacts require attention.

## Top Artifacts
1. powerscan.exe – MALICIOUS (87) – Multi-host (4) – Rare
2. macro_payload.dotm – HIGH (72) – Macro execution factors

## Emerging Techniques
- T1059 (Command / Scripting)
- T1105 (Exfiltration Channel)

## Business Impact
Potential early-stage discovery and macro-based foothold risk in office endpoints.

## Recommended Actions
- Contain affected hosts (HR-LAPTOP-22, FIN-SVR-01)
- Block inbound macro-enabled documents from external senders
- Review Cluster #12 for lateral tooling variants

## Confidence
High (low ambiguity; consistent factor signals).

---
```

---
## 39. Testing Strategy (Frontend)
- Unit: rendering of RiskBadge, factor accordion expansion, polling hook behavior (mock timers)
- Integration: UploadWizard end-to-end parse (stub file object), override flow
- Accessibility: axe-core scan for critical violations
- Performance: Lighthouse target ≥ 80 performance & ≥ 95 accessibility (desktop)

---
## 40. Ready-for-Opus Prompt Snippet
> Generate React (Vite) scaffold implementing: Theme tokens (above), `AppShell` with NavRail (sections), `UploadWizard` (step 1 placeholder), `RiskBadge` component (code provided), route structure for `/executive`, `/upload`, `/coverage`, `/clusters`. Provide TypeScript interfaces from Section 9. Include polling hook from Section 29. Use Zustand store for `batches` + `artifacts`. Dark theme CSS variables per Section 6.

Use this spec as ground truth. Expand only where ambiguity exists—follow naming as given.

---
## 41. Acceptance Criteria (Spec Completeness)
- All enumerated sections 1–41 present
- Provides consistent naming for risk buckets & factor categories
- Includes minimal code examples & a generation prompt
- Distinguishes MVP vs Phase 2
- Clear file format & API contracts
- Brand theme tokens list complete
- Accessibility guidelines explicit

---
## 42. Next Steps (Post-Spec)
1. Approve spec (light adjustments ok) → tag `v0.1-ui-spec`.
2. Generate initial scaffold (LLM or manual) → commit as `frontend/`.
3. Wire real backend endpoints.
4. Conduct first usability review with non-technical reader.
5. Iterate on copy + add calibration & prevalence depth.

---
END OF SPEC
