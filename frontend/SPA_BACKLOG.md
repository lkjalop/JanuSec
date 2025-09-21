# SPA Backlog & Architecture Notes

## Phase 2 (Interactive SPA)
- Tech: Vite + React + TypeScript
- Layout: Sidebar (Navigation) + Main content pane + Live metric mini-panels
- Pages:
  1. Dashboard (latency, queue, alert rate, fallback usage)
  2. Decisions Explorer (filter by verdict, confidence range, time window)
  3. Alert Drill-Down (playbook outcome, custody chain, factors timeline)
  4. Factor Intelligence (top factors, similarity search, embedding visualization)
  5. Risk Register Viewer (link each risk to related metrics & mitigation status)
  6. Settings (thresholds preview, feature flags, Slack config test)

### Component Sketch
- <AppShell/>
- <DecisionTable/>, <DecisionFilters/>
- <AlertDetail/>
- <FactorSearch/>, <FactorHeatmap/>
- <CustodyChainTimeline/>
- <MetricSparkline/>

### Data Fetch Strategy
- REST + SSE hybrid:
  - SSE `/stream/decisions` for incremental append to decision table
  - REST for historical page loads
- Cache layer: in-memory LRU per route (10 min TTL) to reduce DB pressure

### State Management
- React Query (TanStack) for caching/fetch retries
- SSE events normalized into a store (context or Zustand) feeding components

### Auth & Security
- API key or JWT header support (future); hide keys client-side via backend proxy
- Rate limiting on NLP & factor endpoints
- Audit logging for admin configuration changes

### Performance Targets
- Initial load < 2s
- Incremental decision row append < 200ms from event arrival
- ≤ 60 FPS for custody chain timeline interactions

## Phase 3 (Advanced / NLP Overlay)
- Natural language search side panel
- Semantic navigation: “Show lateral movement patterns last 6h with high confidence”
- Factor embedding projection (UMAP) interactive canvas
- Analyst feedback tagging (TP / FP) loops into adaptive tuner
- Multi-tenant scoping (org_id isolation) – DB schema adds org_id columns

### Future Enhancements
- Graph view (entities: host, user, process, IP) with suspicious edge highlighting
- Playbook simulation mode (dry-run) UI
- Inline risk scoring badge per decision row (color-coded)
- One-click export to incident ticket (ServiceNow/Jira integration stubs)

## Open Questions
- Do we standardize factor taxonomy before building heatmaps?
- Should embeddings be cached per factor or per (factor,event) pair? (Current: per event-factor)
- Governance UI for config digests & custody chain verification snapshots

## Milestone Acceptance Criteria
- Phase 2 MVP: Real-time decision table, alert drill-down, factor search, risk register link, metrics dashboard sections.
- Phase 3 MVP: NLP panel returning DSL + results, semantic similarity pivots, analyst feedback capture.
