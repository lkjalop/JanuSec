# JanusSec case workspace: UX direction

The replacement is case-first and evidence-first. It uses one server-owned
`janusec.case-evidence-view/v1` projection so claims, evidence, graph, timeline,
retrieval trace, analyst decisions, and approved actions cannot drift between pages.

## Desktop

```text
┌──────────────┬──────────────────────────────────────────────────────────────────────────────┐
│ JANUSSEC     │ TENANT / CASE-1042                 As known at [2026-08-18 14:30] [Refresh] │
│              │ Suspected identity-to-cloud compromise · Evidence still incomplete          │
│ Cases        ├────────────┬────────────┬────────────┬────────────┬──────────────────────────┤
│ New run      │ Breach     │ Evidence   │ Exposure   │ Impact     │ Urgency                  │
│ Integrations │ suspected  │ 71%        │ high       │ unknown    │ review required          │
│ Health       ├────────────┴────────────┴────────────┴────────────┴──────────────────────────┤
│              │ ! GAPS  Missing EDR 10:02–10:31 · CloudTrail delayed 19m                    │
│              ├──────────────────────────────────────────────────────────────────────────────┤
│              │ Claims & evidence | Causal graph | Timeline | Retrieval | Decisions/actions │
│              ├────────────────────┬────────────────────────────────┬────────────────────────┤
│              │ CLAIMS             │ EVIDENCE / GRAPH / TIMELINE    │ INSPECTOR              │
│              │ ▸ Token replay     │ 10:04 Identity success         │ Selected evidence      │
│              │   inferred · 82%   │ 10:07 Configured role exposure │ occurred: 10:04:11     │
│              │   8 support / 2 ↯  │ 10:11 Candidate device match   │ known:    10:23:08     │
│              │ ▸ Data access      │ ─ ─ candidate, not merged ─ ─  │ source + raw hash      │
│              │   unreviewed       │ 10:16 Observed API download    │ support / contradiction│
│              │                    │                                │ lineage + versions     │
└──────────────┴────────────────────┴────────────────────────────────┴────────────────────────┘
```

## Inbox / new assessment

```text
┌──────────────┬──────────────────────────────────────────────────────────────────────────────┐
│ JANUSSEC     │ CASE INBOX                                                        [New run] │
│ Cases        ├──────────────────────────────────────────────────────────────────────────────┤
│ New run      │ assessment-...   running   normalize   42%   18,440 rows   3 sensor gaps    │
│ Integrations │ assessment-...   ready     complete   100%   7,211 rows   analyst review   │
│ Health       │ assessment-...   failed    capture      3%        0 rows   inspect failure  │
│              ├──────────────────────────────────────────────────────────────────────────────┤
│              │ Drop CSV / JSON / JSONL / XLSX                                             │
│              │ Capture → Parse → Normalize → Analyze (same DAG for every entry path)       │
└──────────────┴──────────────────────────────────────────────────────────────────────────────┘
```

## Narrow screen

```text
┌─────────────────────────────┐
│ J  Cases  New  Health       │
├─────────────────────────────┤
│ CASE-1042          [Refresh]│
│ [Breach] [Evidence] [Impact]│
│ ! 2 coverage gaps           │
├─────────────────────────────┤
│ Claims | Graph | Timeline › │
├─────────────────────────────┤
│ Token replay · inferred 82% │
│ Evidence row ...            │
│ Evidence row ...            │
├─────────────────────────────┤
│ INSPECTOR (bottom drawer)   │
│ provenance / contradictions │
└─────────────────────────────┘
```

The graph accepts only typed backend edges. Shared IP, username, hostname, PID,
or email subject may create a candidate-match edge, never an identity merge or
observed-causal edge.

