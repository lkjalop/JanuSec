# Option C: Full-Featured Demo - Implementation Guide

**Timeline:** 16-20 hours (2-3 days)
**Effort:** HIGH
**Demo Impact:** VERY HIGH
**Risk:** MEDIUM-HIGH

---

## 📋 Executive Summary

Option C is the **complete vision** - everything from Option B plus real historical context, HopGraph attack reconstruction, and vector database for log search. This transforms the platform from "fast triage tool" to "autonomous threat hunter" that learns from past incidents and reconstructs multi-stage attacks automatically.

### What Makes This Different from Option B?

| Feature | Option B | Option C |
|---------|----------|----------|
| Historical Context | Stubbed ("coming soon") | **Real queries to incidents DB** |
| HopGraph | Teaser button | **Full attack graph visualization** |
| Vector DB / RAG | None | **Semantic log search** |
| Confidence Scoring | Backend only | **UI display with explanation** |
| ML Threat Scoring | None | **Optional: Behavioral anomaly detection** |
| Automated Remediation | None | **Optional: One-click containment** |

---

## 🎯 Core Features (Must-Have)

### Feature 1: Historical Incident Querying

#### Problem Statement

When an analyst sees a suspicious artifact, the first question is: **"Have we seen this before?"**

Without historical context:
- ❌ Analysts re-investigate known threats (waste time)
- ❌ Miss patterns (same malware family across hosts)
- ❌ Can't measure recurrence (compliance metrics)

With historical querying:
- ✅ "Similar incident 14 days ago on HOST-042: confirmed Emotet"
- ✅ "This SHA256 escalated to ransomware 3 times in past 90 days"
- ✅ Auto-escalate if historical outcome = malicious

#### Implementation Details

**File:** `src/repositories/historical_incidents_repo.py` (NEW)

```python
"""
Historical incident repository - query past alerts and outcomes.
Enables pattern detection, recurrence analysis, and learning from past investigations.
"""

import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json


class HistoricalIncidentsRepo:
    def __init__(self, db_path: str = 'janusec_dev.db'):
        self.db_path = db_path
        self._init_schema()

    def _init_schema(self):
        """Create historical incidents table if not exists."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS historical_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                process_name TEXT,
                host TEXT,
                user_account TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                domain TEXT,
                mitre_tags TEXT,  -- JSON array
                factors TEXT,  -- JSON array
                dread_score REAL,
                correlation_score REAL,
                verdict TEXT,
                outcome TEXT,  -- 'benign', 'confirmed_malicious', 'false_positive', 'unknown'
                remediation_actions TEXT,  -- JSON array
                analyst_notes TEXT,
                escalated BOOLEAN DEFAULT 0,
                incident_id TEXT,
                first_seen_at DATETIME,
                last_seen_at DATETIME,
                occurrence_count INTEGER DEFAULT 1,
                org TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Indexes for fast lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sha256 ON historical_incidents(sha256)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_process ON historical_incidents(process_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host ON historical_incidents(host)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON historical_incidents(src_ip, dst_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_outcome ON historical_incidents(outcome)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_first_seen ON historical_incidents(first_seen_at)')

        conn.commit()
        conn.close()

    def save_incident(self, row: Dict[str, Any], outcome: str, analyst_notes: str = '') -> int:
        """
        Save or update an incident in historical database.

        Args:
            row: Artifact row
            outcome: 'benign', 'confirmed_malicious', 'false_positive', 'unknown'
            analyst_notes: Optional notes from analyst

        Returns:
            Incident ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        sha256 = row.get('sha256') or row.get('hash_sha256', '')
        process_name = row.get('process_name', '')

        # Check if incident already exists (by SHA256 or process_name+host)
        cursor.execute('''
            SELECT id, occurrence_count, first_seen_at
            FROM historical_incidents
            WHERE (sha256 = ? AND sha256 != '') OR (process_name = ? AND host = ?)
            ORDER BY created_at DESC LIMIT 1
        ''', (sha256, process_name, row.get('host', '')))

        existing = cursor.fetchone()

        if existing:
            # Update existing incident
            incident_id, occurrence_count, first_seen = existing
            cursor.execute('''
                UPDATE historical_incidents
                SET last_seen_at = datetime('now'),
                    occurrence_count = ?,
                    outcome = ?,
                    analyst_notes = ?,
                    escalated = ?
                WHERE id = ?
            ''', (
                occurrence_count + 1,
                outcome,
                analyst_notes,
                1 if row.get('escalated') else 0,
                incident_id
            ))
            conn.commit()
            conn.close()
            return incident_id
        else:
            # Insert new incident
            cursor.execute('''
                INSERT INTO historical_incidents (
                    sha256, process_name, host, user_account,
                    src_ip, dst_ip, domain,
                    mitre_tags, factors,
                    dread_score, correlation_score, verdict, outcome,
                    analyst_notes, escalated, incident_id,
                    first_seen_at, last_seen_at, org
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)
            ''', (
                sha256,
                process_name,
                row.get('host', ''),
                row.get('user', ''),
                row.get('src_ip', ''),
                row.get('dst_ip', ''),
                row.get('domain', ''),
                json.dumps(row.get('mitre_tags', [])),
                json.dumps(row.get('factors', [])),
                float(row.get('_dread', {}).get('score', 0) if isinstance(row.get('_dread'), dict) else 0),
                float(row.get('_correlation', {}).get('score', 0) if isinstance(row.get('_correlation'), dict) else 0),
                row.get('verdict', ''),
                outcome,
                analyst_notes,
                1 if row.get('escalated') else 0,
                row.get('incident_id', ''),
                row.get('org', 'default')
            ))

            incident_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return incident_id

    def query_similar_incidents(
        self,
        row: Dict[str, Any],
        lookback_days: int = 90,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find similar historical incidents based on multiple criteria.

        Similarity criteria (in priority order):
        1. Exact SHA256 match (highest confidence)
        2. Same process name + host (medium confidence)
        3. Same MITRE techniques (lower confidence)
        4. Same IP address (network artifacts)

        Args:
            row: Current artifact to search for
            lookback_days: How far back to search
            limit: Max results to return

        Returns:
            List of similar incidents with similarity scores
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        sha256 = row.get('sha256') or row.get('hash_sha256', '')
        process_name = row.get('process_name', '')
        host = row.get('host', '')
        src_ip = row.get('src_ip', '')
        dst_ip = row.get('dst_ip', '')
        mitre_tags = set(row.get('mitre_tags', []))

        cutoff_date = (datetime.now() - timedelta(days=lookback_days)).isoformat()

        # Priority 1: Exact SHA256 match
        if sha256:
            cursor.execute('''
                SELECT *, 1.0 as similarity_score, 'sha256_match' as match_type
                FROM historical_incidents
                WHERE sha256 = ? AND first_seen_at >= ?
                ORDER BY last_seen_at DESC
                LIMIT ?
            ''', (sha256, cutoff_date, limit))

            results = [dict(row) for row in cursor.fetchall()]
            if results:
                conn.close()
                return results

        # Priority 2: Process name + host match
        if process_name and host:
            cursor.execute('''
                SELECT *, 0.8 as similarity_score, 'process_host_match' as match_type
                FROM historical_incidents
                WHERE process_name = ? AND host = ? AND first_seen_at >= ?
                ORDER BY last_seen_at DESC
                LIMIT ?
            ''', (process_name, host, cutoff_date, limit))

            results = [dict(row) for row in cursor.fetchall()]
            if results:
                conn.close()
                return results

        # Priority 3: MITRE technique overlap (at least 2 common techniques)
        if mitre_tags:
            cursor.execute('''
                SELECT *, 0.6 as similarity_score, 'mitre_overlap' as match_type
                FROM historical_incidents
                WHERE first_seen_at >= ?
                ORDER BY last_seen_at DESC
                LIMIT ?
            ''', (cutoff_date, limit * 2))  # Get more candidates for filtering

            candidates = [dict(row) for row in cursor.fetchall()]
            results = []

            for candidate in candidates:
                candidate_mitre = set(json.loads(candidate['mitre_tags'] or '[]'))
                overlap = mitre_tags & candidate_mitre
                if len(overlap) >= 2:
                    candidate['similarity_score'] = 0.6 + (0.1 * len(overlap))
                    candidate['mitre_overlap'] = list(overlap)
                    results.append(candidate)

            if results:
                conn.close()
                return sorted(results, key=lambda x: x['similarity_score'], reverse=True)[:limit]

        # Priority 4: IP address match (network artifacts)
        if src_ip or dst_ip:
            ip = src_ip or dst_ip
            cursor.execute('''
                SELECT *, 0.5 as similarity_score, 'ip_match' as match_type
                FROM historical_incidents
                WHERE (src_ip = ? OR dst_ip = ?) AND first_seen_at >= ?
                ORDER BY last_seen_at DESC
                LIMIT ?
            ''', (ip, ip, cutoff_date, limit))

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results

        conn.close()
        return []

    def get_recurrence_stats(self, sha256: str = None, process_name: str = None) -> Dict[str, Any]:
        """
        Get recurrence statistics for an artifact.

        Returns:
            {
                'total_occurrences': int,
                'unique_hosts': int,
                'outcomes': {'confirmed_malicious': 5, 'benign': 2, ...},
                'first_seen': datetime,
                'last_seen': datetime,
                'avg_dread_score': float
            }
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        where_clause = 'sha256 = ?' if sha256 else 'process_name = ?'
        param = sha256 if sha256 else process_name

        cursor.execute(f'''
            SELECT
                SUM(occurrence_count) as total_occurrences,
                COUNT(DISTINCT host) as unique_hosts,
                MIN(first_seen_at) as first_seen,
                MAX(last_seen_at) as last_seen,
                AVG(dread_score) as avg_dread_score
            FROM historical_incidents
            WHERE {where_clause}
        ''', (param,))

        stats = cursor.fetchone()

        # Get outcome breakdown
        cursor.execute(f'''
            SELECT outcome, COUNT(*) as count
            FROM historical_incidents
            WHERE {where_clause}
            GROUP BY outcome
        ''', (param,))

        outcomes = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        return {
            'total_occurrences': stats[0] or 0,
            'unique_hosts': stats[1] or 0,
            'first_seen': stats[2],
            'last_seen': stats[3],
            'avg_dread_score': stats[4] or 0,
            'outcomes': outcomes
        }


# Singleton instance
HISTORICAL_REPO = HistoricalIncidentsRepo()
```

**File:** `src/analysis/auto_llm.py` (UPDATE)

Integrate historical context into Tier 2 prompt:

```python
def build_tier2_prompt(row: Dict[str, Any], context: Dict[str, Any], domain: str) -> str:
    # ... existing code ...

    from src.repositories.historical_incidents_repo import HISTORICAL_REPO

    # Query historical incidents
    similar_incidents = HISTORICAL_REPO.query_similar_incidents(row, lookback_days=90, limit=5)

    historical_context = ""
    if similar_incidents:
        incident = similar_incidents[0]
        days_ago = (datetime.now() - datetime.fromisoformat(incident['last_seen_at'])).days

        historical_context = f"""
⚠️ HISTORICAL CONTEXT ALERT:

Similar incident detected {days_ago} days ago:
- Host: {incident['host']}
- Outcome: {incident['outcome'].upper()}
- DREAD: {incident['dread_score']:.1f}
- Occurrences: {incident['occurrence_count']}
- Match Type: {incident['match_type']}
- Similarity: {incident['similarity_score']:.0%}

Analyst Notes from Previous Investigation:
{incident['analyst_notes'] or 'No notes recorded'}
"""

        # Auto-escalate if previous outcome was malicious
        if incident['outcome'] == 'confirmed_malicious':
            historical_context += "\n🚨 AUTO-ESCALATE: Previous instance confirmed malicious.\n"

        # Show recurrence pattern
        if incident['occurrence_count'] > 3:
            historical_context += f"\n⚠️ RECURRENCE PATTERN: This artifact has appeared {incident['occurrence_count']} times.\n"

    else:
        historical_context = "✅ No similar incidents found in past 90 days (novel threat or first occurrence).\n"

    prompt = f"""...

{historical_context}

...
"""

    return prompt
```

**Why This Matters:**

**SOC Analyst Benefit:**
- ✅ Instant context ("we saw this 2 weeks ago - it was ransomware")
- ✅ Learn from past investigations (analyst notes preserved)
- ✅ Reduce duplicate work (don't re-investigate known threats)
- ✅ Pattern detection (same malware family across hosts)

**Business Benefit:**
- 💰 Time savings: 30 min/re-investigation × 20 duplicates/month = 10 hours/month saved
- 📊 Compliance metrics (show recurrence rates, MTTR trends)
- 🎯 Justify log retention ("historical data caught repeat attack")

**Security Benefit:**
- 🔍 Campaign detection (same SHA256 across 5 hosts = coordinated attack)
- 📈 Threat trending (Emotet detections increasing)
- 🚫 Prevent re-infection (auto-escalate known malware)

**Market Benefit:**
- 🏆 "Institutional memory" = unique differentiator
- 📚 "Learn from past incidents" = AI narrative
- 🎯 Enterprise requirement (compliance needs historical audit)

---

### Feature 2: Full HopGraph Attack Reconstruction

#### Problem Statement

Correlation score tells you "this is related to other entities" but doesn't show **what** or **how**.

Without HopGraph:
- ❌ Analysts manually query logs to find parent processes, network connections
- ❌ Miss multi-hop attacks (A → B → C → D lateral movement)
- ❌ Can't explain correlation score to management

With HopGraph:
- ✅ Visual graph shows powershell.exe → network connection → DC compromise
- ✅ Temporal timeline ("attack started 14:32, escalated 14:45")
- ✅ Export graph for reports

#### Implementation Details

**File:** `src/core/graph/hopgraph_integration.py` (NEW)

```python
"""
HopGraph integration - query and visualize attack graphs.
Connects to existing HopGraph Lite implementation.
"""

from typing import Dict, List, Any, Optional
import json


def query_attack_graph(
    row: Dict[str, Any],
    max_hops: int = 3,
    time_window_hours: int = 24
) -> Dict[str, Any]:
    """
    Query HopGraph for related entities and build attack graph.

    Args:
        row: Artifact row (starting node)
        max_hops: Maximum graph traversal depth
        time_window_hours: Time window for correlation

    Returns:
        {
            'nodes': [...],
            'edges': [...],
            'paths': [...],
            'timeline': [...]
        }
    """
    from src.core.graph.hopgraph_lite import HopGraphLite

    graph = HopGraphLite()

    # Build starting node from artifact
    start_node = {
        'id': row.get('sha256') or row.get('process_name') or row.get('src_ip'),
        'type': _detect_node_type(row),
        'label': row.get('process_name') or row.get('src_ip'),
        'properties': {
            'host': row.get('host'),
            'user': row.get('user'),
            'timestamp': row.get('timestamp'),
            'dread_score': row.get('_dread', {}).get('score', 0)
        }
    }

    # Query related entities
    related = graph.find_related_entities(
        start_node['id'],
        max_hops=max_hops,
        time_window_hours=time_window_hours
    )

    # Build nodes and edges
    nodes = [start_node]
    edges = []

    for entity in related:
        nodes.append({
            'id': entity['id'],
            'type': entity['type'],
            'label': entity['label'],
            'properties': entity.get('properties', {})
        })

        edges.append({
            'source': entity.get('parent_id', start_node['id']),
            'target': entity['id'],
            'type': entity.get('relationship', 'unknown'),
            'timestamp': entity.get('timestamp')
        })

    # Detect attack paths (sequences of suspicious nodes)
    paths = _detect_attack_paths(nodes, edges)

    # Build temporal timeline
    timeline = _build_timeline(nodes, edges)

    return {
        'nodes': nodes,
        'edges': edges,
        'paths': paths,
        'timeline': timeline,
        'correlation_explanation': _explain_correlation(nodes, edges)
    }


def _detect_node_type(row: Dict[str, Any]) -> str:
    """Detect node type from artifact attributes."""
    if row.get('process_name') or row.get('file_path'):
        return 'process'
    elif row.get('src_ip') or row.get('dst_ip'):
        return 'network'
    elif row.get('registry_key'):
        return 'registry'
    elif row.get('file_path'):
        return 'file'
    else:
        return 'unknown'


def _detect_attack_paths(nodes: List[Dict], edges: List[Dict]) -> List[List[str]]:
    """
    Detect suspicious paths through the graph.

    Returns list of paths, e.g.:
    [
        ['powershell.exe', 'network_connection', 'C2_server'],
        ['registry_modification', 'scheduled_task', 'persistence']
    ]
    """
    paths = []

    # Simple path detection: follow edges from high-DREAD nodes
    suspicious_nodes = [n for n in nodes if n['properties'].get('dread_score', 0) >= 6]

    for node in suspicious_nodes:
        path = [node['id']]
        current_id = node['id']

        # Follow edges up to 5 hops
        for _ in range(5):
            next_edge = next((e for e in edges if e['source'] == current_id), None)
            if not next_edge:
                break
            path.append(next_edge['target'])
            current_id = next_edge['target']

        if len(path) > 1:
            paths.append(path)

    return paths


def _build_timeline(nodes: List[Dict], edges: List[Dict]) -> List[Dict[str, Any]]:
    """
    Build temporal timeline of attack events.

    Returns:
    [
        {'timestamp': '2025-01-22T14:32:00', 'event': 'powershell.exe spawned', 'severity': 'medium'},
        {'timestamp': '2025-01-22T14:45:00', 'event': 'network connection to C2', 'severity': 'high'},
        ...
    ]
    """
    events = []

    for edge in edges:
        if edge.get('timestamp'):
            source_node = next((n for n in nodes if n['id'] == edge['source']), None)
            target_node = next((n for n in nodes if n['id'] == edge['target']), None)

            if source_node and target_node:
                events.append({
                    'timestamp': edge['timestamp'],
                    'event': f"{source_node['label']} → {edge['type']} → {target_node['label']}",
                    'severity': _classify_severity(source_node, target_node, edge)
                })

    # Sort chronologically
    events.sort(key=lambda e: e['timestamp'])

    return events


def _classify_severity(source: Dict, target: Dict, edge: Dict) -> str:
    """Classify event severity based on nodes and edge type."""
    # High severity: credential access, lateral movement, C2
    high_severity_edges = {'credential_access', 'lateral_movement', 'c2_connection'}
    if edge['type'] in high_severity_edges:
        return 'high'

    # Medium severity: process creation, registry modification
    medium_severity_edges = {'process_creation', 'registry_modification', 'file_modification'}
    if edge['type'] in medium_severity_edges:
        return 'medium'

    # Low severity: everything else
    return 'low'


def _explain_correlation(nodes: List[Dict], edges: List[Dict]) -> str:
    """
    Generate human-readable explanation of correlation score.

    Example:
    "Correlation score 0.73 because:
    - powershell.exe spawned by suspicious parent (excel.exe)
    - Network connection to known C2 IP (203.0.113.42)
    - Registry persistence modification detected
    3 related entities within 15-minute window"
    """
    explanation = "Correlation score calculated from:\n"

    # Count suspicious relationships
    suspicious_count = len([e for e in edges if e['type'] in {'credential_access', 'lateral_movement', 'c2_connection'}])
    if suspicious_count > 0:
        explanation += f"- {suspicious_count} high-risk relationships detected\n"

    # Count unique node types
    node_types = set(n['type'] for n in nodes)
    explanation += f"- {len(node_types)} different entity types involved ({', '.join(node_types)})\n"

    # Time window
    if edges:
        timestamps = [e['timestamp'] for e in edges if e.get('timestamp')]
        if timestamps:
            from datetime import datetime
            times = [datetime.fromisoformat(t) for t in timestamps]
            duration = (max(times) - min(times)).total_seconds() / 60
            explanation += f"- Events occurred within {duration:.0f}-minute window\n"

    explanation += f"- Total entities: {len(nodes)}, relationships: {len(edges)}"

    return explanation
```

**File:** `frontend/static/csv_deep_analysis.html` (UPDATE)

Replace HopGraph teaser with real implementation:

```html
<div class="panel">
  <h3>🕸️ Attack Graph Reconstruction</h3>

  <div id="hopgraphContainer">
    <div id="graphCanvas" style="width:100%; height:500px; border:1px solid var(--border); border-radius:6px;">
      <!-- D3.js or Cytoscape.js graph will render here -->
    </div>

    <div class="graph-controls" style="margin-top:12px; display:flex; gap:8px;">
      <button class="btn" onclick="expandGraph()">Expand (+1 hop)</button>
      <button class="btn" onclick="collapseGraph()">Collapse</button>
      <button class="btn" onclick="exportGraphImage()">Export PNG</button>
      <button class="btn" onclick="showTimeline()">Timeline View</button>

      <label style="margin-left:auto;">
        Time Window:
        <select id="timeWindow" onchange="updateGraph()">
          <option value="1">1 hour</option>
          <option value="24" selected>24 hours</option>
          <option value="168">7 days</option>
        </select>
      </label>
    </div>

    <!-- Timeline view (hidden by default) -->
    <div id="timelineView" style="display:none; margin-top:20px;">
      <h4>Attack Timeline</h4>
      <div id="timelineEvents"></div>
    </div>

    <!-- Correlation explanation -->
    <div class="panel" style="margin-top:16px;">
      <h4>Correlation Score Explanation</h4>
      <pre id="correlationExplanation" style="white-space:pre-wrap; font-size:13px;"></pre>
    </div>
  </div>
</div>

<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
// Global graph data
var graphData = null;
var currentHops = 3;

async function loadAttackGraph() {
  var rowIndex = parseInt(localStorage.getItem('csv_deep_row') || '0', 10);
  var rows = JSON.parse(localStorage.getItem('csv_last_results') || '[]');
  var row = rows[rowIndex];

  var resp = await fetch('/api/v1/graph/attack_reconstruction', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', ...authHeaders()},
    body: JSON.stringify({
      row: row,
      max_hops: currentHops,
      time_window_hours: parseInt(document.getElementById('timeWindow').value)
    })
  });

  if (resp.ok) {
    graphData = await resp.json();
    renderGraph(graphData);
    renderCorrelationExplanation(graphData.correlation_explanation);
  }
}

function renderGraph(data) {
  // D3.js force-directed graph
  var width = document.getElementById('graphCanvas').clientWidth;
  var height = 500;

  var svg = d3.select('#graphCanvas').html('').append('svg')
    .attr('width', width)
    .attr('height', height);

  // Build links and nodes
  var links = data.edges.map(function(e){
    return {source: e.source, target: e.target, type: e.type};
  });

  var nodes = data.nodes.map(function(n){
    return {id: n.id, label: n.label, type: n.type, ...n.properties};
  });

  // Force simulation
  var simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2));

  // Render links
  var link = svg.append('g')
    .selectAll('line')
    .data(links)
    .enter().append('line')
    .attr('stroke', '#999')
    .attr('stroke-width', 2);

  // Render nodes
  var node = svg.append('g')
    .selectAll('circle')
    .data(nodes)
    .enter().append('circle')
    .attr('r', 10)
    .attr('fill', function(d){
      if (d.dread_score >= 7) return '#ff4444';
      if (d.dread_score >= 4) return '#ffaa44';
      return '#44ff44';
    })
    .call(d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended));

  // Node labels
  var label = svg.append('g')
    .selectAll('text')
    .data(nodes)
    .enter().append('text')
    .text(d => d.label)
    .attr('font-size', 10)
    .attr('dx', 12)
    .attr('dy', 4);

  // Update positions on tick
  simulation.on('tick', function(){
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);

    node
      .attr('cx', d => d.x)
      .attr('cy', d => d.y);

    label
      .attr('x', d => d.x)
      .attr('y', d => d.y);
  });

  // Drag functions
  function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }
}

function renderCorrelationExplanation(explanation) {
  document.getElementById('correlationExplanation').textContent = explanation;
}

function showTimeline() {
  if (!graphData || !graphData.timeline) return;

  var timelineDiv = document.getElementById('timelineView');
  timelineDiv.style.display = 'block';

  var html = '<div class="timeline-container">';
  graphData.timeline.forEach(function(event){
    var severityClass = 'severity-' + event.severity;
    html += '<div class="timeline-event ' + severityClass + '">';
    html += '<span class="event-time">' + event.timestamp + '</span>';
    html += '<span class="event-desc">' + event.event + '</span>';
    html += '<span class="event-severity">' + event.severity.toUpperCase() + '</span>';
    html += '</div>';
  });
  html += '</div>';

  document.getElementById('timelineEvents').innerHTML = html;
}

// Load graph on page load
window.addEventListener('DOMContentLoaded', function(){
  loadAttackGraph();
});
</script>

<style>
.timeline-event {
  padding: 8px 12px;
  margin: 6px 0;
  border-left: 4px solid #999;
  background: rgba(255,255,255,0.02);
  border-radius: 4px;
  display: flex;
  gap: 12px;
}
.timeline-event.severity-high {
  border-left-color: #ff4444;
}
.timeline-event.severity-medium {
  border-left-color: #ffaa44;
}
.event-time {
  font-family: monospace;
  font-size: 12px;
  color: var(--text-muted);
  min-width: 180px;
}
.event-desc {
  flex: 1;
}
.event-severity {
  font-size: 11px;
  font-weight: bold;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(255,255,255,0.1);
}
</style>
```

**Why This Matters:**

**SOC Analyst Benefit:**
- ✅ Visual understanding of attack (no manual log correlation)
- ✅ Multi-hop attack detection (catch APTs, not just malware)
- ✅ Timeline shows attack progression (when did lateral movement start?)
- ✅ Export graphs for incident reports

**Business Benefit:**
- 📊 Visual reports for management (executives understand graphs)
- 🎯 Justify SIEM investment ("correlation detects multi-stage attacks")
- 📈 Metrics: "Detected 12-hop attack chain in 5 minutes"

**Security Benefit:**
- 🔗 Complete attack chain visibility (initial access → exfiltration)
- 🚨 Early detection (see attack in progress, not after)
- 🎯 Targeted remediation (isolate all affected hosts)

**Market Benefit:**
- 🏆 Attack graph = killer demo feature (screenshots sell)
- 🎨 "Google-like search graph for security" = marketing gold
- 🔬 Research partnerships (universities want graph data)

---

### Feature 3: Vector Database / RAG for Historical Logs

#### Problem Statement

Searching historical logs is slow (grep/SQL text search).

RAG (Retrieval Augmented Generation) enables:
- ✅ Semantic search ("find credential dumping attempts" instead of exact keywords)
- ✅ Similar log pattern matching
- ✅ LLM-powered log summarization

#### Implementation Details

**File:** `src/integrations/vector_db.py` (NEW)

```python
"""
Vector database integration for semantic log search.
Uses sentence-transformers for embeddings + ChromaDB for storage.
"""

from typing import List, Dict, Any
import chromadb
from sentence_transformers import SentenceTransformer

class VectorLogSearch:
    def __init__(self):
        self.client = chromadb.Client()
        self.collection = self.client.get_or_create_collection("security_logs")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # Fast, lightweight

    def index_logs(self, logs: List[Dict[str, Any]]):
        """
        Index security logs into vector database.

        Args:
            logs: List of log entries with 'id', 'timestamp', 'message', 'metadata'
        """
        documents = [log['message'] for log in logs]
        ids = [log['id'] for log in logs]
        metadatas = [log.get('metadata', {}) for log in logs]

        embeddings = self.model.encode(documents).tolist()

        self.collection.add(
            embeddings=embeddings,
            documents=documents,
            ids=ids,
            metadatas=metadatas
        )

    def search_similar_logs(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Semantic search for similar log entries.

        Args:
            query: Natural language query (e.g., "credential dumping attempts")
            top_k: Number of results to return

        Returns:
            List of similar log entries with similarity scores
        """
        query_embedding = self.model.encode([query]).tolist()

        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=top_k
        )

        return [
            {
                'id': results['ids'][0][i],
                'message': results['documents'][0][i],
                'metadata': results['metadatas'][0][i],
                'similarity': results['distances'][0][i]
            }
            for i in range(len(results['ids'][0]))
        ]
```

**Why This Matters:**

**SOC Analyst Benefit:**
- ✅ Find similar incidents without exact keywords
- ✅ "Show me all lateral movement attempts" (semantic understanding)
- ✅ Learn from similar past investigations

**Business Benefit:**
- 💡 Unlock value from historical log data
- 🎯 Justify log retention costs ("RAG enables threat hunting")

**Security Benefit:**
- 🔍 Discover unknown attack patterns
- 📊 Proactive threat hunting

**Market Benefit:**
- 🤖 "AI-powered log search" = buzzword compliance
- 🏅 Differentiation (competitors don't have RAG)

---

### Feature 4: Confidence Scoring UI

**Why This Matters:** Analysts need to know WHY platform made a decision.

**Implementation:**

```html
<div class="panel">
  <h3>🎯 Confidence Analysis</h3>

  <div class="confidence-breakdown">
    <div class="confidence-meter">
      <label>Overall Confidence:</label>
      <div class="meter-bar">
        <div class="meter-fill" style="width:87%;">87%</div>
      </div>
    </div>

    <h4>Confidence Factors:</h4>
    <ul class="factor-list">
      <li class="factor-item">
        <span class="factor-name">Domain Detection (Endpoint)</span>
        <span class="factor-score">95%</span>
        <span class="factor-reason">5 endpoint-specific factors present</span>
      </li>
      <li class="factor-item">
        <span class="factor-name">MITRE Mapping (T1055)</span>
        <span class="factor-score">90%</span>
        <span class="factor-reason">Process injection patterns detected</span>
      </li>
      <li class="factor-item">
        <span class="factor-name">Historical Match</span>
        <span class="factor-score">100%</span>
        <span class="factor-reason">Exact SHA256 match from 14 days ago</span>
      </li>
      <li class="factor-item">
        <span class="factor-name">Correlation Score</span>
        <span class="factor-score">73%</span>
        <span class="factor-reason">3 related entities within 15-min window</span>
      </li>
    </ul>
  </div>
</div>
```

---

## 🎁 Optional Enhancements (Choose 3-4)

### Enhancement 1: ML-Based Behavioral Anomaly Detection

**Effort:** +6 hours
**Value:** VERY HIGH

Train ML model to detect anomalies based on normal baseline.

**Use Case:**
- User normally logs in from US → login from Russia = anomaly
- Process normally runs during business hours → 3am execution = suspicious

**Implementation:** Use Isolation Forest or Autoencoder for anomaly detection.

---

### Enhancement 2: Automated Remediation (One-Click Containment)

**Effort:** +4 hours
**Value:** HIGH (Enterprise requirement)

**Features:**
- One-click host isolation (EDR API)
- Automated hash blocking (firewall/AV)
- Quarantine file (move to forensic directory)

**Safety:** Require approval for destructive actions.

---

### Enhancement 3: Threat Intelligence Feed Integration

**Effort:** +3 hours
**Value:** MEDIUM

Integrate with AlienVault OTX, MISP, or commercial TI feeds.

**Auto-escalate if:**
- SHA256 appears in APT report
- IP appears in botnet tracker
- Domain appears in phishing database

---

### Enhancement 4: Multi-Tenant Historical Analytics

**Effort:** +5 hours
**Value:** HIGH (for SaaS model)

Dashboard showing:
- "Your false positive rate: 12% (industry avg: 25%)"
- "Most common attack types in your environment"
- "Recurrence trend over time"

---

## 📊 Benefits Analysis

### SOC Analyst Benefits

| Benefit | Option B | Option C | Delta |
|---------|----------|----------|-------|
| Investigation time | -40% | **-60%** | +20% |
| Historical context | None | **Instant recall** | Game-changer |
| Attack understanding | Text description | **Visual graph** | Much clearer |
| Log search | Text/SQL | **Semantic RAG** | Faster discovery |
| Confidence | Backend only | **UI explanation** | Trust in system |

### Business Benefits

| Benefit | Option B | Option C | Delta |
|---------|----------|----------|-------|
| MTTR | 15 min | **10 min** | -33% |
| Training time | 3 days | **1 day** | Graph = intuitive |
| Historical value | None | **$100K/year** | Log retention ROI |
| Competitive moat | Medium | **Very High** | Hard to replicate |

### Security Benefits

| Benefit | Option B | Option C | Delta |
|---------|----------|----------|-------|
| Multi-stage detection | Manual correlation | **Automated graph** | APT detection |
| Recurrence prevention | Manual check | **Auto-escalate** | Stops reinfection |
| Log coverage | MITRE-mapped | **+RAG search** | Find unknown gaps |
| Threat hunting | Manual | **AI-assisted** | Proactive vs reactive |

---

## 🚀 Implementation Plan (16-20 hours)

### Day 1 (8 hours)
**Morning (4 hours):**
- Implement historical incidents repository
- Add query_similar_incidents() to Tier 2 prompt
- Test with mock historical data

**Afternoon (4 hours):**
- Implement HopGraph integration
- Build attack graph API endpoint
- Create D3.js graph visualization

### Day 2 (8 hours)
**Morning (4 hours):**
- Implement vector DB for log search
- Index sample logs
- Add semantic search to Tier 2 prompt

**Afternoon (4 hours):**
- Add confidence scoring UI
- Implement timeline view
- Polish graph controls (expand/collapse/export)

### Day 3 (4-8 hours - Optional Enhancements)
- Choose 3-4 enhancements
- Comprehensive testing
- CEO demo rehearsal

---

## 🎯 Success Criteria

- ✅ Historical queries return results in <200ms
- ✅ HopGraph renders 3-hop graphs with 50+ nodes smoothly
- ✅ Vector search finds relevant logs (precision >= 80%)
- ✅ Confidence UI explains all scoring factors
- ✅ Timeline view shows attack progression chronologically
- ✅ No crashes during CEO demo

---

## 📈 ROI Calculation

### Option C vs Option B

**Additional Investment:** 8 hours @ $38/hour = $304

**Additional Savings:**
- Historical context: 15 min/duplicate × 20/month = 5 hours/month = $1,900/year
- HopGraph visualization: 20 min/complex case × 10/month = 3.3 hours/month = $1,254/year
- RAG log search: 30 min/hunt × 5/month = 2.5 hours/month = $950/year

**Total Additional Savings:** $4,104/year

**Payback Period:** 18 days

---

## ✅ Next Steps

1. **Approve Option C** vs Option B tradeoffs
2. **Allocate 2-3 days** for implementation
3. **Prepare historical data** (seed 20-50 past incidents)
4. **Test HopGraph** with realistic multi-hop attack
5. **Schedule CEO demo** for Day 4

---

**This is the complete vision. Demonstrate this to CEO and you'll be untouchable.**

**Document Version:** 1.0
**Last Updated:** 2025-01-22
**Author:** Implementation Team
**Status:** READY FOR APPROVAL
