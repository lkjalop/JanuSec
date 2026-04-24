/* breach_swimlane.js — Standalone D3 bitemporal swimlane + mini HopGraph
 *
 * Exposed globals (called by breach.js after DOM is ready):
 *   BreachSwimlane.render(containerId, clusters, allRows, assessmentId)
 *   BreachHopGraph.render(containerId, cluster, allRows, assessmentId)
 *
 * Self-contained: does NOT depend on investigate.js state or IIFE internals.
 * Requires D3 v7 loaded before this file.
 */
(function (global) {
  'use strict';

  if (typeof d3 === 'undefined') {
    // D3 not loaded — provide stub so callers don't crash
    global.BreachSwimlane = { render: function () {} };
    global.BreachHopGraph  = { render: function () {} };
    return;
  }

  // ── Shared constants ──────────────────────────────────────────────────────────

  var SEV_COLOR = {
    critical: '#E54848',
    high:     '#FF8A3C',
    medium:   '#E0C446',
    low:      '#3FA860',
    info:     '#5B8FD4',
  };

  var VERDICT_COLOR = {
    'CONFIRMED':   '#E54848',
    'LIKELY REAL': '#FF8A3C',
    'LIKELY':      '#FF8A3C',
    'UNCERTAIN':   '#E0C446',
    'BENIGN':      '#3FA860',
  };

  // ── Timestamp extraction ──────────────────────────────────────────────────────
  // Matches temporal_rag.py _TS_FIELDS exactly

  var _TS_FIELDS = [
    'timestamp_utc', 'date_utc', 'timestamp_iso', 'source_time',
    'ts', 'timestamp', 'eventTime', 'time', 'createdDateTime',
    'activityDateTime', 'TimeGenerated', 'start', 'date', 'datetime',
    '@timestamp', 'event_time', 'UpdatedDateTime',
  ];

  function _extractTs(row) {
    for (var i = 0; i < _TS_FIELDS.length; i++) {
      var val = row[_TS_FIELDS[i]];
      if (val == null) continue;
      if (typeof val === 'number') return new Date(val < 1e12 ? val * 1000 : val);
      if (typeof val === 'string' && val.trim()) {
        var d = new Date(val);
        if (!isNaN(d.getTime())) return d;
      }
    }
    return null;
  }

  function _severityOf(row) {
    return String(row.severity || row.risk_level || 'info').toLowerCase();
  }

  // ── Swimlane ──────────────────────────────────────────────────────────────────

  var BreachSwimlane = {};

  /**
   * Render a bitemporal swimlane into `containerId`.
   *
   * @param {string}  containerId  DOM id of the target div
   * @param {Array}   clusters     correlation_clusters from the assessment
   * @param {Array}   allRows      normalized_rows from the assessment
   * @param {string}  assessmentId the assessment ID (for drill-down links)
   */
  BreachSwimlane.render = function (containerId, clusters, allRows, assessmentId) {
    var container = document.getElementById(containerId);
    if (!container) return;
    if (!clusters || !clusters.length) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:12px;">No clusters to display.</div>';
      return;
    }

    // ── Build row index
    var rowByIndex = {};
    (allRows || []).forEach(function (r) {
      var idx = 'row_index' in r ? r.row_index : (r.row_number != null ? r.row_number : null);
      if (idx != null) rowByIndex[idx] = r;
    });

    // ── Sort clusters by severity then verdict
    var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    var VERDICT_RANK = { 'CONFIRMED': 5, 'LIKELY REAL': 4, 'LIKELY': 4, 'UNCERTAIN': 3, 'BENIGN': 1 };
    function _clusterScore(c) {
      var vr = 2;
      var v = (c.verdict || c.final_verdict || '').toUpperCase();
      for (var k in VERDICT_RANK) { if (v.indexOf(k) !== -1) { vr = VERDICT_RANK[k]; break; } }
      var sr = SEV_RANK[(c.severity || '').toLowerCase()] || 0;
      return vr * 100 + sr * 10 + (c.row_refs || []).length;
    }
    var sorted = clusters.slice().sort(function (a, b) { return _clusterScore(b) - _clusterScore(a); });

    // ── Gather timestamps per cluster
    var clusterData = sorted.map(function (c) {
      var refs = c.row_refs || [];
      var points = refs.map(function (idx) {
        var row = rowByIndex[idx] || rowByIndex[String(idx)] || rowByIndex[Number(idx)];
        if (!row) return null;
        var ts = _extractTs(row);
        if (!ts) return null;
        return { ts: ts, sev: _severityOf(row), row: row };
      }).filter(Boolean);
      points.sort(function (a, b) { return a.ts - b.ts; });
      return { cluster: c, points: points };
    });

    // ── Compute global time domain
    var allTs = [];
    clusterData.forEach(function (d) {
      d.points.forEach(function (p) { allTs.push(p.ts); });
    });
    var minTs = allTs.length ? d3.min(allTs) : new Date(Date.now() - 86400000);
    var maxTs = allTs.length ? d3.max(allTs) : new Date();
    // Add 5% padding
    var span = maxTs - minTs || 3600000;
    minTs = new Date(+minTs - span * 0.05);
    maxTs = new Date(+maxTs + span * 0.05);

    // ── Layout
    var LANE_H       = 44;
    var LABEL_W      = 160;
    var AXIS_H       = 24;
    var DOT_R        = 5;
    var EXPAND_ROWS  = 7;  // show top 7, rest behind Expand

    var visibleData  = clusterData.slice(0, EXPAND_ROWS);
    var hiddenData   = clusterData.slice(EXPAND_ROWS);

    var containerW   = container.offsetWidth || 760;
    var plotW        = containerW - LABEL_W - 24;
    var totalH       = visibleData.length * LANE_H + AXIS_H + 8;

    container.innerHTML = '';

    var svg = d3.select(container)
      .append('svg')
      .attr('width', '100%')
      .attr('height', totalH)
      .style('display', 'block')
      .style('overflow', 'visible');

    var xScale = d3.scaleTime()
      .domain([minTs, maxTs])
      .range([0, plotW]);

    var xAxis = d3.axisBottom(xScale)
      .ticks(6)
      .tickSize(4);

    // ── Axis row
    var axisG = svg.append('g')
      .attr('transform', 'translate(' + LABEL_W + ',' + (totalH - AXIS_H) + ')')
      .call(xAxis);
    axisG.select('.domain').attr('stroke', 'var(--border-subtle, #2a2a2a)');
    axisG.selectAll('text')
      .style('fill', 'var(--text-muted, #888)')
      .style('font-size', '10px');
    axisG.selectAll('.tick line')
      .attr('stroke', 'var(--border-subtle, #2a2a2a)');

    // ── Lane rows
    visibleData.forEach(function (d, i) {
      var c    = d.cluster;
      var cid  = c.cluster_id || ('cluster-' + i);
      var sev  = (c.severity || 'info').toLowerCase();
      var y    = i * LANE_H;
      var midY = y + LANE_H / 2;
      var verdict = (c.verdict || c.final_verdict || '').toUpperCase();

      // Band background
      svg.append('rect')
        .attr('x', LABEL_W)
        .attr('y', y + 2)
        .attr('width', plotW)
        .attr('height', LANE_H - 4)
        .attr('rx', 4)
        .attr('fill', 'var(--bg-card, #1a1a1a)')
        .attr('stroke', 'var(--border-subtle, #2a2a2a)')
        .attr('stroke-width', 1)
        .style('cursor', 'pointer')
        .on('click', function () {
          window.open(
            '/static/breach.html?assessment=' + encodeURIComponent(assessmentId) +
            '&cluster=' + encodeURIComponent(cid),
            '_blank'
          );
        });

      // Severity stripe on left edge of band
      var verdictCol = VERDICT_COLOR[verdict] || SEV_COLOR[sev] || '#5B8FD4';
      svg.append('rect')
        .attr('x', LABEL_W)
        .attr('y', y + 2)
        .attr('width', 3)
        .attr('height', LANE_H - 4)
        .attr('rx', 2)
        .attr('fill', verdictCol);

      // Label (left of band)
      var label = svg.append('text')
        .attr('x', LABEL_W - 8)
        .attr('y', midY + 4)
        .attr('text-anchor', 'end')
        .style('fill', 'var(--text-primary, #e0e0e0)')
        .style('font-size', '11px')
        .style('cursor', 'pointer')
        .on('click', function () {
          window.open(
            '/static/breach.html?assessment=' + encodeURIComponent(assessmentId) +
            '&cluster=' + encodeURIComponent(cid),
            '_blank'
          );
        });

      var prefill = c.tier1_prefill;
      var labelText = prefill && prefill.incident_name
        ? prefill.incident_name
        : cid;
      // Truncate to 20 chars
      if (labelText.length > 20) labelText = labelText.slice(0, 18) + '…';
      label.text(labelText);

      // Event dots
      d.points.forEach(function (p) {
        var dotColor = SEV_COLOR[p.sev] || '#5B8FD4';
        var g = svg.append('g')
          .attr('transform', 'translate(' + (LABEL_W + xScale(p.ts)) + ',' + midY + ')')
          .style('cursor', 'pointer');

        g.append('circle')
          .attr('r', DOT_R)
          .attr('fill', dotColor)
          .attr('fill-opacity', 0.85)
          .attr('stroke', '#fff')
          .attr('stroke-width', 0.5);

        // Tooltip on hover
        var desc = (p.row.description || p.row.activityDisplayName || p.row.operationName || '');
        g.append('title').text(
          '[' + p.sev + '] ' + p.ts.toISOString().slice(0, 16).replace('T', ' ') + '\n' + desc.slice(0, 120)
        );
      });

      // Row count badge
      if (d.points.length === 0) {
        svg.append('text')
          .attr('x', LABEL_W + plotW / 2)
          .attr('y', midY + 4)
          .attr('text-anchor', 'middle')
          .style('fill', 'var(--text-muted, #666)')
          .style('font-size', '10px')
          .text('no timestamps in rows');
      }
    });

    // ── Expand button if there are hidden lanes
    if (hiddenData.length > 0) {
      var expandBtn = document.createElement('button');
      expandBtn.className = 'br-livefeed__btn';
      expandBtn.style.marginTop = '6px';
      expandBtn.style.fontSize = '11px';
      expandBtn.textContent = 'Show ' + hiddenData.length + ' more cluster' + (hiddenData.length > 1 ? 's' : '');
      expandBtn.addEventListener('click', function () {
        expandBtn.remove();
        BreachSwimlane.render(containerId, clusters, allRows, assessmentId);
        // Re-render with full data — simple approach: pass all and remove limit
        // We replace the render with the full set by patching EXPAND_ROWS
        // Actually: re-render without limit by passing a marker
        container.innerHTML = '';
        _renderFull(container, clusterData, minTs, maxTs, plotW, LABEL_W, AXIS_H, LANE_H, DOT_R, assessmentId);
      });
      container.appendChild(expandBtn);
    }
  };

  function _renderFull(container, clusterData, minTs, maxTs, plotW, LABEL_W, AXIS_H, LANE_H, DOT_R, assessmentId) {
    var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    var totalH = clusterData.length * LANE_H + AXIS_H + 8;

    var svg = d3.select(container)
      .append('svg')
      .attr('width', '100%')
      .attr('height', totalH)
      .style('display', 'block')
      .style('overflow', 'visible');

    var xScale = d3.scaleTime().domain([minTs, maxTs]).range([0, plotW]);
    var xAxis = d3.axisBottom(xScale).ticks(6).tickSize(4);

    var axisG = svg.append('g')
      .attr('transform', 'translate(' + LABEL_W + ',' + (totalH - AXIS_H) + ')')
      .call(xAxis);
    axisG.select('.domain').attr('stroke', 'var(--border-subtle, #2a2a2a)');
    axisG.selectAll('text').style('fill', 'var(--text-muted, #888)').style('font-size', '10px');
    axisG.selectAll('.tick line').attr('stroke', 'var(--border-subtle, #2a2a2a)');

    clusterData.forEach(function (d, i) {
      var c = d.cluster;
      var cid = c.cluster_id || ('cluster-' + i);
      var sev = (c.severity || 'info').toLowerCase();
      var y = i * LANE_H;
      var midY = y + LANE_H / 2;
      var verdict = (c.verdict || c.final_verdict || '').toUpperCase();
      var verdictCol = VERDICT_COLOR[verdict] || SEV_COLOR[sev] || '#5B8FD4';

      svg.append('rect').attr('x', LABEL_W).attr('y', y + 2).attr('width', plotW)
        .attr('height', LANE_H - 4).attr('rx', 4)
        .attr('fill', 'var(--bg-card, #1a1a1a)').attr('stroke', 'var(--border-subtle, #2a2a2a)').attr('stroke-width', 1)
        .style('cursor', 'pointer')
        .on('click', function () {
          window.open('/static/breach.html?assessment=' + encodeURIComponent(assessmentId) + '&cluster=' + encodeURIComponent(cid), '_blank');
        });

      svg.append('rect').attr('x', LABEL_W).attr('y', y + 2).attr('width', 3).attr('height', LANE_H - 4).attr('rx', 2).attr('fill', verdictCol);

      var prefill = c.tier1_prefill;
      var labelText = prefill && prefill.incident_name ? prefill.incident_name : cid;
      if (labelText.length > 20) labelText = labelText.slice(0, 18) + '…';
      svg.append('text').attr('x', LABEL_W - 8).attr('y', midY + 4).attr('text-anchor', 'end')
        .style('fill', 'var(--text-primary, #e0e0e0)').style('font-size', '11px').text(labelText);

      d.points.forEach(function (p) {
        var dotColor = SEV_COLOR[p.sev] || '#5B8FD4';
        var g = svg.append('g').attr('transform', 'translate(' + (LABEL_W + xScale(p.ts)) + ',' + midY + ')').style('cursor', 'pointer');
        g.append('circle').attr('r', DOT_R).attr('fill', dotColor).attr('fill-opacity', 0.85).attr('stroke', '#fff').attr('stroke-width', 0.5);
        var desc = (p.row.description || p.row.activityDisplayName || p.row.operationName || '');
        g.append('title').text('[' + p.sev + '] ' + p.ts.toISOString().slice(0, 16).replace('T', ' ') + '\n' + desc.slice(0, 120));
      });
    });
  }


  // ── Mini HopGraph ─────────────────────────────────────────────────────────────

  var BreachHopGraph = {};

  var NODE_COLOR = {
    user:        '#3FA860',
    account:     '#3FA860',
    external_ip: '#E54848',
    src_ip:      '#E54848',
    dst_ip:      '#FF8A3C',
    internal_ip: '#5B8FD4',
    host:        '#9B8EC4',
    hostname:    '#9B8EC4',
    process:     '#E0C446',
    row:         '#7b7bc4',  // lavender — row-level correlation node
    unknown:     '#666',
  };

  // Edge colour by correlation pivot type.
  // These colours are intentional: red=attacker, blue=session, green=host, amber=account.
  var EDGE_COLOR = {
    'attacker_ip':     '#e05252',  // red    — same attacker infrastructure (strongest signal)
    'session':         '#52abe0',  // blue   — same authentication session
    'host':            '#52e07f',  // green  — same compromised host
    'identity_anomaly':'#e08c34',  // orange — same account + anomaly (impossible travel etc.)
    'account':         '#c09f40',  // amber  — same victim account (weaker signal)
    'network_ip':      '#5B8FD4',  // steel  — shared network IP
    'resource':        '#888888',  // gray   — shared resource/artifact
    'behavioral':      '#555555',  // dark   — behavioral pattern match
    '_default':        '#444444',
  };

  var EDGE_LEGEND = [
    { pivot: 'attacker_ip',     label: 'Shared attacker IP',      color: '#e05252' },
    { pivot: 'session',         label: 'Same auth session',        color: '#52abe0' },
    { pivot: 'host',            label: 'Same compromised host',    color: '#52e07f' },
    { pivot: 'identity_anomaly',label: 'Account + anomaly signal', color: '#e08c34' },
    { pivot: 'account',         label: 'Same victim account',      color: '#c09f40' },
  ];

  /**
   * Render a mini force-directed HopGraph for a single cluster.
   *
   * @param {string} containerId  DOM id of the target div
   * @param {Object} cluster      single cluster object
   * @param {Array}  allRows      normalized_rows
   * @param {string} assessmentId used for cluster-tab drill-down links
   */
  BreachHopGraph.render = function (containerId, cluster, allRows, assessmentId) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var cid   = cluster.cluster_id || 'unknown';
    var refs  = new Set(cluster.row_refs || []);
    var rows  = (allRows || []).filter(function (r) {
      var idx = 'row_index' in r ? r.row_index : r.row_number;
      return idx != null && refs.has(idx);
    });

    if (!rows.length) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:8px;">No rows for this cluster.</div>';
      return;
    }

    // ── Extract entity nodes + edges
    var nodeMap = {};  // id → {id, type, label}
    var edges   = [];  // [{source, target}]

    function _addNode(id, type) {
      if (!id) return null;
      var key = type + '::' + id;
      if (!nodeMap[key]) nodeMap[key] = { id: key, type: type, label: id };
      return key;
    }

    rows.forEach(function (r, ri) {
      var userKey = null, ipKey = null, hostKey = null;
      var user = r.user || r.user_principal_name || r.username || r.account;
      if (user) userKey = _addNode(user, 'user');

      var srcIp = r.src_ip || r.source_ip;
      if (srcIp) ipKey = _addNode(srcIp, 'src_ip');

      var dstIp = r.dst_ip || r.destination_ip;
      var dstKey = dstIp ? _addNode(dstIp, 'dst_ip') : null;

      var host = r.hostname || r.host || r.src_host || r.device_name;
      if (host) hostKey = _addNode(host, 'hostname');

      // Edges: user ↔ ip, ip ↔ host, user ↔ host
      if (userKey && ipKey)  edges.push({ source: userKey, target: ipKey, pivot: '_default' });
      if (ipKey && hostKey)  edges.push({ source: ipKey,   target: hostKey, pivot: '_default' });
      if (userKey && hostKey && !ipKey) edges.push({ source: userKey, target: hostKey, pivot: '_default' });
      if (ipKey && dstKey)   edges.push({ source: ipKey,   target: dstKey, pivot: '_default' });
    });

    // ── Overlay top_links edges (backend-computed, confidence-scored, pivot-typed)
    // These are higher-quality than the raw row-field edges above.
    // Both coexist in the graph — row-field connects entity nodes, top_links connects row nodes.
    var topLinks = cluster.top_links || cluster.incident_top_links || [];
    topLinks.forEach(function(lk) {
      var srcKey = _addNode('r' + lk.src, 'row');
      var dstKey = _addNode('r' + lk.dst, 'row');
      if (srcKey && dstKey) {
        edges.push({
          source: srcKey,
          target: dstKey,
          pivot:   lk.pivot   || '_default',
          summary: lk.summary || '',
          conf:    typeof lk.conf === 'number' ? lk.conf : 0.5,
        });
      }
    });

    var nodes = Object.values(nodeMap);
    if (!nodes.length) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:8px;">No named entities found in rows.</div>';
      return;
    }

    // Deduplicate edges
    var edgeSet = new Set();
    edges = edges.filter(function (e) {
      var key = e.source + '→' + e.target;
      if (edgeSet.has(key)) return false;
      edgeSet.add(key);
      return true;
    });

    var W = container.offsetWidth || 600;
    var H = Math.max(container.offsetHeight || 0, nodes.length > 80 ? 600 : nodes.length > 30 ? 400 : 280);
    container.innerHTML = '';

    var svg = d3.select(container)
      .append('svg')
      .attr('width', W)
      .attr('height', H)
      .style('display', 'block')
      .style('background', 'var(--bg-card, #1a1a1a)')
      .style('border-radius', '6px');

    // Scale charge strength with node count so large graphs spread out properly
    var chargeStrength = Math.max(-800, -120 - nodes.length * 2.5);
    var linkDist = nodes.length > 80 ? 40 : 60;
    var sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id(function (d) { return d.id; }).distance(linkDist))
      .force('charge', d3.forceManyBody().strength(chargeStrength))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(14));

    // ── Edge groups: each <g> holds a <line> + <title> tooltip ──────────────────
    var link = svg.append('g')
      .attr('class', 'hopgraph-edges')
      .selectAll('g')
      .data(edges)
      .enter().append('g')
      .attr('class', 'hopgraph-edge-group');

    link.append('line')
      .attr('class', 'hopgraph-edge')
      .attr('stroke', function(d) {
        return EDGE_COLOR[d.pivot] || EDGE_COLOR['_default'];
      })
      .attr('stroke-width', function(d) {
        // Width 1.2–3.5px proportional to confidence; attacker_ip always max
        var conf = typeof d.conf === 'number' ? d.conf : 0.5;
        return d.pivot === 'attacker_ip' ? 3.5 : Math.max(1.2, Math.min(3.0, conf * 3.2));
      })
      .attr('stroke-opacity', function(d) {
        return d.pivot === 'attacker_ip' ? 0.92 : 0.65;
      });

    // Native browser tooltip — zero JS overhead, works on hover
    link.append('title').text(function(d) {
      if (!d.pivot || d.pivot === '_default') return 'linked';
      var pct = d.conf != null ? ' \u00b7 ' + Math.round(d.conf * 100) + '% conf' : '';
      return (d.pivot.replace('_', ' ')) + (d.summary ? ': ' + d.summary : '') + pct;
    });

    var node = svg.append('g')
      .selectAll('g')
      .data(nodes)
      .enter().append('g')
      .style('cursor', 'pointer')
      .call(
        d3.drag()
          .on('start', function (event, d) {
            if (!event.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
          })
          .on('drag', function (event, d) { d.fx = event.x; d.fy = event.y; })
          .on('end', function (event, d) {
            if (!event.active) sim.alphaTarget(0);
            d.fx = null; d.fy = null;
          })
      );

    node.append('circle')
      .attr('r', 10)
      .attr('fill', function (d) { return NODE_COLOR[d.type] || NODE_COLOR.unknown; })
      .attr('fill-opacity', 0.9)
      .attr('stroke', '#fff')
      .attr('stroke-width', 0.8);

    node.append('text')
      .attr('dy', 22)
      .attr('text-anchor', 'middle')
      .style('fill', 'var(--text-muted, #aaa)')
      .style('font-size', '9px')
      .text(function (d) {
        return d.label.length > 18 ? d.label.slice(0, 16) + '…' : d.label;
      });

    node.append('title').text(function (d) { return d.type + ': ' + d.label; });

    var pad = 20;
    sim.on('tick', function () {
      link.select('line')
        .attr('x1', function (d) { return d.source.x; })
        .attr('y1', function (d) { return d.source.y; })
        .attr('x2', function (d) { return d.target.x; })
        .attr('y2', function (d) { return d.target.y; });
      node.attr('transform', function (d) {
        d.x = Math.max(pad, Math.min(W - pad, d.x));
        d.y = Math.max(pad, Math.min(H - pad, d.y));
        return 'translate(' + d.x + ',' + d.y + ')';
      });
    });

    // ── Legend (only if top_links edges present — shows pivot colour mapping) ──
    if (topLinks.length > 0) {
      var pivotsPresent = new Set(topLinks.map(function(lk) { return lk.pivot || '_default'; }));
      var legendItems = EDGE_LEGEND.filter(function(item) { return pivotsPresent.has(item.pivot); });
      if (legendItems.length > 0) {
        var legendH = legendItems.length * 16 + 12;
        var leg = svg.append('g')
          .attr('class', 'hopgraph-legend')
          .attr('transform', 'translate(8,' + (H - legendH - 4) + ')');
        leg.append('rect')
          .attr('width', 188).attr('height', legendH)
          .attr('fill', 'rgba(0,0,0,0.55)').attr('rx', 3);
        legendItems.forEach(function(item, i) {
          var g = leg.append('g').attr('transform', 'translate(8,' + (10 + i * 16) + ')');
          g.append('line')
            .attr('x1', 0).attr('y1', 0).attr('x2', 18).attr('y2', 0)
            .attr('stroke', item.color).attr('stroke-width', 2);
          g.append('text')
            .attr('x', 24).attr('y', 4)
            .attr('fill', '#ccc').attr('font-size', '10px')
            .text(item.label);
        });
      }
    }
  };

  // ── Export ────────────────────────────────────────────────────────────────────

  global.BreachSwimlane = BreachSwimlane;
  global.BreachHopGraph  = BreachHopGraph;

}(window));
