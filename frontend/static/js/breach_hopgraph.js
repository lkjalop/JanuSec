/* breach_hopgraph.js — D3 entity-relationship graph for breach assessment clusters
 * Requires d3.min.js loaded before this file.
 * Exports: window.BreachHopGraph = { render(containerId, cluster, rows, aid) }
 */
(function (window) {
  'use strict';

  var TYPE_COLOR = {
    actor:    '#60a5fa',
    ip:       '#f97316',
    process:  '#a78bfa',
    resource: '#94a3b8',
    technique:'#f472b6',
    geo:      '#34d399',   // teal-green — country/ASN nodes
  };

  // Travel verdict → border color for geo nodes
  var GEO_TRAVEL_COLOR = {
    IMPOSSIBLE:           '#ef4444',  // red
    CONCURRENT_IMPOSSIBLE:'#ef4444',
    SUSPICIOUS:           '#f97316',  // orange
    PLAUSIBLE_TRAVEL:     '#facc15',  // yellow
    LOCAL:                '#34d399',  // green (same home country)
  };

  function _extract(rows, clusterRowRefs, cluster) {
    var refSet = new Set(clusterRowRefs || []);
    var clusterRows = rows.filter(function (r) {
      var idx = r.row_index != null ? r.row_index : r.row_number;
      return refSet.has(idx) || refSet.has(String(idx)) || refSet.has(Number(idx));
    });
    if (!clusterRows.length) clusterRows = rows.slice(0, 60);

    var nodes = {};   // id -> {id, label, type, count}
    var edgeMap = {}; // key -> {source, target, count}

    function _addNode(id, type) {
      if (!id) return;
      var label = String(id).length > 22 ? String(id).slice(0, 20) + '…' : String(id);
      if (!nodes[id]) nodes[id] = { id: id, label: label, type: type, count: 0 };
      nodes[id].count++;
    }
    function _addEdge(a, b) {
      if (!a || !b || a === b) return;
      var k = a < b ? a + '||' + b : b + '||' + a;
      if (!edgeMap[k]) edgeMap[k] = { source: a, target: b, count: 0 };
      edgeMap[k].count++;
    }

    function _stringValue(value, nestedKey) {
      if (value == null) return '';
      if (typeof value === 'object') {
        if (nestedKey && value[nestedKey]) return String(value[nestedKey]);
        if (value.username) return String(value.username);
        if (value.name) return String(value.name);
        if (value.resource || value.namespace || value.subresource) {
          return [
            value.resource,
            value.subresource,
            value.namespace,
            value.name,
          ].filter(Boolean).join('/');
        }
        try { return JSON.stringify(value); } catch (_) { return ''; }
      }
      return String(value);
    }

    // Track per-actor geo visits for travel classification
    var actorGeo = {};  // actor → [{ country, countryCode, ts }]

    clusterRows.forEach(function (r) {
      var actor = r.user_principal_name || r.userPrincipalName || r.username || r.user_name
        || _stringValue(r.user, 'username') || r.actor
        || (r.accounts && r.accounts[0]) || r.initiator || null;
      var ip = r.source_ip || r.src_ip || r.client_ip || r.remote_address || r.sourceIPAddress
        || (r.ips && r.ips[0]) || null;
      var proc = r.process_name || r.process || r.application || r.event_simpleName || null;
      var res = r.resource || r.target || r.destination || r.dest_ip || r.dst_ip || r.destination_ip
        || _stringValue(r.objectRef) || r.rule_destination || null;
      var tech = r.mitre_technique || (r.mitre && r.mitre[0]) || null;

      // Geo extraction — pull from _geo summary or raw event fields
      var geo = r._geo || {};
      var geoCtx = (r.context && typeof r.context === 'object') ? r.context : {};
      var geogCtx = geoCtx.geographicalContext || {};
      var country = geo.country || geogCtx.country || r.geo_country || r.country_name || r.country || null;
      var countryCode = geo.country_code || geogCtx.countryCode || r.country_code || null;
      var city = geo.city || geogCtx.city || r.geo_city || r.city || null;
      var asnOrg = geo.asn_org || r.asn_org || r.as_org || r.isp || null;
      var travelVerdict = geo.travel_verdict || null;

      // Build geo node label: "SG · Singapore" or just "Singapore"
      var geoLabel = null;
      if (country) {
        geoLabel = (countryCode ? countryCode + ' · ' : '') + country;
        if (city) geoLabel += ' (' + city + ')';
      } else if (asnOrg) {
        geoLabel = 'ASN: ' + asnOrg;
      }

      _addNode(actor, 'actor');
      _addNode(ip, 'ip');
      _addNode(proc, 'process');
      _addNode(res, 'resource');
      _addNode(tech, 'technique');
      if (geoLabel) _addNode(geoLabel, 'geo');

      _addEdge(actor, ip);
      _addEdge(actor, proc);
      _addEdge(actor, res);
      _addEdge(ip, res);
      if (geoLabel) {
        _addEdge(ip, geoLabel);    // IP → geo country
        if (actor) _addEdge(actor, geoLabel);  // actor → geo country
      }

      // Track geo visits per actor for travel annotation
      if (actor && geoLabel) {
        if (!actorGeo[actor]) actorGeo[actor] = {};
        actorGeo[actor][geoLabel] = (actorGeo[actor][geoLabel] || 0) + 1;
      }
    });

    // Annotate geo nodes with travel verdict from cluster-level travel_flags if available
    var travelFlags = (cluster && cluster.travel_flags) || (cluster && cluster._geo_summary && cluster._geo_summary.travel_flags) || [];
    travelFlags.forEach(function (flag) {
      var c1 = flag.from_country; var c2 = flag.to_country;
      if (c1 && c2 && nodes[c1]) nodes[c1]._travel = flag.verdict;
      if (c1 && c2 && nodes[c2]) nodes[c2]._travel = flag.verdict;
    });

    var sortedNodes = Object.values(nodes)
      .sort(function (a, b) { return b.count - a.count; })
      .slice(0, 20);
    var nodeIds = new Set(sortedNodes.map(function (n) { return n.id; }));
    var edges = Object.values(edgeMap)
      .filter(function (e) { return nodeIds.has(e.source) && nodeIds.has(e.target); });

    return { nodes: sortedNodes, edges: edges };
  }

  function render(containerId, cluster, rows, aid) {
    var container = document.getElementById(containerId);
    if (!container) return;
    if (typeof d3 === 'undefined') {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:8px;">D3 not loaded — HopGraph unavailable.</div>';
      return;
    }

    var graph = _extract(rows || [], (cluster || {}).row_refs || [], cluster);

    if (!graph.nodes.length) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:8px;">No entity data available for this cluster.</div>';
      return;
    }

    var width = container.offsetWidth || 600;
    var height = 280;
    container.innerHTML = '';

    // Legend — entity types + geo travel colour key
    var legend = document.createElement('div');
    legend.style.cssText = 'display:flex;gap:12px;padding:4px 0 6px;font-size:11px;opacity:.7;flex-wrap:wrap;';
    Object.keys(TYPE_COLOR).forEach(function (t) {
      var dot = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + TYPE_COLOR[t] + ';margin-right:3px;vertical-align:middle;"></span>';
      legend.innerHTML += '<span>' + dot + t + '</span>';
    });
    // Travel border key
    var travelKey = [
      { color: '#ef4444', label: 'impossible travel' },
      { color: '#f97316', label: 'suspicious travel' },
      { color: '#facc15', label: 'plausible travel' },
    ];
    travelKey.forEach(function (k) {
      legend.innerHTML += '<span style="border-left:3px solid ' + k.color + ';padding-left:4px;">' + k.label + '</span>';
    });
    container.appendChild(legend);

    var svg = d3.select(container)
      .append('svg')
      .attr('width', width)
      .attr('height', height)
      .style('background', 'rgba(255,255,255,0.02)')
      .style('border-radius', '4px');

    var sim = d3.forceSimulation(graph.nodes)
      .force('link', d3.forceLink(graph.edges).id(function (d) { return d.id; }).distance(70).strength(0.6))
      .force('charge', d3.forceManyBody().strength(-140))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(28));

    var link = svg.append('g').attr('stroke-opacity', '0.3')
      .selectAll('line').data(graph.edges).enter().append('line')
      .attr('stroke', '#888')
      .attr('stroke-width', function (d) { return Math.min(3, 0.5 + d.count * 0.5); });

    var nodeG = svg.append('g')
      .selectAll('g').data(graph.nodes).enter().append('g')
      .attr('cursor', 'default')
      .call(d3.drag()
        .on('start', function (event, d) {
          if (!event.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on('drag', function (event, d) { d.fx = event.x; d.fy = event.y; })
        .on('end', function (event, d) {
          if (!event.active) sim.alphaTarget(0);
          d.fx = null; d.fy = null;
        }));

    nodeG.append('circle')
      .attr('r', function (d) { return Math.min(20, 7 + Math.sqrt(d.count) * 3); })
      .attr('fill', function (d) { return TYPE_COLOR[d.type] || '#888'; })
      .attr('fill-opacity', 0.85)
      .attr('stroke', function (d) {
        if (d.type === 'geo' && d._travel) return GEO_TRAVEL_COLOR[d._travel] || '#34d399';
        return '#fff';
      })
      .attr('stroke-width', function (d) { return d.type === 'geo' && d._travel ? 2 : 0.5; })
      .attr('stroke-opacity', function (d) { return d.type === 'geo' && d._travel ? 0.9 : 0.3; });

    nodeG.append('text')
      .text(function (d) { return d.label; })
      .attr('text-anchor', 'middle')
      .attr('dy', function (d) { return Math.min(20, 7 + Math.sqrt(d.count) * 3) + 11; })
      .attr('font-size', '9px')
      .attr('fill', '#ccc')
      .attr('pointer-events', 'none');

    nodeG.append('title').text(function (d) {
      var base = d.type + ': ' + d.id + ' (' + d.count + ' events)';
      if (d.type === 'geo' && d._travel) {
        var label = {
          IMPOSSIBLE: '⚠ IMPOSSIBLE TRAVEL — credential compromise likely',
          CONCURRENT_IMPOSSIBLE: '⚠ CONCURRENT LOGIN — same user, two countries simultaneously',
          SUSPICIOUS: '⚠ SUSPICIOUS TRAVEL — high velocity between countries',
          PLAUSIBLE_TRAVEL: '✈ Plausible business travel — verify with HR/calendar',
          LOCAL: '✓ Local access (home region)',
        }[d._travel] || d._travel;
        return base + '\n' + label;
      }
      return base;
    });

    sim.on('tick', function () {
      link
        .attr('x1', function (d) { return Math.max(4, Math.min(width - 4, d.source.x)); })
        .attr('y1', function (d) { return Math.max(4, Math.min(height - 4, d.source.y)); })
        .attr('x2', function (d) { return Math.max(4, Math.min(width - 4, d.target.x)); })
        .attr('y2', function (d) { return Math.max(4, Math.min(height - 4, d.target.y)); });
      nodeG.attr('transform', function (d) {
        return 'translate(' + Math.max(20, Math.min(width - 20, d.x)) + ',' + Math.max(16, Math.min(height - 16, d.y)) + ')';
      });
    });
  }

  window.BreachHopGraph = { render: render };

}(window));
