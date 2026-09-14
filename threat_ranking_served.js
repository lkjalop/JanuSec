// Shared threat ranking & remediation logic
// Provides consistent scoring for multi-source and single-source correlation views.
(function(global){
  'use strict';

  const FACTOR_SEVERITY = {
    // High impact detectors
    'asn_rare': 1.4,
    'dns_exfil': 1.5,
    'file_hash_rarity': 1.3,
    'nxdomain_rate_high': 1.25,
    'temporal_pattern_chain': 1.15,
    // Mapping / correlation boosters
    'mapping_semantics_bonus': 1.10,
    'mapping_semantics_rich': 1.05,
    'multi_source_correlation': 1.10,
    'entity_diversity_high': 1.05,
    // Co-occurrence matrix effect (treat as neutral baseline > could amplify separately)
    'co_occurrence_matrix': 1.00,
    // Rarity enrichment
    'net:high_risk_asn': 1.35,
    'ssl:cert_revoked': 1.30,
    'threat_intel:otx_malicious': 1.40,
    // Fallback
    '__default__': 1.0
  };

  const EDGE_REMEDIATION = {
    'loads_hash': 'Block or quarantine associated file hash in EDR.',
    'spawns': 'Investigate parent-child process lineage for abuse.',
    'gt_sequence': 'Validate execution order; possible staged intrusion.',
    'dns_a': 'Inspect domain resolution; consider sinkhole if malicious.',
    'contacts_domain': 'Review outbound domain reputation; block if C2.',
    'connects_to': 'Examine remote IP/port; add temporary firewall rule.',
    'connects_from': 'Confirm source process legitimacy and origin.',
    'follows': 'Check process succession for persistence or hijack.',
    'tls_cert': 'Verify certificate authenticity & revocation status.',
    'tls_ja3': 'Assess JA3 fingerprint vs known malicious patterns.'
  };

  function factorWeight(f){
    if(!f) return 1.0;
    if(typeof f === 'string') return FACTOR_SEVERITY[f] || FACTOR_SEVERITY.__default__;
    try {
      const name = f.factor || f.name;
      return FACTOR_SEVERITY[name] || FACTOR_SEVERITY.__default__;
    } catch(_) { return 1.0; }
  }

  function collectFactorWeights(factors){
    const weights = [];
    (factors||[]).forEach(f => { weights.push(factorWeight(f)); });
    return weights;
  }

  function remediationForPath(pathScoreObj){
    // Inspect contributions or anomalies for edge hints
    const hints = new Set();
    try {
      const contrib = pathScoreObj.contributions || {};
      Object.keys(contrib).forEach(edgeType => {
        if(EDGE_REMEDIATION[edgeType]) hints.add(EDGE_REMEDIATION[edgeType]);
      });
    } catch(_){}
    // Fallback on anomalies
    try {
      (pathScoreObj.anomalies||[]).forEach(a => {
        if(/high_field_overlap/.test(a)) hints.add('Review overlapping entities for credential/shared host compromise.');
        if(/large_value_intersection/.test(a)) hints.add('Inspect bulk intersection for lateral spray or mass harvest.');
        if(/high_path_score/.test(a)) hints.add('Escalate chain for manual investigation; high composite risk.');
      });
    } catch(_){}
    if(!hints.size) hints.add('Baseline validation: verify legitimacy of involved processes & domains.');
    return Array.from(hints).slice(0,4);
  }

  function computeRiskRankings(summary, topN){
    const pathScores = summary.path_scores || {};
    const factors = summary.factors || [];
    const factorWeights = collectFactorWeights(factors);
    const factorAmplifier = factorWeights.reduce((a,b)=>a+b,0) / Math.max(1, factorWeights.length);
    const confidence = Number(summary.confidence || 0);
    const breakdown = summary.confidence_breakdown || {};
    const chainBonus = Number(breakdown.chain_bonus || 0);
    const mappingBonus = Number(breakdown.mapping_bonus || 0);
    const rows = [];
    Object.keys(pathScores).forEach(key => {
      const ps = pathScores[key] || {}; const sc = Number(ps.score || 0);
      const anomalies = (ps.anomalies || []).length;
      // Risk formula: weighted path score + confidence + anomalies + bonuses * severity amplifier
      const risk = sc*0.55 + confidence*0.25 + anomalies*0.05 + (chainBonus+mappingBonus)*0.3 + (factorAmplifier-1.0)*0.15;
      rows.push({ key, score: sc, anomalies, risk, remediation: remediationForPath(ps) });
    });
    // Fallback if no path scores: derive from correlation matrix
    if(!rows.length){
      const corr = summary.correlation || {};
      Object.keys(corr).forEach(a => {
        Object.keys(corr[a]||{}).forEach(b => {
          const v = Number(corr[a][b]||0); if(v>0){
            const sc = v/10; const risk = sc*0.6 + confidence*0.3 + (factorAmplifier-1.0)*0.1;
            rows.push({ key:`${a}__${b}`, score: sc, anomalies:0, risk, remediation:['Investigate overlapping batches for shared entities.'] });
          }
        });
      });
    }
    rows.sort((a,b)=> b.risk - a.risk);
    return rows.slice(0, topN);
  }

  function bestChainString(entry, summary){
    try {
      const ps = (summary.path_scores||{})[entry.key];
      if(ps){
        const contrib = ps.contributions || {};
        const ordered = Object.keys(contrib).slice(0,6);
        if(ordered.length) return ordered.join(' -> ');
      }
    } catch(_){}
    return entry.key.replace(/__/,' -> ');
  }

  global.ThreatRanking = { computeRiskRankings, bestChainString };
})(window);
