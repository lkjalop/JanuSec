// Shared DREAD scoring helpers used by CSV analyzers and HopGraph views.
// The implementation keeps the math consistent with the latest supply-chain,
// network, and binary analysis guidance so that all surfaces escalate and
// de-escalate alerts the same way.
(function(global){
  'use strict';

  const KEYWORD_PATTERNS = [
    { pattern: /(shai|hulud|supply[_\s-]?chain|npm|pypi|lockfile|slsa|ci\/cd|github|workflow|sbom|package)/, weight: 1.4, label: 'supply' },
    { pattern: /(worm|propagation|lateral|multi[-_\s]?hop|multi[-_\s]?source|hopgraph|correlator)/, weight: 1.2, label: 'graph' },
    { pattern: /(credential|token|secret|wallet|keystore|aws|azure|gcp|cloud)/, weight: 1.3, label: 'credential' },
    { pattern: /(beacon|c2|nxdomain|asn|bgp|network|dns|siem|vpn)/, weight: 1.1, label: 'network' },
    { pattern: /(obfuscat|packer|entropy|binary|payload|dll|driver|shellcode|dropper|lolbin|living[_\s]?off[_\s]?the[_\s]?land)/, weight: 1.0, label: 'binary' },
    { pattern: /(mapping[_\s]?semantics|domain[_\s]?diversity|ewma|graph|session)/, weight: 0.8, label: 'context' },
    { pattern: /(benign|allowlist|known[_\s]?good|false[_\s]?positive|safe)/, weight: -1.2, label: 'trusted' },
    { pattern: /(pass|auto[_\s]?close)/, weight: -2.0, label: 'pass' }
  ];

  const HIGH_VALUE_FIELDS = ['user','username','host','hostname','process','process_name','file_hash','sha256','domain'];
  const SUPPORT_FIELDS = ['ip','ip_dst','dst_ip','ip_src','src_ip','role','cloud_resource','db','secret','email','url'];

  function clamp(value, min, max){
    return Math.max(min, Math.min(max, value));
  }

  function round2(value){
    return Math.round(value * 100) / 100;
  }

  function toNumber(value, fallback){
    if(value === null || typeof value === 'undefined') return fallback || 0;
    if(typeof value === 'number') return isNaN(value) ? (fallback || 0) : value;
    if(typeof value === 'boolean') return value ? 1 : 0;
    const cleaned = String(value).replace(/[^0-9\.\-]/g, '');
    const num = Number(cleaned);
    return isNaN(num) ? (fallback || 0) : num;
  }

  function findCaseInsensitive(obj, key){
    if(!obj || typeof obj !== 'object') return undefined;
    const lower = key.toLowerCase();
    for(const candidate of Object.keys(obj)){
      if(candidate.toLowerCase() === lower){
        return obj[candidate];
      }
    }
    return undefined;
  }

  function extract(raw, keys){
    if(!raw || typeof raw !== 'object') return undefined;
    for(const key of keys){
      if(Object.prototype.hasOwnProperty.call(raw, key)) return raw[key];
      const alt = findCaseInsensitive(raw, key);
      if(typeof alt !== 'undefined') return alt;
    }
    return undefined;
  }

  function hasValue(raw, key){
    if(!raw || typeof raw !== 'object') return false;
    const val = extract(raw, [key]);
    if(typeof val === 'undefined' || val === null) return false;
    if(typeof val === 'string') return val.trim().length > 0;
    if(typeof val === 'number') return !isNaN(val);
    if(typeof val === 'boolean') return true;
    return !!val;
  }

  function computeAvMetrics(raw){
    const av = toNumber(extract(raw, ['avPositives','av_positives','avPos','av_hits','avPositiveCount']), 0);
    const avTotal = Math.max(0, toNumber(extract(raw, ['avTotal','av_total','avSamples','av_sample_count']), 0));
    const ratio = avTotal > 0 ? av / avTotal : 0;
    let score = 0;
    if(av >= 8 || ratio >= 0.5) score = 2.8;
    else if(av >= 4 || ratio >= 0.2) score = 2.2;
    else if(av >= 2 || ratio >= 0.1) score = 1.4;
    else if(av === 1) score = 0.9;
    else if(av === 0 && avTotal >= 40) score = -0.4; // strong signal that engines see it as clean
    else if(av === 0 && avTotal === 0) score = 0.2;  // unknown AV coverage
    return { raw: av, total: avTotal, ratio, score };
  }

  function computeThreatMetrics(raw){
    const tw = toNumber(extract(raw, ['threatWeight','threatweight','ThreatWeight','risk_weight']), 0);
    const vendorScore = toNumber(extract(raw, ['threatScore','threat_score','riskScore']), 0);
    let score = 0;
    if(tw >= 9) score = 2.5;
    else if(tw >= 7) score = 1.8;
    else if(tw >= 5) score = 1.2;
    else if(tw >= 3) score = 0.7;
    else if(tw > 0) score = 0.3;
    score = Math.max(score, vendorScore / 4);
    return { raw: tw || vendorScore, score };
  }

  function computeMappingScore(raw, factors){
    const explicit = clamp(toNumber(extract(raw, ['mapping_semantics_score','mapping_semantics','mappingScore']), 0), 0, 1);
    let highCoverage = 0;
    HIGH_VALUE_FIELDS.forEach(key => { if(hasValue(raw, key)) highCoverage++; });
    const highNorm = Math.min(1, highCoverage / 4);
    let supporting = 0;
    SUPPORT_FIELDS.forEach(key => { if(hasValue(raw, key)) supporting++; });
    const supportNorm = Math.min(1, supporting / 6);
    const factorBonus = Array.isArray(factors) && factors.some(f => /mapping_semantics/.test(String(f || '').toLowerCase())) ? 0.15 : 0;
    const combined = Math.max(explicit, Math.min(1, highNorm + supportNorm * 0.25 + factorBonus));
    return combined * 2.2;
  }

  function computeDiversityScore(raw){
    const direct = clamp(toNumber(extract(raw, ['domain_diversity_score','domain_diversity']), 0), 0, 1);
    const domainHints = new Set();
    if(hasValue(raw, 'user') || hasValue(raw, 'username')) domainHints.add('identity');
    if(hasValue(raw, 'host') || hasValue(raw, 'hostname')) domainHints.add('endpoint');
    if(hasValue(raw, 'process') || hasValue(raw, 'process_name')) domainHints.add('process');
    if(hasValue(raw, 'domain') || hasValue(raw, 'url')) domainHints.add('network');
    if(hasValue(raw, 'sha256') || hasValue(raw, 'file_hash')) domainHints.add('file');
    if(hasValue(raw, 'dst_ip') || hasValue(raw, 'ip_dst') || hasValue(raw, 'ip_src')) domainHints.add('ip');
    if(hasValue(raw, 'cloud_resource') || hasValue(raw, 'subscription')) domainHints.add('cloud');
    if(hasValue(raw, 'sbom') || hasValue(raw, 'package')) domainHints.add('supply');
    const approx = Math.min(1, domainHints.size / 6);
    const combined = Math.max(direct, approx);
    return combined * 1.8;
  }

  function computeBinaryScore(raw){
    let score = 0;
    const signed = extract(raw, ['signed','isSigned','trustedSigner']);
    if(typeof signed !== 'undefined'){
      if(signed === false || String(signed).toLowerCase() === 'false') score += 0.8;
      else score -= 0.3;
    }
    if(extract(raw, ['dynamicAnalysis','dynamic_analysis']) === true) score += 1.0;
    if(extract(raw, ['staticAnalysis','static_analysis']) === true) score += 0.4;
    const threatName = (extract(raw, ['threatName','threat_name']) || '').toString().toLowerCase();
    if(/ransom|trojan|backdoor|worm|shai|hulud/.test(threatName)) score += 1.2;
    const flagName = (extract(raw, ['flagName','flag_name']) || '').toString().toLowerCase();
    if(/verified\s+good/.test(flagName)) score -= 1.2;
    else if(/probably\s+good/.test(flagName)) score -= 0.7;
    return clamp(score, -2, 3);
  }

  function flattenText(raw){
    if(!raw || typeof raw !== 'object') return '';
    const parts = [];
    let added = 0;
    for(const key of Object.keys(raw)){
      if(added >= 25) break;
      const val = raw[key];
      if(typeof val === 'string' && val.length && val.length <= 120){
        parts.push(val);
        added++;
      }else if(typeof val === 'number'){
        parts.push(String(val));
        added++;
      }
    }
    return parts.join(' ').toLowerCase();
  }

  function computeNetworkScore(raw, factors){
    let score = 0;
    if(Array.isArray(factors)){
      if(factors.some(f => /nxdomain|asn|bgp|network|dns|siem|beacon/.test(String(f || '').toLowerCase()))){
        score += 0.8;
      }
    }
    const text = flattenText(raw);
    if(text && /nxdomain|asn|bgp|dns|vpn|beacon|c2|egress/.test(text)){
      score += 0.6;
    }
    if(text && /whitelist|allowlist|trusted/.test(text)){
      score -= 0.4;
    }
    return clamp(score, -1.5, 2.0);
  }

  function deriveStatus(raw, context){
    const verdictSources = [];
    if(context && typeof context === 'object'){
      if(context.verdict) verdictSources.push(context.verdict);
      if(context.initial_verdict) verdictSources.push(context.initial_verdict);
      if(context._initial_verdict) verdictSources.push(context._initial_verdict);
    }
    if(raw && typeof raw === 'object'){
      ['verdict','initial_verdict','final_verdict','status','disposition','decision','manualDisposition'].forEach(key => {
        const value = raw[key];
        if(typeof value !== 'undefined') verdictSources.push(value);
      });
    }
    const verdictString = verdictSources.map(v => String(v || '')).join(' ').toUpperCase();
    if(verdictString.includes('PASS')) return 'PASS';
    if(verdictString.includes('MALICIOUS') || verdictString.includes('THREAT')) return 'MALICIOUS';
    if(verdictString.includes('SUSPICIOUS')) return 'SUSPICIOUS';
    if(verdictString.includes('BENIGN') || verdictString.includes('GOOD') || verdictString.includes('ALLOW')) return 'BENIGN';

    if(raw){
      if(raw.malicious === true) return 'MALICIOUS';
      if(raw.suspicious === true) return 'SUSPICIOUS';
      if(raw.notMalicious === true || raw.benign === true) return 'BENIGN';
      if(raw.pass === true) return 'PASS';
    }

    const flagName = (extract(raw, ['flagName','flag_name']) || '').toString().toLowerCase();
    if(flagName){
      if(/verified\s+good|known\s+good/.test(flagName)) return 'BENIGN';
      if(/needs\s+review|suspicious/.test(flagName)) return 'SUSPICIOUS';
    }
    return 'UNKNOWN';
  }

  function computeStatusBoost(status){
    if(status === 'MALICIOUS') return 1.4;
    if(status === 'SUSPICIOUS') return 0.6;
    if(status === 'BENIGN') return -1.2;
    if(status === 'PASS') return -2.5;
    return 0;
  }

  function computeTrustAdjustment(raw){
    let adj = 0;
    if(!raw || typeof raw !== 'object') return adj;
    if(raw.whitelist === true || raw.whitelisted === true) adj -= 2.5;
    const flagName = (extract(raw, ['flagName','flag_name']) || '').toString().toLowerCase();
    if(/verified\s+good/.test(flagName)) adj -= 1.0;
    if(/probably\s+good/.test(flagName)) adj -= 0.5;
    if(/needs\s+review/.test(flagName)) adj += 0.3;
    if(raw.compromised === true) adj += 1.2;
    const managed = extract(raw, ['managed','managed_state']);
    if(typeof managed !== 'undefined' && managed !== '') adj -= 0.2;
    return adj;
  }

  function computeScore(factors, raw, context){
    const list = Array.isArray(factors) ? factors : [];
    const record = raw && typeof raw === 'object' ? raw : {};
    const status = deriveStatus(record, context);

    let base = 0;
    const factorMatches = [];
    list.forEach(f => {
      const val = String(f || '');
      const lower = val.toLowerCase();
      let applied = false;
      for(const pattern of KEYWORD_PATTERNS){
        if(pattern.pattern.test(lower)){
          base += pattern.weight;
          factorMatches.push({ factor: val, weight: pattern.weight, label: pattern.label });
          applied = true;
          break;
        }
      }
      if(!applied && lower.length){
        base += 0.25;
      }
    });
    base = clamp(base, -3, 5);

    const av = computeAvMetrics(record);
    const threat = computeThreatMetrics(record);
    const mapping = computeMappingScore(record, list);
    const diversity = computeDiversityScore(record);
    const binary = computeBinaryScore(record);
    const network = computeNetworkScore(record, list);
    const statusBoost = computeStatusBoost(status);
    const trustAdjustment = computeTrustAdjustment(record);

    let total = base + av.score + threat.score + mapping + diversity + binary + network + statusBoost + trustAdjustment;

    if(list.length <= 2 && total > 6){
      total -= 1.0; // dampen small-factor spikes to reduce false positives
    }

    const normalized = clamp(round2(total), 0, 10);
    const level = normalized >= 8 ? 'critical'
                 : normalized >= 6 ? 'high'
                 : normalized >= 4 ? 'medium'
                 : normalized >= 2 ? 'low'
                 : 'trace';

    return {
      score: normalized,
      level,
      status,
      details: {
        base: round2(base),
        factors: factorMatches,
        av: av.raw,
        avTotal: av.total,
        avScore: round2(av.score),
        threatWeight: round2(threat.raw || 0),
        twScore: round2(threat.score),
        mapping: round2(mapping),
        diversity: round2(diversity),
        binary: round2(binary),
        network: round2(network),
        statusBoost: round2(statusBoost),
        trustAdjustment: round2(trustAdjustment),
        statusHint: status
      }
    };
  }

  global.dreadMath = Object.assign({}, global.dreadMath, {
    computeScore,
    deriveStatus
  });
})(window);
