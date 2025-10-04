import React, { useEffect, useState, useRef, useCallback } from 'react';
import { getJSON, postJSON, apiBase } from './api.js';
import { tenantHeaders } from './api.js';
// Build-time env for gating overview sampler (Vite)
const SAMPLER_ENABLED = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_OVERVIEW_SAMPLER === '1');

// SVG Icons
const SearchIcon = () => (
  <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
  </svg>
);

const SortIcon = () => (
  <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12"/>
  </svg>
);

const ExportIcon = () => (
  <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
  </svg>
);

const UploadIcon = () => (
  <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"/>
  </svg>
);

const InfoIcon = () => (
  <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
  </svg>
);

// Header Component
const Header = ({ stats, onRefresh }) => (
  <header style={{
    gridColumn: '1 / -1',
    background: 'var(--bg-surface)',
    borderBottom: '1px solid var(--border-default)',
    display: 'flex',
    alignItems: 'center',
    padding: '0 20px',
    gap: '24px',
    height: '56px'
  }}>
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      paddingRight: '24px',
      borderRight: '1px solid var(--border-default)'
    }}>
      <div style={{
        width: '32px',
        height: '32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <svg width="32" height="32" viewBox="0 0 64 64" fill="none">
          <circle cx="32" cy="32" r="30" stroke="var(--accent-primary)" strokeWidth="2"/>
          <path d="M32 8 L32 56" stroke="var(--accent-primary)" strokeWidth="1" opacity="0.3"/>
          <path d="M20 24 Q20 20 24 20 L28 20 L28 44 Q28 48 24 48 L20 48 Z" fill="var(--accent-primary)" opacity="0.8"/>
          <path d="M44 24 Q44 20 40 20 L36 20 L36 44 Q36 48 40 48 L44 48 Z" fill="var(--accent-primary)" opacity="0.8"/>
          <circle cx="24" cy="28" r="2" fill="var(--bg-surface)"/>
          <circle cx="40" cy="28" r="2" fill="var(--bg-surface)"/>
        </svg>
      </div>
      <div style={{
        fontSize: '18px',
        fontWeight: '600',
        letterSpacing: '-0.5px'
      }}>JanuSec</div>
    </div>

    <div style={{
      display: 'flex',
      gap: '32px',
      marginLeft: 'auto'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Live Data</span>
        <span style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)' }}>{stats.liveStatus}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Artifacts</span>
        <span style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-primary)' }}>{stats.totalArtifacts}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Critical</span>
        <span style={{ fontSize: '14px', fontWeight: '600', color: 'var(--risk-critical)' }}>{stats.criticalCount}</span>
      </div>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '6px 12px',
        background: 'rgba(82, 196, 26, 0.1)',
        border: '1px solid rgba(82, 196, 26, 0.3)',
        borderRadius: '6px'
      }}>
        <div style={{
          width: '8px',
          height: '8px',
          background: 'var(--status-active)',
          borderRadius: '50%',
          animation: 'pulse 2s infinite'
        }}></div>
        <span style={{ fontSize: '12px', fontWeight: '500' }}>Processing</span>
      </div>
    </div>
  </header>
);

// Icon set (minimal professional outline style)
const IconDoc = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
  </svg>
);
const IconCluster = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <circle cx="5" cy="19" r="2" />
    <circle cx="19" cy="19" r="2" />
    <circle cx="5" cy="5" r="2" />
    <circle cx="19" cy="5" r="2" />
    <path d="M12 9v-2" />
    <path d="M12 17v-2" />
    <path d="M9 12H7" />
    <path d="M17 12h-2" />
    <path d="M9.8 10.2l-1.4-1.4" />
    <path d="M15.6 15.6l-1.4-1.4" />
  </svg>
);
const IconMitre = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" />
    <rect x="14" y="3" width="7" height="7" />
    <rect x="14" y="14" width="7" height="7" />
    <rect x="3" y="14" width="7" height="7" />
  </svg>
);
const IconTimeline = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 3" />
  </svg>
);
const IconAlerts = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 16v-5a6 6 0 1 0-12 0v5" />
    <path d="M5 16h14l-2 3H7z" />
    <path d="M10 2h4" />
  </svg>
);
const IconReports = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" stroke="currentColor" fill="none" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4 4h16v16H4z" />
    <path d="M8 8h8v2H8zM8 12h5v2H8z" />
  </svg>
);

// Sidebar Navigation
const Sidebar = ({ activeView, setActiveView }) => {
  const navItems = [
    { id: 'artifacts', title: 'Artifacts', icon: <IconDoc /> },
    { id: 'clusters', title: 'Clusters', icon: <IconCluster /> },
    { id: 'mitre', title: 'MITRE ATT&CK', icon: <IconMitre /> },
    { id: 'timeline', title: 'Timeline', icon: <IconTimeline /> },
    { id: 'alerts', title: 'Alerts', icon: <IconAlerts /> },
    { id: 'reports', title: 'Reports', icon: <IconReports /> }
  ];

  return (
    <nav aria-label="Primary navigation" role="navigation" style={{
      background: 'var(--bg-surface)',
      borderRight: '1px solid var(--border-default)',
      padding: '16px 0',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px'
    }}>
      {navItems.map(item => (
        <div
          key={item.id}
          title={item.title}
          onClick={() => setActiveView(item.id)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setActiveView(item.id);} }}
          style={{
            width: '48px',
            height: '48px',
            margin: '0 8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '8px',
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            fontSize: '20px',
            background: activeView === item.id ? 'var(--accent-primary-light)' : 'transparent',
            color: activeView === item.id ? 'var(--accent-primary)' : 'var(--text-muted)',
            position: 'relative',
            outline: 'none'
          }}
        >
          {activeView === item.id && (
            <div style={{
              position: 'absolute',
              left: '0',
              height: '24px',
              width: '3px',
              background: 'var(--accent-primary)',
              borderRadius: '0 2px 2px 0'
            }} />
          )}
          {item.icon}
        </div>
      ))}
    </nav>
  );
};

// Toolbar Component
const Toolbar = ({ searchQuery, setSearchQuery, filters, setFilters, onExport, exportUI, onSort, sortConfig }) => (
  <div role="region" aria-label="Toolbar" style={{
    background: 'var(--bg-surface)',
    padding: '12px 20px',
    borderBottom: '1px solid var(--border-default)',
    display: 'flex',
    gap: '16px',
    alignItems: 'center'
  }}>
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      padding: '8px 12px',
      background: 'var(--bg-surface-2)',
      border: '1px solid var(--border-default)',
      borderRadius: '6px',
      width: '280px',
      transition: 'all 0.2s ease'
    }}>
      <SearchIcon />
      <input
        type="search"
        aria-label="Search artifacts"
        placeholder="Search artifacts, hashes, or hosts..."
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        style={{
          flex: '1',
          background: 'none',
          border: 'none',
          outline: 'none',
          color: 'var(--text-primary)',
          fontSize: '13px'
        }}
      />
    </div>

    <div style={{ display: 'flex', gap: '8px' }}>
      {['All Types', 'High Risk', 'Rare', 'Multi-Host', 'Unsigned'].map(chip => (
        <div
          key={chip}
          onClick={() => setFilters(prev => ({ ...prev, [chip]: !prev[chip] }))}
          role="checkbox"
          aria-checked={!!filters[chip]}
          tabIndex={0}
          onKeyDown={(e)=>{ if(e.key==='Enter' || e.key===' '){ e.preventDefault(); setFilters(prev => ({ ...prev, [chip]: !prev[chip] })); } }}
          style={{
            padding: '6px 12px',
            background: filters[chip] ? 'var(--accent-primary)' : 'var(--bg-surface-2)',
            border: '1px solid var(--border-default)',
            borderRadius: '16px',
            fontSize: '12px',
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            whiteSpace: 'nowrap',
            fontWeight: '500',
            color: filters[chip] ? 'white' : 'var(--text-primary)'
          }}
        >
          {chip}
        </div>
      ))}
    </div>

    <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
      <button onClick={async ()=>{
        try{
          const res = await postJSON('/api/v1/query/nlp',{ text: 'maturity' });
          window.dispatchEvent(new CustomEvent('janusec-nlp', { detail: res }));
        }catch(e){ alert('NLP router unavailable'); }
      }} aria-label="NLP: Maturity" style={{
        padding: '8px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: '500', cursor: 'pointer', transition: 'all 0.2s ease', border: '1px solid var(--border-default)', background: 'var(--bg-surface-2)', color: 'var(--text-primary)'
      }}>Ask</button>
  <button onClick={onSort} aria-label="Sort by risk score" style={{
        padding: '8px 16px',
        borderRadius: '6px',
        fontSize: '12px',
        fontWeight: '500',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        border: '1px solid var(--border-default)',
        background: 'var(--bg-surface-2)',
        color: 'var(--text-primary)'
      }}>
        <SortIcon />
        Sort {sortConfig.direction === 'desc' ? '↓' : '↑'}
      </button>
      <div style={{ position:'relative' }}>
  <button onClick={onExport} aria-haspopup="true" aria-expanded={exportUI.dropdownOpen} aria-label="Export reports" style={{
          padding: '8px 16px',
          borderRadius: '6px',
          fontSize: '12px',
          fontWeight: '500',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          border: '1px solid var(--border-default)',
          background: 'var(--bg-surface-2)',
          color: 'var(--text-primary)'
        }}>
          <ExportIcon />
          Export
        </button>
        {exportUI.dropdownOpen && (
          <div style={{ position:'absolute', top:'100%', right:0, marginTop:'4px', background:'var(--bg-surface-2)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px 12px', display:'flex', flexDirection:'column', gap:'8px', minWidth:'260px', zIndex:30 }}>
            <div style={{ fontSize:'11px', textTransform:'uppercase', letterSpacing:'0.5px', color:'var(--text-muted)' }}>Report Export</div>
            <div style={{ display:'flex', flexDirection:'column', gap:'4px', maxHeight:'140px', overflowY:'auto', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'4px' }}>
              {exportUI.sessions.map(s => (
                <label key={s.session} style={{ display:'flex', alignItems:'center', gap:'6px', fontSize:'11px', cursor:'pointer' }}>
                  <input type='checkbox' checked={exportUI.selectedSessions.includes(s.session)} onChange={() => exportUI.toggleSession(s.session)} />
                  <span style={{flex:1}}>{s.filename || s.session}</span>
                  {s.suspicious_cells>0 && <span style={{ color:'var(--risk-high)', fontSize:'10px' }}>{s.suspicious_cells}</span>}
                </label>
              ))}
              {exportUI.sessions.length === 0 && <div style={{ fontSize:'11px', color:'var(--text-muted)' }}>No sessions</div>}
            </div>
            <input placeholder='Tenant ID (optional)' value={exportUI.tenant || ''} onChange={e=>exportUI.setTenant(e.target.value)} style={{
              background:'var(--bg-surface-3)', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'4px 6px', fontSize:'11px', color:'var(--text-primary)'
            }} />
            <div style={{ display:'flex', gap:'6px' }}>
              <button onClick={() => exportUI.fireExport('json')} style={{ flex:1, background:'var(--bg-surface-3)', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'6px 8px', cursor:'pointer', fontSize:'11px', color:'var(--text-primary)' }}>JSON</button>
              <button onClick={() => exportUI.fireExport('csv')} style={{ flex:1, background:'var(--bg-surface-3)', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'6px 8px', cursor:'pointer', fontSize:'11px', color:'var(--text-primary)' }}>CSV</button>
              <button onClick={() => exportUI.fireExport('html')} style={{ flex:1, background:'var(--bg-surface-3)', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'6px 8px', cursor:'pointer', fontSize:'11px', color:'var(--text-primary)' }}>HTML</button>
              <button onClick={() => exportUI.fireExport('pdf')} style={{ flex:1, background:'var(--bg-surface-3)', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'6px 8px', cursor:'pointer', fontSize:'11px', color:'var(--text-primary)' }}>PDF</button>
              <button onClick={exportUI.close} style={{ background:'var(--bg-surface-3)', border:'1px solid var(--border-default)', borderRadius:'4px', padding:'6px 8px', cursor:'pointer', fontSize:'11px', color:'var(--text-secondary)' }}>Close</button>
            </div>
          </div>
        )}
      </div>
  <button onClick={() => exportUI.triggerUpload()} aria-label="Upload batch" style={{
        padding: '8px 16px',
        borderRadius: '6px',
        fontSize: '12px',
        fontWeight: '500',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        background: 'var(--accent-primary)',
        border: '1px solid var(--accent-primary)',
        color: 'white'
      }}>
        <UploadIcon />
        Upload Batch
      </button>
    </div>
  </div>
);

// Artifact Grid Component
const ArtifactGrid = ({ artifacts, selectedArtifact, setSelectedArtifact }) => {
  const getRiskScoreStyle = (score) => {
    if (score >= 80) return { background: 'rgba(229, 77, 77, 0.2)', color: 'var(--risk-critical)', border: '1px solid rgba(229, 77, 77, 0.3)' };
    if (score >= 60) return { background: 'rgba(230, 126, 34, 0.2)', color: 'var(--risk-high)', border: '1px solid rgba(230, 126, 34, 0.3)' };
    if (score >= 40) return { background: 'rgba(243, 156, 18, 0.2)', color: 'var(--risk-medium)', border: '1px solid rgba(243, 156, 18, 0.3)' };
    return { background: 'rgba(52, 152, 219, 0.2)', color: 'var(--risk-low)', border: '1px solid rgba(52, 152, 219, 0.3)' };
  };

  const getVerdictColor = (verdict) => {
    switch (verdict?.toLowerCase()) {
      case 'malicious': return 'var(--risk-critical)';
      case 'high': return 'var(--risk-high)';
      case 'suspicious': return 'var(--risk-medium)';
      case 'controlled': return 'var(--risk-medium)';
      case 'benign': return 'var(--risk-minimal)';
      default: return 'var(--text-secondary)';
    }
  };

  return (
  <div role="table" aria-label="Artifact results" style={{
      flex: '1',
      overflow: 'auto',
      background: 'var(--bg-base)'
    }}>
      {/* Grid Header */}
  <div role="row" style={{
        position: 'sticky',
        top: '0',
        background: 'var(--bg-surface)',
        display: 'grid',
        gridTemplateColumns: '40px 240px 100px 80px 100px 80px 180px 1fr',
        padding: '12px 20px',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
        color: 'var(--text-muted)',
        borderBottom: '1px solid var(--border-default)',
        zIndex: '10',
        fontWeight: '600'
      }}>
        <div role="columnheader"></div>
        <div role="columnheader">Artifact</div>
        <div role="columnheader">Type</div>
        <div role="columnheader">Risk</div>
        <div role="columnheader">Verdict</div>
        <div role="columnheader">Hosts</div>
        <div role="columnheader">MITRE</div>
        <div role="columnheader">Factors</div>
      </div>

      {/* Grid Rows */}
      {artifacts.map((artifact, index) => (
        <div
          key={artifact.id || index}
          onClick={() => setSelectedArtifact(artifact)}
          role="row"
          tabIndex={0}
          onKeyDown={(e)=>{ if(e.key==='Enter'){ setSelectedArtifact(artifact);} }}
          style={{
            display: 'grid',
            gridTemplateColumns: '40px 240px 100px 80px 100px 80px 180px 1fr',
            padding: '12px 20px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.03)',
            fontSize: '13px',
            transition: 'all 0.15s ease',
            cursor: 'pointer',
            alignItems: 'center',
            background: selectedArtifact?.id === artifact.id ? 'var(--bg-surface-2)' : 'transparent',
            borderLeft: selectedArtifact?.id === artifact.id ? '2px solid var(--accent-primary)' : '2px solid transparent'
          }}
        >
          <div role="gridcell">
            <div style={{
              width: '16px',
              height: '16px',
              border: '1px solid var(--border-default)',
              borderRadius: '3px',
              cursor: 'pointer',
              background: selectedArtifact?.id === artifact.id ? 'var(--accent-primary)' : 'transparent'
            }}></div>
          </div>
          <div role="gridcell" style={{
            fontFamily: "'Monaco', 'Consolas', monospace",
            fontSize: '12px',
            color: 'var(--text-primary)'
          }}>{artifact.name}</div>
          <div role="gridcell" style={{ color: 'var(--text-secondary)' }}>{artifact.type}</div>
          <div role="gridcell">
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '3px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: '600',
              minWidth: '32px',
              ...getRiskScoreStyle(artifact.risk_score)
            }}>
              {artifact.risk_score}
            </span>
          </div>
          <div role="gridcell">
            <span style={{
              fontSize: '11px',
              fontWeight: '600',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              color: getVerdictColor(artifact.verdict)
            }}>
              {artifact.verdict}
            </span>
          </div>
          <div role="gridcell" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
            {artifact.host_count && (
              <>
                <svg width="12" height="12" fill={getVerdictColor(artifact.verdict)} viewBox="0 0 20 20">
                  <circle cx="10" cy="10" r="8"/>
                </svg>
                {artifact.host_count}
              </>
            )}
          </div>
          <div role="gridcell" style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {artifact.mitre_tags?.map(tag => (
              <span key={tag} style={{
                padding: '2px 6px',
                background: 'var(--bg-surface-2)',
                border: '1px solid var(--border-default)',
                borderRadius: '3px',
                fontSize: '10px',
                fontFamily: "'Monaco', 'Consolas', monospace"
              }}>
                {tag}
              </span>
            )) || '-'}
          </div>
          <div role="gridcell" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {artifact.factors?.join(' • ') || 'No factors'}
          </div>
        </div>
      ))}
    </div>
  );
};

// Details Panel Component
const DetailsPanel = ({ selectedArtifact, zeekEvents, setZeekEvents, addToast }) => {
  const [liveEvents, setLiveEvents] = useState([]);
  const sseRef = useRef(null);
  const retryRef = useRef(0);
  const [dread, setDread] = useState(null);

  // Robust SSE with exponential backoff
  useEffect(() => {
    let closed = false;
    function connect() {
      if (closed) return;
      try {
        sseRef.current = new EventSource('/api/v1/stream/decisions');
        sseRef.current.onopen = () => {
          retryRef.current = 0;
          addToast('Live stream connected', 'success', 2500, 'sse-connected');
        };
        sseRef.current.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setLiveEvents(prev => [data, ...prev.slice(0, 20)]);
            if (data.details?.zeek_log_type) {
              setZeekEvents(prev => [data, ...prev.slice(0, 50)]);
            }
          } catch (e) {
            console.error('Error parsing SSE data:', e);
          }
        };
        sseRef.current.onerror = () => {
          if (sseRef.current) sseRef.current.close();
          const attempt = retryRef.current + 1;
            retryRef.current = attempt;
          const delay = Math.min(30000, 500 * Math.pow(2, attempt));
          addToast(`Stream disconnected. Reconnecting in ${Math.round(delay/1000)}s (attempt ${attempt})`, 'warn', 4000);
          setTimeout(connect, delay);
        };
      } catch (err) {
        const attempt = retryRef.current + 1;
        retryRef.current = attempt;
        const delay = Math.min(30000, 500 * Math.pow(2, attempt));
        addToast(`Stream error. Retry in ${Math.round(delay/1000)}s`, 'error', 4000);
        setTimeout(connect, delay);
      }
    }
    connect();
    return () => { closed = true; if (sseRef.current) sseRef.current.close(); };
  }, [setZeekEvents, addToast]);

  if (!selectedArtifact) {
    return (
      <aside style={{
        background: 'var(--bg-surface)',
        borderLeft: '1px solid var(--border-default)',
        padding: '20px',
        overflowY: 'auto'
      }}>
        <h3 style={{
          fontSize: '14px',
          fontWeight: '600',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <InfoIcon />
          Live Zeek Events
        </h3>

        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          {liveEvents.map((event, index) => (
            <div key={index} style={{
              padding: '8px',
              background: 'var(--bg-surface-2)',
              borderRadius: '4px',
              marginBottom: '8px',
              fontSize: '11px',
              fontFamily: "'Monaco', 'Consolas', monospace"
            }}>
              <div style={{ color: 'var(--accent-primary)', marginBottom: '4px' }}>
                {event.event_id || 'Unknown ID'}
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>
                Verdict: <span style={{ color: getVerdictColor(event.verdict) }}>{event.verdict}</span>
              </div>
              {event.confidence && (
                <div style={{ color: 'var(--text-muted)' }}>
                  Confidence: {(event.confidence * 100).toFixed(1)}%
                </div>
              )}
            </div>
          ))}
        </div>
      </aside>
    );
  }

  const getVerdictColor = (verdict) => {
    switch (verdict?.toLowerCase()) {
      case 'malicious': return 'var(--risk-critical)';
      case 'high': return 'var(--risk-high)';
      case 'suspicious': return 'var(--risk-medium)';
      case 'controlled': return 'var(--risk-medium)';
      case 'benign': return 'var(--risk-minimal)';
      default: return 'var(--text-secondary)';
    }
  };

  return (
    <aside style={{
      background: 'var(--bg-surface)',
      borderLeft: '1px solid var(--border-default)',
      padding: '20px',
      overflowY: 'auto'
    }}>
      <h3 style={{
        fontSize: '14px',
        fontWeight: '600',
        marginBottom: '20px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px'
      }}>
        <InfoIcon />
        Artifact Intelligence
      </h3>

      {/* Metrics Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '12px',
        marginBottom: '24px'
      }}>
        <div style={{
          padding: '12px',
          background: 'var(--bg-surface-2)',
          borderRadius: '8px',
          border: '1px solid var(--border-default)'
        }}>
          <div style={{
            fontSize: '24px',
            fontWeight: '600',
            marginBottom: '4px',
            color: selectedArtifact.risk_score >= 80 ? 'var(--risk-critical)' : 'var(--accent-primary)'
          }}>
            {selectedArtifact.risk_score}
          </div>
          <div style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            Risk Score
          </div>
        </div>
        <div style={{
          padding: '12px',
          background: 'var(--bg-surface-2)',
          borderRadius: '8px',
          border: '1px solid var(--border-default)'
        }}>
          <div style={{ fontSize: '24px', fontWeight: '600', marginBottom: '4px' }}>
            {selectedArtifact.host_count || 1}
          </div>
          <div style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            Hosts
          </div>
        </div>
        <div style={{
          padding: '12px',
          background: 'var(--bg-surface-2)',
          borderRadius: '8px',
          border: '1px solid var(--border-default)'
        }}>
          <div style={{ fontSize: '24px', fontWeight: '600', marginBottom: '4px' }}>
            #{selectedArtifact.cluster || 'N/A'}
          </div>
          <div style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            Cluster
          </div>
        </div>
        <div style={{
          padding: '12px',
          background: 'var(--bg-surface-2)',
          borderRadius: '8px',
          border: '1px solid var(--border-default)'
        }}>
          <div style={{
            fontSize: '24px',
            fontWeight: '600',
            marginBottom: '4px',
            color: 'var(--risk-high)'
          }}>
            {selectedArtifact.prevalence || 'RARE'}
          </div>
          <div style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            Prevalence
          </div>
        </div>
      </div>

      {/* DREAD Risk (computed) */}
      <div style={{
          padding: '12px',
          background: 'var(--bg-surface-2)',
          borderRadius: '8px',
          border: '1px solid var(--border-default)',
          marginBottom: '16px'
        }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div style={{ fontSize:'12px', fontWeight:600, color:'var(--text-secondary)' }}>DREAD Risk</div>
          <button onClick={async()=>{
            try{
              const factors = selectedArtifact.factors || [];
              const d = await postJSON('/api/v1/risk/dread', { factors, asset_criticality:1.0, exposure:1.0 });
              setDread(d);
            }catch(e){ addToast('DREAD compute failed','error',3000); }
          }} style={{ fontSize:'11px', padding:'4px 8px' }}>Compute</button>
        </div>
        {dread ? (
          <div style={{ marginTop:'8px', fontSize:'12px' }}>
            <div>Risk Score: <b>{Math.round((dread.risk_score||0)*1000)/1000}</b></div>
            <div style={{ opacity:0.8, marginTop:6 }}>
              <div>Damage: {dread.components.damage}</div>
              <div>Reproducibility: {dread.components.reproducibility}</div>
              <div>Exploitability: {dread.components.exploitability}</div>
              <div>Affected Users: {dread.components.affected_users}</div>
              <div>Discoverability: {dread.components.discoverability}</div>
            </div>
          </div>
        ) : (
          <div style={{ marginTop:'8px', fontSize:'12px', color:'var(--text-muted)' }}>Click Compute to derive DREAD score</div>
        )}
      </div>

      {/* Hash Display */}
      {selectedArtifact.hash && (
        <div style={{ marginBottom: '20px' }}>
          <div style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            marginBottom: '8px',
            textTransform: 'uppercase',
            letterSpacing: '0.5px'
          }}>
            SHA-256 Hash
          </div>
          <div style={{
            padding: '12px',
            background: 'var(--bg-base)',
            borderRadius: '6px',
            fontFamily: "'Monaco', 'Consolas', monospace",
            fontSize: '11px',
            wordBreak: 'break-all',
            color: 'var(--text-muted)'
          }}>
            {selectedArtifact.hash}
          </div>
        </div>
      )}

      {/* Risk Factor Analysis */}
      <div style={{ marginTop: '20px' }}>
        <div style={{
          fontSize: '12px',
          fontWeight: '600',
          marginBottom: '12px',
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
          color: 'var(--text-secondary)'
        }}>
          Risk Factor Analysis
        </div>

        {selectedArtifact.risk_factors?.map((factor, index) => (
          <div key={index} style={{
            display: 'flex',
            justifyContent: 'space-between',
            padding: '8px 0',
            borderBottom: '1px solid var(--border-light)',
            fontSize: '13px'
          }}>
            <span style={{ color: 'var(--text-secondary)' }}>{factor.name}</span>
            <span style={{
              fontWeight: '600',
              fontFamily: "'Monaco', 'Consolas', monospace",
              color: factor.score > 0 ? 'var(--risk-high)' : 'var(--risk-minimal)'
            }}>
              {factor.score > 0 ? '+' : ''}{factor.score}
            </span>
          </div>
        )) || (
          <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
            No risk factors available
          </div>
        )}
      </div>

      {/* Action Panel */}
      <div style={{
        marginTop: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px'
      }}>
        <button style={{
          width: '100%',
          padding: '8px 16px',
          borderRadius: '6px',
          fontSize: '12px',
          fontWeight: '500',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px',
          background: 'var(--accent-primary)',
          border: '1px solid var(--accent-primary)',
          color: 'white'
        }} onClick={async ()=>{
          try {
            const d = await postJSON('/api/v1/incidents', { artifact_id: selectedArtifact.id, title: `Investigation: ${selectedArtifact.name}`, severity: selectedArtifact.risk_score>=80?'critical':'high', tenant_id: selectedArtifact.tenant_id });
            console.log('Incident created', d);
          } catch(e){ console.error('incident create failed', e); }
        }}>
          <InfoIcon />
          Create Critical Incident
        </button>
        <button style={{
          width: '100%',
          padding: '8px 16px',
          borderRadius: '6px',
          fontSize: '12px',
          fontWeight: '500',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px',
          border: '1px solid var(--border-default)',
          background: 'var(--bg-surface-2)',
          color: 'var(--text-primary)'
        }} onClick={async ()=>{
          try {
            const r = await fetch(`/api/v1/decisions/${selectedArtifact.id}/override`, {method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ verdict: 'BENIGN', confidence: 0.05, reason: 'Manual analyst override' })});
            if(r.ok){ const d= await r.json(); console.log('Override applied', d); }
          } catch(e){ console.error('override failed', e); }
        }}>
          Override Verdict
        </button>
        <button style={{
          width: '100%',
          padding: '8px 16px',
          borderRadius: '6px',
          fontSize: '12px',
          fontWeight: '500',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '6px',
          border: '1px solid var(--border-default)',
          background: 'var(--bg-surface-2)',
          color: 'var(--text-primary)'
        }}>
          View in VirusTotal
        </button>
      </div>
    </aside>
  );
};

// Main Platform Component
// Simple toast system
const Toasts = ({ toasts, dismiss }) => (
  <div style={{ position:'fixed', top:10, right:10, display:'flex', flexDirection:'column', gap:'8px', zIndex:9999 }}>
    {toasts.map(t => (
      <div key={t.id} onClick={() => dismiss(t.id)} style={{
        background: t.level === 'error' ? 'rgba(229,77,77,0.12)' : t.level === 'warn' ? 'rgba(243,156,18,0.15)' : 'var(--bg-surface)',
        border: '1px solid var(--border-default)',
        borderLeft: `4px solid ${t.level === 'error' ? 'var(--risk-critical)' : t.level === 'warn' ? 'var(--risk-high)' : 'var(--accent-primary)'}`,
        padding: '8px 12px',
        borderRadius: '4px',
        fontSize: '12px',
        minWidth: '240px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
        cursor:'pointer'
      }}>
        <div style={{ fontWeight:600, marginBottom:2 }}>{t.title}</div>
        {t.msg && <div style={{ opacity:0.85 }}>{t.msg}</div>}
      </div>
    ))}
  </div>
);

// Cost Estimator component
const EstimatorCard = ({ addToast }) => {
  const [hours, setHours] = useState(24);
  const [tenant, setTenant] = useState('all');
  const [modelEnabled, setModelEnabled] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showBreakdown, setShowBreakdown] = useState(false);

  const clampHours = (v) => Math.max(1, Math.min(336, v|0));

  const runEstimate = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams({ window_hours: String(hours), model_enabled: String(modelEnabled), tenant });
  const d = await getJSON(`/api/v1/finops/estimate?${qs.toString()}`);
      setResult(d);
    } catch (e) {
      addToast('Estimator error', 'error', 3000);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
        <label style={{ fontSize:'12px' }}>Window (hours)
          <input type="number" min={1} max={336} value={hours} onChange={e=>setHours(clampHours(parseInt(e.target.value||'0',10)))} style={{ marginLeft:6, width:90 }}/>
        </label>
        <label style={{ fontSize:'12px' }}>Tenant
          <input value={tenant} onChange={e=>setTenant(e.target.value)} style={{ marginLeft:6, width:160 }}/>
        </label>
        <label style={{ fontSize:'12px' }}>
          <input type="checkbox" checked={modelEnabled} onChange={e=>setModelEnabled(e.target.checked)} style={{ marginRight:6 }}/>
          Enable model calls
        </label>
        <button onClick={runEstimate} disabled={loading} style={{ padding:'6px 10px' }}>{loading?'Estimating...':'Estimate'}</button>
        <label style={{ fontSize:'12px', marginLeft: 'auto' }}>
          <input type="checkbox" checked={showBreakdown} onChange={e=>setShowBreakdown(e.target.checked)} style={{ marginRight:6 }}/>
          Show breakdown
        </label>
      </div>
      {result && (
        <div style={{ marginTop:'8px', fontSize:'12px', color:'var(--text-secondary)' }}>
          <div>Window: {result.window_hours}h • Events: {result.events_estimate}</div>
          <div>Fusion candidates: {result.fusion_candidates_estimate} • Model calls: {result.model_calls_estimate}</div>
          <div>Estimated total: <b>{result.cost_units_estimate}</b> ± {result.error_margin_units} ({result.confidence} confidence)</div>
          {showBreakdown && result.breakdown && (
            <div style={{ marginTop:6 }}>
              <div>Base: {result.breakdown.base} • Fusion: {result.breakdown.fusion} • Model: {result.breakdown.model}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const ArtifactIntelligencePlatform = () => {
  // Periodic FinOps overview sampling (env-guarded)
  useEffect(() => {
  const enabled = SAMPLER_ENABLED === true;
    if (!enabled) return;
    let cancelled = false;
    const sampleOverview = async () => {
      try {
        await getJSON('/api/v1/finops/overview');
      } catch (e) {
        // ignore
      }
    };
    const intv = setInterval(() => {
      if (!cancelled) sampleOverview();
    }, 15000); // every 15s
    return () => { cancelled = true; clearInterval(intv); };
  }, []);
  const [activeView, setActiveView] = useState('artifacts');
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({ 'High Risk': true });
  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [artifacts, setArtifacts] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [mitre, setMitre] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [zeekEvents, setZeekEvents] = useState([]);
  const [stats, setStats] = useState({ liveStatus: 'Connected', totalArtifacts: 0, criticalCount: 0 });
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [sessions, setSessions] = useState([]);
  const [selectedSessions, setSelectedSessions] = useState([]);
  const [tenant, setTenant] = useState('');
  const fileInputRef = useRef(null);
  const [sortConfig, setSortConfig] = useState({ key: 'risk_score', direction: 'desc' });
  const [toasts, setToasts] = useState([]);
  const [maturityData, setMaturityData] = useState(null);
  const [finops, setFinops] = useState({ overview:null, ledger:null, daily:null, forecast:null, accuracy:null, history:null });
  const [dreadInfo, setDreadInfo] = useState(null);
  const [webhookInfo, setWebhookInfo] = useState({ vendor: 'generic', secret: '', body: '{"events":[{"id":"demo","foo":"bar"}]}' , sig: '', ts: '' , recent: []});
  const timelinePageSize = 120;
  const [timelinePage, setTimelinePage] = useState(0);

  // toast helpers
  const addToast = useCallback((title, level='info', ttl=3000, idOverride=null, msg='') => {
    setToasts(prev => {
      const id = idOverride || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      // de-dupe on idOverride
      const filtered = idOverride ? prev.filter(t => t.id !== idOverride) : prev;
      return [...filtered, { id, title, level, msg, expires: Date.now()+ttl }];
    });
  }, []);
  // auto expire
  useEffect(() => {
    const t = setInterval(() => {
      setToasts(prev => prev.filter(p => p.expires > Date.now()));
    }, 1000);
    return () => clearInterval(t);
  }, []);
  const dismissToast = (id) => setToasts(prev => prev.filter(t => t.id !== id));

  const handleSort = () => {
    setSortConfig(cfg => ({ key: 'risk_score', direction: cfg.direction === 'desc' ? 'asc' : 'desc' }));
  };

  // Load initial data
  useEffect(() => {
    const loadData = async () => {
      try {
        // Prefer real artifacts endpoint
    const data = await getJSON(`/api/v1/artifacts/list?limit=60`, { headers: tenantHeaders(tenant) });
        const arts = (data.artifacts || []).map((a, i) => ({
          id: a.id || a.name || `artifact-${i}`,
          name: a.name || a.id || `artifact-${i}`,
          type: a.type || 'UNKNOWN',
          risk_score: a.risk_score ?? Math.floor((a.confidence || 0.5) * 100),
          verdict: a.verdict || 'UNKNOWN',
          host_count: a.host_count || a.hosts?.length || 1,
          mitre_tags: a.mitre_tags || a.mitre || [],
          factors: a.factors || a.risk_factors?.map(f => f.name) || [],
          hash: a.hash,
          risk_factors: a.risk_factors || []
        }));
        setArtifacts(arts);
        setStats({
          liveStatus: 'Connected',
          totalArtifacts: arts.length,
          criticalCount: arts.filter(a => a.risk_score >= 80).length
        });
        if (arts.length && !selectedArtifact) setSelectedArtifact(arts[0]);
        return; // Done
      } catch (error) {
        console.warn('Artifacts list failed, fallback to decisions:', error.message);
        try {
          const decisionsData = await getJSON('/api/v1/decisions/recent?limit=20');
          const mockArtifacts = decisionsData.decisions?.map((decision, index) => ({
            id: decision.event_id || `artifact-${index}`,
            name: decision.event_id?.includes('zeek') ?
              `${decision.details?.zeek_log_type || 'unknown'}.log` :
              `artifact_${index}.exe`,
            type: decision.details?.zeek_log_type ? 'NETWORK' : 'EXECUTABLE',
            risk_score: Math.floor((decision.confidence || 0.5) * 100),
            verdict: decision.verdict || 'UNKNOWN',
            host_count: Math.floor(Math.random() * 10) + 1,
            mitre_tags: decision.mitre_techniques || ['T1059'],
            factors: ['unsigned', 'rare', 'network-beacon'],
            hash: `a7c24b7dc90e8a67f9c3b1d4e5f6789abcdef0123456789abcdef01234567${index.toString().padStart(2, '0')}`,
            risk_factors: [
              { name: 'Unsigned Executable', score: 22 },
              { name: 'Multi-Host Spread', score: 18 },
              { name: 'First Seen (Rare)', score: 15 }
            ]
          })) || [];
          setArtifacts(mockArtifacts);
          setStats({ liveStatus: 'Connected', totalArtifacts: mockArtifacts.length, criticalCount: mockArtifacts.filter(a => a.risk_score >= 80).length });
          if (mockArtifacts.length && !selectedArtifact) setSelectedArtifact(mockArtifacts[0]);
        } catch (e2) {
          addToast('Initial artifact load failed', 'error', 5000);
        }
      }
    };
    loadData();
  }, [tenant, addToast, selectedArtifact]);

  // Periodically fetch sessions when dropdown is open
  useEffect(() => {
    let timer;
    const fetchSessions = async () => {
      try {
        const data = await getJSON('/api/v1/upload/tabular/sessions');
        setSessions(data.sessions || []);
      } catch (e) {
        // ignore
      }
      if (dropdownOpen) timer = setTimeout(fetchSessions, 6000);
    };
    if (dropdownOpen) fetchSessions();
    return () => { if (timer) clearTimeout(timer); };
  }, [dropdownOpen]);

  // Handle NLP suggestions by showing a toast and pre-loading data
  useEffect(() => {
    function onNlp(ev){
      const data = ev.detail || {}; const first = (data.actions||[])[0];
      if(first){ addToast(first.title || 'NLP suggestion', 'info', 3000); }
    }
    window.addEventListener('janusec-nlp', onNlp);
    return () => window.removeEventListener('janusec-nlp', onNlp);
  }, [addToast]);

  const exportUI = {
    dropdownOpen,
    sessions,
    selectedSessions,
    tenant,
    setTenant,
    toggleSession: (sid) => setSelectedSessions(prev => prev.includes(sid) ? prev.filter(x=>x!==sid) : [...prev, sid]),
    fireExport: (format) => {
      window.dispatchEvent(new CustomEvent('janusec-export', { detail: { format, sessions: selectedSessions, tenant } }));
    },
    close: () => setDropdownOpen(false),
    triggerUpload: () => fileInputRef.current?.click()
  };

  const handleExport = () => {
    setDropdownOpen(o => !o);
  };

  // Export handling (all formats)
  useEffect(() => {
    async function onExport(ev){
      const fmt = ev.detail?.format || 'json';
      const selSessions = ev.detail?.sessions || [];
      const tenantHeader = ev.detail?.tenant || '';
      try {
        const qs = new URLSearchParams({ format: fmt });
        if (selSessions.length) qs.set('sessions', selSessions.join(','));
        const r = await fetch(`/api/v1/report/ingestion?${qs.toString()}`, { headers: tenantHeader ? { 'X-Tenant-ID': tenantHeader } : {} });
        if (!r.ok) {
          if (fmt === 'pdf' && r.status === 501) { alert('PDF generation not enabled.'); return; }
          throw new Error('Report request failed');
        }
        if (fmt === 'json') {
          const data = await r.json();
          const blob = new Blob([JSON.stringify(data,null,2)], { type:'application/json' });
          const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download='ingestion_report.json'; a.click(); URL.revokeObjectURL(a.href);
        } else if (fmt === 'pdf') {
          const blob = await r.blob(); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download='ingestion_report.pdf'; a.click(); URL.revokeObjectURL(a.href);
        } else if (fmt === 'csv') {
          const text = await r.text(); const blob = new Blob([text], { type:'text/csv' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download='ingestion_report.csv'; a.click(); URL.revokeObjectURL(a.href);
        } else if (fmt === 'html') {
          const text = await r.text(); const blob = new Blob([text], { type:'text/html' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download='ingestion_report.html'; a.click(); URL.revokeObjectURL(a.href);
        }
        addToast(`Report exported (${fmt.toUpperCase()})`, 'info', 3000);
      } catch(e) { console.error('Export error', e); alert('Export failed: '+ e.message); }
    }
    window.addEventListener('janusec-export', onExport); return () => window.removeEventListener('janusec-export', onExport);
  }, [selectedSessions, tenant, addToast]);

  // Upload handling
  const onUploadChange = async (e) => {
    const files = e.target.files; if (!files || !files.length) return;
    // size validation (limit 15MB total)
    const total = [...files].reduce((acc,f)=>acc+f.size,0);
    if (total > 15 * 1024 * 1024) { addToast('Upload exceeds 15MB limit', 'error', 6000); if (fileInputRef.current) fileInputRef.current.value=''; return; }
    const form = new FormData(); for (const f of files) form.append('files', f);
    try { setLoading(true); 
      // For file uploads, keep fetch (multipart/form-data)
      const r = await fetch('/api/v1/upload/tabular', { method:'POST', body: form }); if (!r.ok) throw new Error('Upload failed');
      setTimeout(async ()=>{ try { const d = await getJSON('/api/v1/upload/tabular/sessions'); setSessions(d.sessions||[]); } catch(_){} }, 500);
      addToast('Upload complete', 'success', 4000);
    } catch(err){ console.error(err); addToast('Upload error: '+ err.message, 'error', 6000); } finally { setLoading(false); if (fileInputRef.current) fileInputRef.current.value=''; }
  };

  // Load data for non-artifact views
  useEffect(() => {
    let cancelled = false;
    async function load(){
      if (activeView === 'artifacts') return;
      setErrorMsg(''); setLoading(true);
      try {
        const headers = tenant ? { 'X-Tenant-ID': tenant } : {};
        if (activeView === 'alerts') {
          try { const d = await getJSON('/api/v1/alerts/recent?limit=50'); if(!cancelled) setAlerts(d.alerts||[]); } catch(_){}
          try { const d = await getJSON('/api/v1/alerts/recent?limit=50', { headers: tenantHeaders(tenant) }); if(!cancelled) setAlerts(d.alerts||[]); } catch(_){}
        } else if (activeView === 'clusters') {
          try { const d = await getJSON('/api/v1/analytics/clusters?limit=200'); if(!cancelled) setClusters(d.clusters||[]); } catch(_){}
          try { const d = await getJSON('/api/v1/analytics/clusters?limit=200', { headers: tenantHeaders(tenant) }); if(!cancelled) setClusters(d.clusters||[]); } catch(_){}
        } else if (activeView === 'mitre') {
          try { const d = await getJSON('/api/v1/analytics/mitre?top_n=40'); if(!cancelled) setMitre(d.techniques||[]); } catch(_){}
          try { const d = await getJSON('/api/v1/analytics/mitre?top_n=40', { headers: tenantHeaders(tenant) }); if(!cancelled) setMitre(d.techniques||[]); } catch(_){}
        } else if (activeView === 'timeline') {
          try { const d = await getJSON('/api/v1/analytics/timeline?limit_decisions=400&limit_alerts=200'); if(!cancelled) { setTimeline(d.items||[]); setTimelinePage(0);} } catch(_){}
          try { const d = await getJSON('/api/v1/analytics/timeline?limit_decisions=400&limit_alerts=200', { headers: tenantHeaders(tenant) }); if(!cancelled) { setTimeline(d.items||[]); setTimelinePage(0);} } catch(_){}
        } else if (activeView === 'reports') {
          try {
            const d = await getJSON('/api/v1/dashboard/maturity', { headers: tenantHeaders(tenant) }); if(!cancelled) setMaturityData(d);
          } catch(_){ }
          // Load FinOps metrics in parallel (best-effort)
          try {
            let usedSummary = false;
            try {
              const s = await getJSON('/api/v1/finops/cost_summary', { headers: tenantHeaders(tenant) });
              if (!cancelled && s && (s.overview || s.daily || s.forecast)) {
                setFinops({ overview: s.overview || null, ledger: null, daily: s.daily || null, forecast: s.forecast || null, accuracy: null, history: null });
                usedSummary = true;
              }
            } catch(_){ /* fallback to per-endpoint */ }
            if (!usedSummary) {
              const [o,l,dly,f,a,h] = await Promise.all([
                getJSON('/api/v1/finops/overview').catch(()=>null),
                getJSON('/api/v1/finops/ledger').catch(()=>null),
                getJSON('/api/v1/finops/daily').catch(()=>null),
                getJSON('/api/v1/finops/forecast').catch(()=>null),
                getJSON('/api/v1/finops/accuracy?limit=15').catch(()=>null),
                getJSON('/api/v1/finops/history?limit=60').catch(()=>null),
              ]);
              if(!cancelled) setFinops({ overview:o, ledger:l, daily:dly, forecast:f, accuracy:a, history:h });
            }
          } catch(_){}
        }
      } catch(err){ if(!cancelled) setErrorMsg(err.message || 'load error'); }
      finally { if(!cancelled) setLoading(false); }
    }
    load(); return () => { cancelled = true; };
  }, [activeView, tenant]);

  // auto refresh alerts every 30s when on alerts view
  useEffect(() => {
    if (activeView !== 'alerts') return;
    const headers = tenant ? { 'X-Tenant-ID': tenant } : {};
    const fetchAlerts = async () => {
      try { const d = await getJSON('/api/v1/alerts/recent?limit=50'); setAlerts(d.alerts||[]); } catch(_){}
    };
    const intv = setInterval(fetchAlerts, 30000);
    return () => clearInterval(intv);
  }, [activeView, tenant]);

  // derived artifacts with filtering & sorting
  const displayedArtifacts = artifacts
    .filter(a => a.name.toLowerCase().includes(searchQuery.toLowerCase()) || a.type.toLowerCase().includes(searchQuery.toLowerCase()))
    .sort((a,b) => {
      const dir = sortConfig.direction === 'desc' ? -1 : 1;
      const av = a[sortConfig.key] ?? 0; const bv = b[sortConfig.key] ?? 0;
      if (av < bv) return 1 * dir; if (av > bv) return -1 * dir; return 0;
    });

  const totalTimelinePages = Math.ceil(timeline.length / timelinePageSize);
  const pageItems = timeline.slice(timelinePage * timelinePageSize, (timelinePage+1)*timelinePageSize);

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '64px 1fr 360px',
      gridTemplateRows: '56px 1fr',
      height: '100vh',
      overflow: 'hidden'
    }}>
      <Header stats={stats} />
      <Sidebar activeView={activeView} setActiveView={setActiveView} />

      <main style={{ display:'flex', flexDirection:'column', overflow:'hidden' }}>
        <Toolbar searchQuery={searchQuery} setSearchQuery={setSearchQuery} filters={filters} setFilters={setFilters} onExport={handleExport} exportUI={exportUI} onSort={handleSort} sortConfig={sortConfig} />
        {loading && <div style={{ padding:'10px 16px', fontSize:'12px', color:'var(--text-muted)' }}>Loading...</div>}
        {errorMsg && <div style={{ padding:'10px 16px', fontSize:'12px', color:'var(--risk-high)' }}>Error: {errorMsg}</div>}
        {activeView === 'artifacts' && (
          <ArtifactGrid artifacts={displayedArtifacts} selectedArtifact={selectedArtifact} setSelectedArtifact={setSelectedArtifact} />
        )}
        {activeView === 'alerts' && (
          <div style={{ flex:1, overflow:'auto' }}>
            <table style={{ width:'100%', fontSize:'12px', borderCollapse:'collapse' }}>
              <thead style={{ background:'var(--bg-surface-2)' }}><tr><th style={{ textAlign:'left', padding:'6px 8px' }}>ID</th><th style={{ textAlign:'left', padding:'6px 8px' }}>Title</th><th style={{ textAlign:'left', padding:'6px 8px' }}>Severity</th><th style={{ textAlign:'left', padding:'6px 8px' }}>MITRE</th><th style={{ textAlign:'left', padding:'6px 8px' }}>Age</th></tr></thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id} style={{ borderBottom:'1px solid var(--border-light)' }}>
                    <td style={{ padding:'6px 8px', fontFamily:"'Monaco','Consolas',monospace" }}>{a.id}</td>
                    <td style={{ padding:'6px 8px' }}>{a.title}</td>
                    <td style={{ padding:'6px 8px', fontWeight:600, textTransform:'uppercase' }}>{a.severity}</td>
                    <td style={{ padding:'6px 8px' }}>{a.mitre}</td>
                    <td style={{ padding:'6px 8px' }}>{a.age}</td>
                  </tr>
                ))}
                {alerts.length === 0 && !loading && <tr><td colSpan={5} style={{ padding:'8px 10px', fontSize:'11px', color:'var(--text-muted)' }}>No alerts</td></tr>}
              </tbody>
            </table>
          </div>
        )}
        {activeView === 'clusters' && (
          <div style={{ flex:1, overflow:'auto', padding:'12px 20px' }}>
            <h3 style={{ margin:'4px 0 12px', fontSize:'14px' }}>Similarity Clusters</h3>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(260px,1fr))', gap:'12px' }}>
              {clusters.map(c => (
                <div key={c.signature} style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                  <div style={{ fontSize:'12px', fontWeight:600, wordBreak:'break-all' }}>{c.signature}</div>
                  <div style={{ fontSize:'11px', color:'var(--text-muted)', margin:'4px 0' }}>Size: {c.size} • Avg Conf: {c.avg_confidence}</div>
                  <div style={{ fontSize:'10px', color:'var(--text-secondary)' }}>Sample: {c.sample_members.map(m=>m.event_id).join(', ')}</div>
                </div>
              ))}
              {clusters.length === 0 && !loading && <div style={{ fontSize:'11px', color:'var(--text-muted)' }}>No clusters</div>}
            </div>
          </div>
        )}
        {activeView === 'mitre' && (
          <div style={{ flex:1, overflow:'auto', padding:'12px 20px' }}>
            <h3 style={{ margin:'4px 0 12px', fontSize:'14px' }}>MITRE Technique Frequency</h3>
            <table style={{ width:'100%', fontSize:'12px', borderCollapse:'collapse' }}>
              <thead style={{ background:'var(--bg-surface-2)' }}><tr><th style={{ textAlign:'left', padding:'6px 8px' }}>Technique</th><th style={{ textAlign:'left', padding:'6px 8px' }}>Count</th></tr></thead>
              <tbody>
                {mitre.map(t => (
                  <tr key={t.technique} style={{ borderBottom:'1px solid var(--border-light)' }}>
                    <td style={{ padding:'6px 8px', fontFamily:"'Monaco','Consolas',monospace" }}>{t.technique}</td>
                    <td style={{ padding:'6px 8px' }}>{t.count}</td>
                  </tr>
                ))}
                {mitre.length === 0 && !loading && <tr><td colSpan={2} style={{ padding:'6px 8px', fontSize:'11px', color:'var(--text-muted)' }}>No techniques</td></tr>}
              </tbody>
            </table>
          </div>
        )}
        {activeView === 'timeline' && (
          <div style={{ flex:1, overflow:'auto', padding:'12px 20px', display:'flex', flexDirection:'column' }}>
            <h3 style={{ margin:'4px 0 12px', fontSize:'14px' }}>Unified Timeline</h3>
            <div style={{ fontSize:'11px', color:'var(--text-muted)', marginBottom:8 }}>Items: {timeline.length} • Page {timelinePage+1}/{Math.max(1,totalTimelinePages)}</div>
            <ul style={{ listStyle:'none', margin:0, padding:0, fontSize:'12px', flex:1 }}>
              {pageItems.map((item,i) => (
                <li key={i} style={{ padding:'6px 4px', borderBottom:'1px solid var(--border-light)', display:'flex', gap:'16px' }}>
                  <span style={{ fontFamily:"'Monaco','Consolas',monospace", color:'var(--text-secondary)' }}>{item.ts ? new Date(item.ts*1000).toISOString().split('T')[1].slice(0,8) : '—'}</span>
                  <span style={{ textTransform:'uppercase', fontSize:'10px', fontWeight:600, letterSpacing:'0.5px', color: item.type === 'alert' ? 'var(--risk-high)' : 'var(--accent-primary)' }}>{item.type}</span>
                  <span style={{ flex:1, wordBreak:'break-all' }}>{item.event_id || item.id || '—'}</span>
                </li>
              ))}
              {timeline.length === 0 && !loading && <li style={{ padding:'6px 4px', fontSize:'11px', color:'var(--text-muted)' }}>No timeline items</li>}
            </ul>
            {totalTimelinePages > 1 && (
              <div style={{ display:'flex', gap:'8px', justifyContent:'center', padding:'8px 0' }}>
                <button disabled={timelinePage===0} onClick={()=>setTimelinePage(p=>Math.max(0,p-1))} style={{ padding:'4px 8px', fontSize:'11px', cursor: timelinePage===0 ? 'not-allowed':'pointer' }}>Prev</button>
                <button disabled={timelinePage>=totalTimelinePages-1} onClick={()=>setTimelinePage(p=>Math.min(totalTimelinePages-1,p+1))} style={{ padding:'4px 8px', fontSize:'11px', cursor: timelinePage>=totalTimelinePages-1 ? 'not-allowed':'pointer' }}>Next</button>
              </div>
            )}
          </div>
        )}
        {activeView === 'reports' && (
          <div style={{ flex:1, overflow:'auto', padding:'12px 20px' }}>
            <h3 style={{ margin:'4px 0 12px', fontSize:'14px' }}>Reports</h3>
            <p style={{ fontSize:'12px', color:'var(--text-muted)' }}>Use Export to generate new reports. A history view can be added.</p>
            {/* Maturity Coverage Card */}
            <div style={{ marginTop: '12px', display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
              <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>MAESTRO Coverage</div>
                <ul style={{ listStyle:'none', padding:0, margin:0, fontSize:'12px' }}>
                  {(maturityData?.maestro_phase_coverage||[]).slice(0,10).map(([phase,count],i)=> (
                    <li key={i} style={{ display:'flex', justifyContent:'space-between', borderBottom:'1px solid var(--border-light)', padding:'4px 0' }}>
                      <span>{phase}</span>
                      <span style={{ fontFamily:"'Monaco','Consolas',monospace" }}>{count}</span>
                    </li>
                  ))}
                  {(!maturityData || (maturityData.maestro_phase_coverage||[]).length===0) && <li style={{ color:'var(--text-muted)' }}>No data</li>}
                </ul>
              </div>
              <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>STRIDE Coverage</div>
                <ul style={{ listStyle:'none', padding:0, margin:0, fontSize:'12px' }}>
                  {(maturityData?.stride_category_coverage||[]).slice(0,10).map(([cat,count],i)=> (
                    <li key={i} style={{ display:'flex', justifyContent:'space-between', borderBottom:'1px solid var(--border-light)', padding:'4px 0' }}>
                      <span>{cat}</span>
                      <span style={{ fontFamily:"'Monaco','Consolas',monospace" }}>{count}</span>
                    </li>
                  ))}
                  {(!maturityData || (maturityData.stride_category_coverage||[]).length===0) && <li style={{ color:'var(--text-muted)' }}>No data</li>}
                </ul>
              </div>
            </div>
            {/* FinOps Cost & Ledger */}
            <div style={{ marginTop: '12px', display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
              <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>Cost Overview (EWMA)</div>
                <div style={{ fontSize:'12px', color:'var(--text-secondary)' }}>
                  <div>Points: {finops.overview?.points ?? 0}</div>
                  <div>Latest: {finops.overview?.latest_cost != null ? finops.overview.latest_cost.toFixed(2) : '—'}</div>
                  <div>EWMA: {finops.overview?.ewma != null ? finops.overview.ewma.toFixed(2) : '—'}</div>
                  <div>Threshold: {finops.overview?.ewma_threshold != null ? finops.overview.ewma_threshold.toFixed(2) : '—'}</div>
                  <div>Anomaly: {finops.overview?.anomaly_flag ? 'Yes' : 'No'}</div>
                  {/* Sparkline for EWMA vs Latest */}
                  <div style={{ marginTop:8, height:60, background:'var(--bg-base)', border:'1px solid var(--border-light)', borderRadius:4, position:'relative' }}>
                    {(() => {
                      const pts = finops.history?.points || [];
                      if (!pts.length) return <div style={{ fontSize:'11px', color:'var(--text-muted)', padding:4 }}>No history</div>;
                      const w = 260, h = 60;
                      // scale
                      const vals = pts.flatMap(p=>[p.latest||0,p.ewma||0,p.threshold||0]);
                      const min = Math.min(...vals), max = Math.max(...vals);
                      const x = (i) => (i/(pts.length-1)) * (w-8) + 4;
                      const y = (v) => h - 4 - ((v - min) / ((max-min)||1)) * (h-8);
                      const path = (sel) => pts.map((p,i)=>`${i?'L':'M'}${x(i)},${y(sel(p)||0)}`).join(' ');
                      return (
                        <svg width={w} height={h} style={{ position:'absolute', left:0, top:0 }}>
                          <path d={path(p=>p.threshold)} stroke="#f39c12" fill="none" strokeWidth="1" />
                          <path d={path(p=>p.ewma)} stroke="#3498db" fill="none" strokeWidth="1.5" />
                          <path d={path(p=>p.latest)} stroke="#2ecc71" fill="none" strokeWidth="1" />
                        </svg>
                      );
                    })()}
                  </div>
                </div>
              </div>
              <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>Daily Cost Estimate</div>
                <div style={{ fontSize:'12px', color:'var(--text-secondary)' }}>
                  <div>Day: {finops.daily?.day || '—'}</div>
                  <div>Estimated Today: ${finops.daily?.estimated_usd_day?.toFixed ? finops.daily.estimated_usd_day.toFixed(4) : (finops.daily?.estimated_usd_day ?? '—')}</div>
                  <div>Month-to-Date: ${finops.daily?.estimated_usd_month_to_date?.toFixed ? finops.daily.estimated_usd_month_to_date.toFixed(2) : (finops.daily?.estimated_usd_month_to_date ?? '—')}</div>
                  <div>Artifacts: {finops.daily?.artifacts_processed ?? 0} • LLM Tokens: {finops.daily?.llm_tokens ?? 0}</div>
                </div>
              </div>
            </div>
            {/* Cost Estimator */}
            <div style={{ marginTop: '12px', background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'8px' }}>
                <div style={{ fontSize:'13px', fontWeight:600 }}>Cost Estimator</div>
              </div>
              <EstimatorCard addToast={addToast} />
            </div>
            <div style={{ marginTop: '12px', display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
              <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>Monthly Forecast</div>
                <div style={{ fontSize:'12px', color:'var(--text-secondary)' }}>
                  <div>Forecast Units: {finops.forecast?.forecast_units ?? 0}</div>
                  <div>Avg Daily: {finops.forecast?.avg_daily ?? 0}</div>
                  <div>Basis Days: {finops.forecast?.basis_days ?? 0}</div>
                </div>
              </div>
              <div style={{ background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
                <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>Inference Ledger</div>
                <div style={{ fontSize:'12px', color:'var(--text-secondary)', maxHeight:180, overflowY:'auto' }}>
                  {(finops.ledger?.inference_summary || []).slice(0,8).map((row,i)=> (
                    <div key={i} style={{ display:'grid', gridTemplateColumns:'1fr 60px 70px 60px', gap:'6px', padding:'2px 0', borderBottom:'1px solid var(--border-light)' }}>
                      <span title={`${row.path}`}>{row.tier}</span>
                      <span style={{ fontFamily:"'Monaco','Consolas',monospace"}}>{row.calls}</span>
                      <span>{row.avg_latency_ms} ms</span>
                      <span>{row.tokens ?? 0}</span>
                    </div>
                  ))}
                  {(!finops.ledger || (finops.ledger.inference_summary||[]).length===0) && <div style={{ color:'var(--text-muted)' }}>No ledger data</div>}
                </div>
              </div>
            </div>

            {/* Integrations Quick Actions */}
            <div style={{ marginTop: '12px', background:'var(--bg-surface)', border:'1px solid var(--border-default)', borderRadius:'6px', padding:'10px' }}>
              <div style={{ fontSize:'13px', fontWeight:600, marginBottom:'8px' }}>Integrations</div>
              <div style={{ display:'flex', gap:'8px', flexWrap:'wrap' }}>
                <button onClick={async()=>{ try{ const d=await postJSON('/api/v1/integrations/misp/sync',{}); alert('MISP sync: '+ JSON.stringify(d)); }catch(e){ alert('MISP sync failed'); } }} style={{ padding:'6px 10px' }}>Sync MISP</button>
                <button onClick={async()=>{ try{ const d=await postJSON('/api/v1/integrations/opencti/sync',{}); alert('OpenCTI sync: '+ JSON.stringify(d)); }catch(e){ alert('OpenCTI sync failed'); } }} style={{ padding:'6px 10px' }}>Sync OpenCTI</button>
                <button onClick={async()=>{ try{ const d=await getJSON('/api/v1/integrations/webhooks/audit'); alert('Webhook deliveries: '+ JSON.stringify(d)); }catch(e){ alert('Webhook audit failed'); } }} style={{ padding:'6px 10px' }}>Webhook Audit</button>
              </div>
            </div>
          </div>
        )}
      </main>

      <DetailsPanel selectedArtifact={selectedArtifact} zeekEvents={zeekEvents} setZeekEvents={setZeekEvents} addToast={addToast} />
      <input ref={fileInputRef} type="file" style={{ display:'none' }} multiple onChange={onUploadChange} />
      <Toasts toasts={toasts} dismiss={dismissToast} />
    </div>
  );
};