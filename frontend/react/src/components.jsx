import React, { useEffect, useState, useRef } from 'react';
import { getJSON, postJSON } from './api.js';

export function ApiKeyBar(){
  const [val,setVal] = useState(localStorage.getItem('apiKey')||'');
  return <div style={{background:'#222',color:'#fff',padding:8,display:'flex',gap:8}}>
    <span>API Key:</span>
    <input value={val} onChange={e=>setVal(e.target.value)} placeholder="enter key" />
    <button onClick={()=>{localStorage.setItem('apiKey', val);}}>Save</button>
  </div>;
}

export function DecisionStream(){
  const [lines,setLines] = useState([]);
  useEffect(()=>{
    const ev = new EventSource('/stream/decisions');
    ev.onmessage = e => {
      try {
        const arr = JSON.parse(e.data);
        setLines(prev=>[...arr.map(a=>JSON.stringify(a)), ...prev].slice(0,30));
      } catch{}
    };
    return ()=>ev.close();
  },[]);
  return <div><h2>Decision Stream</h2><pre style={{maxHeight:300,overflow:'auto'}}>{lines.join('\n')}</pre></div>;
}

export function FactorSimilarity(){
  const [q,setQ] = useState('');
  const [res,setRes] = useState([]);
  const search = async ()=>{
    if(!q) return; setRes([{loading:true}]);
    try { const data = await getJSON(`/api/v1/query/factors?similar=${encodeURIComponent(q)}&limit=10`); setRes(data.results||[]);} catch{ setRes([{error:true}]); }
  };
  return <div><h2>Similarity</h2>
    <input value={q} onChange={e=>setQ(e.target.value)} placeholder="privilege escalation" /> <button onClick={search}>Search</button>
    <pre style={{maxHeight:250,overflow:'auto'}}>{JSON.stringify(res,null,2)}</pre>
  </div>;
}

export function FactorStats(){
  const [win,setWin] = useState('1h');
  const [data,setData] = useState([]);
  const load = async ()=>{ try { const d = await getJSON(`/api/v1/stats/factors/top?window=${win}&limit=15`); setData(d.top||[]);} catch{} };
  useEffect(()=>{ load(); },[win]);
  return <div><h2>Factor Stats</h2>
    <select value={win} onChange={e=>setWin(e.target.value)}><option value="30m">30m</option><option value="1h">1h</option><option value="4h">4h</option></select>
    <pre style={{maxHeight:250,overflow:'auto'}}>{JSON.stringify(data,null,2)}</pre>
  </div>;
}

export function FactorWeights(){
  const [weights,setWeights]=useState({});
  const load=async()=>{ try { const d= await getJSON('/api/v1/weights/factors'); setWeights(d.weights||{});} catch{} };
  useEffect(()=>{ load(); const t=setInterval(load,60000); return ()=>clearInterval(t); },[]);
  return <div><h2>Factor Weights</h2><pre>{JSON.stringify(weights,null,2)}</pre></div>;
}

export function EmbeddingMetrics(){
  const [metrics,setMetrics]=useState({});
  const load=async()=>{ try { const d= await getJSON('/api/v1/metrics/embedding'); setMetrics(d);} catch{} };
  useEffect(()=>{ load(); const t=setInterval(load,30000); return ()=>clearInterval(t); },[]);
  return <div><h2>Embedding & Drift</h2><pre>{JSON.stringify(metrics,null,2)}</pre></div>;
}

export function FeedbackForm(){
  const [eventId,setEventId]=useState('');
  const [factor,setFactor]=useState('');
  const send=async(vote)=>{try{await postJSON('/api/v1/feedback/factor',{event_id:eventId,factor,vote});}catch{}}
  return <div><h2>Feedback</h2>
    <input placeholder="event id" value={eventId} onChange={e=>setEventId(e.target.value)} />
    <input placeholder="factor" value={factor} onChange={e=>setFactor(e.target.value)} />
    <button onClick={()=>send(1)}>👍</button>
    <button onClick={()=>send(-1)}>👎</button>
  </div>;
}
