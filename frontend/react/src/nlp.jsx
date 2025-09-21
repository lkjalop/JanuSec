import React, { useState } from 'react';
import { postJSON } from './api.js';

export function NlpQuery(){
  const [query,setQuery] = useState('show malicious events last 1h');
  const [page,setPage] = useState(1);
  const [size,setSize] = useState(25);
  const [loading,setLoading] = useState(false);
  const [error,setError] = useState(null);
  const [dsl,setDsl] = useState(null);
  const [rows,setRows] = useState([]);

  async function run(){
    setLoading(true); setError(null);
    try{
      const data = await postJSON('/api/v1/query/nlp',{query,page,size});
      setDsl(data.dsl); setRows(data.results||[]);
    }catch(e){ setError('Request failed'); }
    setLoading(false);
  }

  return <div>
    <h2>NLP Query</h2>
    <div style={{display:'flex',flexWrap:'wrap',gap:8,alignItems:'center'}}>
      <input style={{flex:'1 1 240px'}} value={query} onChange={e=>setQuery(e.target.value)} />
      <label>Page <input type="number" value={page} min={1} onChange={e=>setPage(parseInt(e.target.value)||1)} style={{width:60}} /></label>
      <label>Size <input type="number" value={size} min={1} max={200} onChange={e=>setSize(parseInt(e.target.value)||25)} style={{width:60}} /></label>
      <button onClick={run} disabled={loading}>{loading? 'Running...' : 'Run'}</button>
    </div>
    {error && <div style={{color:'red'}}>{error}</div>}
    {dsl && <details open><summary>Parsed DSL</summary><pre style={{maxHeight:150,overflow:'auto'}}>{JSON.stringify(dsl,null,2)}</pre></details>}
    <h3>Results</h3>
    <pre style={{maxHeight:300,overflow:'auto',background:'#111',color:'#eee',padding:8}}>{rows.length? JSON.stringify(rows,null,2): '(no results yet)'}</pre>
  </div>;
}
