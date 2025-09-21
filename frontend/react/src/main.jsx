import React from 'react';
import { createRoot } from 'react-dom/client';
import { ApiKeyBar, DecisionStream, FactorSimilarity, FactorStats, FactorWeights, EmbeddingMetrics, FeedbackForm } from './components.jsx';
import { NlpQuery } from './nlp.jsx';

function App(){
  return <div style={{fontFamily:'Arial',padding:12}}>
    <ApiKeyBar />
    <h1>Threat Sifter React Console (Alpha)</h1>
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(340px,1fr))',gap:16}}>
      <div style={{border:'1px solid #ccc',padding:8}}><DecisionStream /></div>
      <div style={{border:'1px solid #ccc',padding:8}}><FactorSimilarity /></div>
      <div style={{border:'1px solid #ccc',padding:8}}><FactorStats /></div>
      <div style={{border:'1px solid #ccc',padding:8}}><FactorWeights /></div>
      <div style={{border:'1px solid #ccc',padding:8}}><EmbeddingMetrics /></div>
      <div style={{border:'1px solid #ccc',padding:8}}><FeedbackForm /></div>
      <div style={{border:'1px solid #ccc',padding:8}}><NlpQuery /></div>
    </div>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);
