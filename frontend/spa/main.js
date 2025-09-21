// Minimal vanilla bootstrap (can be swapped to React later). For now, simple components.
import { DecisionStream } from './modules/decisionStream.js';
import { FactorSimilarity } from './modules/factorSimilarity.js';
import { FactorStats } from './modules/factorStats.js';
import { FeedbackWidget } from './modules/feedback.js';

const root = document.getElementById('root');
root.innerHTML = `
  <h1>Threat Sifter SPA (Alpha)</h1>
  <nav>
    <a href="#stream">Stream</a> | <a href="#similarity">Similarity</a> | <a href="#stats">Stats</a>
  </nav>
  <section id="stream" class="panel"></section>
  <section id="similarity" class="panel"></section>
  <section id="stats" class="panel"></section>
`;

DecisionStream(document.getElementById('stream'));
FactorSimilarity(document.getElementById('similarity'));
FactorStats(document.getElementById('stats'));
FeedbackWidget();
