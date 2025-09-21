export function FactorStats(el){
  el.innerHTML = `<h2>Factor Stats</h2>
  <select id="win">
    <option value="30m">30m</option>
    <option value="1h" selected>1h</option>
    <option value="4h">4h</option>
  </select>
  <button id="refresh">Refresh</button>
  <pre id="stats_box">(no data)</pre>`;
  const box = el.querySelector('#stats_box');
  async function load(){
    const w = el.querySelector('#win').value;
    const r = await fetch(`/api/v1/stats/factors/top?window=${w}&limit=15`);
    if(!r.ok){ box.textContent='error'; return; }
    const j = await r.json();
    box.textContent = JSON.stringify(j.top, null, 2);
  }
  el.querySelector('#refresh').onclick = load;
  load();
}
