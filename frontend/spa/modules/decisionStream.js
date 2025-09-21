export function DecisionStream(el){
  el.innerHTML = `<h2>Decision Stream</h2><pre id="ds_box">(connecting...)</pre>`;
  const box = el.querySelector('#ds_box');
  const ev = new EventSource('/stream/decisions');
  ev.onmessage = (e)=>{
    try {
      const arr = JSON.parse(e.data);
      const existing = box.textContent.split('\n');
      for(const item of arr){
        existing.unshift(JSON.stringify(item));
      }
      box.textContent = existing.slice(0,30).join('\n');
    } catch(err){
      box.textContent = 'Error parsing stream';
    }
  };
}
