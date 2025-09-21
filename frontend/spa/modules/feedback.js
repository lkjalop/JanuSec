export function FeedbackWidget(){
  // Simple global widget to set API key and send feedback via fetch wrapper
  let toolbar = document.getElementById('feedback_toolbar');
  if(!toolbar){
    toolbar = document.createElement('div');
    toolbar.id = 'feedback_toolbar';
    toolbar.style = 'position:fixed;bottom:8px;right:8px;background:#222;color:#fff;padding:8px;font:12px monospace;border-radius:6px;';
    toolbar.innerHTML = `<div>API Key: <input id="apiKeyInput" size="18" placeholder="set key" /> <button id="saveKey">Save</button></div>
    <div style="margin-top:6px">Feedback: Event <input id="fb_event" size="10" placeholder="event id" /> Factor <input id="fb_factor" size="14" placeholder="factor" />
    <button id="fb_up">👍</button> <button id="fb_down">👎</button></div>
    <div id="fb_status"></div>`;
    document.body.appendChild(toolbar);
    toolbar.querySelector('#saveKey').onclick = ()=>{
      const v = toolbar.querySelector('#apiKeyInput').value.trim();
      if(v) localStorage.setItem('apiKey', v);
      toolbar.querySelector('#fb_status').textContent = 'Key saved';
    };
    toolbar.querySelector('#fb_up').onclick = ()=> send(1);
    toolbar.querySelector('#fb_down').onclick = ()=> send(-1);
  }
  function authHeaders(){
    const key = localStorage.getItem('apiKey');
    return key ? { 'x-api-key': key, 'Content-Type':'application/json' } : { 'Content-Type':'application/json' };
  }
  async function send(vote){
    const eventId = toolbar.querySelector('#fb_event').value.trim();
    const factor = toolbar.querySelector('#fb_factor').value.trim();
    if(!eventId || !factor){
      toolbar.querySelector('#fb_status').textContent = 'Missing event or factor';
      return;
    }
    const resp = await fetch('/api/v1/feedback/factor',{method:'POST', headers:authHeaders(), body: JSON.stringify({event_id:eventId, factor, vote: vote})});
    if(!resp.ok){
      toolbar.querySelector('#fb_status').textContent = 'Feedback error';
    } else {
      toolbar.querySelector('#fb_status').textContent = 'Feedback recorded';
    }
  }
}
