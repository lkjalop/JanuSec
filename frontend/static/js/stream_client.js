/* Reconnecting Stream Client
   - Supports EventSource (SSE) primarily, with optional WebSocket fallback stub.
   - Exposes subscribe/unsubscribe and simple backoff jittered reconnect.
   - Usage: const client = new StreamClient('/api/v1/stream/decisions');
            const id = client.subscribe('message', (ev)=>{});
            client.start();
*/
(function(global){

  class StreamClient {
    constructor(url, opts={}){
      this.url = url;
      this.opts = Object.assign({
        type: 'sse', // 'sse'|'ws' (ws not fully implemented)
        maxReconnectDelay: 30000,
        baseDelay: 1000,
        jitter: 0.4,
        maxRetries: Infinity
      }, opts);
      this.state = 'idle';
      this.es = null;
      this.subscribers = new Map(); // event -> Map(id, fn)
      this._nextId = 1;
      this._retries = 0;
      this._reconnectTimer = null;
    }

    _emit(type, ev){
      const m = this.subscribers.get(type);
      if(!m) return;
      for(const fn of m.values()){
        try{ fn(ev); }catch(e){ console.error('stream subscriber error', e); }
      }
    }

    subscribe(eventType, fn){
      if(!this.subscribers.has(eventType)) this.subscribers.set(eventType, new Map());
      const id = this._nextId++;
      this.subscribers.get(eventType).set(id, fn);
      return id;
    }

    unsubscribe(eventType, id){
      const m = this.subscribers.get(eventType); if(!m) return;
      m.delete(id);
      if(m.size===0) this.subscribers.delete(eventType);
    }

    start(){
      if(this.state==='running' || this.state==='connecting') return;
      this._connect();
    }

    stop(){
      this._clearReconnect();
      this._closeSource();
      this.state='stopped';
    }

    _clearReconnect(){ if(this._reconnectTimer){ clearTimeout(this._reconnectTimer); this._reconnectTimer=null; } }

    _closeSource(){ if(this.es){ try{ this.es.close(); }catch{} this.es=null; } }

    _connect(){
      this.state='connecting';
      this._clearReconnect();
      try{
        if(this.opts.type==='sse'){
          const es = new EventSource(this.url);
          this.es = es;
          es.onopen = (ev)=>{ this._retries=0; this.state='running'; this._emit('open', ev); };
          es.onmessage = (ev)=>{ this._emit('message', ev); };
          es.onerror = (ev)=>{ this._emit('error', ev); this._onDisconnect(ev); };
        }else{
          // WebSocket fallback (basic, not fully featured in this initial version)
          const ws = new WebSocket(this.url.replace(/^http/, 'ws'));
          this.es = ws;
          ws.onopen = (ev)=>{ this._retries=0; this.state='running'; this._emit('open', ev); };
          ws.onmessage = (ev)=>{ this._emit('message', ev); };
          ws.onerror = (ev)=>{ this._emit('error', ev); this._onDisconnect(ev); };
          ws.onclose = (ev)=>{ this._emit('close', ev); this._onDisconnect(ev); };
        }
      }catch(err){
        this._emit('error', err);
        this._onDisconnect(err);
      }
    }

    _onDisconnect(ev){
      this._closeSource();
      if(this.state==='stopped') return;
      this.state='reconnecting';
      this._retries += 1;
      if(this._retries > this.opts.maxRetries){ this._emit('permanent-failure', ev); this.state='failed'; return; }
      const base = this.opts.baseDelay * Math.pow(1.5, Math.min(this._retries, 8));
      const jitter = Math.random()*this.opts.jitter*base;
      const delay = Math.min(this.opts.maxReconnectDelay, base + jitter);
      // schedule reconnect
      this._reconnectTimer = setTimeout(()=>{ this._connect(); }, delay);
      this._emit('reconnect-scheduled', { delay, retries: this._retries });
    }
  }

  global.StreamClient = StreamClient;
})(window);
