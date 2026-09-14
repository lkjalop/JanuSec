/* Simple in-memory LRU cache with TTL and capacity.
   API: const c = new LRUCache({capacity:100, ttl:30000});
        c.get(key); c.set(key, value);
*/
(function(global){
  class LRUCache {
    constructor(opts={}){
      this.capacity = opts.capacity || 100;
      this.ttl = opts.ttl || 30000; // ms
      this.map = new Map(); // key -> {value, expires, node}
    }

    _now(){ return Date.now(); }

    _isExpired(entry){ return entry.expires && entry.expires < this._now(); }

    get(key){
      const e = this.map.get(key);
      if(!e) return null;
      if(this._isExpired(e)){ this.map.delete(key); return null; }
      // refresh recency
      this.map.delete(key);
      this.map.set(key, e);
      return e.value;
    }

    set(key, value, ttl){
      if(this.map.has(key)) this.map.delete(key);
      const expires = (ttl===undefined? this._now()+this.ttl : (ttl? this._now()+ttl : null));
      this.map.set(key, { value, expires });
      while(this.map.size > this.capacity){ // evict oldest
        const k = this.map.keys().next().value; this.map.delete(k);
      }
    }

    del(key){ this.map.delete(key); }

    clear(){ this.map.clear(); }
  }

  global.LRUCache = LRUCache;
})(window);
