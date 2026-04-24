(function(window, document){
    'use strict';

    const state = {
        running: false,
        shouldReconnect: true,
        controller: null,
        retryTimer: null,
        retries: 0,
        buffer: '',
        listeners: new Set(),
        status: 'idle',
        lastEvent: null,
    };

    function resolveAuthHeaders(){
        try{
            if(typeof window.authHeaders === 'function'){
                return window.authHeaders();
            }
        }catch(_){}
        try{
            if(typeof window.H === 'function'){
                return window.H();
            }
        }catch(_){}
        try{
            const key = localStorage.getItem('apiKey');
            if(!key){
                return {};
            }
            const headers = { 'x-api-key': key };
            const tenant = localStorage.getItem('tenantId');
            if(tenant) headers['X-Tenant-ID'] = tenant;
            return headers;
        }catch(_){
            return {};
        }
    }

    function subscribe(fn){
        if(typeof fn !== 'function') return;
        state.listeners.add(fn);
        if(state.lastEvent){
            try{ fn(state.lastEvent); }catch(_){}
        }
        return function unsubscribe(){ state.listeners.delete(fn); };
    }

    function notifyListeners(evt){
        state.lastEvent = evt;
        state.listeners.forEach(fn => {
            try{ fn(evt); }catch(err){ console.warn('hopgraph stream listener error', err); }
        });
    }

    function setStatus(newStatus){
        state.status = newStatus;
        const el = document.getElementById('hopgraphStreamStatus');
        if(el){
            el.textContent = newStatus;
            el.setAttribute('data-status', newStatus);
        }
    }

    function scheduleReconnect(){
        if(!state.shouldReconnect) return;
        if(state.retryTimer) return;
        state.running = false;
        const backoff = Math.min(30000, 2000 + state.retries * 2000);
        setStatus('reconnecting in ' + Math.round(backoff/1000) + 's');
        state.retryTimer = setTimeout(()=>{
            state.retryTimer = null;
            connect();
        }, backoff);
        state.retries += 1;
    }

    function handleDisconnect(reason){
        state.connected = false;
        if(state.controller){
            try{ state.controller.abort(); }catch(_){}
            state.controller = null;
        }
        setStatus('disconnected');
        console.warn('HopGraph stream disconnected', reason);
        scheduleReconnect();
    }

    function parseBlock(block){
        if(!block) return null;
        if(block.startsWith(':')) return null; // keepalive
        const dataLines = [];
        const lines = block.split('\n');
        for(let i=0;i<lines.length;i++){
            const line = lines[i];
            if(line.startsWith('data:')){
                dataLines.push(line.slice(5).trim());
            }
        }
        if(!dataLines.length) return null;
        const raw = dataLines.join('\n');
        if(!raw) return null;
        try{
            return JSON.parse(raw);
        }catch(err){
            console.warn('HopGraph stream JSON parse error', err);
            return null;
        }
    }

    function pump(reader){
        const decoder = new TextDecoder('utf-8');
        function readChunk(){
            reader.read().then(({value, done})=>{
                if(done){
                    handleDisconnect('stream-ended');
                    return;
                }
                if(value){
                    state.buffer += decoder.decode(value, {stream:true});
                    const parts = state.buffer.split('\n\n');
                    state.buffer = parts.pop() || '';
                    parts.forEach(part=>{
                        const evt = parseBlock(part);
                        if(evt){
                            setStatus('live');
                            notifyListeners(evt);
                        }
                    });
                }
                readChunk();
            }).catch(err=>{
                handleDisconnect(err);
            });
        }
        readChunk();
    }

    function connect(){
        if(state.running) return;
        state.running = true;
        state.buffer = '';
        state.retries = 0;
        if(state.retryTimer){
            clearTimeout(state.retryTimer);
            state.retryTimer = null;
        }
        setStatus('connecting');
        const controller = new AbortController();
        state.controller = controller;
        const headers = Object.assign({'Accept':'text/event-stream'}, resolveAuthHeaders());
        fetch('/api/v1/graph/session/stream', {
            method: 'GET',
            headers,
            signal: controller.signal,
        }).then(resp=>{
            if(!resp.ok){
                throw new Error('HTTP '+resp.status);
            }
            if(!resp.body){
                throw new Error('no-body');
            }
            setStatus('connected');
            state.retries = 0;
            pump(resp.body.getReader());
        }).catch(err=>{
            handleDisconnect(err);
        });
    }

    function start(){
        state.shouldReconnect = true;
        if(state.running){
            return;
        }
        connect();
    }

    function stop(){
        state.shouldReconnect = false;
        if(state.retryTimer){
            clearTimeout(state.retryTimer);
            state.retryTimer = null;
        }
        if(state.controller){
            try{ state.controller.abort(); }catch(_){}
            state.controller = null;
        }
        state.running = false;
        setStatus('stopped');
    }

    function ensureLiveConsolePanel(){
        const right = document.getElementById('rightPanel');
        if(!right) return;
        if(document.getElementById('hopgraphStreamPanel')) return;
        const panel = document.createElement('div');
        panel.className = 'investigation-section';
        panel.id = 'hopgraphStreamPanel';
        panel.innerHTML = `
            <div class="section-title" style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
                <span>HopGraph Stream</span>
                <span id="hopgraphStreamStatus" class="chip" style="font-size:11px;padding:2px 10px;border-radius:999px;border:1px solid var(--border);color:var(--text-muted);">idle</span>
            </div>
            <div id="hopgraphStreamSummary" class="section-subtext">Watching for supply-chain, binary, and infrastructure overlays.</div>
            <div class="small" style="color:var(--text-muted);margin-bottom:6px;">listening on <code>/api/v1/graph/session/stream</code> (requires <code>x-api-key</code>)</div>
            <div id="hopgraphStreamLog" style="margin-top:10px;max-height:200px;overflow:auto;display:flex;flex-direction:column;gap:8px;"></div>
        `;
        right.insertBefore(panel, right.firstChild || null);
    }

    function formatTags(evt){
        const tags = new Set();
        (evt.kill_chain_tags || []).forEach(t=>tags.add(t));
        (evt.hotspot_tags || []).forEach(t=>tags.add(t));
        return Array.from(tags).slice(0,6);
    }

    function summarizeOverlay(evt){
        const overlay = evt && evt.hopgraph_overlay || {};
        const snapshot = overlay.snapshot || overlay;
        const supply = overlay.supply_chain_nodes != null ? overlay.supply_chain_nodes : countNodesByType(snapshot, ['package','cicd']);
        const binary = overlay.binary_nodes != null ? overlay.binary_nodes : countNodesByType(snapshot, ['binary','dll','driver']);
        const infra = overlay.infrastructure_nodes != null ? overlay.infrastructure_nodes : countNodesByType(snapshot, ['infrastructure','bgp','network_device','macsec']);
        return { supply, binary, infra };
    }

    function countNodesByType(snapshot, types){
        try{
            const set = new Set(types);
            const nodes = (snapshot && snapshot.nodes) || [];
            return nodes.filter(n=> set.has((n.type||'').toLowerCase())).length;
        }catch(_){
            return 0;
        }
    }

    // Translate graph-session internal verdicts to display labels.
    // Graph sessions use escalate/watch/benign/SUSPECT — these are investigation
    // confidence signals, NOT the six-ladder breach verdicts.
    var _SESSION_VERDICT_DISPLAY = {
        'escalate': 'INVESTIGATE (high confidence)',
        'SUSPECT':  'INVESTIGATE (elevated)',
        'watch':    'MONITOR (medium confidence)',
        'benign':   'LOW RISK (investigation)',
    };
    var _SESSION_VERDICT_COLOR = {
        'escalate': '#e05252',
        'SUSPECT':  '#ff8c42',
        'watch':    '#e0c446',
        'benign':   '#52e07f',
    };

    function _sessionVerdictLabel(raw) {
        return _SESSION_VERDICT_DISPLAY[raw] || (raw ? String(raw).toUpperCase() + ' (investigation)' : 'pending');
    }
    function _sessionVerdictColor(raw) {
        return _SESSION_VERDICT_COLOR[raw] || 'var(--text-muted)';
    }

    function updateLiveConsolePanel(evt){
        const summaryEl = document.getElementById('hopgraphStreamSummary');
        const logEl = document.getElementById('hopgraphStreamLog');
        if(!summaryEl || !logEl) return;
        const counts = summarizeOverlay(evt);
        const conf = evt.confidence != null ? Number(evt.confidence).toFixed(2) : 'n/a';
        const nodeCount = ((evt.graph_summary||{}).node_count) || '-';
        const verdictLabel = _sessionVerdictLabel(evt.verdict);
        summaryEl.textContent = `Session ${evt.session_id || 'n/a'} · ${verdictLabel} · conf ${conf} · nodes ${nodeCount} · supply ${counts.supply} · binary ${counts.binary} · infra ${counts.infra}`;
        const item = document.createElement('div');
        item.className = 'hopgraph-stream-item';
        item.style.padding = '10px';
        item.style.border = '1px solid var(--border, #2C3746)';
        item.style.borderRadius = '8px';
        item.style.background = 'var(--bg-tertiary, #1D2531)';
        const tags = formatTags(evt).map(t=>`<span class="pill" style="font-size:10px;margin-right:6px;">${window._htmlEsc ? window._htmlEsc(t) : t}</span>`).join('');
        const vColor = _sessionVerdictColor(evt.verdict);
        item.innerHTML = `
            <div style="font-size:12px;color:var(--text-primary);margin-bottom:4px;">
                ${window._htmlEsc ? window._htmlEsc(evt.session_id || 'session') : (evt.session_id || 'session')}
                <span style="color:var(--text-muted);margin-left:6px;">${new Date().toLocaleTimeString()}</span>
            </div>
            <div style="font-size:11px;margin-bottom:6px;">
                <span style="color:${vColor};font-weight:600;">${verdictLabel}</span>
                <span style="color:var(--text-muted);"> · conf ${conf} · diversity ${(evt.domain_diversity_score||0).toFixed ? Number(evt.domain_diversity_score).toFixed(2) : evt.domain_diversity_score}</span>
            </div>
            <div style="font-size:9px;color:var(--text-muted);margin-bottom:4px;">Investigation confidence — not a breach verdict</div>
            <div>${tags || '<span class="small">no tags</span>'}</div>
            <div style="margin-top:6px;">
                <a href="/static/attack_graph.html" target="_blank" style="font-size:11px;color:var(--accent);text-decoration:none;">Open HopGraph</a>
            </div>
        `;
        logEl.insertBefore(item, logEl.firstChild);
        while(logEl.childElementCount > 5){
            logEl.removeChild(logEl.lastChild);
        }
    }

    function updateHopGraphPage(evt){
        const overlaySummary = document.getElementById('overlaySummary');
        if(!overlaySummary) return;
        const counts = summarizeOverlay(evt);
        overlaySummary.textContent = `Streamed session ${evt.session_id || 'n/a'} · ${_sessionVerdictLabel(evt.verdict)} · supply ${counts.supply} · binary ${counts.binary} · infra ${counts.infra}`;
        if(typeof window.renderOverlay === 'function'){
            try{
                const overlay = evt.hopgraph_overlay || evt.overlay || {};
                window.renderOverlay(overlay);
            }catch(err){
                console.warn('renderOverlay from stream failed', err);
            }
        }
        const presetNodes = document.getElementById('presetNodes');
        if(presetNodes && evt.hopgraph_overlay){
            try{
                const snapshot = evt.hopgraph_overlay.snapshot || evt.hopgraph_overlay;
                presetNodes.textContent = JSON.stringify((snapshot && snapshot.nodes) ? snapshot.nodes.slice(0,10) : snapshot, null, 2);
            }catch(_){}
        }
    }

    function attachDefaultListeners(){
        subscribe(evt=>{
            updateLiveConsolePanel(evt);
            updateHopGraphPage(evt);
        });
    }

    function autoInit(){
        ensureLiveConsolePanel();
        attachDefaultListeners();
        start();
    }

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', autoInit);
    } else {
        setTimeout(autoInit, 200);
    }

    window.HopGraphStreamOverlay = {
        start,
        stop,
        subscribe,
        getStatus: function(){ return state.status; },
        getLastEvent: function(){ return state.lastEvent; }
    };

})(window, document);
