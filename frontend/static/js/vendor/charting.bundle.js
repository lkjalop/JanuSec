// Simulated charting bundle used in demos/tests
(function(){
  window.ChartingLib = {
    init: function(container, data){
      try{
        const el = typeof container === 'string' ? document.getElementById(container) : container;
        if(!el) return null;
        const div = document.createElement('div'); div.className='chart-lib-placeholder'; div.textContent='[chart loaded]'; div.style.padding='6px'; el.appendChild(div);
        return div;
      }catch(e){ return null; }
    }
  };
})();
