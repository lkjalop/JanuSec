minimal = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CSV Analyzer (shim)</title>
</head>
<body>
  <h2 id="csv_title">CSV Analyzer (shim)</h2>
  <input id="fileInput" type="file" />
  <div id="csv_results_ready" style="display:none"></div>
  <script>
    window.__csvReady = true;
    window.ensureTbodyRowsFromList = function(list){ try{ window.LAST_RESULTS=list||[]; var t=document.getElementById('tbody'); if(t) t.innerHTML = (list||[]).slice(0,10).map(function(r,i){return '<tr data-row="'+i+'"><td>'+ (r&&r.verdict||'') +'</td></tr>'; }).join(''); window.dispatchEvent(new Event('csv-results-ready')); }catch(_){}}
  </script>
</body>
</html>\n'''

p = r'd:\AI\Threat_thy_sniffer\frontend\static\csv_analyzer.html'
with open(p, 'w', encoding='utf-8', newline='\n') as f:
    f.write(minimal)
print('wrote', p)
