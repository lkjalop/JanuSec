import asyncio
from src.modules.endpoint_hunter import EndpointHunter
import math

async def debug():
    h = EndpointHunter(config=None)
    base_cmd = 'powershell.exe -nop -c echo hello'
    for i in range(5):
        ev = {'process': {'name': 'powershell.exe'}, 'cmdline': base_cmd + f' {i}'}
        toks = h._tokenize_lolbin_cmd(ev['cmdline'])
        print('train toks:', toks)
        await h.analyze_event(ev)
        print('docs:', h._lolbin_tfidf_docs.get('powershell.exe'), 'df:', dict(h._lolbin_tfidf_df['powershell.exe']))
    rare_cmd = 'powershell.exe -nop -c invoke-randomartifactdownload xqzplatinum'
    evr = {'process': {'name': 'powershell.exe'}, 'cmdline': rare_cmd}
    toks = h._tokenize_lolbin_cmd(evr['cmdline'])
    print('rare toks:', toks)
    # compute idf manually
    docs_seen = h._lolbin_tfidf_docs.get('powershell.exe',0)
    N = docs_seen if docs_seen>0 else 1
    for tok in set(toks):
        df = h._lolbin_tfidf_df['powershell.exe'].get(tok,0)
        denom = df if df>0 else 1
        idf = math.log((N)/denom) if denom>0 else 0.0
        print('tok',tok,'df',df,'idf',idf)
    res = await h.analyze_event(evr)
    print('factors:', res['factors'], 'docs after:', h._lolbin_tfidf_docs.get('powershell.exe'))

asyncio.run(debug())
