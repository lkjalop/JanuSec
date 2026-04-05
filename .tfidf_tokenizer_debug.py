import asyncio, os
from src.modules.endpoint_hunter import EndpointHunter

async def debug():
    os.environ['LOLBIN_TFIDF_ENABLED'] = '1'
    eh = EndpointHunter(config=None)
    eh._lolbin_idf_uncommon = 1.1
    eh._lolbin_idf_susp = 1.4
    eh._lolbin_idf_rare = 2.0
    cmd = "powershell.exe -c echo 1234567890 deadbeefcafebabe set and the copy start 4141414141414141 uniqueTokenX --param testValue"
    variants = [cmd, cmd + ' anotherParam', cmd + ' thirdVariant']
    all_factors = []
    for c in variants:
        ev = {'process': {'name': 'powershell.exe', 'parent_name': 'explorer.exe'}, 'cmdline': c}
        toks = eh._tokenize_lolbin_cmd(c)
        res = await eh.analyze_event(ev)
        print('cmd', c)
        print('tokens', toks)
        print('factors', res['factors'])
        all_factors.extend([f for f in res['factors'] if f.startswith('endpoint:lolbin_cmd_tfidf_')])
    print('unique tfidf_factors', list(dict.fromkeys(all_factors)))
    print('vocab_size', len(eh._lolbin_tfidf_df['powershell.exe']))

asyncio.run(debug())
