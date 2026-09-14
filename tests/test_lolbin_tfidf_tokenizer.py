import pytest
from src.modules.endpoint_hunter import EndpointHunter

@pytest.mark.asyncio
async def test_lolbin_tfidf_tokenizer_filters_noise(monkeypatch):
    monkeypatch.setenv('LOLBIN_TFIDF_ENABLED','1')
    eh = EndpointHunter(config=None)
    # Force low thresholds to trigger uncommon quickly
    eh._lolbin_idf_uncommon = 1.1
    eh._lolbin_idf_susp = 1.4
    eh._lolbin_idf_rare = 2.0
    # Command with many stop words, numeric and hex sequences which should be filtered
    cmd = "powershell.exe -c echo 1234567890 deadbeefcafebabe set and the copy start 4141414141414141 uniqueTokenX --param testValue"
    event = {
        'process': {'name': 'powershell.exe', 'parent_name': 'explorer.exe'},
        'cmdline': cmd
    }
    # Run a few slightly varied commands to build doc frequency and trigger at least uncommon
    tfidf_factors = []
    variants = [cmd, cmd + ' anotherParam', cmd + ' thirdVariant']
    for c in variants:
        event_var = {'process': {'name': 'powershell.exe', 'parent_name': 'explorer.exe'}, 'cmdline': c}
        res = await eh.analyze_event(event_var)
        tfidf_factors.extend([f for f in res['factors'] if f.startswith('endpoint:lolbin_cmd_tfidf_')])
    tfidf_factors = list(dict.fromkeys(tfidf_factors))  # unique preserve order
    assert any('uncommon' in f or 'suspicious' in f or 'rare' in f for f in tfidf_factors), f'Expected some tf-idf rarity factor, got {tfidf_factors}'
    # Ensure only one tier factor per event overall (unique list length <=3 across variants is fine)
    assert len(tfidf_factors) <= 3
    # Additional invocation should not balloon vocab size
    event2 = {'process': {'name': 'powershell.exe', 'parent_name': 'explorer.exe'}, 'cmdline': cmd + ' finalVariant'}
    _ = await eh.analyze_event(event2)
    vocab_size = len(eh._lolbin_tfidf_df['powershell.exe'])
    assert vocab_size < 100, f"Tokenizer noise produced large vocab: {vocab_size}"