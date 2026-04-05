from src.integrations.llm_client import LLMClient


def test_prompt_token_cap_and_mock_response():
    client = LLMClient()
    # Ensure mock disabled by default in test environment; enable for this test
    client.mock = True
    client._mock_data = {
        'responses': [
            {'contains': 'summarize', 'response': {'text': 'summary text', 'model': 'mock-1', 'meta': {}}}
        ],
        'default': {'text': 'default mock', 'model': 'mock-1', 'meta': {}}
    }

    # short prompt should pass
    r = client.generate('please summarize this short text')
    assert 'text' in r and 'summary' in r['text'] or r['text'] == 'summary text'

    # long prompt should raise if over cap
    client.max_tokens = 3
    long_prompt = 'one two three four five six'
    try:
        client.generate(long_prompt)
        assert False, 'Expected ValueError due to token cap'
    except ValueError:
        pass
