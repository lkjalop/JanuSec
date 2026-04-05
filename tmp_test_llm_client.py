from src.integrations.llm_client import LLMClient

client = LLMClient()
resp = client.generate('Say hello from Ollama test', max_tokens=50, model='gpt-like', overrides={'ollama_host':'http://127.0.0.1:11434','ollama_model':'llama3:8b'})
print('Resp model:', resp.get('model'))
print('Text:', resp.get('text')[:300])
print('Meta:', resp.get('meta'))
