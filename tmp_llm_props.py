from src.integrations import llm_client
import os
c = llm_client.DEFAULT_CLIENT
print('provider=', getattr(c,'provider',None))
print('ollama_enabled=', getattr(c,'ollama_enabled',None))
print('ollama_host=', getattr(c,'ollama_host',None))
print('ollama_model=', getattr(c,'ollama_model',None))
print('mock=', getattr(c,'mock',None))
print('timeout=', getattr(c,'timeout',None))
print('ollama_timeout=', getattr(c,'ollama_timeout',None))
print('LLM_PROVIDER env=', os.getenv('LLM_PROVIDER'))
print('OLLAMA_HOST env=', os.getenv('OLLAMA_HOST'))
print('OLLAMA_MODEL env=', os.getenv('OLLAMA_MODEL'))
