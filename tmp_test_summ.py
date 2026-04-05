from src.llm.local_summarizer import summarize_tier1, summarize_tier2
import os

os.environ['USE_OLLAMA'] = '1'
os.environ['OLLAMA_HOST'] = 'http://127.0.0.1:11434'
os.environ['OLLAMA_MODEL'] = 'llama3:8b'

print('T1:', summarize_tier1('Test summary for a suspicious file execution on host X by user Y.'))
print('T2:', summarize_tier2('Detailed analysis text for a suspicious file execution including indicators and context.'))
