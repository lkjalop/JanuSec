import sys
sys.path.insert(0, 'd:/AI/Threat_thy_sniffer')
from src.api import llm_prompts
context = {'rows':[{'process_name':'powershell.exe','host':'ws-finance-01','user':'alice','command_line':'powershell -enc ABC','sha256':'deadbeef'}], 'factors':[{'stage':'Exploit','name':'powershell_enc','value':True}]}
print(llm_prompts.compose_prompt(context)[:1200])
