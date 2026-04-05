import sys, pathlib
sys.path.append(str(pathlib.Path('.').resolve()))
from src.reporting.persona_views import generate_persona_view
rpt={'report_id':'r','verdict':{'final_verdict':'R','final_confidence':0.5,'all_factors':[{'factor_name':'f1','contribution_score':1.0} for _ in range(40)]}, 'evidence_items':[{'extracted_iocs':{'ip':[f'10.0.0.{i}']}} for i in range(40)], 'attack_timeline':[{'entity':f'h{i}'} for i in range(40)], 'recommended_actions':[{'primary_action':f'a{i}','urgency':'normal'} for i in range(40)]}
print('calling...')
print(generate_persona_view(rpt, persona='executive', disclosure_level=2, top_n=5))
