from __future__ import annotations
from typing import Dict, Any, Optional
import os, json, time, random

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

class LLMRefiner:
    def __init__(self):
        self.enabled = os.getenv('ENABLE_ARTIFACT_LLM','0').lower() in ('1','true','yes')
        self.model = os.getenv('ARTIFACT_LLM_MODEL','gpt-4o-mini')
        self.endpoint = os.getenv('ARTIFACT_LLM_ENDPOINT')  # optional custom endpoint
        self.api_key = os.getenv('ARTIFACT_LLM_API_KEY')
        self.max_tokens = int(os.getenv('ARTIFACT_LLM_MAX_TOKENS','512'))
        self.risk_delta_cap = float(os.getenv('ARTIFACT_LLM_RISK_DELTA_CAP','0.08'))

    def refine(self, artifact_summary: Dict[str,Any]) -> Dict[str,Any]:
        if not self.enabled:
            return {'enabled': False}
        # Compose prompt
        prompt = self._build_prompt(artifact_summary)
        narrative = None; delta = 0.0; mitre_add = []
        if self.endpoint and httpx and self.api_key:
            try:
                payload = {
                    'model': self.model,
                    'messages':[{'role':'system','content':'You are a security artifact analyst. Return compact JSON.'},
                                {'role':'user','content': prompt}],
                    'max_tokens': self.max_tokens,
                }
                headers={'Authorization': f'Bearer {self.api_key}'}
                r = httpx.post(self.endpoint, json=payload, headers=headers, timeout=30)
                if r.status_code == 200:
                    txt = r.json().get('choices',[{}])[0].get('message',{}).get('content','')
                    # Try parse JSON inside content
                    parsed = self._extract_json(txt)
                    if parsed:
                        narrative = parsed.get('narrative')
                        mitre_add = parsed.get('mitre_add',[])
                        try:
                            delta = float(parsed.get('risk_delta',0.0))
                        except Exception:
                            delta = 0.0
                else:
                    narrative = f"llm_error_status_{r.status_code}"  # fallback indicator
            except Exception as e:
                narrative = f"llm_exception:{e}"  # fallback
        else:
            # deterministic pseudo-narrative for dev
            narrative = f"Heuristic review suggests {artifact_summary.get('name')} shows dual-use traits."  # dev stub
            delta = random.uniform(0, self.risk_delta_cap/2)
        # Clamp delta
        if delta > self.risk_delta_cap:
            delta = self.risk_delta_cap
        return {
            'enabled': True,
            'risk_delta': round(delta,4),
            'narrative': narrative,
            'mitre_add': mitre_add
        }

    def _build_prompt(self, s: Dict[str,Any]) -> str:
        factors = ','.join(s.get('factors',[])[:25])
        return (
            f"Artifact Type: {s.get('artifact_type')}\nName: {s.get('name')}\nPath: {s.get('path')}\n"
            f"Factors: {factors}\nBase Risk: {s.get('risk')}\n"
            "Return JSON: {\"risk_delta\": <float -0.05..0.1>, \"mitre_add\": [""], \"narrative\": "" }"
        )

    def _extract_json(self, txt: str) -> Optional[Dict[str,Any]]:
        # naive extraction
        start = txt.find('{'); end = txt.rfind('}')
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            return json.loads(txt[start:end+1])
        except Exception:
            return None
