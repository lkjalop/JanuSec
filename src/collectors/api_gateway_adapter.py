from __future__ import annotations
import os, time, random
from typing import List, Dict, Any
from .base import EventCollector

class APIGatewayCollector(EventCollector):
    source = "api_gateway"

    def __init__(self):
        self._log_path = os.getenv("API_GATEWAY_LOG")  # optional local file for simulation

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        # Simulate random method usage to enable rarity heuristic downstream
        sample_methods = ["GET","POST","PUT","DELETE","OPTIONS"]
        out: List[Dict[str, Any]] = []
        for _ in range(3):
            mseq = random.sample(sample_methods, k=min(len(sample_methods), random.randint(2,5)))
            out.append({
                "id": f"apigw-{int(time.time()*1000)}-{random.randint(100,999)}",
                "path": f"/v1/resource/{random.randint(1,50)}",
                "methodsSequence": mseq,
                "status": random.choice([200,404,405,500]),
                "tokenId": f"tok-{random.randint(1,5)}",
                "srcIp": f"10.0.0.{random.randint(1,50)}",
                "published": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            })
        return out

__all__ = ["APIGatewayCollector"]