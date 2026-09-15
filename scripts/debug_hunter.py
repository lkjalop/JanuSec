import sys, time
sys.path.append('d:/AI/Threat_thy_sniffer/src')
from src.modules.certificate_analysis import analyze_cert
from src.modules.network_hunter import NetworkThreatHunter

now = time.time()
nb = now - 60
na = now + 600
event = {
    'cert_self_signed': False,
    'cert_chain_valid': True,
    'cert_not_before': nb,
    'cert_not_after': na,
    'cert_sig_alg': 'sha256WithRSAEncryption',
    'cert_issuer': 'CN=Another Issuer',
    'sni': 'alpha.example',
    'cert_subject': 'CN=beta.example'
}

print('Direct analyze_cert:')
print(analyze_cert(event))

hunter = NetworkThreatHunter({})
import asyncio
res = asyncio.run(hunter.analyze_event(event))
print('\nNetworkThreatHunter.analyze_event:')
print(res)
