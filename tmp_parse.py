from src.api.endpoint_malware_endpoints import AnalyzeRequest
payload = {'registry_events': [{'key_path':'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell','value_name':'Shell','old_value':'explorer.exe','new_value':'badexplorer.exe'}]}
print('Parsing...')
try:
    ar = AnalyzeRequest.parse_obj(payload)
    print('OK', ar)
except Exception as e:
    print('ERR', e)
    import traceback
    traceback.print_exc()
