#!/usr/bin/env python3
import requests
import sys
import os

def main():
    url = os.environ.get('JANUSEC_API_URL','http://127.0.0.1:8080').rstrip('/') + '/api/v1/upload/files'
    apikey = os.environ.get('JANUSEC_API_KEY','devkey123')
    paths = sys.argv[1:] if len(sys.argv)>1 else ['dump/janusec_ep_endpoint.xlsx','dump/janusec_okta_m365_events.json','dump/janusec_net_c2_bgp.csv']
    files = []
    opened = []
    try:
        for p in paths:
            fp = p if os.path.isabs(p) else os.path.join(os.getcwd(), p)
            if not os.path.exists(fp):
                raise FileNotFoundError(fp)
            f = open(fp, 'rb')
            opened.append(f)
            files.append(('files', (os.path.basename(fp), f)))
        print('POST', url, 'with', [os.path.basename(p) for p in paths])
        r = requests.post(url, headers={'x-api-key': apikey}, files=files, timeout=180)
        print('STATUS:', r.status_code)
        try:
            print(r.json())
        except Exception:
            print(r.text)
    except Exception as e:
        print('ERROR:', e)
        raise
    finally:
        for f in opened:
            try:
                f.close()
            except Exception:
                pass

if __name__ == '__main__':
    main()
