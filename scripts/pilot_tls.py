"""Install an operator-provided certificate while the pilot is stopped."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.security.pilot_tls import install

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--cert', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--local-test', action='store_true')
    args = parser.parse_args()
    print(json.dumps(install(args.state, args.cert, args.key, args.hostname, local_test=args.local_test)))
