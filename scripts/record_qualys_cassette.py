"""Record a cassette for Qualys ingestion using vcrpy.

Usage:
  python scripts/record_qualys_cassette.py --cassette sample_recording.yml --client-id X --client-secret Y

This will run the ingest runner and record outgoing HTTP requests/responses.
"""
import argparse
import os
import subprocess
import vcr


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--cassette', default='qualys_recording.yml')
    p.add_argument('--client-id', required=True)
    p.add_argument('--client-secret', required=True)
    p.add_argument('--api-base', default='https://qualysapi.example.com')
    args = p.parse_args()

    cassette_dir = os.path.join('tests', 'integration', 'cassettes')
    os.makedirs(cassette_dir, exist_ok=True)
    cassette_path = os.path.join(cassette_dir, args.cassette)

    myvcr = vcr.VCR(record_mode='all', cassette_library_dir=cassette_dir)
    with myvcr.use_cassette(args.cassette):
        # call the ingest runner as a subprocess so requests are captured
        cmd = [
            'python', '-m', 'src.adapters.run_qualys_ingest',
            '--client-id', args.client_id,
            '--client-secret', args.client_secret,
            '--api-base', args.api_base,
        ]
        print('Running:', ' '.join(cmd))
        subprocess.check_call(cmd)
        print('Recorded cassette to', cassette_path)


if __name__ == '__main__':
    main()
