#!/usr/bin/env python3
"""Synthetic event generator for demo and benchmark purposes.

Produces JSON lines with a safe, synthetic schema. No real or customer data.
"""
import argparse
import json
import random
import time
from datetime import datetime


def random_ip():
    return f"198.51.{random.randint(0,255)}.{random.randint(0,255)}"


def make_event(i):
    event = {
        "event_id": f"evt-{int(time.time())}-{i}",
        "ts": datetime.utcnow().isoformat() + "Z",
        "host": f"host-{random.randint(1,100):03d}",
        "user": f"user-{random.randint(1,50)}",
        "process": random.choice(["powershell.exe","cmd.exe","kape.exe","python.exe","curl.exe"]),
        "src_ip": random_ip(),
        "dst_ip": random_ip(),
        "bytes": random.randint(0,200000000),
    }
    # flag a synthetic KAPE run occasionally
    if random.random() < 0.05:
        event["kape_detected"] = True
        event["process"] = "kape.exe"
    return event


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--count', type=int, default=10)
    p.add_argument('--out', type=str, default='-')
    args = p.parse_args()

    out = None
    if args.out == '-':
        out = None
    else:
        out = open(args.out, 'w')

    for i in range(args.count):
        ev = make_event(i)
        line = json.dumps(ev)
        if out:
            out.write(line + '\n')
        else:
            print(line)

    if out:
        out.close()


if __name__ == '__main__':
    main()
