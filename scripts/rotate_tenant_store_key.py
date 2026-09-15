"""Rotate file-store encryption offline, with an external recovery directory."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.integrations.fernet_rotation import rotate_file_store

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--writers-stopped", action="store_true", required=True)
    args = parser.parse_args()
    print(json.dumps(rotate_file_store(args.store, args.backup), indent=2))
