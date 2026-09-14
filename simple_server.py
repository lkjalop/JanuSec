#!/usr/bin/env python3
"""Simple server launcher without Unicode issues"""

import os
import sys
import uvicorn
from pathlib import Path

# Add src to Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

# Set environment variables
os.environ.setdefault("PYTHONPATH", str(current_dir))
os.environ.setdefault("EVENT_QUEUE_MAX", "2000")
os.environ.setdefault("API_KEYS_JSON", '[{"key":"devkey123","scopes":["*"]}]')
os.environ.setdefault("ENABLE_CSV_UPLOAD", "true")

def main():
    print("Starting JanuSec Platform...")
    print("Server: http://localhost:8080")
    print("Console: http://localhost:8080/console")
    print("CSV Upload: http://localhost:8080/api/v1/csv/upload-page")
    print("API Docs: http://localhost:8080/docs")

    try:
        from api.server import app
        uvicorn.run(
            "api.server:app",
            host="0.0.0.0",
            port=8080,
            reload=False,
            log_level="info"
        )
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()