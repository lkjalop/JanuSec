import argparse

from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Export LLM feedback dataset for offline tuning.")
    parser.add_argument('--limit', type=int, default=5000, help='Maximum entries to export')
    args = parser.parse_args()
    from src.feedback.llm_feedback import export_dataset  # type: ignore
    path = export_dataset(limit=args.limit)
    if not path:
        print("No feedback entries found.")
    else:
        print(f"Dataset written to {path}")


if __name__ == '__main__':
    main()
