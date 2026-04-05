import asyncio, json, os, sys

# Ensure src/ is on sys.path for imports when running from project root
here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
src_path = os.path.join(here, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

try:
    from src.api.csv_handler import get_csv_processor
except Exception:
    try:
        from api.csv_handler import get_csv_processor
    except Exception:
        # ensure src is in sys.path
        if src_path not in sys.path:
            sys.path.insert(0, src_path)
        from api.csv_handler import get_csv_processor

async def run():
    proc = get_csv_processor()
    csv_path = os.path.join(here, 'dump', 'Cyberstash_csv2_sample.csv')
    with open(csv_path, 'rb') as f:
        content = f.read()
    print('Processing CSV:', csv_path)
    res = await proc.process_csv(content, filename='Cyberstash_csv2_sample.csv')
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    asyncio.run(run())
