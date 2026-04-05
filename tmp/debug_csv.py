import asyncio, sys, traceback, pathlib
# Add project root so `src` imports resolve when running scripts from repo root
pr = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(pr))
from src.api.csv_handler import get_csv_processor

def main():
    p = 'demo/sample_attack_chain.csv'
    with open(p, 'rb') as f:
        data = f.read()
    proc = get_csv_processor()
    try:
        res = asyncio.run(proc.process_csv(data, 'sample_attack_chain.csv'))
        print('RESULT:', res)
    except Exception as e:
        print('EXC:', e)
        traceback.print_exc()

if __name__=='__main__':
    main()
