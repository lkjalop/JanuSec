import time
import traceback

def main():
    try:
        start = time.time()
        print('Starting import of src.api.ingest_controller_endpoints')
        import importlib
        mod = importlib.import_module('src.api.ingest_controller_endpoints')
        elapsed = time.time() - start
        print('Imported:', mod, 'elapsed', elapsed)
    except Exception:
        traceback.print_exc()

if __name__ == '__main__':
    main()
