import sys
import traceback

sys.path.insert(0, 'd:/AI/Threat_thy_sniffer')

def main():
    try:
        from src.api.app import app
        ops = {}
        for r in app.routes:
            oid = getattr(r, 'operation_id', None) or getattr(r, 'name', None)
            path = getattr(r, 'path', None)
            method = getattr(r, 'methods', None)
            key = oid
            ops.setdefault(key, []).append((path, method))
        dups = {k: v for k, v in ops.items() if k and len(v) > 1}
        print('Duplicate operation ids count:', len(dups))
        for k, v in list(dups.items())[:500]:
            print('OPID:', k)
            for p, m in v:
                print('  ', p, m)
    except Exception:
        print('Error while inspecting app routes:')
        traceback.print_exc()

if __name__ == '__main__':
    main()
