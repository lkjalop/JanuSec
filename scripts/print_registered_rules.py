from src.core.correlation.rules.registry import CORRELATION_RULES

def main():
    names = [r.name for r in CORRELATION_RULES.list()]
    p = 'data/registered_rules.txt'
    import os
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        for n in names:
            f.write(n + '\n')
    print(f'Wrote {len(names)} rules to {p}')

if __name__ == '__main__':
    main()
