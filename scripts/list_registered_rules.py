"""Safe helper to list registered correlation rules.

This imports the registry and prints rule names, their source module, and total count.
"""
import traceback
import sys
import os


def main():
    # Ensure project root is on sys.path for 'src' imports
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    try:
        from src.core.correlation.rules.registry import CORRELATION_RULES
    except Exception:
        print('Failed to import CORRELATION_RULES:')
        traceback.print_exc()
        sys.exit(2)

    try:
        # Ensure package-level rule modules are imported so registrations occur
        try:
            CORRELATION_RULES._ensure_rules_loaded()
        except Exception:
            pass
        regs = CORRELATION_RULES.list()
    except Exception:
        print('Error while listing rules:')
        traceback.print_exc()
        sys.exit(3)

    outp = []
    outp.append(f'Total registered rules: {len(regs)}')
    for r in regs:
        name = getattr(r, 'name', getattr(r, 'rule_name', str(r)))
        src = getattr(r, 'source_module', getattr(r, 'source', 'unknown'))
        outp.append(f'- {name} (source: {src})')
    # write to file for reliable capture in CI/test environments
    try:
        os.makedirs('data', exist_ok=True)
        with open(os.path.join('data','registered_rules.txt'),'w',encoding='utf-8') as f:
            f.write('\n'.join(outp) + '\n')
    except Exception:
        pass
    # also print a short summary to stdout
    print(outp[0])

if __name__ == '__main__':
    main()
