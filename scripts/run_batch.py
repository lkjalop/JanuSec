import pathlib
import sys
import pytest


def main(batch_file: str = 'batch_1.txt', stop_on_first: bool = True) -> int:
    p = pathlib.Path(batch_file)
    if not p.exists():
        print(f'Batch file not found: {batch_file}', file=sys.stderr)
        return 2
    # Read with utf-8-sig to strip any BOM that may be present
    files = [l.strip() for l in p.read_text(encoding='utf-8-sig').splitlines() if l.strip()]
    if not files:
        print('No tests found in batch file', file=sys.stderr)
        return 2
    print('Running pytest for {} tests/files...'.format(len(files)))
    # Run pytest with provided file list
    args = ['-q'] + files
    if stop_on_first:
        args.insert(1, '--maxfail=1')
    return pytest.main(args)


if __name__ == '__main__':
    import sys as _sys
    stop = True
    # allow caller to pass 'no-stop' to keep running all tests
    if len(_sys.argv) > 2 and _sys.argv[2] in ('no-stop', '--no-stop'):
        stop = False
    exit(main(_sys.argv[1] if len(_sys.argv) > 1 else 'batch_1.txt', stop_on_first=stop))
