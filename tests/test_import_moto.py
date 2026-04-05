def test_import_moto_and_botocore_config():
    import sys
    # Diagnostic: inspect sys.modules entries that may shadow botocore
    bc = sys.modules.get('botocore')
    print('DIAG: sys.modules["botocore"] ->', repr(bc))
    try:
        print('DIAG: botocore __file__ ->', getattr(bc, '__file__', None))
    except Exception:
        pass
    print('DIAG: any keys starting with botocore:', [k for k in sys.modules.keys() if k.startswith('botocore')])

    import moto
    from botocore.config import Config
    assert moto is not None
    assert Config is not None
