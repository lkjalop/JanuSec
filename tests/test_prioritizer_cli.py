import os
from src.core.correlation.rules.prioritizer import run_prioritizer, export_to_csv


def test_prioritizer_exports(tmp_path):
    metas = run_prioritizer(asset_criticality=1.5, exposure=1.2)
    assert metas and metas[0].priority >= metas[-1].priority
    csv_path = os.path.join(str(tmp_path),'out.csv')
    export_to_csv(metas, csv_path)
    assert os.path.exists(csv_path)
