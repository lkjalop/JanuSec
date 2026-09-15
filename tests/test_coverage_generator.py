from src.core.correlation.rules.coverage import generate_coverage_artifacts
import os


def test_coverage_generator_creates_matrix(tmp_path):
    out = generate_coverage_artifacts(out_dir=str(tmp_path))
    assert isinstance(out, dict)
    # Expect at least one MITRE tactic present from seeded registry
    assert len(out) >= 1
    # confirm artifact files exist
    assert os.path.exists(os.path.join(str(tmp_path),'coverage_matrix.json'))
    assert os.path.exists(os.path.join(str(tmp_path),'coverage_report.md'))
