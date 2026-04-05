import os

from artifact.analyze import ArtifactPipeline
from artifact.models import ArtifactObservation, ArtifactType


def make_obs(risk: float):
    return ArtifactObservation(
        artifact_id='a', sha256=None, artifact_type=ArtifactType.EXECUTABLE,
        host='h', path='p', name='x', base_risk=risk, final_risk=risk
    )

def test_ambiguity_band_disabled_no_llm(monkeypatch=None):
    os.environ['ENABLE_ARTIFACT_LLM'] = '0'
    pipe = ArtifactPipeline(enable_embeddings=False)
    o = make_obs(0.5)
    assert pipe._ambiguous(o) is False

def test_ambiguity_band_enabled(monkeypatch=None):
    os.environ['ENABLE_ARTIFACT_LLM'] = '1'
    os.environ['ARTIFACT_AMBIGUITY_LOWER'] = '0.4'
    os.environ['ARTIFACT_AMBIGUITY_UPPER'] = '0.7'
    pipe = ArtifactPipeline(enable_embeddings=False)
    mid = make_obs(0.5)
    assert pipe._ambiguous(mid) is True
    low = make_obs(0.2)
    assert pipe._ambiguous(low) is False
    high = make_obs(0.9)
    assert pipe._ambiguous(high) is False
