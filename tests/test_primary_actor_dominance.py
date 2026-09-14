"""Clustering hardening: primary actor by DOMINANCE, not alphabetical shared_users[0].

On a component with several co-occurring users, the responsible actor is the one who
owns the most breach-phase rows — not whoever sorts first."""
import pytest

from src.core.ingest.cluster_merge import _dominant_actor

pytestmark = pytest.mark.acceptance


def _rows(spec):
    # spec: list of (row_index, user, is_breach_phase)
    return [{"row_index": i, "user": u} for (i, u, _b) in spec], \
           {"p": [i for (i, u, b) in spec if b]}


def test_dominant_actor_prefers_breach_phase_owner_not_alphabetical():
    # anna sorts first but zoe owns all the breach-phase rows.
    rows, phase_hits = _rows([
        (1, "anna", False), (2, "anna", False),
        (3, "zoe", True), (4, "zoe", True), (5, "zoe", True),
    ])
    users = ["anna", "zoe"]   # alphabetical order
    assert _dominant_actor(rows, phase_hits, users) == "zoe"


def test_single_user_returns_that_user():
    rows, ph = _rows([(1, "martin.chen", True)])
    assert _dominant_actor(rows, ph, ["martin.chen"]) == "martin.chen"


def test_falls_back_to_row_count_without_phase_rows():
    rows, ph = _rows([(1, "bob", False), (2, "bob", False), (3, "amy", False)])
    assert _dominant_actor(rows, {}, ["amy", "bob"]) == "bob"   # bob has more rows


def test_case_preserved_from_users_list():
    rows = [{"row_index": 1, "user": "Martin.Chen"}, {"row_index": 2, "user": "Martin.Chen"}]
    # users list carries the display form
    assert _dominant_actor(rows, {"p": [1, 2]}, ["Martin.Chen", "anna"]) == "Martin.Chen"


def test_empty_users():
    assert _dominant_actor([], {}, []) is None
