from src.reporting.summaries import top5_factors


def test_top5_factors_sorted_by_contribution():
    report = {
        "verdict": {
            "all_factors": [
                {"factor_name": "a", "contribution_score": 0.1},
                {"factor_name": "b", "contribution_score": 0.9},
                {"factor_name": "c", "contribution_score": 0.5},
            ]
        }
    }
    res = top5_factors(report)
    # expect ordering b, c, a
    names = [r.get("name") for r in res]
    assert names[:3] == ["b", "c", "a"]
