from src.ml.calibration_runner import score_weights_on_labels, grid_search

def test_score_weights_simple():
    labels = [
        {'decision_id':'d1','label':'true_positive','factors':['f1']},
        {'decision_id':'d2','label':'false_positive','factors':['f2']},
    ]
    w = {'f1': 1.0, 'f2': 0.0}
    m = score_weights_on_labels(w, labels)
    assert m['tp'] >= 0

def test_grid_search_choose_best():
    labels = [
        {'decision_id':'d1','label':'true_positive','factors':['f1']},
        {'decision_id':'d2','label':'true_positive','factors':['f1']},
        {'decision_id':'d3','label':'false_positive','factors':['f2']},
    ]
    cands = [ {'f1':1.0,'f2':0.0}, {'f1':0.0,'f2':0.0} ]
    res = grid_search(cands, labels)
    assert res['winner_index'] == 0
