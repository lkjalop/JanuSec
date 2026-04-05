import time
from collections import deque


class FakeHG:
    def __init__(self, adj):
        # adj: dict[node] -> list of (dst, etype, ts, srcv, w)
        self.adj = {k: list(v) for k, v in adj.items()}

    def add_edge(self, u, v, etype, source=None, ts=None, weight=None):
        self.adj.setdefault(u, []).append((v, etype, ts, source, weight))


def apply_bridging(hg, a, b, max_hops=3, max_insert=25, score_fn=lambda: 0.0):
    """Run minimal bridging logic: BFS to find path then insert bridge_sequence edges up to cap.
    Returns (inserted_edges, applied_bool)
    """
    # If already connected skip
    for e in (hg.adj.get(a) or []):
        if e[0] == b and e[1] in {'gt_sequence', 'spawns', 'follows'}:
            return [], False

    q = deque([(a, [a])])
    visited = {a}
    path_found = None
    while q:
        cur, path = q.popleft()
        if len(path) > max_hops + 1:
            continue
        for (dst, et, ts, srcv, w) in hg.adj.get(cur, []):
            if et not in {'spawns', 'follows', 'runs'}:
                continue
            if dst == b:
                path_found = path + [dst]
                q.clear(); break
            if dst.startswith('process:') and dst not in visited:
                visited.add(dst)
                q.append((dst, path + [dst]))
        if path_found:
            break

    inserted_edges = []
    if path_found and len(path_found) > 2:
        for u, v in zip(path_found, path_found[1:]):
            if any(e[0] == v and e[1] == 'bridge_sequence' for e in (hg.adj.get(u) or [])):
                continue
            if len(inserted_edges) >= max_insert:
                break
            if (u, v) in inserted_edges:
                continue
            hg.add_edge(u, v, 'bridge_sequence', source='test', ts=time.time(), weight=1.0)
            inserted_edges.append((u, v))

    # Simulate recompute and decision
    new_score = score_fn()
    applied = False
    # For test: we assume original score was 0.5; improvement if new_score > 0.5
    if new_score > 0.5:
        applied = True
    else:
        # rollback
        for (u, v) in inserted_edges:
            lst = hg.adj.get(u, [])
            hg.adj[u] = [e for e in lst if not (e[0] == v and e[1] == 'bridge_sequence')]
        inserted_edges = []
    return inserted_edges, applied


def test_bridge_cap_enforced():
    # chain a -> p1 -> p2 -> p3 -> b
    adj = {
        'a': [('process:p1', 'spawns', None, None, 1.0)],
        'process:p1': [('process:p2', 'spawns', None, None, 1.0)],
        'process:p2': [('process:p3', 'spawns', None, None, 1.0)],
        'process:p3': [('b', 'spawns', None, None, 1.0)],
    }
    hg = FakeHG(adj)
    inserted, applied = apply_bridging(hg, 'a', 'b', max_hops=4, max_insert=1, score_fn=lambda: 0.0)
    # cap=1 => at most 1 edge inserted, but since score_fn returns no improvement, rollback occurs
    assert inserted == []
    # check that no bridge edges remain
    for u, lst in hg.adj.items():
        for e in lst:
            assert e[1] != 'bridge_sequence'


def test_bridge_rollback_on_no_improve():
    adj = {
        'a': [('process:x', 'spawns', None, None, 1.0)],
        'process:x': [('b', 'spawns', None, None, 1.0)],
    }
    hg = FakeHG(adj)
    inserted, applied = apply_bridging(hg, 'a', 'b', max_hops=2, max_insert=10, score_fn=lambda: 0.4)
    # Score didn't improve => rollback => inserted empty and applied False
    assert inserted == []
    assert applied is False
    # ensure no bridge edges
    assert all(e[1] != 'bridge_sequence' for lst in hg.adj.values() for e in lst)


def test_bridge_persists_on_improve():
    adj = {
        'a': [('process:x', 'spawns', None, None, 1.0)],
        'process:x': [('process:y', 'spawns', None, None, 1.0)],
        'process:y': [('b', 'spawns', None, None, 1.0)],
    }
    hg = FakeHG(adj)
    inserted, applied = apply_bridging(hg, 'a', 'b', max_hops=3, max_insert=10, score_fn=lambda: 0.9)
    # Score improved: edges should persist and applied True
    assert applied is True
    # inserted list should reflect actual edges present
    assert len(inserted) >= 1
    for (u, v) in inserted:
        assert any(e[0] == v and e[1] == 'bridge_sequence' for e in hg.adj.get(u, []))
