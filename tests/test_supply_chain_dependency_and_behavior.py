from src.domains.supply_chain.dependency_analyzer import build_dependency_graph, detect_dependency_confusion, detect_new_rare_dependencies
from src.domains.supply_chain.package_behavior import analyze_behavior


def test_build_dependency_graph_and_confusion():
    deps = [
        {'name': 'pkgA', 'dependencies': [
            {'name': 'pkgB', 'dependencies': [
                {'name': 'pkgC', 'dependencies': []}
            ]},
            {'name': 'pkgC', 'dependencies': []}
        ]},
        {'name': 'pkgB', 'dependencies': [{'name': 'pkgC', 'dependencies': []}]},
        {'name': 'pkgC', 'dependencies': []},
        # include an internal namespace node to test confusion
        {'name': 'internal.pkgX', 'dependencies': []}
    ]
    graph = build_dependency_graph(deps)
    assert 'pkgA' in graph['adjacency']
    # simulate internal namespace conflict detection
    findings = detect_dependency_confusion(graph, internal_namespaces=['internal'])
    assert isinstance(findings, list)
    assert any(f.get('factor') == 'supply_chain:dependency_confusion' for f in findings)


def test_detect_new_rare_dependencies():
    prior = {'pkgA', 'pkgB'}
    current = {'pkgA', 'pkgB', 'pkgRare'}
    res = detect_new_rare_dependencies(current, prior)
    assert isinstance(res, (list, dict))


def test_package_behavior_analyze():
    declared = {'capabilities': ['network', 'file']}
    runtime = {'observed': {'network': True, 'file': True, 'exec': True}}
    out = analyze_behavior(declared, runtime)
    assert 'issues' in out or 'score' in out
