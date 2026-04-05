import sys, pkgutil
print('sys.path=', sys.path)
print('Listing modules starting with hopgraph token:')
for m in pkgutil.iter_modules():
    if 'hopgraph' in m.name:
        print(' module:', m.name)
try:
    from src.graph import hopgraph
    print('Imported hopgraph OK. HopGraph class:', hasattr(hopgraph, 'HopGraph'))
except Exception as e:
    print('Failed to import src.graph.hopgraph:', e)
