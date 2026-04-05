import os, importlib
os.environ['HOPGRAPH_PERSISTENCE_ENABLED']='true'
os.environ['HOPGRAPH_DB_PATH']='data/hopgraph_test_manual.db'
from src.core.graph import hopgraph_lite
importlib.reload(hopgraph_lite)
print('HopGraph backend type:', type(hopgraph_lite.get_graph().backend))
print('Backend object:', hopgraph_lite.get_graph().backend)
