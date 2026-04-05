import os, tempfile
from src.graph import cooccurrence

fd, path = tempfile.mkstemp(suffix='.sqlite')
os.close(fd)
# set env to use this db
os.environ['COOCCURRENCE_SQLITE_PATH'] = path
# clear any existing
cooccurrence.clear()
cooccurrence.add_pairs([('a','b'),('a','c'),('b','c')])
cooccurrence.add_pairs([('a','b')])
# flush to db
cooccurrence.flush_to_db()
# snapshot counts from DB via get_counts
pair_counts, marg, total = cooccurrence.get_counts()
print('pair_counts:', pair_counts)
print('marginals:', marg)
print('total:', total)
# clear in-memory and ensure get_counts still returns persisted
cooccurrence.clear()
pair_counts2, marg2, total2 = cooccurrence.get_counts()
print('after clear pair_counts:', pair_counts2)
print('after clear total:', total2)
# cleanup
os.remove(path)
