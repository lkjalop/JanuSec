from src.simulations.crq_dkim_sim import run_permutations
res = run_permutations()
for r in res:
    print(r['artifact']['dkim_status'], r['artifact']['has_logs'], r['adjusted_composite'], r['escalate'])
print('TOTAL', len(res))
