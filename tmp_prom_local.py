from prometheus_client import CollectorRegistry, Histogram, Counter
reg = CollectorRegistry()
h = Histogram('test_hist_seconds', 'test', ['depth_bucket','tenant'], registry=reg)
c = Counter('test_counter_total', 'test', ['result','tenant'], registry=reg)
print('collect:', [fam.name for fam in reg.collect()])
