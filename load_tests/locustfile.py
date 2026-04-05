from locust import HttpUser, task, between
import os


class APILoadUser(HttpUser):
    wait_time = between(0.001, 0.005)  # short wait to approximate high throughput

    def on_start(self):
        self.api_key = os.getenv('TEST_API_KEY', 'devkey123')

    @task
    def ingest_health(self):
        headers = {'x-api-key': self.api_key}
        self.client.get('/api/v1/status', headers=headers)


# Run example:
# locust -f load_tests/locustfile.py --headless -u 500 -r 50 --run-time 1m --host http://127.0.0.1:8090
# Adjust users/spawn-rate to reach target throughput (1k req/s) depending on endpoint latency.
