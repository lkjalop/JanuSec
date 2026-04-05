import http from 'k6/http';
import { sleep, check } from 'k6';

export const options = {
  vus: 1,
  iterations: 1,
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const API_KEY = __ENV.API_KEY || 'devkey123';

export default function () {
  const headers = { 'x-api-key': API_KEY };

  // 1) Status
  let res = http.get(`${BASE_URL}/api/v1/dashboard/status`, { headers });
  check(res, { 'status 200': (r) => r.status === 200 });

  // 2) Create incident (lite route supported)
  const payload = JSON.stringify({
    title: 'k6 smoke incident',
    severity: 'low',
    description: 'Automated smoke test',
  });
  res = http.post(`${BASE_URL}/api/v1/incidents`, payload, {
    headers: { ...headers, 'content-type': 'application/json' },
  });
  check(res, { 'incident created': (r) => r.status === 200 || r.status === 201 });

  // 3) Upload small file payload
  const upHeaders = { ...headers };
  const data = { file: http.file('hello world', 'test.txt', 'text/plain') };
  res = http.post(`${BASE_URL}/api/v1/upload/files`, data, { headers: upHeaders });
  check(res, { 'upload ok': (r) => r.status >= 200 && r.status < 500 });

  sleep(0.5);
}
