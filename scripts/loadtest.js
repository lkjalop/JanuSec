// JanuSec Platform - K6 Load Testing Script
// Tests API performance under realistic load conditions

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const eventProcessingTime = new Trend('event_processing_duration');
const successfulEvents = new Counter('successful_events');
const failedEvents = new Counter('failed_events');

// Configuration
export const options = {
  stages: [
    { duration: '2m', target: 10 },   // Ramp up to 10 users over 2 minutes
    { duration: '5m', target: 10 },   // Stay at 10 users for 5 minutes
    { duration: '2m', target: 50 },   // Ramp up to 50 users over 2 minutes
    { duration: '5m', target: 50 },   // Stay at 50 users for 5 minutes
    { duration: '2m', target: 0 },    // Ramp down to 0 users over 2 minutes
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],  // 95% of requests should be below 200ms
    http_req_failed: ['rate<0.01'],    // Error rate should be below 1%
    errors: ['rate<0.05'],             // Custom error rate below 5%
    event_processing_duration: ['p(99)<500'],  // 99% of events processed in <500ms
  },
};

// Environment variables (set via --env flag)
const API_URL = __ENV.API_URL || 'http://localhost:8000';
const API_TOKEN = __ENV.API_TOKEN || 'test-token-12345';

// Sample event payloads (realistic XDR/EDR events)
const sampleEvents = [
  {
    event_type: 'process_execution',
    timestamp: new Date().toISOString(),
    host_id: 'WIN-SERVER-01',
    process_name: 'powershell.exe',
    command_line: 'powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0',
    parent_process: 'cmd.exe',
    user: 'SYSTEM',
    sha256: 'a' + Math.random().toString(36).substring(2, 66),
    severity: 'high',
  },
  {
    event_type: 'network_connection',
    timestamp: new Date().toISOString(),
    host_id: 'LAPTOP-DEV-42',
    src_ip: '10.0.2.15',
    dst_ip: '185.220.101.' + Math.floor(Math.random() * 256),
    dst_port: 443,
    protocol: 'tcp',
    bytes_out: Math.floor(Math.random() * 100000),
    domain: 'suspicious-domain-' + Math.random().toString(36).substring(2, 10) + '.com',
    ja3_hash: 'a0e9f5d64349fb13191bc781f81f42e1',
    severity: 'medium',
  },
  {
    event_type: 'file_creation',
    timestamp: new Date().toISOString(),
    host_id: 'WORKSTATION-HR-07',
    file_path: 'C:\\Users\\Public\\Downloads\\invoice_' + Math.random().toString(36).substring(2, 10) + '.exe',
    file_size: Math.floor(Math.random() * 5000000),
    sha256: 'b' + Math.random().toString(36).substring(2, 66),
    process_name: 'outlook.exe',
    user: 'hr_user',
    severity: 'critical',
  },
  {
    event_type: 'dns_query',
    timestamp: new Date().toISOString(),
    host_id: 'DNS-SERVER-01',
    query: 'cmd-' + Math.random().toString(36).substring(2, 30) + '.example.com',
    query_type: 'TXT',
    response: 'powershell -enc ...',
    client_ip: '10.0.1.' + Math.floor(Math.random() * 256),
    severity: 'high',
  },
  {
    event_type: 'authentication',
    timestamp: new Date().toISOString(),
    host_id: 'DC-PRIMARY',
    user: 'admin_' + Math.floor(Math.random() * 1000),
    auth_type: 'kerberos',
    result: Math.random() > 0.7 ? 'failure' : 'success',
    src_ip: '10.0.3.' + Math.floor(Math.random() * 256),
    ticket_encryption: 'rc4_hmac',
    severity: 'medium',
  },
];

// Helper function to get random event
function getRandomEvent() {
  const event = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
  // Add unique timestamp to avoid caching
  event.timestamp = new Date().toISOString();
  event.id = 'evt-' + Math.random().toString(36).substring(2, 18);
  return event;
}

// Test setup (runs once per VU)
export function setup() {
  console.log(`Starting load test against: ${API_URL}`);

  // Health check before starting
  const healthRes = http.get(`${API_URL}/health`);
  if (healthRes.status !== 200) {
    console.error(`API health check failed: ${healthRes.status}`);
    return { healthy: false };
  }

  console.log('API health check passed, starting load test...');
  return { healthy: true };
}

// Main test function (runs for each VU iteration)
export default function(data) {
  if (!data.healthy) {
    console.error('Skipping test due to failed health check');
    return;
  }

  group('API Health Check', () => {
    const res = http.get(`${API_URL}/health`);
    check(res, {
      'health check is 200': (r) => r.status === 200,
      'health check response time < 100ms': (r) => r.timings.duration < 100,
    });
    errorRate.add(res.status !== 200);
  });

  sleep(1);

  group('Submit Event for Analysis', () => {
    const event = getRandomEvent();
    const payload = JSON.stringify(event);

    const params = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_TOKEN}`,
      },
      tags: { event_type: event.event_type },
    };

    const startTime = new Date().getTime();
    const res = http.post(`${API_URL}/api/v1/events/analyze`, payload, params);
    const duration = new Date().getTime() - startTime;

    eventProcessingTime.add(duration);

    const success = check(res, {
      'event submission is 200 or 201': (r) => r.status === 200 || r.status === 201,
      'response has decision': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.hasOwnProperty('verdict') || body.hasOwnProperty('confidence');
        } catch (e) {
          return false;
        }
      },
      'processing time < 500ms': (r) => r.timings.duration < 500,
    });

    if (success) {
      successfulEvents.add(1);
    } else {
      failedEvents.add(1);
      console.error(`Event submission failed: ${res.status} - ${res.body.substring(0, 200)}`);
    }

    errorRate.add(!success);
  });

  sleep(Math.random() * 3 + 1);  // Random sleep 1-4 seconds (realistic user behavior)

  group('Query Recent Alerts', () => {
    const params = {
      headers: {
        'Authorization': `Bearer ${API_TOKEN}`,
      },
    };

    const res = http.get(`${API_URL}/api/v1/alerts?limit=10&severity=high`, params);

    check(res, {
      'alerts query is 200': (r) => r.status === 200,
      'alerts response time < 200ms': (r) => r.timings.duration < 200,
      'alerts response is array': (r) => {
        try {
          const body = JSON.parse(r.body);
          return Array.isArray(body) || Array.isArray(body.alerts);
        } catch (e) {
          return false;
        }
      },
    });

    errorRate.add(res.status !== 200);
  });

  sleep(2);

  group('Get Metrics Summary', () => {
    const res = http.get(`${API_URL}/api/v1/metrics/summary`);

    check(res, {
      'metrics is 200': (r) => r.status === 200,
      'metrics has expected fields': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.hasOwnProperty('events_processed') ||
                 body.hasOwnProperty('total_events');
        } catch (e) {
          return false;
        }
      },
    });

    errorRate.add(res.status !== 200);
  });

  sleep(1);
}

// Teardown (runs once after test completes)
export function teardown(data) {
  if (!data.healthy) {
    console.log('Test completed (health check had failed)');
    return;
  }

  console.log('Load test completed successfully!');
  console.log(`Total successful events: ${successfulEvents.count}`);
  console.log(`Total failed events: ${failedEvents.count}`);

  // Final health check
  const healthRes = http.get(`${API_URL}/health`);
  if (healthRes.status !== 200) {
    console.warn('Post-test health check failed - API may be degraded');
  } else {
    console.log('Post-test health check passed');
  }
}

// Handle summary (custom results formatting)
export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
    'loadtest-results.json': JSON.stringify(data, null, 2),
  };
}

// Helper function for text summary
function textSummary(data, options = {}) {
  const indent = options.indent || '';
  const colors = options.enableColors || false;

  let summary = '\n' + indent + '═══════════════════════════════════════════════════\n';
  summary += indent + '  JANUSEC LOAD TEST RESULTS\n';
  summary += indent + '═══════════════════════════════════════════════════\n\n';

  // Test duration
  summary += indent + `Duration: ${data.state.testRunDurationMs / 1000}s\n`;
  summary += indent + `VUs: ${data.metrics.vus.values.max}\n\n`;

  // HTTP metrics
  summary += indent + '📊 HTTP Metrics:\n';
  summary += indent + `  Requests: ${data.metrics.http_reqs.values.count}\n`;
  summary += indent + `  Request rate: ${data.metrics.http_reqs.values.rate.toFixed(2)}/s\n`;
  summary += indent + `  Success rate: ${(100 - data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%\n`;
  summary += indent + `  Avg duration: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms\n`;
  summary += indent + `  p95 duration: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms\n`;
  summary += indent + `  p99 duration: ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms\n\n`;

  // Custom metrics
  summary += indent + '🎯 Event Processing:\n';
  summary += indent + `  Successful events: ${data.metrics.successful_events.values.count}\n`;
  summary += indent + `  Failed events: ${data.metrics.failed_events.values.count}\n`;
  summary += indent + `  Avg processing time: ${data.metrics.event_processing_duration.values.avg.toFixed(2)}ms\n`;
  summary += indent + `  p99 processing time: ${data.metrics.event_processing_duration.values['p(99)'].toFixed(2)}ms\n\n`;

  // Thresholds
  summary += indent + '✅ Threshold Results:\n';
  const thresholds = data.root_group.checks;
  for (const check of thresholds) {
    const passed = check.passes === check.fails + check.passes;
    const icon = passed ? '✓' : '✗';
    summary += indent + `  ${icon} ${check.name}: ${check.passes}/${check.passes + check.fails}\n`;
  }

  summary += '\n' + indent + '═══════════════════════════════════════════════════\n\n';

  return summary;
}
