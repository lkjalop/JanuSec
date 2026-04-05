from flask import Flask, Response
import time

app = Flask(__name__)

# Simple in-memory counters for demo
counters = {
    'sultry_events_total': {},
    'sultry_honeypot_hits_total': {}
}

def render_prometheus():
    lines = []
    # help/metric lines
    lines.append('# HELP sultry_events_total Count of matched factor events')
    lines.append('# TYPE sultry_events_total counter')
    for labels, value in counters['sultry_events_total'].items():
        lines.append(f'sultry_events_total{{{labels}}} {value}')

    lines.append('# HELP sultry_honeypot_hits_total Honeypot hits')
    lines.append('# TYPE sultry_honeypot_hits_total counter')
    for labels, value in counters['sultry_honeypot_hits_total'].items():
        lines.append(f'sultry_honeypot_hits_total{{{labels}}} {value}')

    # simple gauge example
    lines.append('# HELP sultry_ewma_intensity EWMA-smoothed correlation intensity')
    lines.append('# TYPE sultry_ewma_intensity gauge')
    lines.append('sultry_ewma_intensity 0.42')

    return "\n".join(lines) + "\n"

@app.route('/metrics')
def metrics():
    return Response(render_prometheus(), mimetype='text/plain; version=0.0.4')

if __name__ == '__main__':
    # populate demo counters
    counters['sultry_events_total']['domain="network",factor="dns_exfil_pattern"'] = 12
    counters['sultry_events_total']['domain="deception",factor="honeypot_interaction"'] = 7
    counters['sultry_honeypot_hits_total']['host="hp1"'] = 5
    print('Serving demo metrics on http://127.0.0.1:8000/metrics')
    app.run(port=8000)
