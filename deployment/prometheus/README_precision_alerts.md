**Loading Precision Alert Rules**

- Copy `precision_alerts.yml` into a directory reachable by your Prometheus server (e.g. `/etc/prometheus/rules/`).
- Add or update the `rule_files` setting in your `prometheus.yml` configuration to include the file or directory. Example:

```yaml
rule_files:
  - "/etc/prometheus/rules/*.yml"
```

- Restart Prometheus or trigger a SIGHUP reload so it picks up the new rules. Example (systemd):

```bash
sudo systemctl reload prometheus
# or use the HTTP reload endpoint if enabled
curl -X POST http://localhost:9090/-/reload
```

**Alert tuning**
- The rule triggers when `janusec_precision_daily < 0.6` for 6 hours. Adjust the threshold and `for` duration to match your tolerance.

**Grafana panel**
- Create a Grafana panel querying `janusec_precision_daily{tenant_id="$tenant"}` and display as a time-series. Use `day` label for grouping if needed.

**Notes**
- If you prefer a rolling precision over recent buckets use PromQL functions, for example:

```promql
avg_over_time(janusec_precision_daily[7d])
```
