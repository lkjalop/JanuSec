Alerting and Dashboards
=======================

This folder contains example Alertmanager configuration and a Grafana dashboard JSON for the Janusec precision metrics.

Alertmanager
-----------

- File: deployment/prometheus/alertmanager_sample.yml
- Usage: copy this to your Alertmanager config location (usually /etc/alertmanager/alertmanager.yml) and update receivers and SMTP/webhook settings.
- Example (reload): `curl -X POST http://<alertmanager-host>:-:9093/-/reload`

Prometheus Rules
----------------
- File: deployment/prometheus/precision_alerts.yml
- Usage: include it in Prometheus `rule_files` in prometheus.yml and reload Prometheus.

Grafana Dashboard
-----------------
- File: deployment/grafana/janusec_precision_dashboard.json
- Usage: Import this JSON into Grafana (Dashboards -> Manage -> Import) or use the API.
- The dashboard includes template variables `tenant` and `test_id` generated from label_values queries against `janusec_precision_daily`.
 - Example (Grafana API import):
	 ```bash
	 curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <GRAFANA_API_KEY>" \
		 http://<grafana-host>:3000/api/dashboards/import -d @deployment/grafana/janusec_precision_dashboard.json
	 ```
 - The dashboard includes template variables `tenant`, `test_id`, and `variant` generated from label_values queries against metric labels.

Notes
-----
- Replace placeholder SMTP and credentials in the Alertmanager sample with your organization's values.
- The dashboard assumes Prometheus is the Grafana datasource named in your Grafana instance. You may need to edit the `datasource` field when importing.
 - The `alertmanager_sample.yml` includes sample receivers for email, Slack, PagerDuty, and MS Teams webhook — replace `api_url`, `service_key`, and `url` with your endpoints and secrets.
 - When importing the dashboard via API, provide a Grafana API key with dashboard write permissions.

Validation & Templates
----------------------
- Use `amtool check-config` (part of Alertmanager's `amtool`) to validate merged configs before reloading:

```bash
amtool check-config /path/to/alertmanager.yml
```

- To inject secrets in CI safely, replace placeholders at deploy time. Example (GitHub Actions):

```yaml
- name: Render Alertmanager config
	env:
		SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
		PAGERDUTY_KEY: ${{ secrets.PAGERDUTY_KEY }}
	run: |
		sed -e "s|REPLACE/ME/HOOK|${SLACK_WEBHOOK}|g" \
				-e "s|REPLACE_PAGERDUTY_KEY|${PAGERDUTY_KEY}|g" \
				deployment/prometheus/alertmanager_sample.yml > /tmp/alertmanager.yml
		amtool check-config /tmp/alertmanager.yml
		scp /tmp/alertmanager.yml prometheus:/etc/alertmanager/alertmanager.yml
		ssh prometheus 'systemctl reload alertmanager'
```

- Templates are supported via the `templates:` block. See `deployment/prometheus/templates/ops_notification.tmpl` for a minimal example. Use `{{ template "ops_notification" . }}` references in receivers if you want formatted bodies.

Merge snippet & CI secrets
-------------------------
- To merge the sample into an existing `alertmanager.yml` safely, you can append the `receivers` and `route.routes` entries then run `amtool check-config` (if you have `amtool` installed) to validate.
- Example merge (manual): copy receivers block into your `receivers:` list and add the `routes:` entries under the top-level `route:` section.
- CI-friendly secrets: avoid committing API keys; use your CI secret store and inject them at deploy time. Example for GitHub Actions:

```yaml
- name: Deploy Alertmanager config
	env:
		SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
	run: |
		sed "s|REPLACE/ME/HOOK|${SLACK_WEBHOOK}|g" deployment/prometheus/alertmanager_sample.yml > /tmp/alertmanager.yml
		scp /tmp/alertmanager.yml prometheus:/etc/alertmanager/alertmanager.yml
		ssh prometheus 'systemctl reload alertmanager'
```
