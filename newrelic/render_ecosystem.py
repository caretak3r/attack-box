#!/usr/bin/env python3
"""Render account-scoped New Relic monitoring assets. No network or account writes."""
import argparse
import json
from pathlib import Path
import re


def identity(value):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", value):
        raise ValueError("sensor identifier must be 1-64 letters, digits, dots, dashes or underscores")
    return value


def render(account, sensor, workload_guid=None):
    if type(account) is not int or account <= 0:
        raise ValueError("account ID must be positive")
    sensor = identity(sensor)
    if workload_guid is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", workload_guid):
        raise ValueError("invalid workload GUID")
    scope = f"sensor_id = '{sensor}'"
    entities = f"accountId = '{account}' AND (tags.sensor_id = '{sensor}' OR tags.docker.host = '{sensor}') AND type != 'WORKLOAD' AND tags.attackbox_retired IS NULL"
    widgets = []

    def widget(title, kind, config, col, row, width, height):
        widgets.append({"title": title, "visualization": {"id": kind},
                        "layout": {"column": col, "row": row, "width": width, "height": height},
                        "rawConfiguration": config})

    def query(title, sql, col, row, width=6, height=3, kind="viz.table"):
        widget(title, kind, {"nrqlQueries": [{"accountIds": [account], "query": sql}],
                            "platformOptions": {"ignoreTimeRange": True}}, col, row, width, height)

    widget("Coverage contract", "viz.markdown", {"text":
        "## Host ecosystem\nNative map edges require real entities and relationships. "
        "A missing node is not proof that a component is absent. Use the expected-component table. "
        "State: **1 yes · 0 no · -1 unknown**. Coverage verification remains unknown until an "
        "end-to-end fixture is checked in this account. Empty results mean no telemetry. "
        "Tables use five-minute windows; check source age before treating a value as current. "
        "Do not interpret an active Compose unit as healthy containers."}, 1, 1, 12, 2)
    # The documented topology.service-map widget returns a UI 404 in this account.
    # The current native Workload Maps route was verified in the browser.
    map_url = (f"https://one.newrelic.com/nr1-core/workloads/automap/{workload_guid}?account={account}"
               if workload_guid else f"https://one.newrelic.com/workloads?account={account}")
    widget("Open the live architecture map", "viz.markdown", {"text":
        f"## [Open New Relic Maps →]({map_url})\n\n"
        "Open the host workload's Maps view. Native host/container links and explicitly declared "
        "deployment links are separate from measured service calls. Historical neighbors can "
        "appear during the selected time range; use current inventory below. "
        "Supply --workload-guid after the workload is created for a direct map link."}, 1, 3, 12, 6)
    query("Expected components: observed / running / ready / coverage", f"SELECT latest(attackbox_component_observed) AS 'Observed', latest(attackbox_component_running) AS 'Running', latest(attackbox_component_ready) AS 'Ready', latest(attackbox_component_coverage_verified) AS 'Coverage verified', latest(attackbox_component_observation_timestamp_seconds) AS 'Observed at Unix seconds' FROM Metric WHERE {scope} FACET component SINCE 5 minutes ago LIMIT MAX", 1, 9, 12, 5)
    query("Inventory validity and source age", f"SELECT latest(attackbox_inventory_snapshot_valid) AS 'Valid', latest(attackbox_inventory_snapshot_age_seconds) AS 'Source age seconds' FROM Metric WHERE {scope} SINCE 5 minutes ago", 1, 14, kind="viz.billboard")
    query("Container health and restart evidence", f"SELECT latest(attackbox_container_health) AS 'Healthy', latest(attackbox_container_restarts) AS 'Restarts', latest(attackbox_container_oom) AS 'OOM', latest(attackbox_container_runtime_approved) AS 'Approved runtime' FROM Metric WHERE {scope} FACET component SINCE 5 minutes ago", 7, 14)
    query("Instrumented Go services", f"SELECT count(*) AS 'Sampled spans', percentile(duration.ms, 50, 95) FROM Span WHERE {scope} FACET service.name SINCE 5 minutes ago", 1, 17)
    query("Recent traces for investigation", f"SELECT latest(name), latest(trace.id), latest(service.name) FROM Span WHERE {scope} FACET id SINCE 5 minutes ago LIMIT 20", 7, 17)
    query("Host CPU", f"SELECT average(host.cpuPercent) FROM Metric WHERE {scope} SINCE 5 minutes ago TIMESERIES", 1, 20, kind="viz.line")
    query("Host memory", f"SELECT average(host.memoryUsedPercent) FROM Metric WHERE {scope} SINCE 5 minutes ago", 7, 20, kind="viz.bar")
    query("Collector export / queue metric discovery", f"SELECT uniques(metricName) FROM Metric WHERE {scope} AND metricName LIKE 'otelcol_exporter%' SINCE 5 minutes ago LIMIT MAX", 1, 23)
    query("Evidence export lag remains a separate signal", f"SELECT percentile(export_lag_ms / 1000, 50, 95) FROM Log, Log_AttackEvidence, Log_Security, Log_Operations WHERE `service.name` = 'attackbox' AND ({scope} OR hostname = '{sensor}') SINCE 5 minutes ago TIMESERIES", 7, 23, kind="viz.line")
    query("Host processes: CPU and resident memory", f"SELECT average(host.process.cpuPercent), average(host.process.memoryResidentSizeBytes) FROM Metric WHERE {scope} FACET process.name SINCE 5 minutes ago LIMIT 100", 1, 26, 12, 5)
    query("Native container resources", f"SELECT average(docker.container.cpuPercent), average(docker.container.memoryUsageBytes), max(docker.container.restartCount) FROM Metric WHERE {scope} FACET entity.name SINCE 5 minutes ago", 1, 31, 12, 4)
    query("Host log files", f"SELECT count(*), latest(timestamp) FROM Log, Log_AttackEvidence, Log_Security, Log_Operations WHERE ({scope} OR hostname = '{sensor}') FACET filePath, logtype SINCE 5 minutes ago LIMIT 30", 1, 35, 6, 4)
    query("Evidence routes: source and direction", f"SELECT count(*), latest(timestamp) FROM Log, Log_AttackEvidence, Log_Security, Log_Operations WHERE `service.name` = 'attackbox' AND ({scope} OR hostname = '{sensor}') FACET source, direction SINCE 5 minutes ago LIMIT 30", 7, 35, 6, 4)
    dashboard = {"name": f"AttackBox · Ecosystem · {sensor}", "description": "Expected inventory, service relationships and monitoring freshness. Empty is unknown.",
                 "permissions": "PRIVATE", "pages": [{"name": "Ecosystem", "widgets": widgets}]}
    workload = ("mutation { workloadCreate(accountId: " + str(account) + ", workload: { name: "
                + json.dumps("AttackBox / " + sensor) + ", entitySearchQueries: [{ query: "
                + json.dumps(entities) + " }], scopeAccounts: { accountIds: [" + str(account)
                + "] } }) { guid } }\n")
    alerts = []
    for name, metric, facet in [("Expected component observation", "attackbox_component_observed", " FACET component"),
                                ("Inventory validity", "attackbox_inventory_snapshot_valid", ""),
                                ("Expected component running", "attackbox_component_running", " FACET component")]:
        alerts.append({"name": f"AttackBox / {sensor} / {name}", "enabled": False,
            "nrql": {"query": f"SELECT min({metric}) FROM Metric WHERE {scope}" + facet},
            "signal": {"aggregationWindow": 60, "aggregationMethod": "EVENT_FLOW", "aggregationDelay": 30, "fillOption": "NONE"},
            "expiration": {"expirationDuration": 180, "openViolationOnExpiration": True, "closeViolationsOnExpiration": False},
            "terms": [{"priority": "CRITICAL", "operator": "BELOW", "threshold": 1, "thresholdDuration": 60, "thresholdOccurrences": "ALL"}]})
    readiness = json.loads(json.dumps(alerts[0]))
    readiness["name"] = f"AttackBox / {sensor} / Readiness probe failed"
    readiness["nrql"]["query"] = f"SELECT max(attackbox_component_probe_failed) FROM Metric WHERE {scope} AND component IN ('attackbox-bait', 'attackbox-proxy', 'attackbox-otel.service', 'attackbox-hostcollector.service') FACET component"
    readiness["terms"][0].update(operator="ABOVE", threshold=0)
    alerts.append(readiness)
    return {"dashboard.json": dashboard, "workload-create.graphql": workload,
            "alert-condition-inputs.json": {"accountId": account, "conditions": alerts,
            "activation_gate": "Inputs for reviewed static NRQL conditions, not an API request. Supply an approved policy. Validate all expected component samples and failed/stale fixtures first; loss of signal only activates after a signal arrives. Configure and test an approved notification destination separately."}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--account-id", type=int, required=True)
    p.add_argument("--sensor-id", required=True)
    p.add_argument("--workload-guid")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    try:
        assets = render(a.account_id, a.sensor_id, a.workload_guid)
    except ValueError as e:
        p.error(str(e))
    a.output.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidental replacement of a reviewed export.
    for name, data in assets.items():
        with (a.output / name).open("x") as f:
            f.write(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n")
    print(f"Rendered {len(assets)} local assets in {a.output.resolve()}; no account writes")


if __name__ == "__main__":
    main()
