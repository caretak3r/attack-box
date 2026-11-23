#!/usr/bin/env python3
"""Check the offline dashboard contract. This does not compile NRQL remotely."""

import argparse
import copy
import json
from pathlib import Path
import re
import sys


DASHBOARD = Path(__file__).resolve().parent / "dashboards" / "attackbox-overview.json"
PAGES = ("Live Watch", "Evidence & Forensics", "Telemetry Health")
VISUALIZATIONS = {"viz.markdown", "viz.billboard", "viz.line", "viz.area", "viz.table", "viz.bar"}


def validate(data):
    errors = []
    pages = data.get("pages", [])
    if tuple(page.get("name") for page in pages) != PAGES:
        errors.append("Expected live, forensic and telemetry pages in that order")
    for page in pages:
        occupied = {}
        titles = set()
        for widget in page.get("widgets", []):
            title = widget.get("title", "")
            label = f"{page.get('name')}: {title}"
            if not title or title in titles:
                errors.append(f"{label}: missing or duplicate title")
            titles.add(title)
            layout = widget.get("layout", {})
            values = [layout.get(key) for key in ("column", "row", "width", "height")]
            if not all(type(value) is int and value > 0 for value in values):
                errors.append(f"{label}: layout needs positive integer coordinates")
                continue
            col, row, width, height = values
            if col + width > 13:
                errors.append(f"{label}: outside the 12-column grid")
            overlaps = set()
            for x in range(col, col + width):
                for y in range(row, row + height):
                    if (x, y) in occupied:
                        overlaps.add(occupied[x, y])
                    occupied[x, y] = title
            if overlaps:
                errors.append(f"{label}: overlaps {', '.join(sorted(overlaps))}")
            viz = widget.get("visualization", {}).get("id")
            cfg = widget.get("rawConfiguration", {})
            if viz not in VISUALIZATIONS:
                errors.append(f"{label}: unsupported visualization {viz}")
            if viz == "viz.markdown":
                if not cfg.get("text") or cfg.get("nrqlQueries"):
                    errors.append(f"{label}: markdown requires text without queries")
                continue
            queries = cfg.get("nrqlQueries", [])
            if not queries:
                errors.append(f"{label}: missing query")
            fixed = page.get("name") != "Evidence & Forensics"
            if cfg.get("platformOptions", {}).get("ignoreTimeRange") is not fixed:
                errors.append(f"{label}: wrong time-picker policy")
            for query in queries:
                if query.get("accountIds") != [0] or "accountId" in query:
                    errors.append(f"{label}: expected offline accountIds [0]")
                sql = query.get("query", "")
                if re.search(r"percentile\([^()]*\)\s*/", sql, re.I):
                    errors.append(f"{label}: convert units before percentile aggregation")
                if not re.search(r"\bSINCE (5|15) minutes ago\b", sql):
                    errors.append(f"{label}: missing explicit 5/15-minute window")
                if re.search(r"\b(event|observations|ship_dropped_total)\.", sql):
                    errors.append(f"{label}: serialized JSON queried as nested attributes")
                if re.search(r"=\s*'(true|false)'", sql, re.I):
                    errors.append(f"{label}: quoted boolean")
                if "FROM Log" not in sql:
                    continue
                if "`service.name` = 'attackbox'" not in sql:
                    errors.append(f"{label}: missing service scope")
                if "count(*)" in sql and "stream = 'heartbeat'" not in sql:
                    errors.append(f"{label}: raw Log count can count chunks/replays")
                if "uniqueCount(record_id" in sql and "chunk_index = 0" not in sql:
                    errors.append(f"{label}: record totals require first-chunk selection")
                if "direction = 'request'" in sql:
                    guards = ("source = 'bait'", "stream = 'edge'", "action != 'capture'", "chunk_index = 0")
                    if not all(guard in sql for guard in guards):
                        errors.append(f"{label}: missing request-count guard")
                if "action = 'capture'" in sql:
                    guards = ("source = 'bait'", "stream = 'edge'", "evidence_encoding = 'base64'")
                    if not all(guard in sql for guard in guards):
                        errors.append(f"{label}: missing raw-evidence guard")
                if "Redacted preview" in sql and "action != 'capture'" not in sql:
                    errors.append(f"{label}: raw evidence can enter contextual previews")
                if "FACET record_id, body_sha256, chunk_index" in sql and "latest(body_chunk)" not in sql:
                    errors.append(f"{label}: chunk preview omits body_chunk")
    return errors


def self_test(data):
    mutations = {
        "overlap": lambda d: d["pages"][0]["widgets"][1]["layout"].update(row=1),
        "live account": lambda d: d["pages"][0]["widgets"][1]["rawConfiguration"]["nrqlQueries"][0].update(accountIds=[123]),
        "wrong time policy": lambda d: d["pages"][0]["widgets"][1]["rawConfiguration"]["platformOptions"].update(ignoreTimeRange=False),
    }
    for name, change in mutations.items():
        bad = copy.deepcopy(data)
        change(bad)
        if not validate(bad):
            raise AssertionError(f"Validator missed {name}")
    for before, after in (
        ("chunk_index = 0", "chunk_index >= 0"),
        ("action != 'capture'", "action IS NOT NULL"),
        ("uniqueCount(record_id, precision: 10000)", "count(*)"),
        ("bait_connected = true", "bait_connected = 'true'"),
        ("latest(event)", "latest(event.dst_ip)"),
        ("percentile(export_lag_ms / 1000, 50, 95)", "percentile(export_lag_ms, 50, 95) / 1000"),
    ):
        bad = json.loads(json.dumps(data).replace(before, after))
        if not validate(bad):
            raise AssertionError(f"Validator missed mutation: {before}")
    print(f"PASS: {len(mutations) + 6} negative contract checks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    data = json.loads(DASHBOARD.read_text())
    errors = validate(data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.self_test:
        self_test(data)
    pages = data["pages"]
    print(f"PASS: {len(pages)} pages, {sum(len(p['widgets']) for p in pages)} widgets; offline dashboard contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
