#!/usr/bin/env python3
"""
Deploy the VerifyAI dashboard to Splunk Observability Cloud.

Creates:
  1. Dashboard group "VerifyAI"
  2. Dashboard "Agent Determinism Posture"
  3. Five charts wired to the verifyai.* metrics

Run locally (stdlib only):
    export SPLUNK_ACCESS_TOKEN=...
    export SPLUNK_REALM=us1
    python3 deploy_dashboard.py

If re-run, will create duplicates. Delete the old dashboard group in the UI
first if you want a clean slate.
"""

import json
import os
import sys
import urllib.error
import urllib.request

TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
REALM = os.environ.get("SPLUNK_REALM", "us1")
API = f"https://api.{REALM}.signalfx.com"

if not TOKEN:
    print("ERROR: export SPLUNK_ACCESS_TOKEN first")
    sys.exit(1)


def api(method, path, body=None):
    url = API + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "X-SF-TOKEN": TOKEN},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"raw": str(e)}
    except Exception as e:
        return -1, {"error": str(e)}


# ─── Chart definitions ──────────────────────────────────────────────────
# Layout: 12-column grid. Five charts laid out as:
#   row 0 (height 2): three KPI tiles across the top
#   row 2 (height 3): determinism over time, full width
#   row 5 (height 4): spread by workflow, full width

CHARTS = [
    {
        "spec": {
            "name": "Overall determinism",
            "description": "Mean determinism score across all accounts and workflows.",
            "programText": "A = data('verifyai.determinism.score').mean().publish(label='A')",
            "options": {
                "type": "SingleValue",
                "maximumPrecision": 3,
            },
        },
        "layout": {"row": 0, "column": 0, "width": 4, "height": 2},
    },
    {
        "spec": {
            "name": "Total sweeps",
            "description": "Cumulative determinism sweeps captured by VerifyAI.",
            "programText": "A = data('verifyai.sweep.count').sum().publish(label='A')",
            "options": {
                "type": "SingleValue",
                "maximumPrecision": 0,
            },
        },
        "layout": {"row": 0, "column": 4, "width": 4, "height": 2},
    },
    {
        "spec": {
            "name": "Posture by framework",
            "description": "Determinism mean grouped by compliance framework (GLBA, SOC 2, ASC 606, SR 11-7).",
            "programText": "A = data('verifyai.determinism.score').mean(by=['framework']).publish(label='A')",
            "options": {
                "type": "List",
                "maximumPrecision": 3,
            },
        },
        "layout": {"row": 0, "column": 8, "width": 4, "height": 2},
    },
    {
        "spec": {
            "name": "Determinism over time",
            "description": "One line per workflow. Drift detection lives here.",
            "programText": "A = data('verifyai.determinism.score').mean(by=['workflow']).publish(label='A')",
            "options": {
                "type": "TimeSeriesChart",
            },
        },
        "layout": {"row": 2, "column": 0, "width": 12, "height": 3},
    },
    {
        "spec": {
            "name": "Spread by (account, workflow)",
            "description": "Determinism mean per workflow. Discrete-decision workflows score 90-99%, multi-step arithmetic 60-80% — the thesis on one screen.",
            "programText": "A = data('verifyai.determinism.score').mean(by=['account','workflow']).publish(label='A')",
            "options": {
                "type": "List",
                "maximumPrecision": 3,
            },
        },
        "layout": {"row": 5, "column": 0, "width": 12, "height": 4},
    },
]


# ─── 1. Group ──────────────────────────────────────────────────────────
print("[1/3] Creating dashboard group 'VerifyAI'...")
status, group = api("POST", "/v2/dashboardgroup", {
    "name": "VerifyAI",
    "description": "Agent determinism + compliance posture across design partners.",
})
if status not in (200, 201):
    print(f"  FAIL ({status}): {group}")
    sys.exit(1)
group_id = group.get("id")
print(f"  group id: {group_id}")


# ─── 2. Charts ─────────────────────────────────────────────────────────
print(f"\n[2/3] Creating {len(CHARTS)} charts...")
chart_refs = []
for idx, ch in enumerate(CHARTS, 1):
    spec = ch["spec"]
    layout = ch["layout"]
    name = spec["name"]
    status, chart = api("POST", "/v2/chart", spec)
    if status not in (200, 201):
        print(f"  [{idx}/{len(CHARTS)}] '{name}' FAIL ({status}): {json.dumps(chart)[:300]}")
        continue
    cid = chart.get("id")
    print(f"  [{idx}/{len(CHARTS)}] '{name}' -> {cid}")
    chart_refs.append({
        "chartId": cid,
        "row": layout["row"],
        "column": layout["column"],
        "width": layout["width"],
        "height": layout["height"],
    })

if not chart_refs:
    print("\nNo charts created. Aborting dashboard creation.")
    sys.exit(1)


# ─── 3. Dashboard ──────────────────────────────────────────────────────
print(f"\n[3/3] Creating dashboard 'Agent Determinism Posture'...")
status, dash = api("POST", "/v2/dashboard", {
    "name": "Agent Determinism Posture",
    "description": "Live posture across Echelor, NCE, Fifth Third, and smoke-test workflows.",
    "groupId": group_id,
    "charts": chart_refs,
})
if status not in (200, 201):
    print(f"  FAIL ({status}): {dash}")
    sys.exit(1)
dash_id = dash.get("id")
print(f"  dashboard id: {dash_id}")

print(f"\n✓ Done. Open:")
print(f"  https://app.{REALM}.observability.splunkcloud.com/#/dashboard/{dash_id}")
