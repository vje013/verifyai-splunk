#!/usr/bin/env python3
"""
Replay historical VerifyAI determinism sweeps from the verifyai-ledger Modal
volume to Splunk Observability Cloud.

What it does:
  1. Lists the verifyai-ledger Modal volume
  2. Downloads every *.jsonl ledger file to a temp directory
  3. Parses each line, keeps determinism-kind sweeps
  4. Re-timestamps the batch evenly across the last N minutes (default 10)
     so the o11y dashboard shows trend, not a single spike
  5. Pushes each sweep as 4 gauges + 1 counter to Splunk
  6. Prints a summary

Run locally on the Mac (not on Modal — no Modal endpoint cost):
    export SPLUNK_ACCESS_TOKEN=dMbrNREKdncgJ7vWBNqbmg
    export SPLUNK_REALM=us1
    python3 replay_to_splunk.py

Requires:
  - modal CLI installed and authenticated (you already have this)
  - python3 stdlib only (no extra pip deps)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

LEDGER_VOLUME = "verifyai-ledger"
WINDOW_MINUTES = 10
THROTTLE_SEC = 0.03  # gentle pace, ~30 pushes/sec ceiling


def _ingest_url(realm):
    return f"https://ingest.{realm}.signalfx.com/v2/datapoint"


def download_ledger():
    """Use `modal volume get` to download the whole ledger to a temp dir."""
    tmpdir = tempfile.mkdtemp(prefix="verifyai_replay_")
    print(f"[download] ledger -> {tmpdir}")

    # First show what's in the volume so we know what to expect
    ls = subprocess.run(
        ["modal", "volume", "ls", LEDGER_VOLUME],
        capture_output=True, text=True
    )
    if ls.returncode != 0:
        print(f"[download] modal volume ls failed: {ls.stderr}")
        sys.exit(1)
    print("[download] volume contents:")
    for line in ls.stdout.splitlines():
        print(f"  {line}")

    # Pull everything in the volume into tmpdir
    get = subprocess.run(
        ["modal", "volume", "get", LEDGER_VOLUME, "/", tmpdir, "--force"],
        capture_output=True, text=True
    )
    if get.returncode != 0:
        # Fall back: some Modal versions don't accept "/" as remote path.
        print(f"[download] root pull failed ({get.stderr.strip()}), trying per-file...")
        # Parse the ls output for .jsonl files and pull each
        for line in ls.stdout.splitlines():
            tok = line.split()
            if not tok:
                continue
            for part in tok:
                if part.endswith(".jsonl"):
                    subprocess.run(
                        ["modal", "volume", "get", LEDGER_VOLUME, part, tmpdir, "--force"],
                        capture_output=True, text=True
                    )
                    print(f"  pulled {part}")
                    break
    return tmpdir


def collect_sweeps(ledger_dir):
    """Walk all *.jsonl files in ledger_dir, return list of determinism sweeps."""
    sweeps = []
    for path in Path(ledger_dir).rglob("*.jsonl"):
        print(f"[parse] {path}")
        n_before = len(sweeps)
        with open(path) as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    entry = json.loads(ln)
                except Exception:
                    continue
                if entry.get("kind") != "determinism":
                    continue
                sweeps.append({
                    "orig_ts": entry.get("ts", int(time.time())),
                    "account": entry.get("account_id", "unknown"),
                    "workflow": entry.get("workflow_id", "unknown"),
                    "framework": (entry.get("framework") or "unknown").replace(" ", "_"),
                    "overall": entry.get("determinism_score", 0),
                    "output_equivalence": entry.get("output_equivalence", 0),
                    "semantic_equivalence": entry.get("semantic_equivalence", 0),
                    "decision_stability": entry.get("decision_stability", 0),
                })
        print(f"  + {len(sweeps) - n_before} determinism sweeps")
    sweeps.sort(key=lambda s: s["orig_ts"])
    return sweeps


def spread_timestamps(sweeps, window_minutes=WINDOW_MINUTES):
    """Re-stamp sweeps to current wall clock spread evenly across last N minutes."""
    if not sweeps:
        return sweeps
    now_ms = int(time.time() * 1000)
    window_ms = window_minutes * 60 * 1000
    n = len(sweeps)
    for i, s in enumerate(sweeps):
        # i=0 -> oldest (now - window_ms), i=n-1 -> now
        frac = i / max(n - 1, 1)
        s["push_ts_ms"] = now_ms - window_ms + int(frac * window_ms)
    return sweeps


def push_sweep(sweep, token, ingest_url):
    """POST one sweep (4 gauges + 1 counter) to Splunk. Returns (ok, body_or_err)."""
    dims = {
        "account": sweep["account"],
        "workflow": sweep["workflow"],
        "framework": sweep["framework"],
        "service": "verifyai",
        "source": "replay",
    }
    ts = sweep["push_ts_ms"]
    body = {
        "gauge": [
            {"metric": "verifyai.determinism.score",   "value": float(sweep["overall"]),              "timestamp": ts, "dimensions": dims},
            {"metric": "verifyai.output_equivalence",  "value": float(sweep["output_equivalence"]),   "timestamp": ts, "dimensions": dims},
            {"metric": "verifyai.semantic_equivalence","value": float(sweep["semantic_equivalence"]), "timestamp": ts, "dimensions": dims},
            {"metric": "verifyai.decision_stability",  "value": float(sweep["decision_stability"]),   "timestamp": ts, "dimensions": dims},
        ],
        "counter": [
            {"metric": "verifyai.sweep.count", "value": 1, "timestamp": ts, "dimensions": dims},
        ],
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        ingest_url, data=data,
        headers={"Content-Type": "application/json", "X-SF-TOKEN": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200, resp.read()
    except Exception as e:
        return False, str(e).encode()


def main():
    token = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
    realm = os.environ.get("SPLUNK_REALM", "us1")
    if not token:
        print("ERROR: export SPLUNK_ACCESS_TOKEN first")
        return 1
    ingest_url = _ingest_url(realm)
    print(f"[config] realm={realm}  ingest={ingest_url}")

    ledger_dir = download_ledger()
    try:
        sweeps = collect_sweeps(ledger_dir)
        print(f"\n[collect] total determinism sweeps: {len(sweeps)}")
        if not sweeps:
            print("Nothing to replay.")
            return 0

        # Breakdown by account
        by_acc = {}
        for s in sweeps:
            by_acc[s["account"]] = by_acc.get(s["account"], 0) + 1
        print("[collect] breakdown by account:")
        for acc, n in sorted(by_acc.items(), key=lambda x: -x[1]):
            print(f"  {acc:40s} {n}")

        # Breakdown by workflow within top account
        sweeps = spread_timestamps(sweeps, WINDOW_MINUTES)
        print(f"\n[push] {len(sweeps)} sweeps spread across last {WINDOW_MINUTES} min")
        ok = fail = 0
        sample_err = None
        for i, sw in enumerate(sweeps):
            okp, body = push_sweep(sw, token, ingest_url)
            if okp:
                ok += 1
            else:
                fail += 1
                if not sample_err:
                    sample_err = body[:300]
            if (i + 1) % 20 == 0 or (i + 1) == len(sweeps):
                print(f"  {i+1:4d}/{len(sweeps)}  ok={ok} fail={fail}")
            time.sleep(THROTTLE_SEC)

        print(f"\n[done] pushed {ok}/{len(sweeps)}  failed={fail}")
        if sample_err:
            print(f"[done] first error sample: {sample_err}")
        return 0 if fail == 0 else 1
    finally:
        try:
            shutil.rmtree(ledger_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
