#!/usr/bin/env python3
"""
VerifyAI MCP Server (v2 — Path C: MCP-to-MCP composition).

Our MCP server exposes 6 tools to any MCP-compatible agent.
Internally, the server is itself an MCP CLIENT to Splunk Observability
Cloud's hosted MCP Gateway over streamable HTTP. The drift query and the
Splunk tool-listing pass through that Gateway.

Architecture:

  Agent (Claude / Cursor / Inspector)
        |  stdio MCP
        v
  VerifyAI MCP Server (this file)
        |        |
        |        +--> Modal backend (compute, ledger, certs)
        |
        +--> Splunk MCP Gateway over streamable HTTP
                  X-SF-TOKEN + X-SF-REALM
                  https://region-<scs_region>.api.scs.splunk.com/system/mcp-gateway/v1/

Tools:
  verifyai_list_workflows       Modal aggregate, all known accounts
  verifyai_get_posture          Modal aggregate, single account
  verifyai_get_drift            Splunk MCP Gateway -> metric query (REST fallback)
  verifyai_run_sweep            Modal run-determinism
  verifyai_get_certificate      Modal certificate
  verifyai_splunk_list_tools    Splunk MCP Gateway -> list available o11y tools

Env:
  SPLUNK_ACCESS_TOKEN  required, the SignalFx access token
  SPLUNK_REALM         default 'us1'
  SPLUNK_MCP_URL       override default; computed from realm if unset
  MODAL_BASE           default 'https://vje013--verifyai-backend'
  VERIFYAI_ACCOUNTS    comma-sep, default 'echelor,nce,fifththird'
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import httpx
from mcp.server.fastmcp import FastMCP
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# ─── Config ─────────────────────────────────────────────────────────────
SPLUNK_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
SPLUNK_REALM = os.environ.get("SPLUNK_REALM", "us1")
SPLUNK_API = f"https://api.{SPLUNK_REALM}.signalfx.com"

# Realm -> SCS Region mapping per Splunk docs (Supported regions table).
SCS_REGION_MAP = {
    "us0": "iad10",   # N. Virginia
    "us1": "pdx10",   # Oregon
    "us3": "pdx10",
    "eu0": "dub10",   # Ireland
    "eu1": "fra10",   # Frankfurt
    "eu2": "lon10",   # London
    "jp0": "tyo10",
    "au0": "syd10",
    "sg0": "sin10",
}


def _splunk_mcp_url() -> str:
    if os.environ.get("SPLUNK_MCP_URL"):
        return os.environ["SPLUNK_MCP_URL"]
    region = SCS_REGION_MAP.get(SPLUNK_REALM.lower(), "pdx10")
    return f"https://region-{region}.api.scs.splunk.com/system/mcp-gateway/v1/"


MODAL_BASE = os.environ.get("MODAL_BASE", "https://vje013--verifyai-backend")
KNOWN_ACCOUNTS = [
    a.strip()
    for a in os.environ.get("VERIFYAI_ACCOUNTS", "echelor,nce,fifththird").split(",")
    if a.strip()
]

mcp = FastMCP("verifyai")


# ─── HTTP helpers (REST) ────────────────────────────────────────────────
def _get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}


def _post(url, body, headers=None, timeout=300):
    data = json.dumps(body).encode()
    hdr = {"Content-Type": "application/json"}
    hdr.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdr, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


# ─── Splunk MCP Gateway client helper ───────────────────────────────────
def _splunk_mcp_headers():
    return {
        "X-SF-TOKEN": SPLUNK_TOKEN,
        "X-SF-REALM": SPLUNK_REALM,
    }


async def _splunk_mcp_call(coro_fn):
    """Open a streamable HTTP MCP session to Splunk Gateway and run coro_fn(session).

    coro_fn is an async callable that takes a ClientSession and returns whatever.
    Returns (ok: bool, result_or_error).
    """
    if not SPLUNK_TOKEN:
        return False, "SPLUNK_ACCESS_TOKEN not configured"
    url = _splunk_mcp_url()
    headers = _splunk_mcp_headers()
    try:
        async with streamablehttp_client(url, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await coro_fn(session)
                return True, result
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ─── Tool 1: list workflows ─────────────────────────────────────────────
@mcp.tool()
def verifyai_list_workflows() -> str:
    """List all (account, workflow) tuples currently monitored by VerifyAI.

    Aggregates posture across known accounts via the Modal backend.
    """
    out = ["VerifyAI — monitored accounts and workflows"]
    out.append("=" * 50)
    for acc in KNOWN_ACCOUNTS:
        try:
            url = f"{MODAL_BASE}-echelor-aggregate.modal.run?account={urllib.parse.quote(acc)}"
            status, body = _get(url, timeout=15)
            if status != 200 or not isinstance(body, dict):
                out.append(f"\n  [{acc}] error: HTTP {status}")
                continue
            workflows = body.get("workflows", [])
            overall = body.get("overall", {})
            out.append(
                f"\n  {body.get('account_id', acc)}  "
                f"overall={overall.get('determinism_rate', 0):.3f}  "
                f"({len(workflows)} workflows)"
            )
            for w in workflows:
                wid = w.get("workflow_id", "?")
                det = (w.get("determinism") or {}).get("score") or 0
                out.append(f"    - {wid:35s}  det={det:.3f}")
        except Exception as e:
            out.append(f"\n  [{acc}] error: {e}")
    return "\n".join(out)


# ─── Tool 2: get posture ────────────────────────────────────────────────
@mcp.tool()
def verifyai_get_posture(account: str, workflow: str = "") -> str:
    """Return current determinism posture for an account, optionally one workflow.

    account: account ID (e.g. 'echelor', 'nce', 'fifththird')
    workflow: optional workflow ID filter
    """
    try:
        url = f"{MODAL_BASE}-echelor-aggregate.modal.run?account={urllib.parse.quote(account)}"
        status, body = _get(url, timeout=15)
        if status != 200 or not isinstance(body, dict):
            return f"Modal returned HTTP {status}: {str(body)[:200]}"

        overall = body.get("overall", {})
        out = [
            f"Account: {body.get('account_id', account)}",
            f"Overall determinism: {overall.get('determinism_rate', 0):.3f}",
            f"Sweeps in window: {overall.get('total_sweeps', 0)}",
            "",
            "Workflows:",
        ]
        matched = 0
        for w in body.get("workflows", []):
            wid = w.get("workflow_id")
            if workflow and wid != workflow:
                continue
            matched += 1
            det = w.get("determinism") or {}
            out.append(f"  {wid}:")
            out.append(f"    score:               {det.get('score', 0):.3f}")
            out.append(f"    output equivalence:  {det.get('output_equivalence', 0):.3f}")
            out.append(f"    semantic equivalence:{det.get('semantic_equivalence', 0):.3f}")
            out.append(f"    decision stability:  {det.get('decision_stability', 0):.3f}")
            out.append(f"    framework:           {w.get('framework', 'unknown')}")
        if workflow and matched == 0:
            out.append(f"  (no workflow matching '{workflow}' in this account)")
        return "\n".join(out)
    except Exception as e:
        return f"get_posture error: {e}"


def _format_signalflow_response(content: str) -> str:
    """Parse Splunk SignalFlow JSON response, render as readable bars."""
    try:
        data = json.loads(content)
    except Exception:
        return content[:1500]

    metadata = data.get("metadata", {})
    timeseries = data.get("timeseries", {})
    if not timeseries:
        return content[:1500]

    # Walk timestamps; empty {} means no data at that resolution bucket.
    points = []
    for ts_str, vals in timeseries.items():
        if not vals:
            continue
        try:
            ts_ms = int(ts_str)
        except Exception:
            continue
        for sid, val in vals.items():
            points.append((ts_ms, sid, val))
    points.sort(key=lambda p: p[0])

    if not points:
        return (
            f"No actual data points returned (received {len(timeseries)} time buckets, "
            f"all empty). Splunk index may not have data in this window yet."
        )

    lines = []
    for sid, dims in metadata.items():
        dim_str = ", ".join(f"{k}={v}" for k, v in dims.items())
        lines.append(f"Series {sid[:12]}  {dim_str}")
    lines.append("")
    lines.append(f"Data points: {len(points)}")
    for ts_ms, sid, val in points[-20:]:
        ts_str = time.strftime("%H:%M:%S", time.localtime(ts_ms / 1000))
        try:
            v = float(val)
        except Exception:
            v = 0.0
        bar = "█" * int(max(0.0, min(1.0, v)) * 30)
        lines.append(f"  {ts_str}  {v:.4f}  {bar}")
    return "\n".join(lines)


# ─── Tool 3: get drift (Splunk MCP Gateway -> REST fallback) ────────────
def _get_drift_via_rest(workflow: str, window_minutes: int) -> str:
    """Fallback: query Splunk SignalFx REST API for metric values."""
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - (window_minutes * 60 * 1000)
    query = f"sf_metric:verifyai.determinism.score AND workflow:{workflow}"
    url = (
        f"{SPLUNK_API}/v1/timeserieswindow"
        f"?query={urllib.parse.quote(query)}"
        f"&startMS={start_ms}&endMS={now_ms}&resolution=60000"
    )
    status, body = _get(
        url,
        headers={"X-SF-TOKEN": SPLUNK_TOKEN, "Accept": "application/json"},
        timeout=15,
    )
    if status != 200 or not isinstance(body, dict):
        return f"[REST] Splunk API HTTP {status}: {str(body)[:300]}"
    data = body.get("data", {})
    if not data:
        return f"[REST] No drift data for workflow='{workflow}' in last {window_minutes} min"
    out = [f"Drift for workflow={workflow} (last {window_minutes} min, via SignalFx REST):"]
    for tsid, points in data.items():
        out.append(f"\nseries={tsid[:24]}")
        for p in points[-15:]:
            ts_str = time.strftime("%H:%M:%S", time.localtime(p[0] / 1000))
            val = p[1]
            bar = "█" * int(max(0, val) * 30)
            out.append(f"  {ts_str}  {val:.3f}  {bar}")
    return "\n".join(out)


@mcp.tool()
async def verifyai_get_drift(workflow: str, window_minutes: int = 60) -> str:
    """Return determinism trend for a workflow over recent time.

    Connects to Splunk Observability Cloud through their MCP Gateway over
    streamable HTTP. Discovers a metric-query tool dynamically, calls it.
    If the Gateway is unreachable or doesn't expose a suitable tool,
    falls back to the direct SignalFx REST API.

    workflow: workflow ID
    window_minutes: lookback window (default 60)
    """
    if not SPLUNK_TOKEN:
        return "SPLUNK_ACCESS_TOKEN not configured"

    async def via_mcp(session: ClientSession):
        tools_result = await session.list_tools()
        tools = tools_result.tools
        # Prefer execute > generate. Splunk's o11y MCP exposes both;
        # execute returns actual data, generate returns a program string.
        preferred = [
            "o11y_execute_signalflow_program",
            "o11y_get_metric_metadata",
            "o11y_get_metric_names",
            "o11y_generate_signalflow_program",
        ]
        tool_name = None
        for p in preferred:
            if any(t.name == p for t in tools):
                tool_name = p
                break
        if not tool_name:
            return {"_no_tool": True, "available": [t.name for t in tools]}

        # Build args based on tool. Splunk's o11y tools expect args
        # wrapped in a `params` object.
        program_text = (
            f"data('verifyai.determinism.score', "
            f"filter=filter('workflow', '{workflow}')).publish()"
        )
        if tool_name == "o11y_execute_signalflow_program":
            # Schema requires: params.program (string), params.time_range.{start,stop} (ISO-8601 durations)
            args = {
                "params": {
                    "program": program_text,
                    "time_range": {
                        "start": f"-{int(window_minutes)}m",
                        "stop": "now",
                    },
                }
            }
        elif tool_name == "o11y_get_metric_metadata":
            args = {
                "params": {
                    "metric_names": ["verifyai.determinism.score"],
                }
            }
        elif tool_name == "o11y_get_metric_names":
            args = {
                "params": {
                    "search_terms": ["verifyai.determinism"],
                }
            }
        else:  # generate_signalflow_program
            args = {
                "params": {
                    "task_description": (
                        f"Get verifyai.determinism.score for workflow={workflow} "
                        f"over last {window_minutes} minutes"
                    ),
                }
            }

        result = await session.call_tool(tool_name, args)
        text_parts = [c.text for c in result.content if hasattr(c, "text")]
        raw_content = "\n".join(text_parts)
        formatted = (
            _format_signalflow_response(raw_content)
            if tool_name == "o11y_execute_signalflow_program"
            else raw_content[:2500]
        )
        return {
            "_tool_used": tool_name,
            "_args_sent": args,
            "content": formatted,
        }

    ok, result = await _splunk_mcp_call(via_mcp)
    if ok and isinstance(result, dict) and not result.get("_no_tool"):
        return (
            f"Drift via Splunk MCP Gateway\n"
            f"Tool used: {result['_tool_used']}\n"
            f"Args sent: {json.dumps(result.get('_args_sent', {}), indent=2)}\n\n"
            f"Response:\n{result['content']}"
        )
    if ok and isinstance(result, dict) and result.get("_no_tool"):
        note = f"[Gateway connected but no metric-query tool found. Available: {result.get('available')}]"
    else:
        note = f"[Gateway path failed: {result}]"
    return f"{note}\n\n{_get_drift_via_rest(workflow, window_minutes)}"


# ─── Tool 4: run sweep ──────────────────────────────────────────────────
@mcp.tool()
def verifyai_run_sweep(
    account: str,
    workflow: str,
    prompt_template: str = "weekly_summary",
    framework: str = "GLBA Safeguards Rule",
    n_runs: int = 10,
) -> str:
    """Trigger a fresh N-run determinism sweep against a workflow.

    Runs on the VerifyAI Modal backend, scores deterministically across
    4 metrics, persists to the ledger, pushes new datapoints to Splunk
    Observability Cloud. Returns the score breakdown.

    account: account ID
    workflow: workflow ID
    prompt_template: fixture template (e.g. 'weekly_summary', 'nce_jobcost_coding')
    framework: compliance framework (default GLBA)
    n_runs: number of probes (default 10, min 5, max 200)
    """
    payload = {
        "spec": {
            "account_id": account,
            "workflow_id": workflow,
            "agent_role": f"{workflow} agent",
            "framework": framework,
        },
        "n_runs": max(5, min(int(n_runs), 200)),
        "temperature": 0,
        "prompt_template": prompt_template,
    }
    try:
        url = f"{MODAL_BASE}-run-determinism.modal.run"
        status, raw = _post(url, payload, timeout=300)
        if status != 200:
            return f"Sweep failed: HTTP {status}\n{raw[:300]!r}"
        text = raw.decode(errors="replace")
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            try:
                evt = json.loads(line[5:].strip())
            except Exception:
                continue
            if evt.get("type") == "done":
                d = evt.get("data", {})
                return (
                    f"Sweep complete for {account}/{workflow}\n"
                    f"  determinism score:    {d.get('determinism_score', 0):.3f}\n"
                    f"  output equivalence:   {d.get('output_equivalence', 0):.3f}\n"
                    f"  semantic equivalence: {d.get('semantic_equivalence', 0):.3f}\n"
                    f"  decision stability:   {d.get('decision_stability', 0):.3f}\n"
                    f"  n_runs:               {d.get('n_runs', 0)}\n"
                    f"  cost:                 ${d.get('cost_usd', 0):.4f}\n"
                    f"  framework:            {d.get('framework')}\n"
                    f"  -> datapoint pushed to Splunk Observability Cloud"
                )
        return f"Sweep ran but no 'done' event found. Tail: {text[-300:]}"
    except Exception as e:
        return f"run_sweep error: {e}"


# ─── Tool 5: get certificate ────────────────────────────────────────────
@mcp.tool()
def verifyai_get_certificate(account: str, workflow: str, fmt: str = "text") -> str:
    """Fetch the latest signed Ed25519 attestation certificate for a workflow.

    Returns the engraved certificate in the requested format.
    Certificate is anchored to the Darwin Agentic Cloud substrate keylist at
    darwin-agentic-cloud.fly.dev/.well-known/substrate-keys.json.

    account: account ID
    workflow: workflow ID
    fmt: 'text' (plain), 'ansi' (terminal colors), 'html' (web)
    """
    if fmt not in ("text", "ansi", "html"):
        return f"fmt must be one of: text, ansi, html (got {fmt!r})"
    try:
        url = (
            f"{MODAL_BASE}-certificate.modal.run"
            f"?account_id={urllib.parse.quote(account)}"
            f"&workflow_id={urllib.parse.quote(workflow)}"
            f"&format={fmt}"
        )
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return f"certificate fetch failed: HTTP {e.code}"
    except Exception as e:
        return f"get_certificate error: {e}"


# ─── Tool 6: Splunk MCP Gateway tool discovery ──────────────────────────
@mcp.tool()
async def verifyai_splunk_list_tools() -> str:
    """List tools available on the Splunk Observability MCP Gateway.

    Demonstrates the Path C composition: this VerifyAI MCP server is itself
    an MCP CLIENT to Splunk's hosted MCP Gateway over streamable HTTP.
    Opens a session, performs MCP handshake, lists tools, returns them.
    """
    url = _splunk_mcp_url()
    out_header = f"Splunk MCP Gateway @ {url}\nRealm: {SPLUNK_REALM}"

    async def list_tools_inner(session: ClientSession):
        result = await session.list_tools()
        return result.tools

    ok, result = await _splunk_mcp_call(list_tools_inner)
    if not ok:
        return f"{out_header}\n\nConnection failed: {result}"

    tools = result
    lines = [out_header, f"Available tools ({len(tools)}):", ""]
    for t in tools:
        lines.append(f"  - {t.name}")
        if t.description:
            desc = " ".join(t.description.split())[:160]
            lines.append(f"      {desc}")
    return "\n".join(lines)


# ─── Tool 7: Splunk MCP Gateway schema introspection ────────────────────
@mcp.tool()
async def verifyai_splunk_describe_tool(tool_name: str) -> str:
    """Return the input schema for a specific tool exposed by Splunk MCP Gateway.

    Useful for understanding what arguments a Splunk o11y tool expects.
    Example: verifyai_splunk_describe_tool('o11y_execute_signalflow_program')
    """
    async def describe_inner(session: ClientSession):
        result = await session.list_tools()
        for t in result.tools:
            if t.name == tool_name:
                return {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.inputSchema,
                }
        return {"_not_found": True, "available": [t.name for t in result.tools]}

    ok, result = await _splunk_mcp_call(describe_inner)
    if not ok:
        return f"Gateway connection failed: {result}"
    if result.get("_not_found"):
        return f"Tool '{tool_name}' not found. Available: {result['available']}"
    return (
        f"Tool: {result['name']}\n"
        f"Description: {result['description']}\n\n"
        f"Input schema:\n{json.dumps(result['inputSchema'], indent=2)}"
    )


# ─── Tool 8: Adversarial sweep (DeepTeam via Modal) ─────────────────────
@mcp.tool()
async def verifyai_run_adversarial_sweep(
    account_id: str,
    workflow_id: str,
    framework: str = "GLBA Safeguards Rule",
    agent_role: str = "regulated financial assistant",
    categories: str = "prompt_injection,pii_leakage",
) -> str:
    """Run an adversarial determinism sweep against the target agent.

    Uses DeepTeam to generate prompt-injection, PII-leakage, and jailbreak
    probes mapped to the named compliance framework, scores them, and
    pushes results to Splunk Observability Cloud as verifyai.adversarial.*
    metrics (pass_rate, probe_count, blocked_count, leaked_count).

    Designed for drop-in compatibility with Splunk Hosted Models
    (Foundation-sec) when accessible to Observability Cloud Free Edition.

    Categories (comma-separated): prompt_injection, pii_leakage,
    excessive_agency, tool_misuse, jailbreak, bias.
    """
    cat_list = [c.strip() for c in categories.split(",") if c.strip()]
    payload = {
        "spec": {
            "account_id": account_id,
            "workflow_id": workflow_id,
            "framework": framework,
            "agent_role": agent_role,
            "deepteam_categories": cat_list,
        }
    }
    url = "https://vje013--verifyai-backend-run-deepteam.modal.run"

    findings = []
    done_event = None
    last_status = None
    event_count = 0
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, read=None)) as client:
            async with client.stream(
                "POST", url,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    return f"Modal returned HTTP {resp.status_code}: {body[:300]!r}"

                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    try:
                        evt = json.loads(data_str)
                    except Exception:
                        continue
                    event_count += 1
                    etype = evt.get("type", "")
                    edata = evt.get("data")
                    if etype == "finding":
                        findings.append(edata)
                    elif etype == "status":
                        last_status = str(edata)[:200]
                    elif etype == "done":
                        done_event = edata
                        break
                    elif etype == "error":
                        return f"Sweep error: {edata}"
    except Exception as e:
        return f"Stream error: {type(e).__name__}: {e} (events={event_count}, last_status={last_status!r}, findings={len(findings)})"

    if not done_event:
        return (
            f"Sweep did not complete (events seen: {event_count}, "
            f"findings collected: {len(findings)}, last status: {last_status!r})"
        )

    pass_rate = done_event.get("pass_rate", 0.0)
    total = done_event.get("total", 0)
    controls = done_event.get("controls_tested", [])

    # Group findings by vulnerability for breakdown
    by_vuln = {}
    for f in findings:
        v = f.get("vulnerability", "unknown")
        by_vuln.setdefault(v, {"total": 0, "blocked": 0})
        by_vuln[v]["total"] += 1
        if f.get("passed"):
            by_vuln[v]["blocked"] += 1

    lines = [
        f"Adversarial sweep: {account_id} / {workflow_id}",
        f"Framework: {framework}",
        f"Pass rate: {pass_rate:.1%}  ({sum(1 for f in findings if f.get('passed'))}/{total} blocked)",
        "",
        "By vulnerability class:",
    ]
    for v, counts in sorted(by_vuln.items()):
        rate = counts["blocked"] / counts["total"] if counts["total"] else 0
        bar = "█" * int(rate * 20)
        lines.append(f"  {v[:30]:30}  {counts['blocked']}/{counts['total']}  {bar}")

    lines.append("")
    lines.append(f"Controls tested: {', '.join(controls[:6])}{'...' if len(controls) > 6 else ''}")
    lines.append("")
    lines.append("Metrics pushed to Splunk:")
    lines.append("  verifyai.adversarial.pass_rate (gauge)")
    lines.append("  verifyai.adversarial.probe_count, .blocked_count, .leaked_count (counters)")
    lines.append(f"  dimensions: account={account_id}, workflow={workflow_id}, framework={framework.replace(' ', '_')}, source=adversarial")

    return "\n".join(lines)


# ─── Run ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run()
