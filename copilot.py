"""
copilot.py — Real-Time NOC Copilot with two-level alerting

TWO-LEVEL ALERT SYSTEM:
  Risk 30–59 → [WARNING]  precursor detected, fault is building up, NOC should watch
  Risk 60+   → [ALERT]    fault is active/imminent, LLM fires with full analysis

This means the NOC gets warned WHILE the fault is ramping,
not only after it has fully developed.
"""

import json, sys, os, threading, time, urllib.request, urllib.error, importlib.util
from pathlib import Path
from datetime import datetime

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("rag_pipeline", os.path.join(_here, "rag_pipeline.py"))
_rm   = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_rm)
build_rag_index = _rm.build_rag_index

OLLAMA_BASE_URL  = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
ANALYTICS_PATH   = Path("data/processed/analytics_results.json")
INCIDENTS_PATH   = Path("data/incidents.jsonl")

WARN_THRESHOLD   = 30    # fires a text warning — no LLM needed, instant
ALERT_THRESHOLD  = 60    # fires full LLM analysis
ALERT_COOLDOWN   = 120   # seconds before same link can alert again
WARN_COOLDOWN    = 60    # seconds before same link can warn again

SYSTEM_PROMPT = """You are an expert NOC (Network Operations Center) AI copilot for an enterprise SD-WAN/MPLS network operating in an air-gapped environment.

When given a network alert, respond in plain operator language. Write as if briefing a NOC engineer verbally.

Structure your response exactly like this:

PREDICTED ISSUE: [one sentence — what service or link will fail and how]

CONFIDENCE: [HIGH/MEDIUM/LOW] [percentage] — [one sentence why]

ROOT CAUSE: [specific technical cause — reference the link name, protocol, and symptom]

AFFECTED SCOPE: [which sites, VRFs, and SLA classes — GOLD/SILVER/BRONZE impact]

TIME TO IMPACT: [estimated minutes before SLA breach, or "imminent" if under 5 minutes]

ACTIONS:
1. [CLI command]
2. [step]
3. [step referencing the runbook ID provided]
4. [escalation step]

WATCH: [two or three specific metrics with exact thresholds to monitor next]

Do not say I or you. Write like a system alert. Only use runbook IDs explicitly given to you."""


def _http_post(url, payload, timeout=120):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def call_ollama(prompt: str) -> str:
    try:
        resp = _http_post(f"{OLLAMA_BASE_URL}/api/chat", {
            "model": OLLAMA_MODEL, "stream": False,
            "options": {"temperature": 0.1, "top_p": 0.9, "num_predict": 600},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        })
        return resp["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return f"[ERROR] {e}"
    except Exception as e:
        return f"[ERROR] {e}"
    try:
        resp = _http_post(f"{OLLAMA_BASE_URL}/api/generate", {
            "model": OLLAMA_MODEL, "stream": False,
            "prompt": f"[INST] {SYSTEM_PROMPT}\n\n{prompt} [/INST]",
            "options": {"temperature": 0.1, "num_predict": 600},
        })
        return resp.get("response", "").strip()
    except Exception as e:
        return f"[ERROR] Both endpoints failed: {e}"


def _build_rag_query(alert: dict) -> str:
    signals   = alert.get("contributing_signals", [])
    link_type = alert.get("link_type", "")
    loss      = alert.get("loss_max", 0)

    parts = []
    if any("util" in s.lower() for s in signals):
        parts.append("high utilization congestion bandwidth saturation")
    if any("loss" in s.lower() for s in signals) or loss > 1:
        parts.append("packet loss mpls underlay failure")
    if any("jitter" in s.lower() for s in signals):
        parts.append("jitter tunnel degradation ipsec rekey")
    if any("latency" in s.lower() for s in signals):
        parts.append("latency rising bgp instability")

    if "mpls_access" in link_type:
        parts.append("mpls access hub spoke link")
    elif "mpls_core" in link_type:
        parts.append("mpls core underlay failure")
    elif "sdwan" in link_type:
        parts.append("sdwan overlay tunnel ipsec")

    return " ".join(parts) if parts else "network link degradation"


def _load_past_incidents(top_n: int = 3) -> str:
    """Load recent incidents from incidents.jsonl for RAG context."""
    if not INCIDENTS_PATH.exists():
        return "No past incidents on record."
    lines = []
    try:
        with open(INCIDENTS_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(json.loads(line))
    except Exception:
        return "No past incidents on record."

    if not lines:
        return "No past incidents on record."

    # Most recent first
    recent = lines[-top_n:][::-1]
    text = "PAST INCIDENTS (most recent first):\n"
    for inc in recent:
        text += (f"  {inc.get('timestamp','')[:19]}  {inc.get('link','')}  "
                 f"risk={inc.get('risk_score',0)}  fault={inc.get('fault_type','')}  "
                 f"signals={', '.join(inc.get('signals',[]))}\n")
    return text


def build_alert_prompt(alert: dict, rag_docs: list, analytics: dict) -> str:
    docs_text = ""
    for d in rag_docs:
        docs_text += f"\n[{d['id']} — {d['title']}]\n{d['content'].strip()}\n"

    past = _load_past_incidents()
    s    = analytics["summary"]
    tick = analytics.get("tick", "?")
    faults = analytics.get("active_faults", {})
    signals_text = "\n".join(f"  • {sig}" for sig in alert.get("contributing_signals", []))

    return f"""LIVE NETWORK ALERT — tick={tick}  time={analytics['generated_at'][:19]}
Network: DC1 (Hyderabad) → HUB1 (Mumbai) / HUB2 (Bangalore) → BRANCH1-5
Active faults: {faults or 'none'}
Network summary: {s['high_risk_links']} high-risk, {s['bgp_anomaly_sites']} BGP anomalies, {s['degraded_tunnels']} degraded tunnels

ALERT DETAILS:
Link: {alert['link']}  |  Type: {alert['link_type']}
Risk score: {alert['risk_score']}/100  |  Health: {alert.get('health_status','?')}  |  Trend: {alert.get('util_trend_dir','?')}
Fault probability: {alert['fault_probability']*100:.0f}%
Utilization (avg): {alert['util_mean']}%
Latency (avg): {alert['lat_mean']} ms
Max packet loss: {alert['loss_max']}%
Minutes to SLA breach: {alert['minutes_to_impact'] if alert['minutes_to_impact'] > 0 else 'unknown'}

Signals detected (why risk is elevated):
{signals_text}

{past}

RETRIEVED RUNBOOKS (use ONLY these IDs):
{docs_text}

Provide your NOC analysis now. Reference only the runbook IDs listed above."""


def build_query_prompt(query: str, rag_docs: list, analytics: dict) -> str:
    docs_text = "\n".join(
        f"\n[{d['id']} — {d['title']}]\n{d['content'].strip()}" for d in rag_docs
    )
    top5 = analytics.get("link_fault_predictions", [])[:5]

    # Tell LLM if network is clean — prevents hallucinated problems
    if all(a["risk_score"] == 0 for a in top5):
        network_state = "Network is currently HEALTHY — all links at risk=0, no active faults."
    else:
        network_state = "\n".join(
            f"  {a['link']:<28} risk={a['risk_score']:5.1f}  "
            f"status={a.get('health_status','?')}  "
            f"trend={a.get('util_trend_dir','?')}  "
            f"{', '.join(a['contributing_signals'][:2])}"
            for a in top5 if a["risk_score"] > 0
        ) or "All links normal."

    past = _load_past_incidents()

    return f"""OPERATOR QUERY — tick={analytics.get('tick','?')}

CURRENT NETWORK STATE:
{network_state}

Active faults: {analytics.get('active_faults') or 'none'}

{past}

RELEVANT RUNBOOKS:
{docs_text}

Operator asks: {query}

Answer in plain language. If network is healthy, say so clearly. Only use runbook IDs listed above."""


class RealtimeCopilot:
    def __init__(self):
        self.rag_store    = build_rag_index()
        self._alerted     = {}   # link → last ALERT timestamp
        self._warned      = {}   # link → last WARNING timestamp
        self._last_tick   = -1
        self.RISK_THRESHOLD = ALERT_THRESHOLD  # used by run_pipeline patched check

    def _since(self, store: dict, link: str) -> float:
        return time.time() - store.get(link, 0)

    def _load_analytics(self):
        if not ANALYTICS_PATH.exists():
            return None
        try:
            with open(ANALYTICS_PATH) as f:
                return json.load(f)
        except Exception:
            return None

    def check_and_alert(self):
        analytics = self._load_analytics()
        if not analytics:
            return

        tick = analytics.get("tick", 0)
        if tick == self._last_tick:
            return
        self._last_tick = tick

        alerts = analytics.get("link_fault_predictions", [])

        for alert in alerts:
            risk = alert["risk_score"]
            link = alert["link"]

            # ── Level 1: WARNING (30-59) — instant, no LLM ──────────────────
            if WARN_THRESHOLD <= risk < ALERT_THRESHOLD:
                if self._since(self._warned, link) > WARN_COOLDOWN:
                    self._warned[link] = time.time()
                    tti = alert.get("minutes_to_impact", -1)
                    tti_str = f"{tti} min" if tti > 0 else "unknown"
                    print(f"\n⚠  [WARNING  tick={tick}  {datetime.now().strftime('%H:%M:%S')}]"
                          f"  {link}  Risk={risk}/100  "
                          f"trend={alert.get('util_trend_dir','?')}  "
                          f"tti={tti_str}")
                    print(f"   Signals: {', '.join(alert['contributing_signals'])}")
                    print(f"   → Fault is BUILDING UP. Monitor closely. LLM fires at risk≥60.\n")

            # ── Level 2: ALERT (60+) — full LLM analysis ────────────────────
            elif risk >= ALERT_THRESHOLD:
                if self._since(self._alerted, link) > ALERT_COOLDOWN:
                    self._alerted[link] = time.time()

                    print(f"\n{'='*64}")
                    print(f"🔴 [ALERT  tick={tick}  {datetime.now().strftime('%H:%M:%S')}]")
                    print(f"   {link}  Risk={risk}/100  "
                          f"Health={alert.get('health_status','?')}  "
                          f"Trend={alert.get('util_trend_dir','?')}")
                    print(f"   Signals: {', '.join(alert['contributing_signals'])}")
                    print(f"{'='*64}")

                    rag_query = _build_rag_query(alert)
                    rag_docs  = self.rag_store.search(rag_query, top_k=2)
                    print(f"   [RAG] Retrieved: "
                          f"{', '.join(d['id']+' ('+d['title']+')' for d in rag_docs)}")
                    print(f"   [LLM] Querying {OLLAMA_MODEL}...\n")

                    response = call_ollama(build_alert_prompt(alert, rag_docs, analytics))
                    print(response)
                    print(f"\n{'─'*64}\n")

        # BGP HIGH alerts — no LLM, instant text
        for b in analytics.get("bgp_anomalies", []):
            if b["risk"] == "HIGH":
                print(f"  [BGP ALERT tick={tick}] {b['site']}: "
                      f"{b['bgp_flaps']} flaps — "
                      f"run: show bgp summary | inc {b['site']}")

    def query(self, text: str):
        analytics = self._load_analytics()
        if not analytics:
            print("[!] No analytics data yet.")
            return
        rag_docs = self.rag_store.search(text, top_k=3)
        print(f"\n[RAG] Retrieved: "
              f"{', '.join(d['id']+' ('+d['title']+')' for d in rag_docs)}")
        print(f"[LLM] Querying {OLLAMA_MODEL}...\n")
        print(call_ollama(build_query_prompt(text, rag_docs, analytics)))
        print()

    def watch_loop(self, poll_interval: float = 3.0):
        print(f"[COPILOT] Two-level alerting: "
              f"WARNING at {WARN_THRESHOLD}/100 (instant), "
              f"ALERT at {ALERT_THRESHOLD}/100 (LLM) ...")
        while True:
            try:
                self.check_and_alert()
            except Exception as e:
                print(f"[COPILOT] Error: {e}")
            time.sleep(poll_interval)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", type=str)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--watch", action="store_true")
    args = parser.parse_args()

    cop = RealtimeCopilot()

    if args.check:
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as r:
                models = [m["name"] for m in json.loads(r.read()).get("models", [])]
            print(f"[+] Ollama running. Models: {models}")
        except Exception as e:
            print(f"[!] Ollama not reachable: {e}")
    elif args.query:
        cop.query(args.query)
    elif args.watch:
        try:
            cop.watch_loop()
        except KeyboardInterrupt:
            print("\n[COPILOT] Stopped.")
    else:
        cop.check_and_alert()
