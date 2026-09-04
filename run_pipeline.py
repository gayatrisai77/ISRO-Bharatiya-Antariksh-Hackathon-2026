"""
run_pipeline.py — Real-Time Master Orchestrator (Clean Terminal Version)

What changed vs previous version:
  - LLM output is buffered and printed ONLY between noc> prompts, not mid-typing
  - Added --no-llm flag so you can watch scoring without waiting 90s per alert
  - Added --threshold flag so you control when LLM fires
  - 'status' command now shows a clean table
  - Seeding progress is quieter

Usage:
    python3 run_pipeline.py                        # full pipeline, LLM on
    python3 run_pipeline.py --no-llm               # scoring only, instant feedback
    python3 run_pipeline.py --ticks 5              # tick every 5s (default)
    python3 run_pipeline.py --threshold 60         # only alert when risk >= 60

Commands while running:
    status                          — show all link risk scores right now
    inject congestion HUB1--BRANCH1 — inject a fault on a link
    inject mpls_fail DC1--HUB1
    inject bgp_flap HUB1--BRANCH2
    inject tunnel_degrade DC1--BRANCH1
    inject controller_drift HUB2--BRANCH4
    query what is causing high latency on HUB1
    quit
"""

import sys, os, argparse, threading, time, importlib.util, json, queue
from pathlib import Path
from datetime import datetime

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Shared print queue so background threads don't stomp on noc> prompt ───────

_print_queue = queue.Queue()

def _background_print(msg: str):
    """Called by background threads — queues message for main thread to print."""
    _print_queue.put(msg)

def _flush_prints():
    """Drain the queue. SIM logs printed dimly, NOC alerts printed prominently."""
    msgs = []
    while not _print_queue.empty():
        try:
            msgs.append(_print_queue.get_nowait())
        except queue.Empty:
            break

    if not msgs:
        return False

    sim_logs = [m for m in msgs if m.strip().startswith("[SIM]")]
    noc_msgs = [m for m in msgs if not m.strip().startswith("[SIM]")]

    # Print SIM logs quietly in a collapsed block
    if sim_logs:
        print(f"\n  ┌─ internal ({'─'*40})")
        for m in sim_logs:
            print(f"  │  {m.strip()}")
        print(f"  └{'─'*44}")

    # Print NOC messages prominently with clear separation
    for m in noc_msgs:
        print(m)

    return True


# ── Patched copilot that uses the print queue ─────────────────────────────────

def make_patched_copilot(cop_mod, no_llm: bool, threshold: int):
    """
    Returns a RealtimeCopilot that uses the two-level alert system:
      WARNING (instant, no LLM) at risk >= 30  — fault is building up
      ALERT   (full LLM)        at risk >= 60  — fault is active/imminent
    Output goes through _background_print so it never stomps the noc> prompt.
    """
    # Disable LLM inside copilot if --no-llm flag set
    if no_llm:
        original_ollama = cop_mod.call_ollama
        cop_mod.call_ollama = lambda prompt: "[LLM skipped — run without --no-llm to enable]"

    # Wrap check_and_alert so all prints go through the queue
    original_check = cop_mod.RealtimeCopilot.check_and_alert

    def patched_check(self):
        import io, sys
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            original_check(self)
        finally:
            sys.stdout = old_stdout
        output = buf.getvalue()
        if output.strip():
            _background_print(output.rstrip())

    cop_mod.RealtimeCopilot.check_and_alert = patched_check
    cop = cop_mod.RealtimeCopilot()
    return cop


def run_realtime(tick_interval: float, batch_ticks: int, no_llm: bool, threshold: int):
    topo_mod = _load("topology",         "topology.py")
    eng_mod  = _load("analytics_engine", "analytics_engine.py")
    cop_mod  = _load("copilot",          "copilot.py")

    # Override threshold in copilot module
    cop_mod.RISK_THRESHOLD = threshold
    cop_mod.ALERT_COOLDOWN = 120

    # Build copilot with patched output
    cop    = make_patched_copilot(cop_mod, no_llm, threshold)
    engine = eng_mod.StreamingAnalyticsEngine(alert_callback=None)

    # Batch seed rolling windows
    if batch_ticks > 0:
        print(f"[*] Seeding {batch_ticks} ticks to warm up scoring windows...")
        seed_sim = topo_mod.NetworkSimulator(
            tick_callback=engine.process_tick,
            tick_interval=0,
            log_callback=lambda msg: None,  # suppress seed logs
        )
        for i in range(batch_ticks):
            td = seed_sim._run_tick()
            seed_sim.tick_count += 1
            engine.process_tick(td)
        print(f"[*] Done — windows ready.\n")

    sim = topo_mod.NetworkSimulator(
        tick_callback=engine.process_tick,
        tick_interval=tick_interval,
        log_callback=_background_print,   # SIM logs go to queue, not direct stdout
    )

    sim_thread = threading.Thread(target=sim.stream, daemon=True, name="simulator")
    cop_thread = threading.Thread(target=cop.watch_loop, args=(3.0,), daemon=True, name="copilot")

    print("="*64)
    print("  REAL-TIME NOC COPILOT — SD-WAN/MPLS Air-Gapped")
    print("="*64)
    print(f"  Tick interval  : {tick_interval}s")
    print(f"  Alert threshold: {threshold}/100")
    print(f"  LLM model      : {cop_mod.OLLAMA_MODEL}")
    print(f"  LLM calls      : {'DISABLED (--no-llm)' if no_llm else 'ENABLED (~60-90s per alert on Intel Mac)'}")
    print("="*64)
    print("\n  Commands:")
    print("    status                          — live risk scores for all links")
    print("    inject <scenario> <link>        — inject a fault scenario")
    print("    query <your question>           — ask the copilot anything")
    print("    quit                            — stop")
    print("\n  Scenarios: congestion, mpls_fail, bgp_flap, tunnel_degrade, controller_drift")
    print("  Example:   inject mpls_fail DC1--HUB1")
    print("\n  TIP: Use --no-llm for fast scoring without waiting for LLM responses.")
    print("  TIP: Alerts print between your commands — just press Enter to re-show noc>")
    print()

    FAULT_MAP = {
        "congestion":       "congestion_buildup",
        "bgp_flap":         "bgp_route_flap",
        "mpls_fail":        "mpls_underlay_failure",
        "tunnel_degrade":   "tunnel_degradation",
        "controller_drift": "controller_misconfig",
    }

    sim_thread.start()
    time.sleep(0.5)
    cop_thread.start()

    # ── Main REPL ─────────────────────────────────────────────────────────────
    while True:
        # Print any queued background messages first
        _flush_prints()

        try:
            cmd = input("noc> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down.")
            sim.stop()
            break

        # Flush again after input (alerts may have arrived while you were typing)
        _flush_prints()

        if not cmd:
            continue

        parts = cmd.split(maxsplit=2)
        verb  = parts[0].lower()

        if verb == "quit":
            sim.stop()
            break

        elif verb == "inject":
            if len(parts) < 3:
                print("  Usage: inject <scenario> <link>")
                print(f"  Scenarios: {', '.join(FAULT_MAP.keys())}")
                print("  Links: DC1--HUB1, DC1--HUB2, HUB1--HUB2, HUB1--BRANCH1,")
                print("         HUB1--BRANCH2, HUB1--BRANCH3, HUB2--BRANCH4, HUB2--BRANCH5")
                continue
            scenario_key = parts[1].lower()
            link         = parts[2]
            fault_name   = FAULT_MAP.get(scenario_key)
            if not fault_name:
                print(f"  Unknown scenario '{scenario_key}'. Choose: {', '.join(FAULT_MAP.keys())}")
                continue
            sim.inject_fault(link, fault_name)
            print(f"  [*] Injected '{fault_name}' on {link}.")
            print(f"  [*] Alert will appear within {int(tick_interval * 12)}s "
                  f"(need 10 ticks to build scoring window).")

        elif verb == "query":
            if len(parts) < 2:
                print("  Usage: query <your question>")
                continue
            query_text = " ".join(parts[1:])
            print(f"  [*] Querying RAG + LLM for: '{query_text}'")
            print(f"  [*] This takes ~60-90s on Intel Mac...")
            cop.query(query_text)

        elif verb == "status":
            analytics = engine.latest()
            if not analytics:
                print("  [*] No data yet — wait a few ticks.")
                continue

            tick = analytics.get("tick", "?")
            ts   = analytics.get("generated_at", "")[:19]
            s    = analytics["summary"]
            faults = analytics.get("active_faults") or "none"

            print(f"\n  ── STATUS  tick={tick}  {ts} ──────────────────────────────")
            print(f"  High-risk: {s['high_risk_links']}  "
                  f"BGP anomalies: {s['bgp_anomaly_sites']}  "
                  f"Degraded tunnels: {s['degraded_tunnels']}")
            print(f"  Active injected faults: {faults}")
            print()
            print(f"  {'Link':<28} {'Type':<16} {'Util%':>6} {'Loss%':>6} {'Risk':>6}  Fault")
            print(f"  {'─'*28} {'─'*16} {'─'*6} {'─'*6} {'─'*6}  {'─'*22}")

            for a in analytics.get("link_fault_predictions", []):
                risk = a["risk_score"]
                flag = " ← ALERT" if risk >= threshold else (" ← warn" if risk >= 30 else "")
                print(f"  {a['link']:<28} {a['link_type']:<16} "
                      f"{a['util_mean']:>5.1f}% {a['loss_max']:>5.3f}%  "
                      f"{risk:>5.1f}  {a['fault_type']}{flag}")
            print()

        else:
            print("  Commands: status | inject <scenario> <link> | query <text> | quit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-Time NOC Copilot")
    parser.add_argument("--ticks",      type=float, default=5.0,
                        help="Seconds per tick (default: 5)")
    parser.add_argument("--batch-sim",  type=int,   default=50,
                        help="Seed N ticks before going live (default: 50)")
    parser.add_argument("--threshold",  type=int,   default=60,
                        help="Risk score that triggers LLM alert (default: 60)")
    parser.add_argument("--no-llm",     action="store_true",
                        help="Disable LLM calls — scoring and dashboard only (fast mode)")
    args = parser.parse_args()

    run_realtime(
        tick_interval=args.ticks,
        batch_ticks=args.batch_sim,
        no_llm=args.no_llm,
        threshold=args.threshold,
    )
