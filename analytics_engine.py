"""
analytics_engine.py — Real-Time Streaming Analytics (ISRO Hackathon Version)

Key fixes vs previous version:
1. Per-link-type latency threshold — access/overlay links have higher base latency
   so healthy links score exactly 0.0, not 8.0
2. score=0.0 when no signals fire — no phantom scores
3. BGP false-positive threshold raised: 5 flaps (was 3), 3 withdrawals (was 2)
4. Added health_status: CRITICAL / DEGRADED / WATCH / NORMAL
5. Added util_trend_dir: RISING / STABLE / FALLING
6. Incident logger — appends to data/incidents.jsonl for RAG past-incidents
"""

import json, math, threading
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

WINDOW_SIZE   = 10
ALERT_THRESH  = 60
PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
INCIDENTS_PATH = Path("data/incidents.jsonl")

# Latency-to-BW ratio threshold per link type
# Access links have 15-22ms base latency on 100Mbps — that is NORMAL
# Core links have 8-12ms on 1Gbps — a bit disproportionate but acceptable
# Only flag latency when it's significantly above the per-type baseline
LATENCY_BW_RATIO = {
    "mpls_core":     0.05,
    "mpls_access":   0.30,   # 22ms / 100Mbps = 0.22 — threshold above this
    "sdwan_overlay": 0.80,   # 35ms / 50Mbps  = 0.70 — threshold above this
}


class RollingBuffer:
    def __init__(self, maxlen=WINDOW_SIZE):
        self.util   = deque(maxlen=maxlen)
        self.lat    = deque(maxlen=maxlen)
        self.jitter = deque(maxlen=maxlen)
        self.loss   = deque(maxlen=maxlen)

    def push(self, row: dict):
        self.util.append(float(row["util_out_pct"]))
        self.lat.append(float(row["latency_ms"]))
        self.jitter.append(float(row["jitter_ms"]))
        self.loss.append(float(row["packet_loss_pct"]))

    def ready(self) -> bool:
        return len(self.util) >= WINDOW_SIZE


def _trend(lst):
    lst = list(lst)
    return (lst[-1] - lst[0]) / len(lst) if len(lst) >= 2 else 0.0

def _mean(lst): return sum(lst) / len(lst) if lst else 0.0

def _std(lst):
    m = _mean(lst)
    return math.sqrt(sum((x-m)**2 for x in lst) / len(lst)) if lst else 0.0

def extract_features_live(buf, row, link):
    utils = list(buf.util); lats = list(buf.lat)
    jits  = list(buf.jitter); loss = list(buf.loss)
    return {
        "link":                  link,
        "site":                  row["site"],
        "peer":                  row["peer_site"],
        "link_type":             row["link_type"],
        "util_mean":             _mean(utils),
        "util_std":              _std(utils),
        "util_trend":            _trend(utils),
        "util_max":              max(utils),
        "lat_mean":              _mean(lats),
        "lat_trend":             _trend(lats),
        "jit_mean":              _mean(jits),
        "jit_trend":             _trend(jits),
        "loss_mean":             _mean(loss),
        "loss_max":              max(loss),
        "consecutive_high_util": sum(1 for u in utils[-5:] if u > 75),
        "bandwidth_mbps":        int(row["bandwidth_mbps"]),
        "fault_type":            row["fault_type"],
        "timestamp":             row["timestamp"],
    }


class RuleBasedPredictor:
    def score(self, feat: dict) -> dict:
        score   = 0.0
        reasons = []
        lt      = feat["link_type"]

        if feat["util_mean"] > 80:
            score += 30; reasons.append(f"High avg util {feat['util_mean']:.1f}%")
        if feat["util_trend"] > 1.5:
            score += 20; reasons.append(f"Rising util trend +{feat['util_trend']:.2f}%/tick")
        if feat["util_max"] > 90:
            score += 15; reasons.append(f"Peak util spike {feat['util_max']:.1f}%")
        if feat["consecutive_high_util"] >= 4:
            score += 15; reasons.append("4+ consecutive high-util ticks")
        if feat["lat_trend"] > 2:
            score += 10; reasons.append(f"Latency trending +{feat['lat_trend']:.2f} ms/tick")

        # Per-link-type latency threshold — prevents 8.0 on healthy access links
        lat_ratio = LATENCY_BW_RATIO.get(lt, 0.30)
        if feat["lat_mean"] > feat["bandwidth_mbps"] * lat_ratio:
            score += 8; reasons.append("Latency abnormally high for link type")

        if feat["loss_max"] > 0.5:
            score += 15; reasons.append(f"Packet loss spike {feat['loss_max']:.2f}%")
        if feat["jit_trend"] > 0.3:
            score += 7;  reasons.append("Jitter trending upward")

        # If NO signals fired, score is exactly 0 — no phantom scores
        if not reasons:
            score = 0.0

        score = min(100.0, score)

        tti = max(1, int((90 - feat["util_mean"]) / max(0.1, feat["util_trend"]))) \
              if feat["util_trend"] > 0 and feat["util_mean"] < 95 else -1

        fault_type = \
            "mpls_underlay_failure" if feat["loss_max"] > 2.0 else \
            "congestion_buildup"    if feat["util_trend"] > 2.0 and feat["util_mean"] > 75 else \
            "tunnel_degradation"    if feat["jit_trend"] > 0.5 else \
            "none"

        health = \
            "CRITICAL" if score >= 75 else \
            "DEGRADED" if score >= 50 else \
            "WATCH"    if score >= 25 else \
            "NORMAL"

        ut = feat["util_trend"]
        trend_dir = "RISING" if ut > 0.5 else ("FALLING" if ut < -0.5 else "STABLE")

        return {
            "link":                 feat["link"],
            "site":                 feat["site"],
            "peer":                 feat["peer"],
            "link_type":            lt,
            "fault_probability":    round(score / 100, 3),
            "risk_score":           round(score, 1),
            "fault_type":           fault_type,
            "minutes_to_impact":    tti,
            "contributing_signals": reasons,
            "util_mean":            round(feat["util_mean"], 1),
            "lat_mean":             round(feat["lat_mean"], 1),
            "loss_max":             round(feat["loss_max"], 3),
            "health_status":        health,
            "util_trend_dir":       trend_dir,
            "timestamp":            feat["timestamp"],
        }


class BGPAnomalyDetector:
    def __init__(self): self._site_events = defaultdict(list)

    def push(self, bgp_rows):
        for r in bgp_rows:
            self._site_events[r["site"]].append(r)
            if len(self._site_events[r["site"]]) > 40:
                self._site_events[r["site"]] = self._site_events[r["site"]][-40:]

    def alerts(self):
        out = []
        for site, events in self._site_events.items():
            recent = events[-20:]
            flaps  = sum(1 for e in recent if e["event_type"] == "flap")
            withs  = sum(1 for e in recent if e["event_type"] == "withdrawn")
            rate   = sum(1 for e in recent if int(e["is_anomaly"])) / len(recent)
            # Raised thresholds to avoid false positives on normal BGP keepalives
            if flaps >= 5 or withs >= 3 or rate > 0.4:
                out.append({
                    "site": site, "bgp_flaps": flaps,
                    "bgp_withdrawals": withs,
                    "anomaly_rate": round(rate, 2),
                    "risk": "HIGH" if flaps >= 8 else "MEDIUM",
                    "timestamp": events[-1]["timestamp"],
                })
        return out


class TunnelHealthScorer:
    def __init__(self): self._tunnel_rows = defaultdict(list)

    def push(self, tunnel_rows):
        for r in tunnel_rows:
            key = f"{r['src_site']}--{r['dst_site']}"
            self._tunnel_rows[key].append(r)
            if len(self._tunnel_rows[key]) > 60:
                self._tunnel_rows[key] = self._tunnel_rows[key][-60:]

    def scores(self):
        out = []
        for link, rows in self._tunnel_rows.items():
            recent    = rows[-30:]
            down_pct  = sum(1 for r in recent if r["tunnel_state"] == "down")    / len(recent) * 100
            deg_pct   = sum(1 for r in recent if r["tunnel_state"] == "degraded") / len(recent) * 100
            avg_rekey = sum(int(r["rekey_failures"]) for r in recent) / len(recent)
            avg_esp   = sum(int(r["esp_errors"])     for r in recent) / len(recent)
            health    = max(0, min(100, 100 - down_pct*2 - deg_pct - avg_rekey*5 - avg_esp*0.5))
            out.append({
                "tunnel": link, "health_score": round(health, 1),
                "down_pct": round(down_pct, 1), "degrad_pct": round(deg_pct, 1),
                "avg_rekey_failures": round(avg_rekey, 2),
                "avg_esp_errors": round(avg_esp, 2),
                "status": "CRITICAL" if health < 60 else ("DEGRADED" if health < 85 else "OK"),
                "timestamp": rows[-1]["timestamp"],
            })
        return out


def _log_incident(alert: dict):
    """Append high-risk alerts to incidents.jsonl for RAG past-incidents."""
    INCIDENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp":   alert["timestamp"],
        "link":        alert["link"],
        "link_type":   alert["link_type"],
        "risk_score":  alert["risk_score"],
        "fault_type":  alert["fault_type"],
        "signals":     alert["contributing_signals"],
        "util_mean":   alert["util_mean"],
        "loss_max":    alert["loss_max"],
    }
    with open(INCIDENTS_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")


class StreamingAnalyticsEngine:
    def __init__(self, alert_callback=None):
        self._buffers       = defaultdict(RollingBuffer)
        self._predictor     = RuleBasedPredictor()
        self._bgp           = BGPAnomalyDetector()
        self._tunnel        = TunnelHealthScorer()
        self._lock          = threading.Lock()
        self.alert_callback = alert_callback
        self._last_results  = {}
        self._logged_alerts = set()   # avoid logging same link repeatedly

    def process_tick(self, tick_data: dict):
        with self._lock:
            iface_rows  = tick_data["interface_rows"]
            bgp_rows    = tick_data["bgp_rows"]
            tunnel_rows = tick_data["tunnel_rows"]

            link_alerts = []
            for row in iface_rows:
                link = f"{row['site']}--{row['peer_site']}"
                buf  = self._buffers[link]
                buf.push(row)
                if not buf.ready():
                    continue
                feat   = extract_features_live(buf, row, link)
                scored = self._predictor.score(feat)
                link_alerts.append(scored)

                # Log new high-risk alerts to incidents file
                if scored["risk_score"] >= 60 and link not in self._logged_alerts:
                    _log_incident(scored)
                    self._logged_alerts.add(link)
                elif scored["risk_score"] < 30:
                    self._logged_alerts.discard(link)  # reset when link recovers

            link_alerts.sort(key=lambda x: x["risk_score"], reverse=True)

            self._bgp.push(bgp_rows)
            self._tunnel.push(tunnel_rows)
            bgp_alerts    = self._bgp.alerts()
            tunnel_scores = self._tunnel.scores()

            results = {
                "generated_at":           tick_data["timestamp"],
                "tick":                   tick_data["tick"],
                "mode":                   "realtime",
                "link_fault_predictions": link_alerts,
                "bgp_anomalies":          bgp_alerts,
                "tunnel_health":          tunnel_scores,
                "active_faults":          tick_data.get("active_faults", {}),
                "summary": {
                    "high_risk_links":   sum(1 for a in link_alerts if a["risk_score"] >= 60),
                    "medium_risk_links": sum(1 for a in link_alerts if 30 <= a["risk_score"] < 60),
                    "watch_links":       sum(1 for a in link_alerts if 0 < a["risk_score"] < 30),
                    "normal_links":      sum(1 for a in link_alerts if a["risk_score"] == 0),
                    "bgp_anomaly_sites": len(bgp_alerts),
                    "degraded_tunnels":  sum(1 for t in tunnel_scores if t["status"] != "OK"),
                }
            }

            with open(PROCESSED_DIR / "analytics_results.json", "w") as f:
                json.dump(results, f)
            self._last_results = results

            if self.alert_callback:
                high = [a for a in link_alerts if a["risk_score"] >= ALERT_THRESH]
                if high:
                    self.alert_callback(results, high)

    def latest(self) -> dict:
        with self._lock:
            return self._last_results
