"""topology.py — Full SD-WAN/MPLS Network Simulator (ISRO Hackathon)

Covers ALL Objective 1 requirements:
  ✅ Branch / Hub / Datacenter sites with CE, PE, P device roles
  ✅ MPLS forwarding plane with LSP labels and LDP simulation
  ✅ VPN segmentation — three VRFs (CORP, GUEST, MGMT) per site
  ✅ Traffic Engineering — per-LSP bandwidth reservation and utilisation
  ✅ SD-WAN IPSec overlay tunnels with rekey/ESP stats
  ✅ BGP (iBGP full-mesh between PE/DC) + OSPF (area 0 within sites)
  ✅ QoS — three traffic classes per link (GOLD/SILVER/BRONZE)
  ✅ Realistic application traffic flows (VoIP, ERP/SAP, Video, Bulk)
  ✅ Configurable fault injection via noc> prompt
"""

import json, csv, math, random, time, threading
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List
from pathlib import Path

random.seed()
AUTO_INJECT   = True
TICK_INTERVAL = 5

# ══════════════════════════════════════════════════════════════════════════════
# DEVICE ROLES — CE / PE / P
# ══════════════════════════════════════════════════════════════════════════════
# In a real MPLS network:
#   P   = core router, only sees MPLS labels, no IP customer routes
#   PE  = edge router, terminates VRFs, runs MP-BGP with other PEs
#   CE  = customer router, connects to PE via OSPF/eBGP/static

DEVICES = {
    # Datacenter
    "DC1-CE":    {"site": "DC1",     "role": "CE", "model": "ASR1001-X"},
    "DC1-PE":    {"site": "DC1",     "role": "PE", "model": "ASR9001"},
    # Core P routers (provider backbone, no CE knowledge)
    "CORE-P1":   {"site": "CORE",    "role": "P",  "model": "CRS-1"},
    "CORE-P2":   {"site": "CORE",    "role": "P",  "model": "CRS-1"},
    # Hub sites
    "HUB1-PE":   {"site": "HUB1",    "role": "PE", "model": "ASR9001"},
    "HUB1-CE":   {"site": "HUB1",    "role": "CE", "model": "ISR4451"},
    "HUB2-PE":   {"site": "HUB2",    "role": "PE", "model": "ASR9001"},
    "HUB2-CE":   {"site": "HUB2",    "role": "CE", "model": "ISR4451"},
    # Branch CEs (connect to hub PEs via MPLS access)
    "BR1-CE":    {"site": "BRANCH1", "role": "CE", "model": "ISR4331"},
    "BR2-CE":    {"site": "BRANCH2", "role": "CE", "model": "ISR4331"},
    "BR3-CE":    {"site": "BRANCH3", "role": "CE", "model": "ISR4331"},
    "BR4-CE":    {"site": "BRANCH4", "role": "CE", "model": "ISR4331"},
    "BR5-CE":    {"site": "BRANCH5", "role": "CE", "model": "ISR4331"},
}

# ══════════════════════════════════════════════════════════════════════════════
# VPN SEGMENTATION — three VRFs carried over every PE-to-PE LSP
# ══════════════════════════════════════════════════════════════════════════════
VRFS = {
    "CORP":  {"rd": "65001:10", "rt_import": "65001:10", "rt_export": "65001:10",
              "description": "Corporate data — ERP, SAP, internal apps"},
    "GUEST": {"rd": "65001:20", "rt_import": "65001:20", "rt_export": "65001:20",
              "description": "Guest WiFi — internet breakout only"},
    "MGMT":  {"rd": "65001:99", "rt_import": "65001:99", "rt_export": "65001:99",
              "description": "Out-of-band management — SSH, SNMP, Netconf"},
}

# ══════════════════════════════════════════════════════════════════════════════
# APPLICATION TRAFFIC PROFILES (QoS classes)
# ══════════════════════════════════════════════════════════════════════════════
# Each link's utilisation is split across 4 application types.
# GOLD = LLQ (priority queue), SILVER = CBWFQ, BRONZE = best-effort
APP_PROFILES = {
    "voip": {
        "qos_class":  "GOLD",
        "dscp":       "EF",       # Expedited Forwarding
        "bandwidth_pct": 0.10,    # 10% of link BW reserved
        "latency_sla_ms": 20,
        "loss_sla_pct":   0.1,
        "jitter_sla_ms":  5,
        "description": "VoIP — G.711/G.729 voice calls",
    },
    "video": {
        "qos_class":  "GOLD",
        "dscp":       "AF41",
        "bandwidth_pct": 0.20,
        "latency_sla_ms": 50,
        "loss_sla_pct":   0.5,
        "jitter_sla_ms":  10,
        "description": "Video conferencing — HD streams",
    },
    "erp": {
        "qos_class":  "SILVER",
        "dscp":       "AF21",
        "bandwidth_pct": 0.40,
        "latency_sla_ms": 100,
        "loss_sla_pct":   1.0,
        "jitter_sla_ms":  50,
        "description": "ERP/SAP — transactional business apps",
    },
    "bulk": {
        "qos_class":  "BRONZE",
        "dscp":       "BE",
        "bandwidth_pct": 0.30,
        "latency_sla_ms": 500,
        "loss_sla_pct":   2.0,
        "jitter_sla_ms":  999,
        "description": "Bulk transfers — backups, file sync",
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# TOPOLOGY — sites, links, LSPs
# ══════════════════════════════════════════════════════════════════════════════
TOPOLOGY = {
    "sites": {
        "DC1":     {"role": "datacenter", "city": "Hyderabad", "as": 65001},
        "HUB1":    {"role": "hub",        "city": "Mumbai",    "as": 65001},
        "HUB2":    {"role": "hub",        "city": "Bangalore", "as": 65001},
        "BRANCH1": {"role": "branch",     "city": "Delhi",     "as": 65001},
        "BRANCH2": {"role": "branch",     "city": "Kolkata",   "as": 65001},
        "BRANCH3": {"role": "branch",     "city": "Ahmedabad", "as": 65001},
        "BRANCH4": {"role": "branch",     "city": "Chennai",   "as": 65001},
        "BRANCH5": {"role": "branch",     "city": "Lucknow",   "as": 65001},
    },
    "links": [
        # (site_a, site_b, bw_mbps, base_lat_ms, link_type, ce_a, ce_b, pe_a, pe_b)
        ("DC1",  "HUB1",    1000, 8.0,  "mpls_core",    "DC1-CE",  "HUB1-CE",  "DC1-PE",  "HUB1-PE"),
        ("DC1",  "HUB2",    1000, 12.0, "mpls_core",    "DC1-CE",  "HUB2-CE",  "DC1-PE",  "HUB2-PE"),
        ("HUB1", "HUB2",    500,  10.0, "mpls_core",    "HUB1-CE", "HUB2-CE",  "HUB1-PE", "HUB2-PE"),
        ("HUB1", "BRANCH1", 100,  15.0, "mpls_access",  "HUB1-CE", "BR1-CE",   "HUB1-PE", None),
        ("HUB1", "BRANCH2", 100,  22.0, "mpls_access",  "HUB1-CE", "BR2-CE",   "HUB1-PE", None),
        ("HUB1", "BRANCH3", 100,  18.0, "mpls_access",  "HUB1-CE", "BR3-CE",   "HUB1-PE", None),
        ("HUB2", "BRANCH4", 100,  14.0, "mpls_access",  "HUB2-CE", "BR4-CE",   "HUB2-PE", None),
        ("HUB2", "BRANCH5", 100,  20.0, "mpls_access",  "HUB2-CE", "BR5-CE",   "HUB2-PE", None),
        ("DC1",  "BRANCH1", 50,   25.0, "sdwan_overlay","DC1-CE",  "BR1-CE",   None,       None),
        ("DC1",  "BRANCH4", 50,   28.0, "sdwan_overlay","DC1-CE",  "BR4-CE",   None,       None),
        ("HUB1", "BRANCH4", 50,   30.0, "sdwan_overlay","HUB1-CE", "BR4-CE",   None,       None),
        ("HUB2", "BRANCH2", 50,   35.0, "sdwan_overlay","HUB2-CE", "BR2-CE",   None,       None),
    ]
}

# MPLS LSPs (Label Switched Paths) — Traffic Engineering tunnels
# Each LSP has a reserved bandwidth and an explicit path through P routers
MPLS_LSPS = [
    {"id": "LSP-DC1-HUB1-TE",  "src": "DC1-PE",  "dst": "HUB1-PE",
     "path": ["DC1-PE", "CORE-P1", "HUB1-PE"], "reserved_mbps": 800, "priority": 0},
    {"id": "LSP-DC1-HUB2-TE",  "src": "DC1-PE",  "dst": "HUB2-PE",
     "path": ["DC1-PE", "CORE-P2", "HUB2-PE"], "reserved_mbps": 800, "priority": 0},
    {"id": "LSP-HUB1-HUB2-TE", "src": "HUB1-PE", "dst": "HUB2-PE",
     "path": ["HUB1-PE", "CORE-P1", "CORE-P2", "HUB2-PE"], "reserved_mbps": 400, "priority": 1},
]

# OSPF areas — within each site, CE↔PE run OSPF area 0
OSPF_AREAS = {
    "DC1":     {"area": "0.0.0.0", "process": 1, "neighbors": ["DC1-CE", "DC1-PE"]},
    "HUB1":    {"area": "0.0.0.0", "process": 1, "neighbors": ["HUB1-CE", "HUB1-PE"]},
    "HUB2":    {"area": "0.0.0.0", "process": 1, "neighbors": ["HUB2-CE", "HUB2-PE"]},
    "BRANCH1": {"area": "0.0.0.1", "process": 1, "neighbors": ["BR1-CE"]},
    "BRANCH2": {"area": "0.0.0.2", "process": 1, "neighbors": ["BR2-CE"]},
    "BRANCH3": {"area": "0.0.0.3", "process": 1, "neighbors": ["BR3-CE"]},
    "BRANCH4": {"area": "0.0.0.4", "process": 1, "neighbors": ["BR4-CE"]},
    "BRANCH5": {"area": "0.0.0.5", "process": 1, "neighbors": ["BR5-CE"]},
}

FAULT_SCENARIOS = {
    "congestion_buildup":    {"duration_ticks": 30, "affected_util": 0.92},
    "bgp_route_flap":        {"duration_ticks": 8,  "affected_util": 0.30},
    "mpls_underlay_failure": {"duration_ticks": 20, "affected_util": 1.00},
    "tunnel_degradation":    {"duration_ticks": 15, "affected_util": 0.70},
    "controller_misconfig":  {"duration_ticks": 40, "affected_util": 0.50},
    "lsp_reroute":           {"duration_ticks": 10, "affected_util": 0.60},
    "ospf_adjacency_loss":   {"duration_ticks": 6,  "affected_util": 0.20},
    "vrf_leak":              {"duration_ticks": 25, "affected_util": 0.45},
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class InterfaceMetric:
    timestamp: str; site: str; peer_site: str; link_type: str
    ce_local: str; ce_remote: str; pe_local: str
    util_in_pct: float; util_out_pct: float; latency_ms: float
    jitter_ms: float; packet_loss_pct: float; bandwidth_mbps: int
    # Per-class QoS utilisation
    qos_gold_util_pct: float; qos_silver_util_pct: float; qos_bronze_util_pct: float
    # Per-class SLA breach flags
    voip_sla_breach: int; video_sla_breach: int; erp_sla_breach: int
    # MPLS info
    mpls_label_in: int; mpls_label_out: int; ldp_session_state: str
    # VRF info
    active_vrfs: str   # comma-separated: "CORP,MGMT"
    is_fault_precursor: int; is_fault_active: int
    fault_type: str; label_time_to_impact: int

@dataclass
class BGPEvent:
    timestamp: str; site: str; peer: str; peer_device: str
    event_type: str; prefix_count: int; as_path_length: int
    is_anomaly: int; vrf: str; route_distinguisher: str

@dataclass
class OSPFEvent:
    timestamp: str; site: str; device: str; neighbor: str
    area: str; event_type: str; lsa_count: int; is_anomaly: int

@dataclass
class TunnelStat:
    timestamp: str; src_site: str; dst_site: str
    tunnel_state: str; throughput_mbps: float
    rekey_failures: int; esp_errors: int; uptime_pct: float
    ike_version: str; cipher: str; is_anomaly: int

@dataclass
class LSPStat:
    timestamp: str; lsp_id: str; src: str; dst: str
    state: str; actual_bw_mbps: float; reserved_bw_mbps: float
    utilisation_pct: float; reroutes: int; is_anomaly: int

@dataclass
class AppFlowMetric:
    timestamp: str; link: str; app_type: str; qos_class: str
    dscp: str; throughput_mbps: float; latency_ms: float
    jitter_ms: float; loss_pct: float
    sla_breach: int; sla_latency_ms: float; sla_loss_pct: float


# ══════════════════════════════════════════════════════════════════════════════
# SIMULATOR
# ══════════════════════════════════════════════════════════════════════════════

class NetworkSimulator:
    def __init__(self, raw_dir="data/raw", live_dir="data/live",
                 tick_interval=TICK_INTERVAL, tick_callback=None, log_callback=None):
        self._log_callback  = log_callback
        self.raw_dir        = Path(raw_dir)
        self.live_dir       = Path(live_dir)
        self.tick_interval  = tick_interval
        self.tick_callback  = tick_callback
        self.tick_count     = 0
        self._stop          = threading.Event()
        self.new_tick       = threading.Event()
        self.link_state:    Dict[str, dict] = {}
        self.active_faults: Dict[str, dict] = {}
        self.bgp_state:     Dict[str, dict] = {}
        self.ospf_state:    Dict[str, dict] = {}
        self.lsp_state:     Dict[str, dict] = {}
        self._fault_lock    = threading.Lock()
        self._label_counter = 1000

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.live_dir.mkdir(parents=True, exist_ok=True)
        self._init_states()

        # CSV paths
        self._iface_path   = self.raw_dir / "interface_metrics.csv"
        self._bgp_path     = self.raw_dir / "bgp_events.csv"
        self._ospf_path    = self.raw_dir / "ospf_events.csv"
        self._tunnel_path  = self.raw_dir / "tunnel_stats.csv"
        self._lsp_path     = self.raw_dir / "lsp_stats.csv"
        self._app_path     = self.raw_dir / "app_flow_metrics.csv"

        self._iface_fields  = list(InterfaceMetric.__dataclass_fields__.keys())
        self._bgp_fields    = list(BGPEvent.__dataclass_fields__.keys())
        self._ospf_fields   = list(OSPFEvent.__dataclass_fields__.keys())
        self._tunnel_fields = list(TunnelStat.__dataclass_fields__.keys())
        self._lsp_fields    = list(LSPStat.__dataclass_fields__.keys())
        self._app_fields    = list(AppFlowMetric.__dataclass_fields__.keys())
        self._write_headers()

    def _link_key(self, a, b): return f"{a}--{b}"

    def _alloc_label(self):
        self._label_counter += random.randint(1, 50)
        return self._label_counter

    def _init_states(self):
        for a, b, bw, lat, lt, ce_a, ce_b, pe_a, pe_b in TOPOLOGY["links"]:
            k = self._link_key(a, b)
            self.link_state[k] = {
                "util":     random.uniform(0.15, 0.25),
                "base_lat": lat, "bw": bw, "link_type": lt,
                "ce_a": ce_a or "", "ce_b": ce_b or "",
                "pe_a": pe_a or "",
                "label_in":  self._alloc_label(),
                "label_out": self._alloc_label(),
                "ldp_state": "operational",
            }
        for site, info in TOPOLOGY["sites"].items():
            self.bgp_state[site] = {
                "prefix_count": random.randint(80, 200),
                "flap_counter": 0,
            }
        for site, info in OSPF_AREAS.items():
            self.ospf_state[site] = {
                "adjacencies": len(info["neighbors"]),
                "lsa_count":   random.randint(20, 80),
                "flap_counter": 0,
            }
        for lsp in MPLS_LSPS:
            self.lsp_state[lsp["id"]] = {
                "state":        "up",
                "reroutes":     0,
                "reserved_bw":  lsp["reserved_mbps"],
            }

    def _write_headers(self):
        for path, fields in [
            (self._iface_path,  self._iface_fields),
            (self._bgp_path,    self._bgp_fields),
            (self._ospf_path,   self._ospf_fields),
            (self._tunnel_path, self._tunnel_fields),
            (self._lsp_path,    self._lsp_fields),
            (self._app_path,    self._app_fields),
        ]:
            if not path.exists():
                with open(path, "w", newline="") as f:
                    csv.DictWriter(f, fieldnames=fields).writeheader()

    def inject_fault(self, link: str, scenario: str):
        params = FAULT_SCENARIOS.get(scenario)
        if not params:
            print(f"[!] Unknown scenario: {scenario}")
            print(f"    Available: {', '.join(FAULT_SCENARIOS.keys())}")
            return
        with self._fault_lock:
            self.active_faults[link] = {
                "type":        scenario,
                "remaining":   params["duration_ticks"],
                "total":       params["duration_ticks"],
                "target_util": params["affected_util"],
                "start_tick":  self.tick_count,
            }
        _msg = (f"[SIM] Fault injected: {scenario} on {link} "
                f"({params['duration_ticks']} ticks = "
                f"{params['duration_ticks'] * self.tick_interval}s)")
        if self._log_callback: self._log_callback(_msg)
        else: print(_msg)

    def _tick_faults(self, link_key: str):
        if link_key in self.active_faults:
            f = self.active_faults[link_key]
            f["remaining"] -= 1
            if f["remaining"] <= 0:
                msg = f"[SIM] Fault resolved: {f['type']} on {link_key}"
                if self._log_callback:
                    self._log_callback(msg)
                else:
                    print(msg)
                del self.active_faults[link_key]
        elif AUTO_INJECT:
            # Probability per tick per link (independent of FAULT_SCENARIOS keys)
            FAULT_PROBS = {
                "congestion_buildup":    0.10,
                "mpls_underlay_failure": 0.03,
                "bgp_route_flap":        0.04,
                "tunnel_degradation":    0.06,
                "controller_misconfig":  0.02,
            }
            for fname, prob in FAULT_PROBS.items():
                if fname in FAULT_SCENARIOS and random.random() < prob:
                    fp = FAULT_SCENARIOS[fname]
                    self.active_faults[link_key] = {
                        "type":        fname,
                        "remaining":   fp["duration_ticks"],
                        "total":       fp["duration_ticks"],
                        "target_util": fp["affected_util"],
                        "start_tick":  self.tick_count,
                    }
                    msg = f"[SIM] AUTO-FAULT: {fname} on {link_key}"
                    if self._log_callback:
                        self._log_callback(msg)
                    else:
                        print(msg)
                    break

    def _diurnal(self) -> float:
        h = datetime.now().hour
        return 0.12 + 0.43 * math.sin(math.pi * max(0, h - 8) / 12) if 8 <= h <= 20 else 0.12

    def _split_qos(self, total_util: float, link_bw: int) -> dict:
        """
        Split total utilisation across QoS classes.
        GOLD (VoIP+Video) gets priority — always served first.
        SILVER (ERP) gets next allocation.
        BRONZE (Bulk) gets the rest.
        Under congestion, BRONZE drops first, then SILVER, then GOLD last.
        """
        gold_base   = APP_PROFILES["voip"]["bandwidth_pct"] + APP_PROFILES["video"]["bandwidth_pct"]
        silver_base = APP_PROFILES["erp"]["bandwidth_pct"]
        bronze_base = APP_PROFILES["bulk"]["bandwidth_pct"]

        if total_util < 0.80:
            # Normal: all classes proportional to their base allocation
            gold   = gold_base   * total_util / (gold_base + silver_base + bronze_base) * 1.0
            silver = silver_base * total_util / (gold_base + silver_base + bronze_base) * 1.0
            bronze = bronze_base * total_util / (gold_base + silver_base + bronze_base) * 1.0
        elif total_util < 0.92:
            # Congestion: bronze starts dropping
            gold   = min(gold_base,   total_util * 0.35)
            silver = min(silver_base, total_util * 0.45)
            bronze = max(0, total_util - gold - silver)
        else:
            # Severe: silver starts dropping too
            gold   = min(gold_base, total_util * 0.40)
            silver = max(0, min(silver_base, total_util - gold))
            bronze = max(0, total_util - gold - silver)

        return {
            "gold":   round(gold * 100, 2),
            "silver": round(silver * 100, 2),
            "bronze": round(bronze * 100, 2),
        }

    def _check_sla(self, app: str, latency: float, loss: float, util: float) -> int:
        p = APP_PROFILES[app]
        # SLA breach if latency OR loss exceeds threshold
        lat_breach  = latency > p["latency_sla_ms"]
        loss_breach = loss    > p["loss_sla_pct"]
        # Also breach if queue utilisation is saturated for this class
        if p["qos_class"] == "BRONZE" and util > 0.95:
            return 1
        if p["qos_class"] == "SILVER" and util > 0.97:
            return 1
        return 1 if (lat_breach or loss_breach) else 0

    def _run_tick(self) -> dict:
        ts      = datetime.now().isoformat()
        diurnal = self._diurnal()
        iface_rows, bgp_rows, ospf_rows, tunnel_rows, lsp_rows, app_rows = \
            [], [], [], [], [], []

        with self._fault_lock:
            # ── Interface + QoS + App flows ───────────────────────────────────
            for a, b, bw, base_lat, lt, ce_a, ce_b, pe_a, pe_b in TOPOLOGY["links"]:
                k     = self._link_key(a, b)
                state = self.link_state[k]
                self._tick_faults(k)

                noise       = random.gauss(0, 0.012)
                target_util = diurnal * random.uniform(0.5, 0.90) + noise
                target_util = max(0.10, min(0.55, target_util))

                fault      = self.active_faults.get(k)
                fault_type = fault["type"] if fault else "none"
                is_active  = False; tti = -1

                if fault:
                    elapsed     = 1.0 - (fault["remaining"] / fault["total"])
                    target_util = min(1.0, target_util + elapsed * fault["target_util"])
                    is_active   = elapsed > 0.3
                    tti         = max(0, int(fault["remaining"] * 0.3))
                    # LSP reroute fault: mark affected LSPs
                    if fault_type == "lsp_reroute":
                        for lsp in MPLS_LSPS:
                            if a in lsp["path"] or b in lsp["path"]:
                                self.lsp_state[lsp["id"]]["state"]    = "rerouting"
                                self.lsp_state[lsp["id"]]["reroutes"] += 1
                    # OSPF adjacency loss: mark site OSPF
                    if fault_type == "ospf_adjacency_loss" and a in self.ospf_state:
                        self.ospf_state[a]["flap_counter"] += 1
                    # VRF leak: affects GUEST VRF
                    if fault_type == "vrf_leak":
                        active_vrfs = "CORP,GUEST,MGMT,LEAKED"
                    else:
                        active_vrfs = "CORP,MGMT" if lt == "mpls_core" else "CORP,GUEST,MGMT"
                else:
                    active_vrfs = "CORP,MGMT" if lt == "mpls_core" else "CORP,GUEST,MGMT"

                state["util"] = state["util"] * 0.78 + target_util * 0.22
                util = min(1.0, max(0.0, state["util"] + random.gauss(0, 0.008)))

                lat_factor = 1.0 + 3.0 * max(0, util - 0.7) ** 2
                latency    = base_lat * lat_factor + random.gauss(0, 0.3)
                jitter     = random.uniform(0.1, 0.5) + (5.0 * util if util > 0.85 else 0)
                loss = 0.0
                if util > 0.92:
                    loss = random.uniform(0.1, 1.5) * (util - 0.92) * 10
                if fault_type == "mpls_underlay_failure" and is_active:
                    loss    = random.uniform(5.0, 30.0)
                    latency += random.uniform(20, 80)
                    state["ldp_state"] = "down"
                else:
                    state["ldp_state"] = "operational"

                # QoS split
                qos = self._split_qos(util, bw)

                # SLA breach per class
                voip_breach  = self._check_sla("voip",  latency, loss, util)
                video_breach = self._check_sla("video", latency, loss, util)
                erp_breach   = self._check_sla("erp",   latency, loss, util)

                row = asdict(InterfaceMetric(
                    timestamp=ts, site=a, peer_site=b, link_type=lt,
                    ce_local=state["ce_a"], ce_remote=state["ce_b"],
                    pe_local=state["pe_a"],
                    util_in_pct=round(util * 100, 2),
                    util_out_pct=round((util + random.gauss(0, 0.006)) * 100, 2),
                    latency_ms=round(max(1, latency), 2),
                    jitter_ms=round(jitter, 2),
                    packet_loss_pct=round(loss, 3),
                    bandwidth_mbps=bw,
                    qos_gold_util_pct=qos["gold"],
                    qos_silver_util_pct=qos["silver"],
                    qos_bronze_util_pct=qos["bronze"],
                    voip_sla_breach=voip_breach,
                    video_sla_breach=video_breach,
                    erp_sla_breach=erp_breach,
                    mpls_label_in=state["label_in"],
                    mpls_label_out=state["label_out"],
                    ldp_session_state=state["ldp_state"],
                    active_vrfs=active_vrfs,
                    is_fault_precursor=1 if fault else 0,
                    is_fault_active=1 if is_active else 0,
                    fault_type=fault_type,
                    label_time_to_impact=tti,
                ))
                iface_rows.append(row)

                # ── App flow metrics per link ──────────────────────────────────
                for app, prof in APP_PROFILES.items():
                    app_util   = util * prof["bandwidth_pct"]
                    app_lat    = latency * (1.0 if prof["qos_class"] == "GOLD" else
                                 1.2 if prof["qos_class"] == "SILVER" else 1.5)
                    app_loss   = loss * (0.1 if prof["qos_class"] == "GOLD" else
                                 0.5 if prof["qos_class"] == "SILVER" else 2.0)
                    app_jitter = jitter * (0.5 if prof["qos_class"] == "GOLD" else 1.0)
                    breach     = self._check_sla(app, app_lat, app_loss, util)
                    app_rows.append(asdict(AppFlowMetric(
                        timestamp=ts, link=k, app_type=app,
                        qos_class=prof["qos_class"], dscp=prof["dscp"],
                        throughput_mbps=round(app_util * bw, 2),
                        latency_ms=round(app_lat, 2),
                        jitter_ms=round(app_jitter, 2),
                        loss_pct=round(app_loss, 3),
                        sla_breach=breach,
                        sla_latency_ms=prof["latency_sla_ms"],
                        sla_loss_pct=prof["loss_sla_pct"],
                    )))

                # ── SD-WAN tunnel stats ────────────────────────────────────────
                if lt == "sdwan_overlay":
                    t_state = "up"; rekey_fail = 0; esp_err = 0
                    if util > 0.85:
                        t_state = "degraded"
                        rekey_fail = random.randint(0, 2)
                        esp_err    = random.randint(0, 8)
                    if fault_type == "mpls_underlay_failure" and is_active:
                        t_state    = "down" if random.random() < 0.4 else "degraded"
                        rekey_fail = random.randint(2, 8)
                        esp_err    = random.randint(5, 40)
                    if fault_type == "tunnel_degradation" and is_active:
                        rekey_fail = random.randint(5, 15)
                        esp_err    = random.randint(10, 50)
                        t_state    = "degraded"
                    tunnel_rows.append(asdict(TunnelStat(
                        timestamp=ts, src_site=a, dst_site=b,
                        tunnel_state=t_state,
                        throughput_mbps=round(util * bw, 1),
                        rekey_failures=rekey_fail, esp_errors=esp_err,
                        uptime_pct=round(100-(random.uniform(0,5) if t_state!="up" else 0), 2),
                        ike_version="IKEv2",
                        cipher="AES-256-GCM",
                        is_anomaly=1 if t_state != "up" else 0,
                    )))

            # ── BGP events (per VRF per site) ──────────────────────────────────
            pe_devices = {s: d for s, d in DEVICES.items() if d["role"] == "PE"}
            for site, info in TOPOLOGY["sites"].items():
                bs = self.bgp_state[site]
                for vrf_name, vrf_info in VRFS.items():
                    event_type = "established"; is_anomaly = 0
                    if random.random() < 0.003:
                        event_type = "flap"; bs["flap_counter"] += 1; is_anomaly = 1
                    elif random.random() < 0.002:
                        event_type = "withdrawn"; is_anomaly = 1
                    elif bs["flap_counter"] > 5:
                        event_type = "route_change"; bs["flap_counter"] = 0; is_anomaly = 1
                    peer_sites = [s for s in TOPOLOGY["sites"] if s != site]
                    peer = random.choice(peer_sites)
                    peer_dev = next(
                        (k for k, v in DEVICES.items()
                         if v["site"] == peer and v["role"] == "PE"), peer)
                    bgp_rows.append(asdict(BGPEvent(
                        timestamp=ts, site=site,
                        peer=peer, peer_device=peer_dev,
                        event_type=event_type,
                        prefix_count=bs["prefix_count"] + random.randint(-2, 2),
                        as_path_length=random.randint(2, 6),
                        is_anomaly=is_anomaly,
                        vrf=vrf_name,
                        route_distinguisher=vrf_info["rd"],
                    )))

            # ── OSPF events (per site) ─────────────────────────────────────────
            for site, area_info in OSPF_AREAS.items():
                os = self.ospf_state[site]
                event_type = "hello_ok"; is_anomaly = 0
                if os["flap_counter"] > 0:
                    event_type = "adjacency_lost"; is_anomaly = 1
                    os["flap_counter"] -= 1
                elif random.random() < 0.002:
                    event_type = "lsa_flood"; is_anomaly = 0
                    os["lsa_count"] += random.randint(1, 5)
                neighbors = area_info["neighbors"]
                ospf_rows.append(asdict(OSPFEvent(
                    timestamp=ts, site=site,
                    device=neighbors[0] if neighbors else site,
                    neighbor=neighbors[1] if len(neighbors) > 1 else "spine",
                    area=area_info["area"],
                    event_type=event_type,
                    lsa_count=os["lsa_count"],
                    is_anomaly=is_anomaly,
                )))

            # ── MPLS LSP stats ─────────────────────────────────────────────────
            for lsp in MPLS_LSPS:
                ls   = self.lsp_state[lsp["id"]]
                # Recover rerouting state after 3 ticks
                if ls["state"] == "rerouting" and random.random() < 0.3:
                    ls["state"] = "up"
                actual_bw = lsp["reserved_mbps"] * random.uniform(0.3, 0.95)
                util_pct  = actual_bw / lsp["reserved_mbps"] * 100
                lsp_rows.append(asdict(LSPStat(
                    timestamp=ts, lsp_id=lsp["id"],
                    src=lsp["src"], dst=lsp["dst"],
                    state=ls["state"],
                    actual_bw_mbps=round(actual_bw, 1),
                    reserved_bw_mbps=lsp["reserved_mbps"],
                    utilisation_pct=round(util_pct, 1),
                    reroutes=ls["reroutes"],
                    is_anomaly=1 if ls["state"] != "up" else 0,
                )))

        # Write all CSVs
        self._append_csv(self._iface_path,  self._iface_fields,  iface_rows)
        self._append_csv(self._bgp_path,    self._bgp_fields,    bgp_rows)
        self._append_csv(self._ospf_path,   self._ospf_fields,   ospf_rows)
        self._append_csv(self._tunnel_path, self._tunnel_fields,  tunnel_rows)
        self._append_csv(self._lsp_path,    self._lsp_fields,    lsp_rows)
        self._append_csv(self._app_path,    self._app_fields,    app_rows)

        tick_data = {
            "tick": self.tick_count, "timestamp": ts,
            "interface_rows": iface_rows,
            "bgp_rows":       bgp_rows,
            "ospf_rows":      ospf_rows,
            "tunnel_rows":    tunnel_rows,
            "lsp_rows":       lsp_rows,
            "app_rows":       app_rows,
            "active_faults":  {k: v["type"] for k, v in self.active_faults.items()},
        }
        with open(self.live_dir / "latest_tick.json", "w") as f:
            json.dump(tick_data, f)
        return tick_data

    def _append_csv(self, path, fields, rows):
        with open(path, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=fields).writerows(rows)

    def stream(self):
        def _log(msg):
            if self._log_callback: self._log_callback(msg)
            else: print(msg)

        _log(f"[SIM] Streaming every {self.tick_interval}s  "
             f"({'AUTO_INJECT=ON' if AUTO_INJECT else 'manual-faults-only'})  Ctrl+C to stop")
        _log("[SIM] Generating: interface + BGP + OSPF + tunnel + LSP + app-flow metrics")

        while not self._stop.is_set():
            t0        = time.time()
            tick_data = self._run_tick()
            self.tick_count += 1
            self.new_tick.set(); self.new_tick.clear()
            if self.tick_callback:
                self.tick_callback(tick_data)
            if self.tick_count % 10 == 0:
                faults = tick_data["active_faults"]
                sla_breaches = sum(
                    r["voip_sla_breach"] + r["video_sla_breach"] + r["erp_sla_breach"]
                    for r in tick_data["interface_rows"]
                )
                _log(f"[SIM] tick={self.tick_count}  "
                     f"{tick_data['timestamp'][:19]}  "
                     f"faults={faults or 'none'}  "
                     f"sla_breaches={sla_breaches}")
            time.sleep(max(0, self.tick_interval - (time.time() - t0)))

    def stop(self):
        self._stop.set()
