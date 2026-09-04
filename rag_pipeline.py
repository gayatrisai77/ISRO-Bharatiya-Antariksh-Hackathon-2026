"""
rag_pipeline.py — Hybrid RAG (BM25 keyword + TF-IDF vector, fused via RRF)
Why hybrid?
  - BM25 catches exact technical terms: "show crypto ipsec sa", "BGP-5-ADJCHANGE"
  - TF-IDF vector catches semantic meaning: "link saturating" → congestion runbook
  - Neither alone is sufficient for technical ops documents
  - Reciprocal Rank Fusion (RRF) combines both ranked lists without needing weights

Replace TF-IDF with sentence-transformers embeddings if you have them installed.
"""

import re, math, json
from collections import defaultdict
from pathlib import Path

# ── Runbook corpus ────────────────────────────────────────────────────────────

RUNBOOKS = [
    {
        "id": "RB-001", "title": "Congestion Buildup — Hub-Spoke Link",
        "category": "congestion",
        "keywords": ["congestion", "utilization", "saturation", "qos", "shaping", "bandwidth"],
        "content": """
SYMPTOMS: Interface utilization >80% for 5+ consecutive polling cycles.
Latency trending upward. Jitter increasing. No packet loss yet.
ROOT CAUSE: Traffic volume approaching physical bandwidth limit.
Common triggers: backup jobs, video conferencing spike, SD-WAN path preference change.
IMMEDIATE ACTIONS:
1. show interfaces <if> counters rate
2. NetFlow top talkers: top-n by bytes/sec on affected link
3. policy-map SHAPE-HUB rate 80000000 bps
4. show policy-map interface <if>
5. SD-WAN path preference to redistribute to overlay tunnel
ESCALATION: util >95% for >10 min → page on-call NOC lead.
RESOLUTION TIME: 15-30 minutes
""",
    },
    {
        "id": "RB-002", "title": "BGP Route Flap — Upstream Provider",
        "category": "bgp",
        "keywords": ["bgp", "flap", "route", "prefix", "adjchange", "neighbor", "dampening", "ldp"],
        "content": """
SYMPTOMS: BGP session repeatedly going established/idle.
BGP-5-ADJCHANGE: neighbor X.X.X.X Down / Up within short intervals.
Prefix count oscillating. Route table instability.
ROOT CAUSE: Physical layer issue on MPLS access port, keepalive mismatch,
BGP timer misconfiguration, or upstream provider maintenance.
IMMEDIATE ACTIONS:
1. show bgp summary | inc <peer>
2. show interfaces <if> | inc error
3. show bgp neighbors <peer> | inc timer
4. neighbor <peer> dampening
5. show mpls ldp neighbor
6. Contact MPLS provider if physical errors present
ESCALATION: >5 flaps in 10 minutes = Severity 2. Engage provider TAC.
RESOLUTION TIME: 20-60 minutes
""",
    },
    {
        "id": "RB-003", "title": "MPLS Underlay Failure — Tunnel Fallback",
        "category": "mpls_failure",
        "keywords": ["mpls", "underlay", "failure", "packet loss", "latency spike", "pe", "ce", "p1"],
        "content": """
SYMPTOMS: High packet loss (>5%) on MPLS link. Latency spike >100ms.
SD-WAN controller showing path quality degraded. Backup overlay tunnel activating.
ROOT CAUSE: Physical cut, provider PoP issue, or CE/PE misconfiguration.
IMMEDIATE ACTIONS:
1. ping mpls ipv4 <prefix>/32 repeat 100
2. show interfaces <if> | inc line|error
3. traceroute mpls ipv4 <prefix>/32
4. sdwan policy preferred-path internet
5. Open P1 ticket with MPLS provider
6. Notify affected branch site
ESCALATION: Immediate P1 if MPLS completely down. SLA clock starts now.
RESOLUTION TIME: 30 min - 4 hours (provider-dependent)
""",
    },
    {
        "id": "RB-004", "title": "SD-WAN IPSec Tunnel Degradation",
        "category": "tunnel",
        "keywords": ["ipsec", "tunnel", "rekey", "esp", "ike", "isakmp", "crypto", "certificate", "nat", "udp4500"],
        "content": """
SYMPTOMS: Tunnel rekey failures increasing. ESP errors in counter.
Throughput below baseline. Intermittent packet drops through overlay.
ROOT CAUSE: IKE/IPSec negotiation failure due to crypto mismatch, NAT traversal
issue, underlay ISP port blocking UDP 4500, or certificate expiry.
IMMEDIATE ACTIONS:
1. show crypto ipsec sa peer <ip>
2. show crypto isakmp sa | inc <peer>
3. debug crypto isakmp <peer>
4. ping <dst> size 1400 df-bit
5. show crypto pki cert | inc expires
6. clear crypto sa peer <ip>
ESCALATION: rekey failures >10/hour → SD-WAN vendor TAC.
RESOLUTION TIME: 10-30 minutes
""",
    },
    {
        "id": "RB-005", "title": "Controller Misconfiguration — Policy Drift",
        "category": "config_drift",
        "keywords": ["controller", "policy", "drift", "misconfiguration", "template", "rollback", "config", "rca"],
        "content": """
SYMPTOMS: Unexpected traffic paths. Branches using suboptimal paths.
QoS policies not matching expected behaviour. Audit log shows config push.
ROOT CAUSE: SD-WAN controller policy push with incorrect parameters.
IMMEDIATE ACTIONS:
1. diff <running-config> <golden-config>
2. Check controller change log — last 4 hours
3. Identify affected sites from controller topology view
4. controller > Templates > Revert to last-known-good
5. app-route statistics — validate traffic paths post-rollback
6. Raise change advisory and document RCA
ESCALATION: >5 branches affected → invoke change management process.
RESOLUTION TIME: 15-45 minutes
""",
    },
]

TOPOLOGY_DOCS = [
    {
        "id": "TOPO-001", "title": "Network Topology Overview",
        "category": "topology",
        "keywords": ["dc1", "hub1", "hub2", "branch", "mpls", "sdwan", "vrf", "bgp", "ospf"],
        "content": """
Sites: DC1 (Hyderabad datacenter), HUB1 (Mumbai hub), HUB2 (Bangalore hub),
BRANCH1-5 (Delhi, Kolkata, Ahmedabad, Chennai, Lucknow).
MPLS Core: DC1↔HUB1 (1Gbps), DC1↔HUB2 (1Gbps), HUB1↔HUB2 (500Mbps)
MPLS Access: Each HUB→BRANCH (100Mbps)
SD-WAN Overlays: Internet IPSec backup DC1/HUB→BRANCHes (50Mbps)
VPN: CORP (VRF-10), GUEST (VRF-20), MGMT (VRF-99)
Routing: iBGP full-mesh between DCs/HUBs, OSPF area 0 within sites
QoS: LLQ voice/video, CBWFQ critical data, BE rest
""",
    },
    {
        "id": "TOPO-002", "title": "SLA Thresholds",
        "category": "topology",
        "keywords": ["sla", "gold", "silver", "bronze", "latency", "jitter", "loss", "voip", "erp"],
        "content": """
GOLD (VoIP/Video): latency <20ms, jitter <5ms, loss <0.1%
SILVER (ERP/SAP): latency <50ms, jitter <10ms, loss <0.5%
BRONZE (Bulk/Backup): latency <150ms, loss <2%
Utilization SLA: sustained >85% triggers alert, >95% = incident
""",
    },
]


# ── BM25 keyword search ────────────────────────────────────────────────────────

class BM25Index:
    """
    Classic BM25 retrieval.
    Scores documents by: how rare a query term is (IDF) × how often it appears here (TF).
    k1=1.5 and b=0.75 are standard defaults that work well for short ops docs.
    """
    def __init__(self, k1=1.5, b=0.75):
        self.k1   = k1
        self.b    = b
        self.docs = []
        self.tf   = []       # term freq per doc
        self.df   = defaultdict(int)
        self.avgdl = 0

    def _tokenize(self, text: str):
        return re.findall(r"[a-z0-9]+", text.lower())

    def add_documents(self, docs: list):
        self.docs = docs
        self.tf   = []
        self.df   = defaultdict(int)
        dl_sum    = 0

        for doc in docs:
            # Include explicit keyword list + title + content
            text   = " ".join(doc.get("keywords", [])) + " " + doc["title"] + " " + doc["content"]
            tokens = self._tokenize(text)
            dl_sum += len(tokens)
            tf = defaultdict(int)
            for t in tokens:
                tf[t] += 1
            self.tf.append(dict(tf))
            for t in set(tokens):
                self.df[t] += 1

        self.avgdl = dl_sum / len(docs) if docs else 1

    def search(self, query: str, top_k: int = 3):
        tokens = self._tokenize(query)
        N      = len(self.docs)
        scores = []

        for i, tf in enumerate(self.tf):
            dl    = sum(tf.values())
            score = 0.0
            for t in tokens:
                if t not in self.df:
                    continue
                idf = math.log((N - self.df[t] + 0.5) / (self.df[t] + 0.5) + 1)
                tf_norm = tf.get(t, 0) * (self.k1 + 1) / \
                          (tf.get(t, 0) + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
                score += idf * tf_norm
            scores.append((score, i))

        scores.sort(reverse=True)
        return [(round(s, 4), i) for s, i in scores[:top_k]]


# ── TF-IDF vector search ──────────────────────────────────────────────────────

class TFIDFIndex:
    """
    Semantic similarity using TF-IDF cosine.
    Catches meaning even when exact words differ.
    In production: replace with sentence-transformers all-MiniLM-L6-v2 embeddings.
    """
    def __init__(self):
        self.docs   = []
        self.matrix = []
        self.vocab  = {}

    def _tokenize(self, text): return re.findall(r"[a-z0-9]+", text.lower())

    def add_documents(self, docs: list):
        self.docs = docs
        N  = len(docs)
        tf_lists = []
        df = defaultdict(int)

        for doc in docs:
            text   = doc["title"] + " " + doc["content"]
            tokens = self._tokenize(text)
            tf = defaultdict(int)
            for t in tokens: tf[t] += 1
            tf_lists.append(dict(tf))
            for t in set(tokens): df[t] += 1

        vocab = sorted(df.keys())
        self.vocab = {w: i for i, w in enumerate(vocab)}

        for tf in tf_lists:
            total = sum(tf.values()) or 1
            vec = []
            for w in vocab:
                t_score = tf.get(w, 0) / total
                idf     = math.log((N + 1) / (df[w] + 1)) + 1
                vec.append(t_score * idf)
            norm = math.sqrt(sum(x**2 for x in vec)) or 1
            self.matrix.append([x / norm for x in vec])

    def search(self, query: str, top_k: int = 3):
        tokens = self._tokenize(query)
        q_vec  = [0.0] * len(self.vocab)
        for t in tokens:
            if t in self.vocab: q_vec[self.vocab[t]] += 1
        norm = math.sqrt(sum(x**2 for x in q_vec)) or 1
        q_vec = [x / norm for x in q_vec]

        scores = []
        for i, dv in enumerate(self.matrix):
            sim = sum(a * b for a, b in zip(q_vec, dv))
            scores.append((sim, i))
        scores.sort(reverse=True)
        return [(round(s, 4), i) for s, i in scores[:top_k]]


# ── Reciprocal Rank Fusion ────────────────────────────────────────────────────

def reciprocal_rank_fusion(ranked_lists: list, k: int = 60) -> list:
    """
    Merges multiple ranked lists without needing to tune weights.
    Formula: RRF(doc) = Σ 1/(k + rank)
    k=60 is the standard default — docs ranked first get ~1/61, ranked 10th get ~1/70.
    """
    scores = defaultdict(float)
    for ranked in ranked_lists:
        for rank, (_, doc_idx) in enumerate(ranked):
            scores[doc_idx] += 1.0 / (k + rank + 1)
    return sorted(scores.items(), key=lambda x: x[1], reverse=True)


# ── Hybrid RAG store ──────────────────────────────────────────────────────────

class HybridRAGStore:
    def __init__(self):
        self.docs   = []
        self._bm25  = BM25Index()
        self._tfidf = TFIDFIndex()

    def build(self):
        all_docs = []
        for rb in RUNBOOKS:
            all_docs.append({
                "id": rb["id"], "title": rb["title"],
                "content": rb["content"], "type": "runbook",
                "category": rb["category"],
                "keywords": rb.get("keywords", []),
            })
        for td in TOPOLOGY_DOCS:
            all_docs.append({
                "id": td["id"], "title": td["title"],
                "content": td["content"], "type": "topology",
                "category": td["category"],
                "keywords": td.get("keywords", []),
            })
        self.docs = all_docs
        self._bm25.add_documents(all_docs)
        self._tfidf.add_documents(all_docs)

        # Save index metadata
        Path("rag").mkdir(exist_ok=True)
        with open("rag/index_meta.json", "w") as f:
            json.dump({"doc_count": len(all_docs),
                       "retrieval": "hybrid_bm25_tfidf_rrf",
                       "docs": [{"id": d["id"], "title": d["title"]} for d in all_docs]}, f, indent=2)
        print(f"[RAG] Hybrid index built: {len(all_docs)} docs "
              f"(BM25 keyword + TF-IDF vector, fused via RRF)")
        return self

    def search(self, query: str, top_k: int = 3) -> list:
        bm25_ranks  = self._bm25.search(query,  top_k=top_k * 2)
        tfidf_ranks = self._tfidf.search(query, top_k=top_k * 2)

        fused = reciprocal_rank_fusion([bm25_ranks, tfidf_ranks])

        results = []
        for doc_idx, rrf_score in fused[:top_k]:
            d = dict(self.docs[doc_idx])
            d["relevance_score"] = round(rrf_score, 4)
            d["retrieval"] = "hybrid_bm25+tfidf_rrf"
            results.append(d)
        return results


def build_rag_index() -> HybridRAGStore:
    store = HybridRAGStore()
    store.build()
    return store


if __name__ == "__main__":
    store = build_rag_index()
    print("\n--- Test: congestion query ---")
    for r in store.search("high utilization link saturating latency rising", top_k=2):
        print(f"  [{r['relevance_score']:.4f}] {r['id']}: {r['title']}  ({r['retrieval']})")

    print("\n--- Test: BGP exact term ---")
    for r in store.search("BGP-5-ADJCHANGE neighbor flap dampening", top_k=2):
        print(f"  [{r['relevance_score']:.4f}] {r['id']}: {r['title']}  ({r['retrieval']})")

    print("\n--- Test: tunnel crypto ---")
    for r in store.search("ipsec rekey failure ESP error isakmp", top_k=2):
        print(f"  [{r['relevance_score']:.4f}] {r['id']}: {r['title']}  ({r['retrieval']})")
