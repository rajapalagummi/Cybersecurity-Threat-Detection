# Cybersecurity Threat Detection & Network Anomaly Intelligence Platform
## PyTorch Autoencoder + Graph Analysis + Real-Time Attack Injection | 10 Attack Types

---

## Overview

Every organization's network generates thousands of events per second. Most are normal. A few are attacks. The challenge is telling them apart automatically, in real time, before damage is done.

This project builds a production-grade network security analytics platform that detects anomalous behaviour using a PyTorch autoencoder (trained exclusively on normal traffic, flags deviations), Isolation Forest ensemble scoring, and NetworkX graph analysis for attack path detection. A live attack injector simulates 10 distinct attack types — each with its own network signature — demonstrating detection in real time through Grafana dashboards and Neo4j graph visualization.

---

## Live Demo Attack Types

```bash
python3 inject_attack.py --type brute_force          # SSH/RDP repeated failed logins → success
python3 inject_attack.py --type ddos                 # 20 sources flooding single target
python3 inject_attack.py --type port_scan            # Sequential port probing (recon)
python3 inject_attack.py --type lateral_movement     # Compromised host → 8 internal hops
python3 inject_attack.py --type data_exfiltration    # Large outbound transfers (~38MB)
python3 inject_attack.py --type ransomware           # SMB spread + file encryption
python3 inject_attack.py --type credential_stuffing  # 15 rotating IPs, 60 accounts
python3 inject_attack.py --type sql_injection        # Web → DB anomalous query patterns
python3 inject_attack.py --type privilege_escalation # user_012 → admin → root progression
python3 inject_attack.py --type c2_beacon            # Periodic callbacks (beaconing pattern)
python3 inject_attack.py --type all                  # All 10 sequentially
```

---

## Architecture

```
Network Event Simulator (src/network_simulator.py)
    ↓ Realistic baseline traffic (logins, transfers, DNS, HTTP)
    ↓ SQLite event store (data/events.db)

Attack Injector (inject_attack.py)
    ↓ 10 attack types with distinct network signatures
    ↓ Injected into same event stream

Anomaly Detection Engine (src/detector.py)
    ↓ Feature extraction: 8 numerical features per event
    ↓ PyTorch Autoencoder: trained on normal traffic only
    ↓ Isolation Forest: ensemble anomaly scoring
    ↓ Weighted ensemble: 60% autoencoder + 40% IsoForest
    ↓ Per-event anomaly score [0-1]

Graph Analysis (NetworkX + Neo4j)
    ↓ Directed graph: IP nodes, connection edges
    ↓ Attack pattern detection: high out-degree, centrality, attack edges
    ↓ Visual path exploration in Neo4j browser

Dashboards
    ↓ Grafana: real-time anomaly timeline, attack type breakdown, alerts
    ↓ Neo4j: interactive network graph with attack path highlighting
```

---

## Technical Implementation

### 1. PyTorch Autoencoder — Unsupervised Anomaly Detection

Trained exclusively on normal traffic. Learns to reconstruct normal events with low error. Attack events have high reconstruction error = high anomaly score.

```python
class NetworkAutoencoder(nn.Module):
    def __init__(self, input_dim=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(32, 16), nn.ReLU(),
            nn.Linear(16, 8),  nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.ReLU(),
            nn.Linear(16, 32), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(32, input_dim),
        )

    def reconstruction_error(self, x):
        recon  = self.forward(x)
        errors = torch.mean((x - recon) ** 2, dim=1)
        return errors.numpy()
```

**Threshold:** 95th percentile of training reconstruction errors. Events above threshold = anomalous.

### 2. Feature Engineering — 8 Network Features

```python
features["bytes_sent_log"]   = np.log1p(df["bytes_sent"])
features["bytes_recv_log"]   = np.log1p(df["bytes_recv"])
features["duration_log"]     = np.log1p(df["duration_ms"])
features["dst_port_norm"]    = df["dst_port"] / 65535.0
features["src_port_norm"]    = df["src_port"] / 65535.0
features["is_external_src"]  = ...
features["is_external_dst"]  = ...
features["is_failure"]       = (df["status"] == "failed")
```

### 3. Ensemble Scoring

```python
ae_scores    = autoencoder.reconstruction_error(X) / threshold
iso_scores   = -isolation_forest.score_samples(X)
final_scores = 0.6 * ae_scores + 0.4 * iso_scores
```

### 4. Graph Attack Pattern Detection

```python
for node in G.nodes():
    if G.out_degree(node) > 10:
        findings.append({"type": "high_out_degree", "severity": "HIGH"})

centrality = nx.betweenness_centrality(G)
high_pivots = [(n, c) for n, c in centrality.items() if c > 0.3]
```

### 5. Attack Signatures — What Makes Each Attack Detectable

| Attack | Signature | Key Feature |
|---|---|---|
| Brute Force | 29 failures + 1 success | is_failure spike from single src_ip |
| DDoS | 100 packets, 20 sources, tiny duration | bytes_recv ≈ 0, high volume |
| Port Scan | Sequential ports, tiny bytes, fast | dst_port variety, small payload |
| Lateral Movement | Internal→internal, multiple services | is_external=0 on both sides |
| Data Exfiltration | 500KB-5MB outbound, external dst | bytes_sent_log very high |
| Ransomware | SMB dst_port=445, high write volume | service=smb, high bytes |
| Credential Stuffing | Many users, rotating IPs, auth failures | is_failure=1, src_ip variety |
| SQL Injection | DB port 3306, large recv (data dump) | dst_port=3306, bytes_recv spike |
| Privilege Escalation | user→admin→root progression | username pattern |
| C2 Beacon | Consistent timing, small payload | duration_ms consistent |

---

## Key Metrics

- **655 total events** processed (300 baseline + 355 attack)
- **10 attack types** with distinct network signatures
- **54.2% attack rate** after full injection demo
- **PyTorch Autoencoder**: 8-dimensional encoding, 100 epochs, final loss 0.4679
- **Ensemble scoring**: 60% autoencoder + 40% Isolation Forest
- **3 graph patterns** detected: high out-degree, attack edges, centrality pivots
- **Real-time**: events scored in batches, dashboards refresh every 5s
- **Zero paid APIs**: fully local, no cloud dependency

---

## How to Run

```bash
# 1. Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Run full pipeline
python3 main.py

# 3. Start dashboards
docker-compose up -d
# Grafana:  http://localhost:3001  (credentials in docker-compose.yml)
# Neo4j:    http://localhost:7474  (credentials in docker-compose.yml)

# 4. Live demo — Terminal 1: continuous traffic
python3 -c "from src.network_simulator import run_simulator; run_simulator(3.0)"

# 5. Live demo — Terminal 2: inject attacks
python3 inject_attack.py --type brute_force
python3 inject_attack.py --type ddos
python3 inject_attack.py --type ransomware
python3 inject_attack.py --type all

# 6. Load Neo4j graph
python3 src/neo4j_loader.py
# Query in Neo4j browser: MATCH p=(a)-[r:CONNECTED_TO]->(b) WHERE r.is_attack=true RETURN p LIMIT 50
```

---

*Built by Raja Palagummi | rajapalagummi.com | github.com/rajapalagummi*
