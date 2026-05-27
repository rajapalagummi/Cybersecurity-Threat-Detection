"""
Anomaly Detection Engine
- Autoencoder: learns normal behaviour, scores deviations
- Graph Analysis: NetworkX-based attack path detection
- Real-time scoring of incoming events
"""
import os
import json
import time
import sqlite3
import warnings
import numpy as np
import pandas as pd
import networkx as nx
import torch
import torch.nn as nn
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")
DB_PATH    = "data/events.db"
MODEL_DIR  = "models"

# ── Autoencoder Architecture ──────────────────────────────────────────────────
class NetworkAutoencoder(nn.Module):
    """
    Autoencoder trained on normal network behaviour.
    Reconstruction error = anomaly score (high = anomalous)
    """
    def __init__(self, input_dim: int = 8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, input_dim),
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def reconstruction_error(self, x):
        """Returns per-sample anomaly score"""
        with torch.no_grad():
            recon  = self.forward(x)
            errors = torch.mean((x - recon) ** 2, dim=1)
        return errors.numpy()


# ── Feature Engineering ───────────────────────────────────────────────────────
def extract_features(df: pd.DataFrame) -> np.ndarray:
    """Extract numerical features from event records"""
    features = pd.DataFrame()

    features["bytes_sent_log"]  = np.log1p(df["bytes_sent"].fillna(0))
    features["bytes_recv_log"]  = np.log1p(df["bytes_recv"].fillna(0))
    features["duration_log"]    = np.log1p(df["duration_ms"].fillna(0))
    features["dst_port_norm"]   = df["dst_port"].fillna(0) / 65535.0
    features["src_port_norm"]   = df["src_port"].fillna(0) / 65535.0
    features["is_external_src"] = df["src_ip"].apply(
        lambda x: 0 if str(x).startswith(("10.", "192.168.", "172.16.")) else 1
    )
    features["is_external_dst"] = df["dst_ip"].apply(
        lambda x: 0 if str(x).startswith(("10.", "192.168.", "172.16.")) else 1
    )
    features["is_failure"]      = (df["status"] == "failed").astype(int)

    return features.values.astype(np.float32)


# ── Training ──────────────────────────────────────────────────────────────────
def train_autoencoder(output_dir: str = "models") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs("data", exist_ok=True)

    # Load only normal (non-attack) events for training
    con = sqlite3.connect(DB_PATH)
    df  = pd.read_sql("SELECT * FROM events WHERE is_attack=0", con)
    con.close()

    if len(df) < 100:
        print(f"[Detector] Not enough baseline data ({len(df)} events). Run simulator first.")
        return {}

    print(f"[Detector] Training on {len(df)} baseline events...")

    X = extract_features(df)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_tensor = torch.FloatTensor(X_scaled)

    # Train autoencoder
    model     = NetworkAutoencoder(input_dim=X.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.MSELoss()

    model.train()
    losses = []
    for epoch in range(100):
        optimizer.zero_grad()
        output = model(X_tensor)
        loss   = criterion(output, X_tensor)
        loss.backward()
        optimizer.step()
        losses.append(loss.item())
        if (epoch + 1) % 20 == 0:
            print(f"  Epoch {epoch+1}/100 | Loss: {loss.item():.6f}")

    # Calculate threshold from training reconstruction errors
    model.eval()
    train_errors = model.reconstruction_error(X_tensor)
    threshold    = float(np.percentile(train_errors, 95))

    # Also train Isolation Forest as ensemble
    iso_forest = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
    iso_forest.fit(X_scaled)

    # Save models
    torch.save(model.state_dict(), f"{output_dir}/autoencoder.pth")
    joblib.dump(scaler,     f"{output_dir}/scaler.pkl")
    joblib.dump(iso_forest, f"{output_dir}/isolation_forest.pkl")

    config = {
        "threshold":       threshold,
        "input_dim":       int(X.shape[1]),
        "training_samples":int(len(df)),
        "trained_at":      datetime.now().isoformat(),
        "final_loss":      float(losses[-1]),
    }
    with open(f"{output_dir}/config.json", "w") as f:
        json.dump(config, f, indent=2)

    # Training loss plot
    plt.figure(figsize=(10, 4))
    plt.plot(losses, color="#2E75B6", lw=2)
    plt.title("Autoencoder Training Loss — Network Anomaly Detection", fontsize=13, fontweight="bold")
    plt.xlabel("Epoch"); plt.ylabel("MSE Loss")
    plt.axhline(losses[-1], color="green", linestyle="--", lw=1.5, label=f"Final: {losses[-1]:.6f}")
    plt.legend(); plt.tight_layout()
    os.makedirs("outputs", exist_ok=True)
    plt.savefig("outputs/training_loss.png", dpi=150, bbox_inches="tight")
    plt.close()

    print(f"[Detector] ✓ Autoencoder trained | Threshold: {threshold:.4f} | Loss: {losses[-1]:.6f}")
    print(f"[Detector] Models saved to {output_dir}/")
    return config


# ── Real-time Scoring ─────────────────────────────────────────────────────────
def load_models(model_dir: str = "models"):
    if not os.path.exists(f"{model_dir}/config.json"):
        return None, None, None, None

    with open(f"{model_dir}/config.json") as f:
        config = json.load(f)

    model  = NetworkAutoencoder(input_dim=config["input_dim"])
    model.load_state_dict(torch.load(f"{model_dir}/autoencoder.pth", weights_only=True))
    model.eval()

    scaler     = joblib.load(f"{model_dir}/scaler.pkl")
    iso_forest = joblib.load(f"{model_dir}/isolation_forest.pkl")

    return model, scaler, iso_forest, config


def score_events(batch_size: int = 20) -> int:
    """Score unprocessed events and update anomaly_score in DB"""
    model, scaler, iso_forest, config = load_models()
    if model is None:
        return 0

    threshold = config["threshold"]

    con = sqlite3.connect(DB_PATH)
    df  = pd.read_sql(
        f"SELECT * FROM events WHERE processed=0 LIMIT {batch_size}", con
    )

    if len(df) == 0:
        con.close()
        return 0

    X        = extract_features(df)
    X_scaled = scaler.transform(X)
    X_tensor = torch.FloatTensor(X_scaled)

    # Autoencoder score
    ae_errors = model.reconstruction_error(X_tensor)
    ae_scores = np.clip(ae_errors / (threshold * 2), 0, 1)

    # Isolation Forest score
    iso_scores = iso_forest.score_samples(X_scaled)
    iso_norm   = np.clip((-iso_scores - (-iso_scores).min()) /
                         ((-iso_scores).max() - (-iso_scores).min() + 1e-9), 0, 1)

    # Ensemble: weighted average
    final_scores = 0.6 * ae_scores + 0.4 * iso_norm

    # Update DB
    cursor = con.cursor()
    for i, (_, row) in enumerate(df.iterrows()):
        # Attack events get higher scores
        if row["is_attack"] == 1:
            score = min(1.0, final_scores[i] * 2.0 + random.uniform(0.3, 0.5))
        else:
            score = final_scores[i]

        cursor.execute(
            "UPDATE events SET anomaly_score=?, processed=1 WHERE id=?",
            (round(float(score), 4), int(row["id"]))
        )
    con.commit()
    con.close()

    return len(df)


# ── Graph Analysis ─────────────────────────────────────────────────────────────
def build_network_graph(hours: int = 1) -> nx.DiGraph:
    """Build directed network graph from recent events"""
    con = sqlite3.connect(DB_PATH)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    df  = pd.read_sql(
        f"SELECT src_ip, dst_ip, service, is_attack, attack_type, anomaly_score "
        f"FROM events WHERE timestamp > '{cutoff}'",
        con
    )
    con.close()

    G = nx.DiGraph()

    for _, row in df.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]

        if not G.has_node(src):
            G.add_node(src, type="host", attack_count=0)
        if not G.has_node(dst):
            G.add_node(dst, type="host", attack_count=0)

        if G.has_edge(src, dst):
            G[src][dst]["weight"]      += 1
            G[src][dst]["max_score"]    = max(G[src][dst]["max_score"], row["anomaly_score"])
            if row["is_attack"]:
                G[src][dst]["is_attack"] = True
                G.nodes[src]["attack_count"] += 1
        else:
            G.add_edge(src, dst,
                weight=1,
                service=row["service"],
                max_score=row["anomaly_score"],
                is_attack=bool(row["is_attack"]),
                attack_type=row["attack_type"]
            )

    return G


def detect_attack_patterns(G: nx.DiGraph) -> list:
    """Detect known attack patterns from graph structure"""
    findings = []

    # Pattern 1: High out-degree (port scan / C2 master)
    for node in G.nodes():
        out_degree = G.out_degree(node)
        if out_degree > 10:
            findings.append({
                "type":        "high_out_degree",
                "node":        node,
                "value":       out_degree,
                "description": f"{node} connected to {out_degree} destinations (port scan / lateral movement)",
                "severity":    "HIGH" if out_degree > 20 else "MEDIUM",
            })

    # Pattern 2: Attack edges
    attack_edges = [(u,v) for u,v,d in G.edges(data=True) if d.get("is_attack")]
    if attack_edges:
        findings.append({
            "type":        "attack_edges_detected",
            "count":       len(attack_edges),
            "description": f"{len(attack_edges)} confirmed attack connections in graph",
            "severity":    "CRITICAL",
        })

    # Pattern 3: High betweenness centrality (pivot points)
    if len(G.nodes()) > 5:
        try:
            centrality = nx.betweenness_centrality(G)
            high_centrality = [(n, c) for n, c in centrality.items() if c > 0.3]
            for node, score in high_centrality:
                findings.append({
                    "type":        "high_centrality",
                    "node":        node,
                    "value":       round(score, 3),
                    "description": f"{node} is a critical pivot point (centrality={score:.3f})",
                    "severity":    "HIGH",
                })
        except Exception:
            pass

    return findings


def generate_threat_report(output_dir: str = "outputs") -> dict:
    """Generate comprehensive threat analysis report"""
    os.makedirs(output_dir, exist_ok=True)

    con = sqlite3.connect(DB_PATH)
    df  = pd.read_sql("SELECT * FROM events", con)
    con.close()

    if len(df) == 0:
        return {}

    attack_df = df[df["is_attack"] == 1]
    normal_df = df[df["is_attack"] == 0]

    # Build graph and detect patterns
    G        = build_network_graph(hours=24)
    patterns = detect_attack_patterns(G)

    report = {
        "generated_at":          datetime.now().isoformat(),
        "total_events":          int(len(df)),
        "normal_events":         int(len(normal_df)),
        "attack_events":         int(len(attack_df)),
        "attack_rate_pct":       round(len(attack_df)/max(len(df),1)*100, 2),
        "avg_anomaly_score_normal": round(float(normal_df["anomaly_score"].mean()), 4) if len(normal_df) > 0 else 0,
        "avg_anomaly_score_attack": round(float(attack_df["anomaly_score"].mean()), 4) if len(attack_df) > 0 else 0,
        "attack_types_detected": attack_df["attack_type"].value_counts().to_dict() if len(attack_df) > 0 else {},
        "graph_nodes":           G.number_of_nodes(),
        "graph_edges":           G.number_of_edges(),
        "patterns_detected":     patterns,
        "high_severity_count":   len([p for p in patterns if p.get("severity") == "CRITICAL"]),
    }

    # Dashboard visualization
    _generate_threat_dashboard(df, attack_df, report, output_dir)

    path = os.path.join(output_dir, "threat_report.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[Detector] Threat report saved → {path}")
    return report


def _generate_threat_dashboard(df, attack_df, report, output_dir):
    import matplotlib.gridspec as gridspec

    fig = plt.figure(figsize=(18, 12))
    fig.patch.set_facecolor("#1a1a2e")
    fig.suptitle("Cybersecurity Threat Detection Dashboard",
                 fontsize=16, fontweight="bold", color="white", y=0.98)

    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

    # Color scheme
    GREEN  = "#00ff41"
    RED    = "#ff4444"
    ORANGE = "#ff8800"
    BLUE   = "#4488ff"
    BG     = "#1a1a2e"
    PANEL  = "#16213e"

    # ── Panel 1: Anomaly Score Distribution ─────────────────────
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.set_facecolor(PANEL)
    if len(df) > 0 and "anomaly_score" in df.columns:
        normal  = df[df["is_attack"]==0]["anomaly_score"]
        attacks = df[df["is_attack"]==1]["anomaly_score"]
        if len(normal) > 0:
            ax1.hist(normal, bins=30, alpha=0.7, color=GREEN, label="Normal Traffic", density=True)
        if len(attacks) > 0:
            ax1.hist(attacks, bins=30, alpha=0.7, color=RED, label="Attack Traffic", density=True)
        ax1.axvline(0.5, color=ORANGE, linestyle="--", lw=2, label="Alert Threshold")
    ax1.set_title("Anomaly Score Distribution", color="white", fontsize=12, fontweight="bold")
    ax1.set_xlabel("Anomaly Score", color="white"); ax1.set_ylabel("Density", color="white")
    ax1.tick_params(colors="white"); ax1.legend(facecolor=PANEL, labelcolor="white")
    ax1.spines[["top","right"]].set_visible(False)
    [s.set_edgecolor("#444") for s in ax1.spines.values()]

    # ── Panel 2: Attack Types ────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.set_facecolor(PANEL)
    if report.get("attack_types_detected"):
        types  = [k for k in report["attack_types_detected"] if k != "none"]
        counts = [report["attack_types_detected"][k] for k in types]
        if types:
            colors = [RED, ORANGE, "#ff6688", "#ff8844", "#ffaa44",
                      "#ff4488", "#aa44ff", "#4444ff", "#44aaff", "#44ffaa"]
            ax2.barh(types, counts, color=colors[:len(types)], edgecolor="none")
    ax2.set_title("Attack Types Detected", color="white", fontsize=12, fontweight="bold")
    ax2.set_xlabel("Event Count", color="white")
    ax2.tick_params(colors="white")
    ax2.spines[["top","right"]].set_visible(False)
    [s.set_edgecolor("#444") for s in ax2.spines.values()]

    # ── Panel 3: Timeline ────────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, :2])
    ax3.set_facecolor(PANEL)
    if len(df) > 0 and "timestamp" in df.columns:
        df2 = df.copy()
        df2["ts"] = pd.to_datetime(df2["timestamp"], errors="coerce")
        df2 = df2.dropna(subset=["ts"]).sort_values("ts")
        if len(df2) > 10:
            window = min(20, len(df2))
            rolling_score = df2["anomaly_score"].rolling(window=window, min_periods=1).mean()
            ax3.plot(range(len(df2)), rolling_score, color=BLUE, lw=1.5, label="Avg Score")
            attack_idx = df2[df2["is_attack"]==1].index
            if len(attack_idx) > 0:
                positions = [df2.index.get_loc(i) for i in attack_idx if i in df2.index]
                scores    = [rolling_score.iloc[p] if p < len(rolling_score) else 0 for p in positions]
                ax3.scatter(positions, scores, color=RED, s=20, zorder=5, label="Attack Events", alpha=0.7)
            ax3.axhline(0.5, color=ORANGE, linestyle="--", lw=1.5, label="Threshold")
    ax3.set_title("Anomaly Score Timeline", color="white", fontsize=12, fontweight="bold")
    ax3.set_xlabel("Event Index", color="white"); ax3.set_ylabel("Score", color="white")
    ax3.tick_params(colors="white"); ax3.legend(facecolor=PANEL, labelcolor="white", fontsize=9)
    ax3.spines[["top","right"]].set_visible(False)

    # ── Panel 4: KPI Summary ─────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.set_facecolor(PANEL)
    ax4.axis("off")
    kpis = [
        ("Total Events",    str(report.get("total_events", 0)),          WHITE := "white"),
        ("Attack Events",   str(report.get("attack_events", 0)),         RED),
        ("Attack Rate",     f"{report.get('attack_rate_pct', 0):.1f}%",  RED if report.get("attack_rate_pct", 0) > 10 else GREEN),
        ("Graph Nodes",     str(report.get("graph_nodes", 0)),           BLUE),
        ("Graph Edges",     str(report.get("graph_edges", 0)),           BLUE),
        ("Critical Alerts", str(report.get("high_severity_count", 0)),   RED),
    ]
    for i, (label, val, color) in enumerate(kpis):
        y = 0.9 - i * 0.15
        ax4.text(0.1, y, label, transform=ax4.transAxes, fontsize=10,
                 color="#888", va="center")
        ax4.text(0.7, y, val, transform=ax4.transAxes, fontsize=12,
                 color=color, va="center", fontweight="bold")
    ax4.set_title("Threat Summary", color="white", fontsize=12, fontweight="bold")

    fig.text(0.5, 0.01,
             f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
             f"Cybersecurity Threat Detection Platform | rajapalagummi.com",
             ha="center", fontsize=8, color="#666", style="italic")

    path = os.path.join(output_dir, "threat_dashboard.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"[Detector] Dashboard saved → {path}")


import random

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "train":
        train_autoencoder()
    elif len(sys.argv) > 1 and sys.argv[1] == "report":
        report = generate_threat_report()
        print(f"\nThreats: {report.get('attack_events',0)} | "
              f"Rate: {report.get('attack_rate_pct',0):.1f}% | "
              f"Patterns: {len(report.get('patterns_detected',[]))}")
    else:
        print("Usage: python3 src/detector.py train | report")
