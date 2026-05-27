"""
Cybersecurity Threat Detection Platform — Main Orchestrator
Runs: data generation → model training → real-time scoring → reporting

Usage:
    python3 main.py                    # Full pipeline
    python3 main.py --demo             # Quick demo mode (faster)
    python3 main.py --train-only       # Train model only
    python3 main.py --report           # Generate threat report only
"""
import os
import sys
import time
import argparse
import threading
import sqlite3
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.network_simulator import run_simulator, setup_db, generate_baseline_event, insert_event
from src.detector import train_autoencoder, score_events, generate_threat_report

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║      Cybersecurity Threat Detection & Network Anomaly Platform   ║
║                                                                  ║
║  Stage 1: Generate baseline network traffic (500 events)         ║
║  Stage 2: Train autoencoder anomaly detection model              ║
║  Stage 3: Score events + detect attack patterns                  ║
║  Stage 4: Generate threat dashboard + report                     ║
║                                                                  ║
║  Live Demo Commands:                                             ║
║    python3 inject_attack.py --type brute_force                   ║
║    python3 inject_attack.py --type ddos                          ║
║    python3 inject_attack.py --type ransomware                    ║
║    python3 inject_attack.py --type all                           ║
╚══════════════════════════════════════════════════════════════════╝
"""


def generate_baseline(n_events: int = 500):
    """Generate baseline traffic before training"""
    setup_db()
    print(f"[Pipeline] Generating {n_events} baseline events...")
    for i in range(n_events):
        event = generate_baseline_event()
        insert_event(event)
        if (i+1) % 100 == 0:
            print(f"  {i+1}/{n_events} events generated")
    print(f"[Pipeline] ✓ Baseline generation complete")


def run_scoring_loop(duration_seconds: int = 30):
    """Continuously score new events"""
    start = time.time()
    scored = 0
    print(f"[Scorer] Running for {duration_seconds}s...")
    while time.time() - start < duration_seconds:
        n = score_events(batch_size=50)
        scored += n
        time.sleep(0.5)
    print(f"[Scorer] ✓ Scored {scored} events")
    return scored


def run_pipeline(demo_mode: bool = False):
    print(BANNER)
    os.makedirs("data",    exist_ok=True)
    os.makedirs("outputs", exist_ok=True)
    os.makedirs("models",  exist_ok=True)

    n_baseline  = 300 if demo_mode else 500
    score_secs  = 10  if demo_mode else 30

    # Stage 1
    print("=" * 60)
    print("  STAGE 1: Baseline Traffic Generation")
    print("=" * 60)
    generate_baseline(n_baseline)

    # Stage 2
    print("\n" + "=" * 60)
    print("  STAGE 2: Autoencoder Training")
    print("=" * 60)
    config = train_autoencoder()
    if not config:
        print("[Pipeline] Training failed — check data")
        return

    # Stage 3
    print("\n" + "=" * 60)
    print("  STAGE 3: Event Scoring")
    print("=" * 60)
    scored = run_scoring_loop(score_secs)

    # Stage 4
    print("\n" + "=" * 60)
    print("  STAGE 4: Threat Report Generation")
    print("=" * 60)
    report = generate_threat_report()

    # Summary
    print(f"""
{'='*60}
  ✓ PIPELINE COMPLETE
{'='*60}

📊 Results:
   Baseline events:    {n_baseline}
   Events scored:      {scored}
   Attack events:      {report.get('attack_events', 0)}
   Attack rate:        {report.get('attack_rate_pct', 0):.1f}%
   Patterns detected:  {len(report.get('patterns_detected', []))}

📁 Outputs:
   outputs/threat_dashboard.png  ← Portfolio hero image
   outputs/training_loss.png     ← Model training curve
   outputs/threat_report.json    ← Full threat analysis

🎮 LIVE DEMO — Run these in a NEW terminal:

   # Start continuous traffic:
   python3 -c "from src.network_simulator import run_simulator; run_simulator(3.0)"

   # Inject attacks (each in a new terminal):
   python3 inject_attack.py --type brute_force
   python3 inject_attack.py --type ddos
   python3 inject_attack.py --type port_scan
   python3 inject_attack.py --type lateral_movement
   python3 inject_attack.py --type data_exfiltration
   python3 inject_attack.py --type ransomware
   python3 inject_attack.py --type credential_stuffing
   python3 inject_attack.py --type sql_injection
   python3 inject_attack.py --type privilege_escalation
   python3 inject_attack.py --type c2_beacon
   python3 inject_attack.py --type all    # Run all sequentially

   # Load graph into Neo4j (after docker-compose up):
   python3 src/neo4j_loader.py

🐳 Start dashboards:
   docker-compose up -d
   # Grafana:  http://localhost:3001  (admin/cybersec123)
   # Neo4j:    http://localhost:7474  (neo4j/cybersec123)
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cybersecurity Threat Detection Platform")
    parser.add_argument("--demo",       action="store_true", help="Quick demo mode")
    parser.add_argument("--train-only", action="store_true", help="Train model only")
    parser.add_argument("--report",     action="store_true", help="Generate report only")
    args = parser.parse_args()

    if args.train_only:
        generate_baseline(300)
        train_autoencoder()
    elif args.report:
        report = generate_threat_report()
        print(f"Threats: {report.get('attack_events',0)} | Patterns: {len(report.get('patterns_detected',[]))}")
    else:
        run_pipeline(demo_mode=args.demo)
