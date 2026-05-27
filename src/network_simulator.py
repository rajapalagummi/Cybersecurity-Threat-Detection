"""
Network Event Simulator
Generates realistic baseline network traffic and streams to SQLite queue
Simulates: login events, data transfers, port connections, DNS queries, HTTP requests
"""
import os
import json
import time
import random
import sqlite3
import threading
import ipaddress
from datetime import datetime
import numpy as np

random.seed(None)  # True randomness for live demo

DB_PATH = "data/events.db"

# ── Network Topology ──────────────────────────────────────────────────────────
INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3.", "192.168.1.", "172.16.0."]
EXTERNAL_IPS = [f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(50)]
SERVICES = ["ssh", "http", "https", "ftp", "smtp", "dns", "rdp", "smb", "mysql", "ldap"]
USERS = [f"user_{i:03d}" for i in range(1, 51)] + ["admin", "root", "sysadmin", "dbadmin", "service_acct"]
DEVICES = [f"workstation-{i:02d}" for i in range(1, 31)] + [f"server-{i:02d}" for i in range(1, 11)] + ["dc-01", "fileserver-01", "db-01"]

SERVICE_PORTS = {
    "ssh": 22, "http": 80, "https": 443, "ftp": 21, "smtp": 25,
    "dns": 53, "rdp": 3389, "smb": 445, "mysql": 3306, "ldap": 389
}

def random_internal_ip():
    subnet = random.choice(INTERNAL_SUBNETS)
    return f"{subnet}{random.randint(2, 254)}"

def random_external_ip():
    return random.choice(EXTERNAL_IPS)

def setup_db():
    os.makedirs("data", exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            service     TEXT,
            username    TEXT,
            device      TEXT,
            bytes_sent  INTEGER,
            bytes_recv  INTEGER,
            duration_ms INTEGER,
            event_type  TEXT,
            status      TEXT,
            anomaly_score REAL DEFAULT 0.0,
            is_attack   INTEGER DEFAULT 0,
            attack_type TEXT DEFAULT 'none',
            processed   INTEGER DEFAULT 0
        )
    """)
    con.commit()
    con.close()
    print(f"[Simulator] Database ready: {DB_PATH}")

def generate_baseline_event():
    """Generate a single realistic normal network event"""
    event_type = random.choices(
        ["login_success", "login_fail", "data_transfer", "dns_query", "http_request", "port_connect"],
        weights=[0.30, 0.05, 0.25, 0.20, 0.15, 0.05]
    )[0]

    service = random.choice(SERVICES)
    src_ip  = random_internal_ip()
    dst_ip  = random_internal_ip() if random.random() < 0.7 else random_external_ip()

    # Normal behaviour patterns
    if event_type == "login_success":
        bytes_sent = random.randint(200, 1000)
        bytes_recv = random.randint(500, 2000)
        duration   = random.randint(50, 500)
        status     = "success"
    elif event_type == "login_fail":
        bytes_sent = random.randint(100, 300)
        bytes_recv = random.randint(100, 400)
        duration   = random.randint(20, 200)
        status     = "failed"
    elif event_type == "data_transfer":
        bytes_sent = random.randint(1000, 100000)
        bytes_recv = random.randint(500, 50000)
        duration   = random.randint(100, 5000)
        status     = "success"
    else:
        bytes_sent = random.randint(50, 2000)
        bytes_recv = random.randint(50, 5000)
        duration   = random.randint(10, 1000)
        status     = "success"

    return {
        "timestamp":   datetime.now().isoformat(),
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    random.randint(1024, 65535),
        "dst_port":    SERVICE_PORTS.get(service, random.randint(1, 1024)),
        "protocol":    random.choice(["TCP", "UDP", "ICMP"]),
        "service":     service,
        "username":    random.choice(USERS),
        "device":      random.choice(DEVICES),
        "bytes_sent":  bytes_sent,
        "bytes_recv":  bytes_recv,
        "duration_ms": duration,
        "event_type":  event_type,
        "status":      status,
        "anomaly_score": round(random.uniform(0.01, 0.15), 4),
        "is_attack":   0,
        "attack_type": "none",
    }

def insert_event(event: dict):
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        INSERT INTO events (timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, service, username, device, bytes_sent, bytes_recv,
            duration_ms, event_type, status, anomaly_score, is_attack, attack_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"], event["src_ip"], event["dst_ip"],
        event["src_port"], event["dst_port"], event["protocol"],
        event["service"], event["username"], event["device"],
        event["bytes_sent"], event["bytes_recv"], event["duration_ms"],
        event["event_type"], event["status"], event["anomaly_score"],
        event["is_attack"], event["attack_type"]
    ))
    con.commit()
    con.close()

def run_simulator(events_per_second: float = 5.0, max_events: int = None):
    """
    Continuous baseline traffic generator
    events_per_second: rate of normal traffic generation
    max_events: stop after N events (None = run forever)
    """
    setup_db()
    count = 0
    interval = 1.0 / events_per_second

    print(f"[Simulator] Starting baseline traffic at {events_per_second} events/sec")
    print(f"[Simulator] Press Ctrl+C to stop")

    try:
        while True:
            event = generate_baseline_event()
            insert_event(event)
            count += 1

            if count % 50 == 0:
                print(f"[Simulator] {count} baseline events generated | "
                      f"{datetime.now().strftime('%H:%M:%S')}")

            if max_events and count >= max_events:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[Simulator] Stopped. Total events: {count}")

if __name__ == "__main__":
    run_simulator(events_per_second=3.0)
