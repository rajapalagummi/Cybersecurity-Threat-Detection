"""
Attack Injector — Live Demo Tool
Injects realistic attack patterns into the event stream.
Each attack type has a distinct signature for visual differentiation on dashboards.

Usage:
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
    python3 inject_attack.py --type all   (runs all attacks sequentially)
"""
import argparse
import sqlite3
import time
import random
from datetime import datetime
from src.network_simulator import (
    random_internal_ip, random_external_ip,
    USERS, DEVICES, SERVICE_PORTS, DB_PATH, setup_db
)

# ── Attack signature definitions ─────────────────────────────────────────────

ATTACK_CATALOG = {

    "brute_force": {
        "description": "SSH/RDP brute force — repeated failed logins from single IP, then success",
        "color":       "🔴",
        "anomaly_range": (0.75, 0.95),
    },
    "ddos": {
        "description": "Distributed Denial of Service — massive traffic volume from many IPs",
        "color":       "🟠",
        "anomaly_range": (0.85, 0.99),
    },
    "port_scan": {
        "description": "Network reconnaissance — sequential port scanning across IP range",
        "color":       "🟡",
        "anomaly_range": (0.60, 0.80),
    },
    "lateral_movement": {
        "description": "Lateral movement — compromised host accessing multiple internal systems",
        "color":       "🔴",
        "anomaly_range": (0.70, 0.90),
    },
    "data_exfiltration": {
        "description": "Data exfiltration — large outbound data transfers to external IP",
        "color":       "🔴",
        "anomaly_range": (0.80, 0.97),
    },
    "ransomware": {
        "description": "Ransomware propagation — SMB lateral spread + file encryption activity",
        "color":       "🔴",
        "anomaly_range": (0.90, 0.99),
    },
    "credential_stuffing": {
        "description": "Credential stuffing — automated logins across many accounts from rotating IPs",
        "color":       "🟠",
        "anomaly_range": (0.65, 0.85),
    },
    "sql_injection": {
        "description": "SQL injection — anomalous database query patterns from web tier",
        "color":       "🟡",
        "anomaly_range": (0.70, 0.88),
    },
    "privilege_escalation": {
        "description": "Privilege escalation — standard user gaining admin/root access",
        "color":       "🔴",
        "anomaly_range": (0.75, 0.92),
    },
    "c2_beacon": {
        "description": "C2 beacon — periodic callback to command-and-control server (periodic timing)",
        "color":       "🟠",
        "anomaly_range": (0.60, 0.78),
    },
}


def insert_attack_event(event: dict):
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
        1, event["attack_type"]
    ))
    con.commit()
    con.close()


# ── Individual attack generators ──────────────────────────────────────────────

def inject_brute_force(n_attempts: int = 30):
    """SSH/RDP brute force: many failed logins → one success"""
    attacker_ip = random_external_ip()
    target_ip   = random_internal_ip()
    target_user = random.choice(["admin", "root", "sysadmin"])
    service     = random.choice(["ssh", "rdp"])
    port        = SERVICE_PORTS[service]

    print(f"  [{service.upper()} Brute Force] {attacker_ip} → {target_ip}:{port} as '{target_user}'")

    for i in range(n_attempts):
        is_success = (i == n_attempts - 1)
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      attacker_ip,
            "dst_ip":      target_ip,
            "src_port":    random.randint(40000, 65000),
            "dst_port":    port,
            "protocol":    "TCP",
            "service":     service,
            "username":    target_user,
            "device":      random.choice(DEVICES),
            "bytes_sent":  random.randint(100, 400),
            "bytes_recv":  random.randint(100, 300) if not is_success else random.randint(2000, 5000),
            "duration_ms": random.randint(20, 100),
            "event_type":  "login_success" if is_success else "login_fail",
            "status":      "success" if is_success else "failed",
            "anomaly_score": round(random.uniform(0.75, 0.95), 4),
            "attack_type": "brute_force",
        })
        time.sleep(0.05)

    print(f"  [✓] Brute force complete — {n_attempts-1} failures, 1 success")


def inject_ddos(n_packets: int = 100):
    """DDoS: massive flood from many IPs to single target"""
    target_ip   = random_internal_ip()
    target_port = random.choice([80, 443, 8080])
    attacker_ips = [random_external_ip() for _ in range(20)]

    print(f"  [DDoS] {len(attacker_ips)} sources → {target_ip}:{target_port}")

    for i in range(n_packets):
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      random.choice(attacker_ips),
            "dst_ip":      target_ip,
            "src_port":    random.randint(1024, 65535),
            "dst_port":    target_port,
            "protocol":    random.choice(["TCP", "UDP", "ICMP"]),
            "service":     "http",
            "username":    "anonymous",
            "device":      "unknown",
            "bytes_sent":  random.randint(500, 2000),
            "bytes_recv":  random.randint(0, 100),
            "duration_ms": random.randint(1, 20),
            "event_type":  "ddos_packet",
            "status":      "flooded",
            "anomaly_score": round(random.uniform(0.85, 0.99), 4),
            "attack_type": "ddos",
        })
        time.sleep(0.02)

    print(f"  [✓] DDoS complete — {n_packets} packets from {len(attacker_ips)} sources")


def inject_port_scan(n_ports: int = 50):
    """Port scan: sequential port probing from single source"""
    attacker_ip = random_external_ip()
    target_ip   = random_internal_ip()
    ports       = random.sample(range(1, 65535), n_ports)

    print(f"  [Port Scan] {attacker_ip} → {target_ip} scanning {n_ports} ports")

    for port in sorted(ports):
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      attacker_ip,
            "dst_ip":      target_ip,
            "src_port":    random.randint(40000, 65000),
            "dst_port":    port,
            "protocol":    "TCP",
            "service":     "unknown",
            "username":    "unknown",
            "device":      "scanner",
            "bytes_sent":  random.randint(40, 80),
            "bytes_recv":  random.randint(0, 60),
            "duration_ms": random.randint(1, 50),
            "event_type":  "port_probe",
            "status":      random.choice(["open", "closed", "filtered"]),
            "anomaly_score": round(random.uniform(0.60, 0.80), 4),
            "attack_type": "port_scan",
        })
        time.sleep(0.03)

    print(f"  [✓] Port scan complete — {n_ports} ports probed")


def inject_lateral_movement(n_hops: int = 8):
    """Lateral movement: compromised host spreads to internal targets"""
    compromised = random_internal_ip()
    targets     = [random_internal_ip() for _ in range(n_hops)]
    services    = ["smb", "rdp", "ssh", "ldap", "mysql"]

    print(f"  [Lateral Movement] Compromised: {compromised} → {n_hops} internal targets")

    for i, target in enumerate(targets):
        svc = random.choice(services)
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      compromised,
            "dst_ip":      target,
            "src_port":    random.randint(1024, 65535),
            "dst_port":    SERVICE_PORTS.get(svc, 445),
            "protocol":    "TCP",
            "service":     svc,
            "username":    random.choice(["admin", "sysadmin", "service_acct"]),
            "device":      random.choice(DEVICES),
            "bytes_sent":  random.randint(5000, 50000),
            "bytes_recv":  random.randint(1000, 20000),
            "duration_ms": random.randint(200, 2000),
            "event_type":  "lateral_connection",
            "status":      "success",
            "anomaly_score": round(random.uniform(0.70, 0.90), 4),
            "attack_type": "lateral_movement",
        })
        print(f"    Hop {i+1}: → {target} via {svc.upper()}")
        time.sleep(0.15)

    print(f"  [✓] Lateral movement complete — {n_hops} hops")


def inject_data_exfiltration(n_transfers: int = 15):
    """Data exfiltration: large outbound transfers to external C2"""
    src_ip  = random_internal_ip()
    dst_ip  = random_external_ip()
    user    = random.choice(["admin", "dbadmin"])

    print(f"  [Data Exfiltration] {src_ip} → {dst_ip} ({user})")

    for i in range(n_transfers):
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    random.randint(1024, 65535),
            "dst_port":    random.choice([443, 8443, 4444, 1337]),
            "protocol":    "TCP",
            "service":     "https",
            "username":    user,
            "device":      "db-01",
            "bytes_sent":  random.randint(500000, 5000000),  # Large transfers
            "bytes_recv":  random.randint(100, 500),
            "duration_ms": random.randint(5000, 30000),
            "event_type":  "data_exfiltration",
            "status":      "success",
            "anomaly_score": round(random.uniform(0.80, 0.97), 4),
            "attack_type": "data_exfiltration",
        })
        time.sleep(0.1)

    print(f"  [✓] Exfiltration complete — {n_transfers} transfers, ~{n_transfers*2.5:.0f}MB sent")


def inject_ransomware(n_events: int = 40):
    """Ransomware: SMB spread + file encryption activity"""
    patient_zero = random_internal_ip()
    targets      = [random_internal_ip() for _ in range(10)]

    print(f"  [Ransomware] Patient zero: {patient_zero} → spreading via SMB")

    for i in range(n_events):
        target = random.choice(targets)
        event_type = random.choices(
            ["smb_write", "file_encrypt", "smb_lateral", "ransom_note"],
            weights=[0.4, 0.3, 0.2, 0.1]
        )[0]

        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      patient_zero,
            "dst_ip":      target,
            "src_port":    random.randint(1024, 65535),
            "dst_port":    445,
            "protocol":    "TCP",
            "service":     "smb",
            "username":    random.choice(["service_acct", "admin"]),
            "device":      random.choice(DEVICES),
            "bytes_sent":  random.randint(100000, 1000000),
            "bytes_recv":  random.randint(1000, 10000),
            "duration_ms": random.randint(500, 5000),
            "event_type":  event_type,
            "status":      "success",
            "anomaly_score": round(random.uniform(0.90, 0.99), 4),
            "attack_type": "ransomware",
        })
        time.sleep(0.06)

    print(f"  [✓] Ransomware simulation complete — {len(targets)} hosts affected")


def inject_credential_stuffing(n_attempts: int = 60):
    """Credential stuffing: rotating IPs, many accounts, automated timing"""
    target_ip  = random_internal_ip()
    target_svc = random.choice(["http", "https"])
    attacker_ips = [random_external_ip() for _ in range(15)]

    print(f"  [Credential Stuffing] {len(attacker_ips)} rotating IPs → {target_ip}")

    for i in range(n_attempts):
        user = random.choice(USERS)
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      random.choice(attacker_ips),
            "dst_ip":      target_ip,
            "src_port":    random.randint(1024, 65535),
            "dst_port":    SERVICE_PORTS[target_svc],
            "protocol":    "TCP",
            "service":     target_svc,
            "username":    user,
            "device":      "bot",
            "bytes_sent":  random.randint(200, 800),
            "bytes_recv":  random.randint(100, 500),
            "duration_ms": random.randint(50, 200),
            "event_type":  "login_fail",
            "status":      "failed",
            "anomaly_score": round(random.uniform(0.65, 0.85), 4),
            "attack_type": "credential_stuffing",
        })
        time.sleep(0.04)

    print(f"  [✓] Credential stuffing complete — {n_attempts} attempts, {len(attacker_ips)} IPs")


def inject_sql_injection(n_queries: int = 20):
    """SQL injection: anomalous DB query patterns from web tier"""
    web_server = random_internal_ip()
    db_server  = "10.0.3.50"

    print(f"  [SQL Injection] Web: {web_server} → DB: {db_server}")

    payloads = [
        "' OR 1=1--", "'; DROP TABLE users--", "' UNION SELECT * FROM admin--",
        "1; SELECT * FROM information_schema--", "' OR 'x'='x",
    ]

    for i in range(n_queries):
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      web_server,
            "dst_ip":      db_server,
            "src_port":    random.randint(30000, 65000),
            "dst_port":    3306,
            "protocol":    "TCP",
            "service":     "mysql",
            "username":    "webapp_user",
            "device":      "webserver-01",
            "bytes_sent":  random.randint(5000, 50000),
            "bytes_recv":  random.randint(10000, 500000),
            "duration_ms": random.randint(10, 500),
            "event_type":  "sql_injection",
            "status":      random.choice(["success", "error"]),
            "anomaly_score": round(random.uniform(0.70, 0.88), 4),
            "attack_type": "sql_injection",
        })
        time.sleep(0.08)

    print(f"  [✓] SQL injection complete — {n_queries} malicious queries")


def inject_privilege_escalation(n_events: int = 12):
    """Privilege escalation: user → admin → root progression"""
    attacker_ip = random_internal_ip()
    user        = random.choice(["user_012", "user_034", "user_021"])

    stages = [
        ("user_access",    user,        0.50),
        ("sudo_attempt",   user,        0.75),
        ("sudo_success",   user,        0.85),
        ("admin_access",   "admin",     0.88),
        ("root_escalation","root",      0.92),
        ("rootkit_install","root",      0.95),
    ]

    print(f"  [Privilege Escalation] {attacker_ip} — {user} → root")

    for stage, username, base_score in stages:
        for _ in range(2):
            insert_attack_event({
                "timestamp":   datetime.now().isoformat(),
                "src_ip":      attacker_ip,
                "dst_ip":      random_internal_ip(),
                "src_port":    random.randint(1024, 65535),
                "dst_port":    22,
                "protocol":    "TCP",
                "service":     "ssh",
                "username":    username,
                "device":      random.choice(DEVICES),
                "bytes_sent":  random.randint(1000, 10000),
                "bytes_recv":  random.randint(500, 5000),
                "duration_ms": random.randint(100, 2000),
                "event_type":  stage,
                "status":      "success",
                "anomaly_score": round(base_score + random.uniform(0, 0.05), 4),
                "attack_type": "privilege_escalation",
            })
            time.sleep(0.12)
        print(f"    Stage: {stage} as '{username}'")

    print(f"  [✓] Privilege escalation complete — user → root")


def inject_c2_beacon(n_beacons: int = 20):
    """C2 beacon: periodic callback with consistent timing (beaconing pattern)"""
    infected_host = random_internal_ip()
    c2_server     = random_external_ip()
    beacon_interval = 30  # seconds in real attack — simulated as 0.3s

    print(f"  [C2 Beacon] {infected_host} → {c2_server} (periodic callbacks)")

    for i in range(n_beacons):
        insert_attack_event({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      infected_host,
            "dst_ip":      c2_server,
            "src_port":    random.randint(40000, 65000),
            "dst_port":    random.choice([443, 8443, 80, 4444]),
            "protocol":    "TCP",
            "service":     "https",
            "username":    random.choice(USERS),
            "device":      random.choice(DEVICES),
            "bytes_sent":  random.randint(200, 600),   # Small, consistent beacon
            "bytes_recv":  random.randint(100, 400),
            "duration_ms": random.randint(80, 150),    # Consistent duration
            "event_type":  "c2_beacon",
            "status":      "success",
            "anomaly_score": round(random.uniform(0.60, 0.78), 4),
            "attack_type": "c2_beacon",
        })
        print(f"    Beacon {i+1}/{n_beacons} sent", end="\r")
        time.sleep(0.15)  # Consistent timing = beaconing signature

    print(f"\n  [✓] C2 beaconing complete — {n_beacons} callbacks at consistent intervals")


# ── Main dispatcher ────────────────────────────────────────────────────────────

ATTACK_FUNCTIONS = {
    "brute_force":          inject_brute_force,
    "ddos":                 inject_ddos,
    "port_scan":            inject_port_scan,
    "lateral_movement":     inject_lateral_movement,
    "data_exfiltration":    inject_data_exfiltration,
    "ransomware":           inject_ransomware,
    "credential_stuffing":  inject_credential_stuffing,
    "sql_injection":        inject_sql_injection,
    "privilege_escalation": inject_privilege_escalation,
    "c2_beacon":            inject_c2_beacon,
}


def run_attack(attack_type: str):
    setup_db()

    if attack_type == "all":
        print(f"\n{'='*60}")
        print(f"  RUNNING ALL ATTACK TYPES SEQUENTIALLY")
        print(f"{'='*60}")
        for name, fn in ATTACK_FUNCTIONS.items():
            info = ATTACK_CATALOG[name]
            print(f"\n{info['color']} {name.upper().replace('_',' ')}")
            print(f"   {info['description']}")
            fn()
            time.sleep(1.0)
        print(f"\n{'='*60}")
        print(f"  ALL ATTACKS COMPLETE")
        print(f"{'='*60}")
        return

    if attack_type not in ATTACK_FUNCTIONS:
        print(f"[Error] Unknown attack type: '{attack_type}'")
        print(f"Available types: {', '.join(ATTACK_FUNCTIONS.keys())}, all")
        return

    info = ATTACK_CATALOG[attack_type]
    print(f"\n{'='*55}")
    print(f"  {info['color']} INJECTING: {attack_type.upper().replace('_',' ')}")
    print(f"  {info['description']}")
    print(f"{'='*55}")

    ATTACK_FUNCTIONS[attack_type]()

    print(f"\n  Check dashboards:")
    print(f"  → Grafana:  http://localhost:3001")
    print(f"  → Kibana:   http://localhost:5601")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cybersecurity Attack Injector — Live Demo Tool"
    )
    parser.add_argument(
        "--type", required=True,
        choices=list(ATTACK_FUNCTIONS.keys()) + ["all"],
        help="Attack type to inject"
    )
    args = parser.parse_args()
    run_attack(args.type)
