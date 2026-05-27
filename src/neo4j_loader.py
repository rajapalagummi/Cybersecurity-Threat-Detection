"""
Neo4j Graph Loader
Loads network events into Neo4j for visual graph exploration
Shows attack paths, lateral movement chains, and network topology
"""
import sqlite3
import pandas as pd
from neo4j import GraphDatabase
from datetime import datetime, timedelta

NEO4J_URI  = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "cybersec123"
DB_PATH    = "data/events.db"


def load_to_neo4j(hours: int = 1):
    """Load recent events into Neo4j as a graph"""
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    except Exception as e:
        print(f"[Neo4j] Cannot connect: {e}")
        print(f"[Neo4j] Start Neo4j with: docker-compose up neo4j")
        return

    con    = sqlite3.connect(DB_PATH)
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    df     = pd.read_sql(
        f"SELECT * FROM events WHERE timestamp > '{cutoff}' ORDER BY timestamp DESC LIMIT 500",
        con
    )
    con.close()

    if len(df) == 0:
        print("[Neo4j] No events to load")
        return

    print(f"[Neo4j] Loading {len(df)} events into graph...")

    with driver.session() as session:
        # Clear existing graph
        session.run("MATCH (n) DETACH DELETE n")

        # Create IP nodes and relationships
        for _, row in df.iterrows():
            session.run("""
                MERGE (src:IPAddress {ip: $src_ip})
                SET src.is_external = $src_external

                MERGE (dst:IPAddress {ip: $dst_ip})
                SET dst.is_external = $dst_external

                CREATE (src)-[r:CONNECTED_TO {
                    service:       $service,
                    protocol:      $protocol,
                    anomaly_score: $anomaly_score,
                    is_attack:     $is_attack,
                    attack_type:   $attack_type,
                    timestamp:     $timestamp,
                    bytes_sent:    $bytes_sent,
                    event_type:    $event_type
                }]->(dst)
            """, {
                "src_ip":       row["src_ip"],
                "dst_ip":       row["dst_ip"],
                "src_external": not str(row["src_ip"]).startswith(("10.", "192.168.", "172.")),
                "dst_external": not str(row["dst_ip"]).startswith(("10.", "192.168.", "172.")),
                "service":      row["service"],
                "protocol":     row["protocol"],
                "anomaly_score":float(row["anomaly_score"]),
                "is_attack":    bool(row["is_attack"]),
                "attack_type":  row["attack_type"],
                "timestamp":    row["timestamp"],
                "bytes_sent":   int(row["bytes_sent"]),
                "event_type":   row["event_type"],
            })

        # Mark attack nodes
        session.run("""
            MATCH (n:IPAddress)-[r:CONNECTED_TO]->(m)
            WHERE r.is_attack = true
            SET n.is_attacker = true
            SET m.is_victim = true
        """)

        # Count stats
        result  = session.run("MATCH (n) RETURN count(n) as nodes")
        n_nodes = result.single()["nodes"]
        result  = session.run("MATCH ()-[r]->() RETURN count(r) as edges")
        n_edges = result.single()["edges"]

    driver.close()
    print(f"[Neo4j] ✓ Graph loaded: {n_nodes} nodes, {n_edges} edges")
    print(f"[Neo4j] Open: http://localhost:7474")
    print(f"[Neo4j] Query to see attack paths:")
    print(f"  MATCH p=(a)-[r:CONNECTED_TO*1..3]->(b)")
    print(f"  WHERE r[0].is_attack = true")
    print(f"  RETURN p LIMIT 50")


if __name__ == "__main__":
    load_to_neo4j(hours=24)
