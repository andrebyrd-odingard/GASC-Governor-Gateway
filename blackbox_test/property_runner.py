import time, uuid, json, random, threading
import harness as H
from gasc import req, mint_jwt, now
import signing as S
import sqlite3
import numpy as np

def get_db(): return req("GET","/db-state",token=H.ADMIN).get("json",{})
def get_continuity(): return req("GET","/continuity-report",token=H.ADMIN).get("json",{})

class Oracle:
    def __init__(self):
        self.db = get_db()
        self.dag = self.db.get("dag", {})
        self.q_ledger = self.db.get("quarantine_ledger", [])
        self.q_events = self.db.get("quarantine_events", [])
        self.cont = get_continuity()
        self.q_set = set(self.q_ledger)

    def independent_bfs(self, start_nodes):
        children_map = {n: [] for n in self.dag}
        covers_map = {n: [] for n in self.dag}
        
        for nid, data in self.dag.items():
            for c in data.get("parent_dependency_commitments", []):
                p = c.get("parent_node_id")
                if p in children_map:
                    children_map[p].append(nid)
            for cov in data.get("covers", []):
                if cov in covers_map:
                    covers_map[cov].append(nid)
                    
        visited = set()
        queue = list(start_nodes)
        while queue:
            curr = queue.pop(0)
            if curr not in visited:
                visited.add(curr)
                queue.extend(children_map.get(curr, []))
                queue.extend(covers_map.get(curr, []))
        return visited

    def check_containment(self):
        q_roots = {ev.get("poisoned_root_id") for ev in self.q_events if ev.get("poisoned_root_id")}
        closure = self.independent_bfs(q_roots)
        leaks = closure - self.q_set
        if leaks:
            return False, f"Containment Leak! Nodes {leaks} descend from poison but are not in Q."
        return True, "Containment OK"

    def check_closure_correctness(self):
        root_to_cp = {}
        for ev in self.q_events:
            p = ev.get("poisoned_root_id")
            if not p: continue
            if p not in root_to_cp:
                root_to_cp[p] = set()
            root_to_cp[p].update(ev.get("computed_blast_radius_C_p", []))
            
        for p, recorded_cp in root_to_cp.items():
            actual_cp = self.independent_bfs([p])
            if recorded_cp != actual_cp:
                return False, f"Closure mismatch for {p}. Recorded union: {len(recorded_cp)}, Actual: {len(actual_cp)}. Oracle found extra nodes: {actual_cp - recorded_cp}"
        return True, "Oracle verified closure correctness. C_p matches BFS reachability."

    def check_continuity(self):
        exposures = {e.get("node_id") for e in self.cont.get("exposures", [])}
        escalations = set()
        for ev in self.q_events:
            if "continuity" in ev and isinstance(ev["continuity"], dict):
                for esc in ev["continuity"].get("escalations", []):
                    escalations.add(esc)
        
        for nid in self.q_set:
            ndata = self.dag.get(nid, {})
            if ndata.get("criticality_weight", 0) > 0:
                if nid not in exposures and nid not in escalations:
                    return False, f"Missing continuity for critical node {nid}"
        return True, "Continuity OK"

    def run_all(self):
        c_ok, c_msg = self.check_containment()
        if not c_ok: return False, c_msg
        
        cl_ok, cl_msg = self.check_closure_correctness()
        if not cl_ok: return False, cl_msg
        
        cont_ok, cont_msg = self.check_continuity()
        if not cont_ok: return False, cont_msg
        
        return True, "Oracle assertions passed."


def prove_falsifiability():
    print("\n--- 0. Prove Falsifiability ---")
    H.reset()
    
    # Build test graph: P1 (poison root) -> D1 (descendant). C1 covers P1.
    p1, _ = H.submit(["clean-parent-1"], {"v": "P1"})
    d1, _ = H.submit([p1], {"v": "D1"})
    
    def mutate_c1(p):
        p["node_type"] = "COMPACTION"
        p["covers"] = [p1]
        p["summarizer"] = {"method_id": "m", "config_digest": "c"*64}
        
    c1, _ = H.submit(["clean-parent-1"], {"v": "C1"}, mutate=mutate_c1)
    
    # Designate P1
    H.designate(p1)
    
    oracle = Oracle()
    
    # Verify baseline is green
    assert oracle.check_containment()[0] == True
    assert oracle.check_closure_correctness()[0] == True
    
    print(f"d1: {d1}, c1: {c1}, q_set: {oracle.q_set}")
    res = H.designate(p1)
    print(f"designate response: {res}")


    # Case 1: Parent-edge leak (Literal C1 shape)
    oracle.q_set.remove(d1)
    passed, _ = oracle.check_containment()
    assert passed == False, "Oracle failed to detect Parent-edge leak!"
    oracle.q_set.add(d1)
    
    # Case 2: Covers-edge leak
    oracle.q_set.remove(c1)
    passed, _ = oracle.check_containment()
    assert passed == False, "Oracle failed to detect Covers-edge leak!"
    oracle.q_set.add(c1)
    
    # Case 3: C_p Ledger Tamper
    ev = oracle.q_events[0]
    ev["computed_blast_radius_C_p"].remove(d1)
    passed, _ = oracle.check_closure_correctness()
    assert passed == False, "Oracle failed to detect C_p subset mismatch!"
    ev["computed_blast_radius_C_p"].append(d1)
    
    print("PASS: Oracle explicitly verified falsifiable against C1 bugs (Parent/Covers leaks) and Ledger subset violations.")


def run_concurrency_storm():
    print("\n--- 1. Sustained Concurrency Write Storm ---")
    H.reset()
    start_dag_size = len(get_db()["dag"])
    
    results = {"200": 0, "403": 0, "429": 0, "5xx": 0, "timeout": 0, "other": 0}
    errors_5xx = []
    failed_payload_ids = []
    lock = threading.Lock()
    active_nodes = ["clean-parent-1"]
    
    def worker():
        for _ in range(5):
            parent = random.choice(active_nodes)
            try:
                nid, r = H.submit([parent], {"v": str(uuid.uuid4())})
                status = r.get("status")
                with lock:
                    if status == 200:
                        results["200"] += 1
                        active_nodes.append(nid)
                    elif status == 403:
                        results["403"] += 1
                    elif status == 429:
                        results["429"] += 1
                    elif status and status >= 500:
                        results["5xx"] += 1
                        failed_payload_ids.append(nid)
                        if len(errors_5xx) < 10: errors_5xx.append(r)
                    else:
                        results["other"] += 1
            except Exception:
                with lock:
                    results["timeout"] += 1

    stop_designator = False
    def designator():
        while not stop_designator:
            parent = random.choice(active_nodes)
            H.designate(parent)
            time.sleep(0.01)

    threads = [threading.Thread(target=worker) for _ in range(200)]
    d_thread = threading.Thread(target=designator)
    
    d_thread.start()
    for t in threads: t.start()
    for t in threads: t.join()
    
    stop_designator = True
    d_thread.join()
    
    end_dag_size = len(get_db()["dag"])
    diff = end_dag_size - start_dag_size
    
    print(f"Results across 1,000 writes: {results}")
    if errors_5xx:
        print(f"Sample 5xx errors: {errors_5xx[:2]}")
    # DAG growth is 200s + 403s (since 403s are tainted and logged, while 5xxs MUST rollback)
    expected_growth = results["200"] + results["403"]
    if diff == expected_growth:
        print(f"PASS: Exact accounting. DAG growth ({diff}) == 200s ({results['200']}) + 403s ({results['403']}). 5xx writes rolled back cleanly.")
    else:
        print(f"FAIL: Data drop or leak! DAG growth ({diff}) != expected ({expected_growth}).")

    # Assert that NO payload_ids that got 5xx are in the final DAG
    final_dag = get_db()["dag"]
    leaks = [pid for pid in failed_payload_ids if pid in final_dag]
    if leaks:
        print(f"FAIL: Transaction atomicity broken! {len(leaks)} nodes returned 5xx but were committed to the DAG.")
    else:
        print(f"PASS: Transaction atomicity holds. 0 nodes that returned 5xx exist in the DAG.")


def run_sleeper_agent_race():
    print("\n--- 2. Sleeper Agent Race Condition ---")
    H.reset()
    
    nodes = ["clean-parent-1"]
    for i in range(10):
        nid, _ = H.submit([random.choice(nodes)], {"v": f"clean-{i}"})
        nodes.append(nid)
    
    poison_id, _ = H.submit([random.choice(nodes)], {"secret": "sleeper-poison"})
    
    mon_ok = True
    max_q = 0
    stop_poll = False
    def poller():
        nonlocal mon_ok, max_q
        while not stop_poll:
            q_len = len(get_db().get("quarantine_ledger", []))
            if q_len < max_q:
                mon_ok = False
            max_q = max(max_q, q_len)
            time.sleep(0.01)
    
    p_thread = threading.Thread(target=poller)
    p_thread.start()
    
    def designator_strike(): H.designate(poison_id)
    def greedy_child(): H.submit([poison_id], {"v": "greedy-child"})
        
    t1 = threading.Thread(target=designator_strike)
    t2 = threading.Thread(target=greedy_child)
    t3 = threading.Thread(target=greedy_child)
    t1.start(); t2.start(); t3.start()
    t1.join(); t2.join(); t3.join()
    
    stop_poll = True
    p_thread.join()
    
    if not mon_ok:
        print("FAIL: Monotonicity violation detected during storm.")
        return
        
    oracle = Oracle()
    passed, msg = oracle.run_all()
    if passed:
        print(f"PASS: Oracle verified containment after sleeper attack race. |Q| monotonic.")
    else:
        print(f"FAIL: Oracle caught an invariant failure: {msg}")


def build_scale_dag(db_path, size):
    con = sqlite3.connect(db_path)
    con.execute("DELETE FROM nodes")
    con.execute("DELETE FROM edges")
    con.execute("DELETE FROM quarantine_ledger")
    con.execute("DELETE FROM quarantine_events")
    
    nodes_data = [("clean-parent-1", '{"v":"root"}', "c"*64, "commitroot")]
    edges_data = []
    
    node_ids = ["clean-parent-1"]
    for i in range(1, size):
        nid = f"n{i}"
        
        parent_count = min(random.randint(1, 3), len(node_ids))
        window_size = min(100, len(node_ids))
        parents = random.sample(node_ids[-window_size:], parent_count)
        
        commitments = [{"parent_node_id": p, "parent_content_hash": "c"*64} for p in parents]
        payload = {"v": nid, "parent_dependency_commitments": commitments}
        
        if len(node_ids) > 0 and random.random() < 0.1:
            covers_count = min(random.randint(1, 2), len(node_ids))
            covers = random.sample(node_ids, covers_count)
            covers = [c for c in covers if c not in parents]
            if covers:
                payload["covers"] = covers
                for c in covers:
                    edges_data.append((nid, c, "COVERS"))
        
        nodes_data.append((nid, json.dumps(payload), "c"*64, f"commit{i}"))
        for p in parents:
            edges_data.append((nid, p, "MATERIAL"))
            
        node_ids.append(nid)

    con.executemany("INSERT INTO nodes (node_id, payload_json, content_hash, commitment) VALUES (?,?,?,?)", nodes_data)
    con.executemany("INSERT INTO edges (child_id, parent_id, edge_class) VALUES (?,?,?)", edges_data)
    con.commit()
    con.close()
    return node_ids

def run_large_scale_latency_test():
    print("\n--- 3. Real-Scale Latency Curve ---")
    db_path = "state.db"
    sizes = [100, 1000, 10000, 50000]
    
    for size in sizes:
        node_ids = build_scale_dag(db_path, size)
        
        # Target the oldest 5% of nodes to guarantee deep blast radii
        oldest_nodes = node_ids[:max(1, int(size * 0.05))]
        
        samples = []
        for _ in range(20):
            p = random.choice(oldest_nodes)
            con = sqlite3.connect(db_path)
            con.execute("DELETE FROM quarantine_ledger")
            con.execute("DELETE FROM quarantine_events")
            con.commit()
            con.close()
            t0 = time.perf_counter()
            r = H.designate(p)
            t1 = time.perf_counter()
            cp_size = len(r.get("json", {}).get("event", {}).get("computed_blast_radius_C_p", []))
            samples.append((cp_size, t1 - t0))
            
        # Group by approximate blast radius sizes
        samples.sort(key=lambda x: x[0])
        print(f"Size: {size:6d} nodes | Deep Roots:")
        for cp_size, latency in samples[:3] + samples[-3:]:
            print(f"  |C_p|: {cp_size:6d} -> Latency: {latency:.4f}s")

if __name__ == "__main__":
    prove_falsifiability()
    run_concurrency_storm()
    run_sleeper_agent_race()
    run_large_scale_latency_test()
