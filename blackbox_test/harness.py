import sys, os, json, uuid, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gasc import req, mint_jwt, now, sha256hex, PRIV
import signing as S

ADMIN = mint_jwt({"sub":"x","role":"admin"})

# track node_id -> stored content digest so we can declare correct parent hashes
DIGEST = {"clean-parent-1": ""}

def content_digest(state):
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()

def reset():
    return req("POST","/reset-db", body={}, token=ADMIN)

def db():
    return req("GET","/db-state", token=ADMIN).get("json",{})

def submit(parents, state, role="agent", identity_id=None, mutate=None, fix_parent_hash=True):
    """Build a valid candidate on given parent node ids, optionally mutate before send."""
    p = S.build_valid_candidate(parents, state, role=role)
    if fix_parent_hash:
        for pc in p["parent_dependency_commitments"]:
            h = DIGEST.get(pc["parent_node_id"])
            if h:  # only override when we know a non-empty stored hash
                pc["parent_content_hash"] = h
    if identity_id is not None:
        p["ephemeral_nhi"]["identity_id"] = identity_id
    if mutate:
        mutate(p)
    r = req("POST","/submit-candidate", body=p)
    if r.get("status")==200:
        DIGEST[p["payload_id"]] = content_digest(p["state_content"])
    return p["payload_id"], r

def designate(node_id, source="human_report", confidence=1.0, reason="poison", at=None, extra=None):
    body = {"poisoned_node_id":node_id,"detected_at_utc":at or now(),
            "source":source,"confidence_score":confidence,"reason":reason}
    if extra: body.update(extra)
    tok = mint_jwt({"sub":"designator","role":"designator"})
    return req("POST","/designate", body=body, token=tok)

def quarantine_set():
    return set(db().get("quarantine_ledger",[]))

def dag_ids():
    return set(db().get("dag",{}).keys())

if __name__ == "__main__":
    print("== reset ==", reset()["status"])
    print("seed dag:", dag_ids(), "seed Q:", quarantine_set())
    # baseline: chain A->B->C on clean-parent-1
    a,ra = submit(["clean-parent-1"], {"v":"A"})
    print("submit A:", ra["status"], ra.get("body","")[:120], "id=",a)
    b,rb = submit([a], {"v":"B"})
    print("submit B(child of A):", rb["status"], rb.get("body","")[:120])
    c,rc = submit([b], {"v":"C"})
    print("submit C(child of B):", rc["status"], rc.get("body","")[:120])
    print("dag:", dag_ids())
    print("== designate A as poison ==", designate(a)["status"])
    print("Q after designate A:", quarantine_set())
    # try to build on quarantined B (descendant)
    d,rd = submit([b], {"v":"D-on-quarantined"})
    print("submit child of quarantined B:", rd["status"], rd.get("body","")[:160])
