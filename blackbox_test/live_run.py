import time, uuid, json, random, threading
import harness as H
from gasc import req, mint_jwt, now
import signing as S

DESIG = mint_jwt({"sub":"d","role":"designator"}); ADMIN=H.ADMIN
def p(s="",d=0.0): print(s, flush=True); time.sleep(d)
def banner(t): p("\n"+"="*74,0); p("  "+t,0); p("="*74,0.6)
def verdict(secure, label):
    p(f"    >>> {'SECURE (fix holds)' if secure else 'VULNERABLE'}  [{label}]", 0.8)

def compaction(parent, covers, state):
    key,idhex=S.make_agent_keypair(); dig=H.content_digest(state)
    b={"payload_id":str(uuid.uuid4()),"timestamp_utc":now(),
       "ephemeral_nhi":{"identity_id":idhex,"session_token":S.make_session_token(idhex),"expires_at_utc":now(3600)},
       "declared_evidence_boundary":{"boundary_id":str(uuid.uuid4()),"fixed_at_utc":now(),"boundary_digest":"f"*64},
       "parent_dependency_commitments":[{"parent_node_id":parent,"parent_content_hash":"e"*64}],
       "state_content":state,"content_digest_sha256":dig,"agent_signature":S._raw_signature_hex(key,dig.encode()),
       "signature_algorithm":"ECDSA-P256-SHA256","node_type":"COMPACTION","covers":covers,
       "summarizer":{"method_id":"m","config_digest":"d"}}
    return b["payload_id"], req("POST","/submit-candidate",body=b)

p("GASC Governor Gateway — BLACK-BOX RE-RUN against patched build", 0.3)
p("target http://127.0.0.1:8000   enforcement="+req("GET","/readyz").get("json",{}).get("enforcement_mode","?"),0.6)

banner("C1  (critical, obj 1+2)  compaction covers[] laundering")
p("reset -> "+str(H.reset()["status"]),0.3)
pnode,_=H.submit(["clean-parent-1"],{"secret":"POISON"}); p(f"submit poison node -> {pnode[:8]}",0.3)
p("designate poison -> "+str(H.designate(pnode)["status"])+"   Q="+str(sorted(x[:8] for x in H.quarantine_set())),0.4)
p("SEQUENCE: submit COMPACTION node, clean parent, covers=[poison]",0.2)
comp,rc=compaction("clean-parent-1",[pnode],{"summary":"distilled from poison"})
p(f"EXPECTED: refused OR quarantined",0.2)
p(f"OBSERVED: status={rc['status']}  body={str(rc.get('body',''))[:80]}",0.2)
p(f"          compaction in quarantine = {comp in H.quarantine_set()}",0.3)
verdict(rc["status"]!=200 or comp in H.quarantine_set(), "C1 designate-first")
p("\nreverse order: create compaction first, THEN designate poison",0.2)
H.reset(); pn,_=H.submit(["clean-parent-1"],{"secret":"POISON"})
c2,rc2=compaction("clean-parent-1",[pn],{"summary":"x"}); p(f"  compaction committed status={rc2['status']}",0.2)
H.designate(pn); swept = c2 in H.quarantine_set()
p(f"  after designating poison: covering compaction in Q = {swept}",0.3)
verdict(swept, "C1 designate-after")

banner("C2  (high, obj 6)  report must reflect the breach")
H.reset(); pn,_=H.submit(["clean-parent-1"],{"secret":"POISON"}); H.designate(pn)
c3,r3=compaction("clean-parent-1",[pn],{"summary":"s"})
mc=req("GET","/measured-cost",token=ADMIN).get("json",{})
br=mc.get("safety",{}).get("containment_breaches")
p(f"laundering blocked now: compaction status={r3['status']}",0.2)
p(f"/measured-cost safety.containment_breaches = {br}",0.3)
verdict(r3["status"]!=200 or (c3 in H.quarantine_set()) or (br and br>0), "C2 report integrity")

banner("C3  (med/high, obj 5)  root designation must not permanently deny writes")
H.reset(); H.submit(["clean-parent-1"],{"v":"A"})
p("designate clean-parent-1 (the only writable root) -> "+str(H.designate("clean-parent-1")["status"]),0.4)
_,rw=H.submit(["clean-parent-1"],{"v":"write on quarantined root"})
p(f"  writes on the quarantined root are (correctly) blocked: {rw['status']}",0.3)
p("  recovery path: admin POST /seed-root {root_id:'new-root-1'}",0.2)
sr=req("POST","/seed-root",body={"root_id":"new-root-1"},token=ADMIN)
p(f"  /seed-root -> {sr['status']} {str(sr.get('body',''))[:60]}",0.3)
newhash=H.db()["dag"].get("new-root-1",{}).get("content_digest_sha256","")
H.DIGEST["new-root-1"]=newhash
_,rw2=H.submit(["new-root-1"],{"v":"availability restored"})
p(f"EXPECTED: writes resume on a freshly seeded independent root",0.2)
p(f"OBSERVED: write on new root status={rw2['status']}  {str(rw2.get('body',''))[:60]}",0.3)
# also confirm non-admin cannot seed
srx=req("POST","/seed-root",body={"root_id":"evil"},token=mint_jwt({"sub":"s","role":"agent"}))
p(f"  non-admin /seed-root -> {srx['status']} (expect 401/403)",0.2)
verdict(rw2["status"]==200 and srx["status"] in (401,403), "C3 availability restored + admin-gated")

banner("C4  (low)  reusing a quarantined payload_id must be refused")
H.reset(); x,_=H.submit(["clean-parent-1"],{"v":"orig"}); H.designate(x)
def mut(pl): pl["payload_id"]=x
_,rr=H.submit(["clean-parent-1"],{"v":"attacker"},mutate=mut)
p(f"reuse quarantined id -> status={rr['status']}  {str(rr.get('body',''))[:70]}",0.3)
verdict(rr["status"]!=200, "C4 no id reuse")

banner("NEGATIVE GUARDS (must stay held)")
H.reset(); pn,_=H.submit(["clean-parent-1"],{"v":"P"}); H.designate(pn)
r=req("POST","/renew-trust",body={"node_id":pn},token=DESIG)
p(f"R6 renew-trust on quarantined -> {r['status']} (expect 403)",0.3); verdict(r["status"]==403,"R6 no rehab")
# monotonicity 120 ops
H.reset(); nodes=["clean-parent-1"]
for i in range(6):
    nid,rx=H.submit([random.choice(nodes)],{"i":i});  nodes.append(nid) if rx["status"]==200 else None
H.designate(nodes[1]); maxq=set(H.quarantine_set()); shr=0
p("R9 monotonicity hammer: 120 mixed designate/observe/renew/checkpoint/substitute ops",0.2)
for _i in range(120):
    if _i%10==0: print(f"    ops {_i:3d}/120   |Q|={len(maxq):2d}  shrinks={shr}", flush=True)
    n=random.choice(nodes[1:]); op=random.choice(["designate","observe","renew","checkpoint","substitute"])
    try:
        if op=="designate": H.designate(n)
        elif op=="observe": req("POST","/observe",body={"node_id":n,"recurrence_class":"IDENTICAL","detected_at_utc":now()},token=DESIG)
        elif op=="renew": req("POST","/renew-trust",body={"node_id":n},token=DESIG)
        elif op=="checkpoint": req("POST","/checkpoint",body={"checkpoint_id":str(uuid.uuid4()),"target_node_id":n,"declared_at_utc":now(),"snapshot_data":{}},token=ADMIN)
        else: req("POST","/declare-substitute",body={"target_node_id":n,"substitute_source_id":random.choice(nodes),"declared_at_utc":now()},token=ADMIN)
    except Exception: pass
    cur=H.quarantine_set()
    if not maxq.issubset(cur): shr+=1
    maxq|=cur
p(f"R9 result: 120 mixed ops, shrinks={shr} (expect 0)",0.3); verdict(shr==0,"R9 append-only")
# concurrency 60
p("R10 submit/designate race: 60 concurrent trials",0.2)
slip=0
for t in range(60):
    if t%10==0: print(f"    trial {t:3d}/60   escapes={slip}", flush=True)
    H.reset(); root,_=H.submit(["clean-parent-1"],{"v":"r"}); leaf,_=H.submit([root],{"v":"l"})
    res={}
    def dd(): res["d"]=H.designate(root)
    def ss(): res["c"]=H.submit([leaf],{"v":"c%d"%t})[1]
    a1=threading.Thread(target=dd); a2=threading.Thread(target=ss); a1.start();a2.start();a1.join();a2.join()
    q=H.quarantine_set()
    if leaf in q:
        dag=H.db()["dag"]
        if [n for n,rec in dag.items() if any(pc.get("parent_node_id")==leaf for pc in rec.get("parent_dependency_commitments",[])) and n not in q]: slip+=1
p(f"R10 result: 60 trials, escapes={slip} (expect 0)",0.3); verdict(slip==0,"R10 race safe")

p("\n"+"#"*74,0); p("  RE-RUN COMPLETE",0); p("#"*74,0.3)
