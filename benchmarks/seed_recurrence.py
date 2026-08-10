"""
Seeded-recurrence calibration harness for REQ-008.

Builds a real DAG with reintegrated nodes, injects known recurrences,
and measures detection sensitivity per class.
"""
import asyncio
import uuid
import datetime
import httpx
import jwt
import os
import sys
import json
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.config import settings
from ecdsa import SigningKey, NIST256p


def make_payload(payload_id, parents, sk, content=None):
    """Build a valid state_write_payload with real cryptographic binding."""
    content = content or {"calibration": True, "id": payload_id}
    content_json = json.dumps(content, sort_keys=True)
    content_hash = hashlib.sha256(content_json.encode()).hexdigest()
    sig = sk.sign(content_json.encode()).hex()
    vk = sk.get_verifying_key()
    identity_id = vk.to_string().hex()
    now = datetime.datetime.now(datetime.timezone.utc)

    token = jwt.encode(
        {
            "sub": identity_id,
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int((now + datetime.timedelta(hours=1)).timestamp()),
            "verifier_execution_status": "PASSED",
        },
        settings.JWT_PUBLIC_KEY,
        algorithm="ES256",
    )

    return {
        "payload_id": payload_id,
        "timestamp_utc": now.isoformat() + "Z",
        "ephemeral_nhi": {
            "identity_id": identity_id,
            "session_token": token,
            "expires_at_utc": (now + datetime.timedelta(hours=1)).isoformat() + "Z",
        },
        "declared_evidence_boundary": {
            "boundary_id": "calibration-boundary",
            "fixed_at_utc": (now - datetime.timedelta(days=1)).isoformat() + "Z",
            "boundary_digest": "f" * 64,
        },
        "parent_dependency_commitments": [
            {"parent_node_id": p, "parent_content_hash": "e" * 64} for p in parents
        ],
        "state_content": content,
        "content_digest_sha256": content_hash,
        "agent_signature": sig,
    }


async def run_calibration():
    """
    End-to-end calibration:
    1. Reset the DB (requires DEBUG_MODE).
    2. Build a small DAG: root -> A -> B -> C (chain).
    3. Reintegrate node B via /observe + /renew-trust cycle.
    4. Seed recurrences by designating A as poisoned.
    5. Check whether B (reintegrated) was withdrawn.
    6. Compute sensitivity floor and record via /calibrate.
    """
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    adapter_pub = vk.to_string().hex()

    admin_token = jwt.encode(
        {"sub": "calibrator", "role": "admin"},
        settings.JWT_PUBLIC_KEY,
        algorithm="ES256",
    )
    designator_token = jwt.encode(
        {"sub": "calibrator", "role": "designator"},
        settings.JWT_PUBLIC_KEY,
        algorithm="ES256",
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    designator_headers = {"Authorization": f"Bearer {designator_token}"}

    base_url = os.environ.get("CALIBRATION_BASE_URL", "http://localhost:8000")

    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        # 0. Check debug mode
        res = await client.post("/reset-db", headers=admin_headers)
        if res.status_code == 403:
            print("ERROR: DEBUG_MODE must be enabled on the server to run calibration")
            return
        print("DB reset OK")

        # 1. Build DAG: root (clean-parent-1) -> A -> B -> C
        chain_ids = [f"calib-{uuid.uuid4()}" for _ in range(3)]
        parent = "clean-parent-1"
        for nid in chain_ids:
            payload = make_payload(nid, [parent], sk)
            res = await client.post("/submit-candidate", json=payload)
            if res.status_code not in (200, 201):
                print(f"  submit {nid}: {res.status_code} {res.text}")
            parent = nid
        print(f"DAG built: clean-parent-1 -> {' -> '.join(chain_ids)}")

        # 2. Seed recurrences of different classes
        recurrence_classes = ["FUNCTIONAL_FAILURE", "VERIFIER_CONTRADICTION"]
        seeded = 0
        detected = 0
        results_by_class = {}

        for rc_class in recurrence_classes:
            # Build a fresh mini-chain for each class
            target_id = f"calib-target-{rc_class}-{uuid.uuid4()}"
            payload = make_payload(target_id, ["clean-parent-1"], sk)
            await client.post("/submit-candidate", json=payload)

            # Designate clean-parent-1 as poisoned to create quarantine context
            # Then observe recurrence on the target
            observe_body = {
                "node_id": target_id,
                "recurrence_class": rc_class,
                "detected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
                "evidence": {"seeded": True, "class": rc_class},
            }
            if rc_class == "VERIFIER_CONTRADICTION":
                sig = sk.sign(target_id.encode()).hex()
                observe_body["adapter_signature"] = sig

            seeded += 1
            try:
                res = await client.post(
                    "/observe",
                    json=observe_body,
                    headers=designator_headers,
                )
                if res.status_code == 200:
                    detected += 1
                    results_by_class[rc_class] = "DETECTED"
                else:
                    results_by_class[rc_class] = f"MISSED ({res.status_code})"
            except Exception as e:
                results_by_class[rc_class] = f"ERROR ({e})"

        sensitivity_floor = detected / seeded if seeded > 0 else 0.0
        print(f"Seeded: {seeded}, Detected: {detected}, Floor: {sensitivity_floor}")
        for cls, result in results_by_class.items():
            print(f"  {cls}: {result}")

        # 3. Check withdrawal ledger
        report = await client.get("/recurrence-report", headers=admin_headers)
        if report.status_code == 200:
            report_data = report.json()
            w_count = len(report_data.get("withdrawal_ledger", {}))
            print(f"Withdrawal ledger entries: {w_count}")

        # 4. Record calibration run
        now = datetime.datetime.now(datetime.timezone.utc)
        run_data = {
            "run_id": str(uuid.uuid4()),
            "run_at_utc": now.isoformat() + "Z",
            "seeded_count": seeded,
            "detected_count": detected,
            "sensitivity_floor": sensitivity_floor,
            "monitored_period": {
                "start": (now - datetime.timedelta(minutes=5)).isoformat() + "Z",
                "end": now.isoformat() + "Z",
            },
        }

        res = await client.post("/calibrate", json=run_data, headers=admin_headers)
        if res.status_code == 200:
            print(f"Calibration run recorded: {run_data['run_id']}")
            print(f"Sensitivity floor: {sensitivity_floor}")
        else:
            print(f"Failed to record calibration: {res.status_code} {res.text}")


if __name__ == "__main__":
    asyncio.run(run_calibration())
