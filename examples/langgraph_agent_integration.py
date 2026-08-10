import os
import uuid
import json
import httpx
from datetime import datetime, timezone

# ---------------------------------------------------------------------
# This is a mock example showing how an agent framework (like LangGraph)
# should wrap its tool outputs before writing to a shared database.
# Instead of writing directly to the database, the agent submits a 
# candidate payload to the GASC-Governor-Gateway.
# ---------------------------------------------------------------------

GOVERNOR_URL = os.getenv("GOVERNOR_URL", "http://localhost:8000")

def sign_payload(payload_dict: dict, private_key: str) -> str:
    # In a real implementation, this would use a cryptographic library 
    # to sign the digest of the payload.
    return "mock_cryptographic_signature_from_agent"

def compute_digest(content: dict) -> str:
    # In a real implementation, this would compute the SHA256 of the content.
    return "mock_sha256_hash_of_content"

def submit_agent_action_to_governor(agent_id: str, action_data: dict, parent_nodes: list[str]):
    """
    Wraps an agent's intended action into a GASC_StateWritePayload
    and submits it to the Governor Gateway for compliance verification.
    """
    payload_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).isoformat()
    
    # 1. Build the GASC Compliant Payload
    payload = {
        "payload_id": payload_id,
        "timestamp_utc": now_utc,
        "ephemeral_nhi": {
            "identity_id": agent_id,
            "session_token": f"session_{uuid.uuid4().hex[:8]}",
            "expires_at_utc": "2026-12-31T23:59:59Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "langgraph-agent-boundary",
            "fixed_at_utc": now_utc,
            "boundary_digest": "mock_boundary_digest"
        },
        # 2. Declare all dependencies explicitly (for Transitive Taint Propagation)
        "parent_dependency_commitments": [
            {
                "parent_node_id": parent_id,
                "parent_content_hash": "mock_hash" # Must match actual parent hash
            } for parent_id in parent_nodes
        ],
        "state_content": action_data,
        "content_digest_sha256": compute_digest(action_data),
    }

    # 3. Agent cryptographically signs the payload
    payload["agent_signature"] = sign_payload(payload, "agent_private_key")
    payload["signature_algorithm"] = "ECDSA-P256-SHA256"

    print(f"[*] Agent {agent_id} submitting payload {payload_id} to Governor...")
    
    # 4. Submit to Gateway
    try:
        response = httpx.post(
            f"{GOVERNOR_URL}/submit-candidate",
            json=payload,
            timeout=5.0
        )
        
        if response.status_code == 200:
            print("[+] Success: Governor approved and committed the transaction.")
            return response.json()
        elif response.status_code == 403:
            print(f"[-] Forbidden: Governor rejected the transaction. Reason: {response.text}")
            # The agent should handle this rejection (e.g. Irreducibility escalation)
        else:
            print(f"[!] Error: {response.status_code} - {response.text}")
            
    except httpx.RequestError as e:
        print(f"[!] Network error communicating with Governor: {e}")

if __name__ == "__main__":
    # Example Usage: Agent attempts to create an order
    submit_agent_action_to_governor(
        agent_id="langgraph-order-agent-01",
        action_data={"action": "create_order", "item": "laptop", "qty": 1},
        parent_nodes=["clean-parent-node-123"]
    )
