import uuid
import datetime
from typing import List, Dict

async def process_recurrence(backend, node_id: str, recurrence_class: str, signal_source: str, evidence: dict = None):
    """
    Computes the withdrawal closure and applies the transaction.
    If it exceeds amplification limits, it escalates instead.
    """
    from src.config import settings
    # Closure is just compute_blast_radius because it's forward reachability
    w_r = await backend.compute_blast_radius(node_id)
    
    event = {
        "event_id": str(uuid.uuid4()),
        "node_id": node_id,
        "recurrence_class": recurrence_class,
        "detected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "signal_source": signal_source,
        "evidence": evidence or {}
    }
    
    if len(w_r) > settings.MAX_WITHDRAWAL_AMPLIFICATION:
        event["escalated"] = True
        event["escalation_reason"] = "MAX_WITHDRAWAL_AMPLIFICATION_EXCEEDED"
        # We still record the event, but we pass an empty withdrawal ledger update
        await backend.apply_withdrawal_transaction(event, [])
    else:
        await backend.apply_withdrawal_transaction(event, w_r)
