from .base import DetectorAdapter
from typing import Optional, Tuple
from datetime import datetime, timezone


# Detectors whose findings indicate retroactive tampering regardless of action
_TAMPER_DETECTORS = {"protected_key"}

# Operations that indicate the content was already stored
_POST_STORE_OPERATIONS = frozenset({"read", "lifecycle", "integrity_check"})


class AMGAdapter(DetectorAdapter):
    """Maps OWASP Agent Memory Guard SecurityEvents to GASC DesignationEvents.

    The critical distinction: events where AMG BLOCKED a write at ingress
    are NOT designations (the poison never landed, C(p) is empty). Only
    events indicating retroactive detection of already-committed content
    produce designations.
    """

    def source_class(self) -> str:
        return "amg_tamper_check"

    async def to_designation(self, raw_event: dict) -> Tuple[Optional[dict], Optional[str]]:
        action = raw_event.get("action", "").lower()
        operation = raw_event.get("operation", "write").lower()
        detector = raw_event.get("detector", "")
        metadata = raw_event.get("metadata", {})

        # Resolve GASC node_id from the event
        node_id = raw_event.get("gasc_node_id") or metadata.get("gasc_node_id")
        if not node_id:
            return None, "no gasc_node_id in event or metadata"

        # --- Ingress blocks: AMG prevented the write, nothing to contain ---
        if action == "allow":
            return None, f"action=allow, no threat detected"
        if action == "redact":
            return None, f"action=redact, content modified at ingress, not a designation"
        if action == "block" and operation == "write":
            return None, f"ingress block: AMG blocked write before storage (detector={detector})"

        # --- Retroactive detection: content already committed ---
        is_designation = False
        reason_parts = []

        # Protected-key tampering: SHA-256 baseline mismatch on immutable key
        if detector in _TAMPER_DETECTORS:
            is_designation = True
            reason_parts.append(f"SHA-256 baseline tampering detected by {detector}")

        # Quarantine of already-stored content (not an ingress write block)
        if action == "quarantine" and operation != "write":
            is_designation = True
            reason_parts.append(f"quarantine of stored content (operation={operation})")

        # Self-reinforcement that wasn't blocked at ingress
        if detector == "self_reinforcement" and action != "block":
            is_designation = True
            reason_parts.append(f"self-reinforcement loop detected (action={action})")

        # Lifecycle retirement (retire_if predicate)
        if operation == "lifecycle" and metadata.get("pre_snapshot_id"):
            is_designation = True
            reason_parts.append(f"retire_if predicate fired (snapshot={metadata['pre_snapshot_id']})")

        if not is_designation:
            return None, f"event does not indicate retroactive detection (action={action}, operation={operation}, detector={detector})"

        # Map severity to confidence score
        severity_map = {"critical": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5, "info": 0.3}
        severity = raw_event.get("severity", "medium")
        if isinstance(severity, str):
            confidence = severity_map.get(severity.lower(), 0.7)
        else:
            confidence = 0.7

        timestamp = raw_event.get("timestamp")
        if isinstance(timestamp, (int, float)):
            detected_at = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() + "Z"
        else:
            detected_at = raw_event.get("detected_at_utc", datetime.now(timezone.utc).isoformat() + "Z")

        return {
            "poisoned_node_id": node_id,
            "detected_at_utc": detected_at,
            "source": "amg_tamper_check",
            "confidence_score": confidence,
            "reason": "; ".join(reason_parts),
        }, None
