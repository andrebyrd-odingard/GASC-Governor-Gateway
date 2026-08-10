from .base import DetectorAdapter
from typing import Optional, Tuple
from datetime import datetime, timezone


class HumanReportAdapter(DetectorAdapter):
    """Trivial adapter: a human or incident channel names a node."""

    def source_class(self) -> str:
        return "human_report"

    async def to_designation(self, raw_event: dict) -> Tuple[Optional[dict], Optional[str]]:
        node_id = raw_event.get("node_id")
        if not node_id:
            return None, "missing required field: node_id"

        return {
            "poisoned_node_id": node_id,
            "detected_at_utc": raw_event.get("detected_at_utc",
                                               datetime.now(timezone.utc).isoformat() + "Z"),
            "source": "human_report",
            "confidence_score": float(raw_event.get("confidence_score", 1.0)),
            "reason": raw_event.get("reason", "Human-reported incident"),
        }, None
