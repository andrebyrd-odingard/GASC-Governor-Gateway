from abc import ABC, abstractmethod
from typing import Optional, Tuple


class DetectorAdapter(ABC):
    """Maps a foreign detector's event format to a GASC DesignationEvent."""

    @abstractmethod
    def source_class(self) -> str:
        """Return the DesignationSource value this adapter produces."""
        ...

    @abstractmethod
    async def to_designation(self, raw_event: dict) -> Tuple[Optional[dict], Optional[str]]:
        """Map a foreign event to DesignationEvent fields, or None if not a designation.

        Returns a dict with keys: poisoned_node_id, detected_at_utc, source,
        confidence_score, reason.  Returns None (with a reason string) when
        the event should be dropped (e.g. an ingress block).

        Returns:
            tuple: (designation_dict_or_None, drop_reason_or_None)
        """
        ...
