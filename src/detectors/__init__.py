from .base import DetectorAdapter
from .human_report import HumanReportAdapter
from .amg import AMGAdapter

DETECTOR_REGISTRY: dict[str, DetectorAdapter] = {
    "human_report": HumanReportAdapter(),
    "amg": AMGAdapter(),
}

__all__ = ["DetectorAdapter", "HumanReportAdapter", "AMGAdapter", "DETECTOR_REGISTRY"]
