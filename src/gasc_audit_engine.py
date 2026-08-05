#!/usr/bin/env python3
"""
GASC-ED v1.1 Automated Audit Engine (SPEC-009 Section 3 Compliance)
Executes row-by-row verification over platform telemetry logs.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any


class GASCAuditEngine:
    def __init__(self, audit_manifest_path: str):
        with open(audit_manifest_path, 'r') as f:
            self.manifest: Dict[str, Any] = json.load(f)
        
        self.results: List[Dict[str, Any]] = []
        self.not_exercised_count = 0
        self.self_attested_count = 0
        self.disclosed_rows: List[str] = []

    def audit_req_001_traceability(self) -> Dict[str, Any]:
        """REQ-001: Integrity-Bound Lineage"""
        writes = self.manifest.get("admitted_writes", [])
        if not writes:
            self.not_exercised_count += 1
            return {"req_id": "GASC-REQ-001", "status": "NOT-EXERCISED", "reason": "No admitted records submitted."}
        
        valid_writes = 0
        for w in writes:
            has_boundary = bool(w.get("declared_evidence_boundary"))
            has_deps = len(w.get("parent_dependency_commitments", [])) >= 1
            if has_boundary and has_deps:
                valid_writes += 1

        pass_rate = valid_writes / len(writes)
        status = "PASS" if pass_rate == 1.0 else "FAIL"
        return {
            "req_id": "GASC-REQ-001",
            "status": status,
            "metrics": {"total_writes": len(writes), "valid_lineage_fraction": pass_rate}
        }

    def audit_req_002_transitive_containment(self) -> Dict[str, Any]:
        """REQ-002: Transitive Containment (Requires Second Source per Rule 2)"""
        incidents = self.manifest.get("quarantine_incidents", [])
        if not incidents:
            self.not_exercised_count += 1
            return {"req_id": "GASC-REQ-002", "status": "NOT-EXERCISED", "reason": "No poison incidents occurred."}

        for inc in incidents:
            second_source = inc.get("independent_snapshot_hash")
            if not second_source:
                self.self_attested_count += 1
                return {
                    "req_id": "GASC-REQ-002",
                    "status": "SELF-ATTESTED",
                    "reason": "Rule 2 Violation: Missing independent graph snapshot second source."
                }
            
            # Verify poisoned node is inside computed C(p)
            c_p = inc.get("computed_blast_radius_C_p", [])
            if inc.get("poisoned_root_id") not in c_p:
                return {"req_id": "GASC-REQ-002", "status": "FAIL", "reason": "Poisoned root missing from C(p)."}

        return {"req_id": "GASC-REQ-002", "status": "PASS", "incidents_evaluated": len(incidents)}

    def audit_req_003_monotonicity(self) -> Dict[str, Any]:
        """REQ-003: Historical Monotonicity"""
        transitions = self.manifest.get("quarantine_transitions", [])
        if not transitions:
            self.not_exercised_count += 1
            return {"req_id": "GASC-REQ-003", "status": "NOT-EXERCISED", "reason": "Quarantine set remained empty."}

        for i in range(len(transitions) - 1):
            q_t = set(transitions[i]["quarantine_set"])
            q_next = set(transitions[i+1]["quarantine_set"])
            if not q_t.issubset(q_next):
                return {
                    "req_id": "GASC-REQ-003",
                    "status": "FAIL",
                    "reason": f"Monotonicity breach between transition {i} and {i+1}."
                }

        return {"req_id": "GASC-REQ-003", "status": "PASS", "transitions_checked": len(transitions)}

    def audit_req_006_verification_separation(self) -> Dict[str, Any]:
        """REQ-006: Verification Separation"""
        campaign = self.manifest.get("fault_injection_campaign")
        if not campaign or not campaign.get("preregistered_suite_run"):
            self.disclosed_rows.append("GASC-REQ-006")
            return {
                "req_id": "GASC-REQ-006",
                "status": "CONFORMANT-WITH-DISCLOSURE",
                "reason": "Fault injection suite not run. Disclosed per Rule 3."
            }

        shared_deps_inventory = campaign.get("shared_dependency_inventory_published", False)
        if not shared_deps_inventory:
            return {
                "req_id": "GASC-REQ-006",
                "status": "FAIL",
                "reason": "Separation claim unfalsifiable: Shared dependency inventory missing."
            }

        catch_rate = campaign.get("observed_catch_rate", 0.0)
        target_rate = campaign.get("preregistered_target_catch_rate", 1.0)
        
        status = "PASS" if catch_rate >= target_rate else "FAIL"
        return {
            "req_id": "GASC-REQ-006",
            "status": status,
            "metrics": {"observed_catch_rate": catch_rate, "preregistered_target": target_rate}
        }

    def run_full_audit(self) -> Dict[str, Any]:
        results = [
            self.audit_req_001_traceability(),
            self.audit_req_002_transitive_containment(),
            self.audit_req_003_monotonicity(),
            self.audit_req_006_verification_separation()
        ]
        
        # Rule 3 Enforcement: Max 2 disclosures allowed; cannot cover REQ-002, 003, 006
        illegal_disclosures = [r for r in self.disclosed_rows if r in ["GASC-REQ-002", "GASC-REQ-003", "GASC-REQ-006"]]
        audit_failed_by_rule3 = len(illegal_disclosures) > 0 or len(self.disclosed_rows) > 2

        return {
            "audit_metadata": {
                "specification_version": "GASC-ED v1.1",
                "audited_at_utc": datetime.now(timezone.utc).isoformat(),
                "operating_envelope": self.manifest.get("operating_envelope_declaration", "UNSTATED"),
                "declared_evidence_boundary_id": self.manifest.get("boundary_id", "UNKNOWN")
            },
            "conformance_summary": {
                "overall_audit_passed": not audit_failed_by_rule3 and all(r["status"] in ["PASS", "NOT-EXERCISED", "CONFORMANT-WITH-DISCLOSURE"] for r in results),
                "total_requirements_evaluated": len(results),
                "not_exercised_count": self.not_exercised_count,
                "self_attested_count": self.self_attested_count,
                "disclosed_rows": self.disclosed_rows,
                "rule_3_compliance_breached": audit_failed_by_rule3
            },
            "row_by_row_results": results
        }


if __name__ == "__main__":
    # Example execution schema
    import tempfile
    dummy_manifest = {
        "boundary_id": "BOUNDARY-PROD-2026-A",
        "operating_envelope_declaration": "Production Multi-Agent Supply Chain Engine (Max 50 Nodes)",
        "admitted_writes": [
            {
                "declared_evidence_boundary": {"boundary_id": "B1"},
                "parent_dependency_commitments": [{"parent_node_id": "N1"}]
            }
        ],
        "quarantine_incidents": [],
        "quarantine_transitions": [],
        "fault_injection_campaign": {
            "preregistered_suite_run": True,
            "shared_dependency_inventory_published": True,
            "observed_catch_rate": 0.98,
            "preregistered_target_catch_rate": 0.95
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as tmp:
        json.dump(dummy_manifest, tmp)
        manifest_path = tmp.name

    engine = GASCAuditEngine(manifest_path)
    print(json.dumps(engine.run_full_audit(), indent=2))
