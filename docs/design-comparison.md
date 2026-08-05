# Design Comparison: GASC-ED vs OWASP Agent Memory Guard (AMG)

## Overview

OWASP Agent Memory Guard (AMG) and GASC-ED approach multi-agent security from different ends of the lifecycle. AMG is primarily a **write-time ingress gate**, relying on point-in-time snapshot rollbacks for recovery. GASC-ED is a **late-detection recovery layer**, relying on mathematically rigorous monotonic quarantine and fail-closed reconstruction.

This document serves as a tradeoff analysis between the two paradigms, explicitly positioning them as complementary defenses rather than competing alternatives.

## Ingress Gating vs. Late Detection

AMG intercepts memory writes and screens them against a pipeline of detectors. If poison is detected *at write time*, AMG blocks the write. The poison is never committed, the blast radius is `C(p) = {p}`, and no downstream honest agents consume it. For this 92.5% of poison, AMG is the optimal defense.

GASC-ED is designed for the remaining 7.5%—the poison that AMG misses, which is only detected **arbitrarily later** after honest agents have already consumed, re-expressed, and derived new state from it. At this point, the blast radius `C(p)` spans a topological web of downstream consequences.

## Snapshot Rollback vs. Monotonic Quarantine

When late detection occurs, AMG relies on point-in-time snapshots, allowing an operator to roll the memory state back to a known-good checkpoint. 

GASC-ED objects to this recovery semantics based on the principles of **Historical Monotonicity** (CSR-PUB-0005 §4). Rolling back a snapshot deletes the audit trail of what happened in the interim. A malicious payload and its downstream consequences are permanently erased from the ledger, destroying the forensic record of the attack propagation.

GASC-ED enforces **Monotonic Quarantine**:
1. The historical timeline is immutable.
2. Detected poison and its topologically reachable descendants are placed in a quarantined state.
3. Recovery occurs not by rollback, but by **Reconstruct-Forward**: honest state is re-derived from an unpoisoned frontier and committed under a fresh identity, preserving the topological audit trail of the attempted attack while guaranteeing structural isolation.

## Conformance Notes for GASC-Governor-Gateway

The GASC-Governor-Gateway is a reference implementation of the GASC-ED v1.1 specification. 

However, because the Gateway lacks an internal LLM to execute R1-R5 (reconstruction), it defaults to default irreducibility (sweeping all descendants). 

Therefore, under CSR-PUB-0005 §7.3, the following conformance rows are currently scored as **NOT-EXERCISED**:
- **Row 5 (Governed reconstruction)**: The reconstruction path is not exercised.
- **Row 9 (Irreducibility)**: Because the irreducible fraction is 100% by construction, the non-vacuity condition (at least one target disposed in *each* direction) cannot be met.
