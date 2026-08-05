# Recovery Semantics in Multi-Agent Shared Stores

**Status:** Draft / Outline
**Target:** OWASP AMG Documentation (Post v1.0.0 Multi-Agent Roadmap)

## 1. Introduction
- Definition of the problem: In a single-agent context, snapshot/rollback is mathematically sound. In a multi-agent context, shared state introduces a latency window between a poisoned write and detection.
- The Core Conflict: During this window, honest agents read the poisoned value and write derived records. 
- Why traditional rollback fails:
  - **Option A (Full Rollback):** Destroys all honest work done since the poisoned write (collateral damage).
  - **Option B (Targeted Key Rollback):** Leaves derived records intact, which now carry contamination with clean provenance and no detector signal (laundering).

## 2. Theoretical Foundation
- Distinguish between **Material edges** (data derivation) and **Incidental edges** (read-only observations).
- Mention that tracking provenance across shared state requires explicitly linking derived writes to their upstream dependencies.

## 3. The Forward-Construction Approach
- **Concept:** Instead of rolling back the state (which breaks historical monotonicity), treat recovery as an append-only forward-construction problem.
- **Mechanism:**
  - Isolate and quarantine the poisoned root and all its causal descendants (the blast radius).
  - Emit a *replacement record* under a new identity, derived purely from provably uncontaminated sources.
  - Leave the quarantined original in place as evidence (auditability).
- **Tradeoffs:**
  - Costs more compute to perform re-derivation.
  - May fail closed (irreducibility) if no clean derivation path exists. (Note: A substantial fraction of governed targets may turn out to be irreducible depending on the task).

## 4. Implementation Guidelines for Shared Stores
- **Idempotency and Side Effects:** Forward-construction requires robust idempotency keys to ensure that re-deriving a state doesn't duplicate external side effects (e.g., double payments).
- **Lineage Metadata:** Shared stores must require agents to declare the upstream dependencies they read when committing a write (`parent_dependency_commitments`), allowing the platform to compute the true blast radius.

## 5. Conclusion
- Summary of why forward-construction (despite its fail-closed irreducibility) is the only mathematically sound approach to maintaining integrity in shared agent state.
