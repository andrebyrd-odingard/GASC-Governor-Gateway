# Design: The `CARRIED` Edge Class and `COMPACTION` Nodes

**Status:** Draft — non-normative
**Applies to:** GASC-ED v1.2+ / GASC-Governor-Gateway
**Grounding:** CSR-PUB-0001b (soundness boundary, over-containment), CSR-PUB-0002 §7.4 Table 4 (policy comparison), CSR-PUB-0004 §4 (repair architecture), CSR-PUB-0005 §7.3 (conformance)

> [!WARNING]
> **Auditability, not availability (CDoS is not avoided yet).** 
> The current Gateway implementation lacks an internal LLM to execute R1-R5 (reconstruction). As a result, all `COMPACTION` nodes are disposed as `IRREDUCIBLE`. This means their downstream descendants are blindly swept into the blast radius `C(p)`. The containment footprint is thus identical to treating `CARRIED` edges as `MATERIAL` edges. This implementation provides auditability (a typed disposition and an escalation record) but does NOT yet avoid Containment Denial of Service (CDoS). Avoidance only arrives when R1-R5 can actually re-derive.

---

## 1. The problem

Long-running agents compact context. When a session's history is summarized, dependencies that existed as observed reads are replaced by a summary that records no edges. Under the current model those dependencies are carried across the boundary **without a re-read**, which is exactly the condition CSR-PUB-0001b §5 measured:

| Carry fraction | 0.00 | 0.25 | 0.50 | 0.75 | 1.00 |
|---|---|---|---|---|---|
| Mean cross-session recall | 100% | 83% | 65% | 35% | 3% |

Anything surviving only as summary sits at carry fraction ≈ 1.0. Measured recall: **3%**. The containment guarantee effectively ends at the compaction boundary, silently.

This is not a corner case. Compaction is the default architecture of every long-horizon agent harness, and independent measurement confirms the lineage loss: a benchmark of 36,611 production messages found all three tested summarization approaches scored 2.19–2.45 out of 5.0 on artifact tracking — freeform summaries silently discard precise technical detail. The same phenomenon appears in the memory-poisoning literature as a named write channel ("compaction-driven write").

## 2. Why the obvious fix is worse than the bug

The obvious fix is to make the compaction a node whose `parent_dependency_commitments` list everything it summarized, at full strength.

**Do not ship this.** Under `exact-observed-reachable` traversal, any poison anywhere in the compaction span puts the compaction node in `C(p)`, and therefore every node derived after the boundary. Since the post-boundary session derives from the summary by construction, `C(p)` becomes the entire remainder of the session, deterministically, on every compaction.

CSR-PUB-0001b already measured 92% over-containment (7.7% precision) for an early poison in an independent-chain topology and identified that shape as containment denial-of-service. Full-strength compaction edges convert that from a worst case into the **guaranteed** case: every compaction boundary becomes a hub that a single upstream poison saturates.

We would be shipping the attack CSR-PUB-0002 defined.

## 3. Why the *second* obvious fix is also wrong

The next instinct is to stop traversal at the boundary — don't propagate past a compaction node. That is depth-bounding, and CSR-PUB-0002 Table 4 already measured what depth-bounding costs:

| Policy | CPI | WCAL | RER | ALF |
|---|---|---|---|---|
| exact-observed-reachable | 1.000 | 1.000 | **0.000** | 3,301.3 |
| full-memory-invalidation | 1.000 | 1.000 | **0.000** | 3,333.3 |
| dependency-strength-aware | 0.952 | 0.953 | **0.000** | 1,603.3 |
| session-termination | 0.250 | 0.253 | 0.750 | 833.3 |
| criticality-aware | 0.289 | 0.069 | 0.332 | 289.3 |
| time-window-bounded | 0.006 | 0.005 | 0.994 | 21.7 |
| depth-bounded | 0.007 | 0.008 | 0.968 | 17.7 |

Depth-bounded gets leverage down to 17.7 — and leaves **96.8% residual exposure**. Time-window-bounded is worse at 99.4%. Both policies buy their small footprint by failing to contain nearly all material taint. Truncating at the compaction boundary is the same trade under a different name.

The load-bearing observation from Table 4 is this: **`dependency-strength-aware` is the only policy that reduces leverage while holding RER at exactly zero.** It cuts median ALF roughly in half against exact traversal (1,603.3 vs 3,301.3) at CPI 0.952, with no residual exposure admitted.

That is the mechanism class compaction belongs in. Not depth. Not time. Strength.

> **Scope caveat.** Table 4 measured strength-aware containment over the frozen CSR-BENCH-1.0 population with authored synthetic dependency truth and no compaction construct. That a strength mechanism transfers to compaction edges is a **design hypothesis**, not a parent result, and must be labeled as such wherever it appears. CSR-PUB-0005 §10 records recommendations of this kind as design inferences.

## 4. Specification

### 4.1 Edge classes

Every entry in `parent_dependency_commitments` gains a required `edge_class`:

| Class | Meaning | Propagation |
|---|---|---|
| `MATERIAL` | Declared, direct data dependency | Full strength |
| `INCIDENTAL` | Observed read, not known to be used (the no-clear-scope population) | Full strength; labeled for measurement |
| `CARRIED` | Dependency surviving only through a compaction boundary | See §4.3 |

`INCIDENTAL` is not a behavior change — it labels the population CSR-PUB-0001b identified as the dominant source of over-containment (precision 38.7% even at zero ignored reads). Labeling it lets us report precision by edge class instead of in aggregate.

### 4.2 The `COMPACTION` node

```json
{
  "node_type": "COMPACTION",
  "payload_id": "<fresh identity>",
  "boundary_id": "<stable id for this compaction event>",
  "covers": ["<node ids in the compacted span>"],
  "parent_dependency_commitments": [
    { "parent_node_id": "...", "edge_class": "CARRIED" }
  ],
  "content_digest_sha256": "<digest of the summary text>",
  "summarizer": { "method_id": "...", "config_digest": "..." }
}
```

`covers` and `parent_dependency_commitments` are distinct on purpose: `covers` is the audit record of the span, `parent_dependency_commitments` is what traversal uses. `boundary_id` is chosen to align with the lineage field under discussion in the Agent Client Protocol (`compactedThroughMessageId`), so an upstream adopter can populate it without knowing about GASC-ED.

`summarizer.method_id` and `config_digest` exist because §4.3 may need to re-run it.

### 4.3 Propagation rule for `CARRIED`

**A `COMPACTION` node reached through a `CARRIED` edge does not propagate taint directly. It enters `repair-candidate` and is routed through the governed reconstruction path.**

This is the key move. A compaction node is not a pass-through — it is a *re-derivation* of new content from a set of sources under a new identity. That is structurally identical to what CSR-PUB-0004 §4 already specifies for repair. So we do not need a new mechanism; we need to route compaction through the mechanism we already built.

On designation of poison `p` where `C(p)` intersects `covers`:

1. **R1 — Admissible frontier.** Compute `covers \ C(p)`. Emit the included set, its digest, and a reason for every exclusion. Uncertainty fails closed.
2. **R2 — Planner.** Select `deterministic recomputation` if `summarizer.method_id` is available and re-runnable; otherwise `verified checkpoint reconstruction` against a pre-boundary checkpoint; otherwise `fail-closed escalation`.
3. **R3 — Reconstruction.** Re-summarize the admissible frontier. Emit under **new identity**. The original `COMPACTION` node stays quarantined-historical; it is never rewritten.
4. **R4 — Verifier.** Second derivation path re-derives the frontier and the method selection independently (Python planner / Rego verifier). Disagreement is typed rejection, no tie-break.
5. **R5 — Reintegration gate.** Prove against the proposed post-reintegration graph that no path runs from historical quarantine into trusted active state through the new node. Admit atomically.
6. **Irreducible.** If no admissible method exists — summarizer unavailable, non-deterministic, or the excluded content is load-bearing to the summary — the target is **irreducible**. Decline reconstruction, escalate, and quarantine the post-boundary subtree.

The post-boundary session is swept **only** in the irreducible case. In the reducible case the session continues on a re-derived summary with fresh identity and complete provenance against the declared boundary.

### 4.4 Degraded mode

Where the reconstruction path is unavailable (no summarizer, no checkpoint, deployment declines to run R1–R5), `CARRIED` edges fall back to strength-aware propagation under the `dependency-strength-aware` policy, with the strength of a `CARRIED` edge set below `MATERIAL`. This is the Table 4 trade, and it must be reported as a degraded configuration, not the default.

**Never** fall back to depth- or time-bounded truncation. Table 4 shows both leak (RER 0.968 / 0.994).

## 5. Conformance mapping (CSR-PUB-0005 §7.3)

| Row | Effect of this design |
|---|---|
| 1 — Traceability | `CARRIED` is a declared dependency class. Disclosure clause ("which classes of dependency are outside the boundary") is answered by naming carry channels that remain uninstrumented. |
| 2 — Transitive containment | `C(p)` must include the `COMPACTION` node when the span intersects. Recomputation from an independent snapshot must reproduce it. |
| 3 — Historical monotonicity | The original compaction node is never released or rewritten. The re-derived node is a new identity with its own reintegration fact. |
| 5 — Governed reconstruction | Compaction re-derivation is a reconstruction and carries the same provenance-completeness obligation against `D`. |
| 6 — Verification separation | Frontier re-derivation in Rego is a genuinely different evaluation engine and serializer; the shared-dependency inventory must record the shared SHA-256 primitive and type declarations. |
| 9 — Irreducibility | Compaction irreducibility is a typed disposition with reason and escalation record, reported with its denominator. |

## 6. New adversarial surface this creates

Making compaction a governed transition creates a lever an adversary can pull. Two variants worth naming and testing:

- **Boundary forcing.** An adversary who can influence context growth can force an early compaction to maximize the `CARRIED` population, then poison upstream. This is a CDoS variant against a defensive mechanism — the same shape CSR-PUB-0002 defined, aimed at the compaction gate rather than the containment gate.
- **Representation laundering.** An adversary places poison such that its content is materially represented in the summary while its identity is not in `covers` — the dependency-hiding adversary of CSR-PUB-0001 §5.3, specialized to summarization. Unsolved there; unsolved here. State it.

The CSR-PUB-0002 taxonomy is frozen at eight classes, so these are new-work items, not amendments.

## 7. What must be measured before this is claimed

Non-vacuity requires exercise, not implementation. Minimum:

- **Reducibility rate of compaction boundaries** — what fraction reach R5 vs. dispose irreducible. Report with denominator and reason distribution, as CSR-PUB-0004 did for its ~38.7%.
- **Recall recovery** — cross-session recall with `CARRIED` edges instrumented, against the 3% baseline at carry fraction 1.0.
- **Over-containment by edge class** — precision for `MATERIAL` / `INCIDENTAL` / `CARRIED` separately. Aggregate precision hid the no-clear-scope effect in 0001b; do not repeat that.
- **Re-derivation fidelity.** Open risk: summarization already loses artifact detail (2.19–2.45 / 5.0). Re-summarizing a *reduced* frontier may lose more. If a re-derived summary degrades task performance, R3 has restored provenance while destroying function — which CSR-PUB-0004's TFR result (median paired difference 0.000) already warns is a real outcome.
- **Cost.** Compaction re-derivation is an LLM call on the incident path. Latency and token cost belong in the Repair Burden vector.

## 8. Open questions

1. Is `deterministic recomputation` ever honest for an LLM summarizer? A frozen `config_digest` plus temperature 0 is reproducible-ish, not deterministic. If not, R2 should never select it and checkpoint reconstruction becomes the only real path.
2. Should `covers` be required to be complete? A summarizer that omits a node from `covers` produces a silently narrower declared boundary — the §6.1.1 narrowing problem, in a place where the system under audit does not choose it.
3. Does the re-derived summary inherit the original `boundary_id`, or get a new one? Monotonicity argues for new; downstream references argue for a forwarding record.

---

**Bottom line:** compaction is not an edge case to be truncated. It is the most common governed transition in a long-running agent, and treating it as one turns the reconstruction machinery from CSR-PUB-0004 into the load-bearing path rather than an unimplemented README claim.
