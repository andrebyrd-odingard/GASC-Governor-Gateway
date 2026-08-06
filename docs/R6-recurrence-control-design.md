# Design: R6 — Recurrence Control

**Status:** Draft for review — non-normative
**Target:** GASC-Governor-Gateway, post-`v1.4.0` (`93f542c`)
**Implements:** CSR-PUB-0004 §4 R6, CSR-PUB-0005 §6.3, §7.2 row 8
**Verified against:** live clone @ `93f542c`, 66 tests passing, 0 skipped

---

## 0. Why this is the last piece

The Gateway currently performs a **one-shot** recovery: designate → contain → frontier → plan → reconstruct → verify → admit. Nothing ever revisits admitted state.

That is the exact configuration CSR-PUB-0004 measured as unstable. H6 failed because governed recurrence exceeded substitute reconstruction beyond the frozen 0.005 non-inferiority margin — composition bought coverage and cost recurrence. The platform today has the coverage gain and none of the recurrence control that failure calls for.

Rows 4 and 8 are the only §7.2 requirements with no mechanism at all. This document covers row 8.

---

## 1. The core design decision: expiry first, withdrawal second

The obvious implementation is a monitor that watches for recurrence and withdraws affected state. **That design has a 25-year failure record in an adjacent field, and we should not repeat it.**

### 1.1 What PKI learned the hard way

Certificate revocation is the same problem: state was admitted as trusted, later found untrustworthy, and every relying party must stop trusting it.

The industry tried, in order: CRLs (too large), OCSP (too slow, ~300 ms median), OCSP stapling (frequently misconfigured, stapled responses expire), and vendor-specific lists like CRLSets (only "important" revocations). Every one of them landed on **soft-fail**: if the revocation check doesn't answer, trust the certificate anyway.

Adam Langley's description is the one that matters here — soft-fail revocation is *a seatbelt that snaps in a crash*. It stops working at exactly the moment it is needed, because an attacker who can present bad state can usually also suppress the check. Mozilla reported nearly half of their system failures came from the revocation infrastructure itself.

Hard-fail is not the fix either: it makes every monitor outage a total outage.

**The resolution the industry actually reached was neither. It was short lifetimes.** CA/Browser Forum is driving certificate validity to 47 days; SPIFFE/SPIRE defaults to roughly one hour. Trust expires on its own, so revocation stops being load-bearing.

### 1.2 What that means for R6

> **Reintegrated state carries a bounded trust lifetime. It is not trusted past its horizon unless re-attested. Withdrawal is the fast path, not the safety property.**

Concretely, every record admitted through R5 gets `trust_expires_at = admitted_at + continuation_horizon`. After that instant it is not eligible for trusted use until a renewal attestation is recorded.

This inverts every failure mode above:

| Failure | Withdrawal-only design | Expiry-first design |
|---|---|---|
| Monitor is down | Admitted state stays trusted indefinitely — soft-fail hole | State expires on schedule; unavailability is the safe direction |
| Attacker suppresses the recurrence signal | Suppression works | Suppression only delays; expiry still fires |
| Withdrawal record lost or never propagated | Stale trust persists | Bounded by the horizon |
| Ledger growth | Grows forever, like a CRL | Expired entries need no permanent broadcast |

CSR-PUB-0004 already defines a "frozen continuation horizon." This design makes that horizon **semantically load-bearing** rather than merely the window in which a monitor happens to be looking.

**Do not implement soft-fail anywhere in this component.** If the monitor cannot answer, the answer is not-trusted.

---

## 2. Scope

**In scope:** detection and typing of recurrence against reintegrated state; transitive withdrawal; trust expiry and renewal; seeded-recurrence calibration; row 8 evidence emission.

**Out of scope:** producing the recurrence signal from semantic analysis (R6 consumes signals, as TTP consumes designation events); anything touching rows 4, 5, or 7; external side effects (already non-claimed).

---

## 3. Recurrence classes

CSR-PUB-0004 R6 names four. Each needs a distinct detection path, because they arrive from different places.

| Class | Trigger | Source |
|---|---|---|
| `RENEWED_DESIGNATION` | A new `/designate` names a reintegrated node, or its `C(p)` contains one | Internal — falls out of the existing designation path |
| `PROHIBITED_PATH` | A path from historical quarantine into active state is discovered through an admitted node | Internal — re-run of the R5 graph-safety predicate |
| `VERIFIER_CONTRADICTION` | The adapter later disagrees with a candidate it previously signed | External — adapter-initiated |
| `FUNCTIONAL_FAILURE` | The reconstructed record fails in use | External — application-initiated |

The first two are computable from state the Gateway already holds and should fire automatically. The last two require an inbound signal.

**`PROHIBITED_PATH` is the highest-value one and is nearly free.** R5 proves no prohibited path exists *at admission time*. The graph keeps growing afterward. A later write can create a path that did not exist when the gate ran. Re-running the R5 predicate over the active horizon set on every commit is the single cheapest real recurrence detector available, and it needs no external signal at all.

---

## 4. Transitive withdrawal, and the amplification problem

### 4.1 The rule

CSR-PUB-0005 §6.3 is unambiguous: withdrawal is transitive for the same reason contamination is. Every dependent of a withdrawn record is re-examined; a dependent that cannot be shown unaffected is withdrawn; **one left un-examined is withdrawn by default.**

### 4.2 Why that rule, implemented naively, destroys the system

Default-withdraw-if-unexamined over a forward closure is a positive feedback loop. It is structurally identical to the retry-storm pattern that produces cascading failure in distributed systems: a small trigger, an amplifying response, and no damping term.

Worse, it hands an adversary a new lever. CSR-PUB-0002 defines CDoS-0006 as strategic poison **designation** — high-reach false designation. R6 introduces *strategic recurrence designation*: one crafted `FUNCTIONAL_FAILURE` signal against a well-placed reintegrated node withdraws its entire forward closure. Given CSR-PUB-0001b measured ~92% over-containment for a well-placed early poison, the expected damage is comparable, and the attacker's cost is one HTTP request instead of a compromised agent.

Add the base-rate problem (Axelsson, already cited in CSR-PUB-0002's references): recurrence is rare, so even a good monitor produces mostly false positives, each of which triggers a full transitive sweep.

### 4.3 The circuit breaker

Withdrawal must be **bounded and interruptible**:

1. **Amplification bound.** `MAX_WITHDRAWAL_AMPLIFICATION` (default 100): if `|W(r)| / |directly implicated|` exceeds it, **stop and escalate**. Do not withdraw. Emit `WITHDRAWAL_ESCALATED` with the computed closure attached for human decision. This is irreducibility applied to withdrawal — unavailable-but-honest over an automated mass action.
2. **Signal authority.** `VERIFIER_CONTRADICTION` and `FUNCTIONAL_FAILURE` require the `designator` role, same as `/designate`. `VERIFIER_CONTRADICTION` additionally requires an ECDSA signature verifying against `RECOVERY_ADAPTER_PUBLIC_KEY` — only the adapter that signed a candidate may contradict it.
3. **Rate limiting.** A per-identity cap on recurrence signals per horizon. Exceeding it escalates rather than processing.
4. **Withdrawal is not quarantine.** Withdrawn state enters `recurrence-quarantined` — a distinct ninth state from Paper 4. It is not merged into the historical quarantine ledger. The original repair decision is never rewritten (§6.3).

**The 100 default is a guess and must be labeled as one.** It should be calibrated against the seeded-recurrence harness (§6) and reported, not asserted.

---

## 5. Data model and API

Written against the verified `v1.4.0` structures.

### 5.1 Config (`src/config.py`)

```python
CONTINUATION_HORIZON_SECONDS: int = 86400   # declared, finite, never unbounded
MAX_WITHDRAWAL_AMPLIFICATION: int = 100     # circuit breaker; calibrate, don't assume
RECURRENCE_SIGNAL_RATE_LIMIT: int = 10      # per identity per horizon
TRUST_RENEWAL_REQUIRED: bool = True         # expiry-first; False is a documented downgrade
```

### 5.2 SQLite tables (`src/sqlite_backend.py`)

```sql
CREATE TABLE IF NOT EXISTS reintegration_horizon (
    node_id           TEXT PRIMARY KEY,
    admitted_at_utc   TEXT NOT NULL,
    trust_expires_utc TEXT NOT NULL,
    predecessor_id    TEXT NOT NULL,   -- the quarantined original; never reactivated
    renewal_count     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_horizon_expiry ON reintegration_horizon(trust_expires_utc);

CREATE TABLE IF NOT EXISTS recurrence_events (
    event_id        TEXT PRIMARY KEY,
    node_id         TEXT NOT NULL,
    recurrence_class TEXT NOT NULL,
    detected_at_utc TEXT NOT NULL,
    signal_source   TEXT NOT NULL,   -- identity that raised it
    event_json      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS withdrawal_ledger (   -- append-only, mirrors quarantine_ledger
    node_id        TEXT PRIMARY KEY,
    withdrawn_at_utc TEXT NOT NULL,
    triggering_event_id TEXT NOT NULL,
    withdrawal_reason   TEXT NOT NULL   -- DIRECTLY_IMPLICATED | UNEXAMINED_DEPENDENT | EXAMINED_AFFECTED
);

CREATE TABLE IF NOT EXISTS calibration_runs (
    run_id          TEXT PRIMARY KEY,
    run_at_utc      TEXT NOT NULL,
    seeded_count    INTEGER NOT NULL,
    detected_count  INTEGER NOT NULL,
    sensitivity_floor REAL NOT NULL,
    monitored_period_json TEXT NOT NULL
);
```

### 5.3 Backend interface (`src/state_backend.py`)

```python
@abstractmethod
async def record_reintegration(self, node_id: str, predecessor_id: str, horizon_seconds: int): pass
@abstractmethod
async def get_active_horizon_set(self) -> Dict[str, dict]: pass      # unexpired admitted state
@abstractmethod
async def get_expired_horizon_set(self) -> List[str]: pass
@abstractmethod
async def renew_trust(self, node_id: str, horizon_seconds: int): pass
@abstractmethod
async def apply_withdrawal_transaction(self, event: dict, w_r: List[str]): pass
@abstractmethod
async def get_withdrawal_ledger(self) -> Dict[str, dict]: pass
@abstractmethod
async def record_calibration_run(self, run: dict): pass
@abstractmethod
async def get_calibration_runs(self) -> List[dict]: pass
```

`apply_withdrawal_transaction` mirrors `apply_quarantine_transaction` exactly — one atomic append-only transaction, never mutating prior records.

### 5.4 Forward closure

Reuse the existing recursive CTE verbatim. Withdrawal closure is the same forward reachability the blast radius already computes; only the seed and the destination table differ. **Do not write a second traversal.** One traversal, two callers, is also a cleaner story for row 6.

### 5.5 Endpoints

```
POST /observe        role: designator
POST /renew-trust    role: designator
GET  /recurrence-report  role: admin
POST /calibrate      role: admin   (test/staging only; refuses when DEBUG_MODE is False)
```

`POST /observe` body:

```json
{
  "node_id": "...",
  "recurrence_class": "FUNCTIONAL_FAILURE",
  "detected_at_utc": "...",
  "evidence": { },
  "adapter_signature": "..."
}
```

`adapter_signature` is required for `VERIFIER_CONTRADICTION` and verified against `RECOVERY_ADAPTER_PUBLIC_KEY`.

**Internal hooks (no endpoint):**
- `/designate` — after computing `C(p)`, intersect with the active horizon set; any hit raises `RENEWED_DESIGNATION`
- `/submit-candidate` — after commit, re-run the R5 prohibited-path predicate against the active horizon set; any hit raises `PROHIBITED_PATH`

---

## 6. Seeded-recurrence calibration

**Row 8 scores `NOT-EXERCISED` without this, no matter how good the monitor is.** Its non-vacuity condition is that a seeded-recurrence calibration was run over the monitored period, and its invariant requires the monitor to detect seeded recurrences at or above a stated floor.

This is the same trap row 9 was in before the success-path test existed.

`benchmarks/seed_recurrence.py`:

1. Build a graph with known reintegrated nodes
2. Inject *N* recurrences of known class and position — including some outside the horizon and some in unmonitored classes
3. Measure detected / seeded per class
4. Emit `sensitivity_floor`, per-class detection rates, the monitored period, and an explicit list of what is unmonitored
5. Write to `calibration_runs` so `gasc-audit` can read it

**Expect a floor well below 1.0, and report it.** `FUNCTIONAL_FAILURE` detection is entirely dependent on applications reporting failures, which most will not. That is a real limit and it belongs in row 8's disclosure field.

Use the calibration to set `MAX_WITHDRAWAL_AMPLIFICATION` empirically rather than keeping the guess.

---

## 7. Failure modes and mitigations

| # | Failure | Source | Mitigation |
|---|---|---|---|
| 1 | Soft-fail: monitor down, state stays trusted | PKI/OCSP, 25 years | Expiry-first (§1). Monitor unavailability causes expiry, not continued trust |
| 2 | Withdrawal storm from one false signal | Cascading-failure literature; positive feedback | Amplification circuit breaker (§4.3) |
| 3 | Strategic recurrence designation as CDoS | CSR-PUB-0002 CDoS-0006, generalized | Role + signature authority, rate limiting, amplification bound |
| 4 | Base-rate fallacy — most detections false | Axelsson, in CSR-PUB-0002 refs | Calibrated floor; escalation over automated mass withdrawal |
| 5 | Dormant payload outlives the horizon | Trojan Hippo (topic-triggered dormancy) | **Unmitigated.** Declare the horizon; state that recurrence rate is a lower bound, as CSR-PUB-0004 §11 already does |
| 6 | Withdrawal ledger grows unbounded | CRL size problem | Expiry means most entries need no permanent broadcast; ledger stays append-only for audit but is not the trust path |
| 7 | Monitor becomes the outage | Mozilla: ~half of failures were OCSP infra | Monitor is off the read path entirely; hooks are post-commit and async |
| 8 | Renewal becomes a rubber stamp | Generic | Renewal requires re-running the R5 predicate, not just a timestamp bump. Record `renewal_count`; a high count is a smell worth reporting |
| 9 | `VERIFIER_CONTRADICTION` forged | — | Only the adapter key that signed the candidate may contradict it |

---

## 8. Non-claims

- R6 does not detect recurrence semantically. It consumes signals and computes consequences.
- Recurrence rate is a **lower bound**, bounded by the declared horizon.
- `FUNCTIONAL_FAILURE` coverage depends entirely on application cooperation.
- Withdrawal does not undo external side effects. The existing semantic-rollback non-claim applies unchanged.
- A calibrated sensitivity floor is a floor against *seeded* recurrences of *known* classes. It says nothing about unknown classes.

---

## 9. Test plan

Parametrized over both backends, matching the existing `conftest.py`.

**Must pass:**
1. Reintegrated node gets a `trust_expires_utc`; it is not trusted after that instant without renewal
2. Renewal re-runs the R5 predicate and extends the horizon; `renewal_count` increments
3. `RENEWED_DESIGNATION` fires when `C(p)` intersects the active horizon set
4. `PROHIBITED_PATH` fires when a post-admission write creates a path from historical quarantine through an admitted node
5. `VERIFIER_CONTRADICTION` without a valid adapter signature → 403
6. `/observe` without the `designator` role → 401/403
7. Transitive withdrawal reaches a dependent **two hops** past the directly implicated node (the depth-bounding check that caught the compaction bug)
8. An unexamined dependent is withdrawn by default
9. The quarantined predecessor is **never** reactivated by any withdrawal
10. The original repair decision is present and unmodified after withdrawal
11. Amplification above the bound → escalation, and **zero withdrawals applied**
12. Rate limit exceeded → escalation, not processing
13. Calibration run records a floor and per-class rates; `gasc-audit` reads it
14. **Row 8 scores `NOT-EXERCISED` when no calibration has been run** — assert this explicitly so it can't be quietly claimed later

**Must fail closed:** monitor unavailable → expired state not trusted; withdrawal transaction interrupted → nothing partially applied.

---

## 10. Conformance mapping

| Row | Effect |
|---|---|
| 3 — Historical monotonicity | Withdrawal ledger is append-only and separate from the quarantine ledger; predecessors never reactivated; repair decisions never rewritten |
| 8 — Recurrence control | Becomes exercisable. Evidence: monitor output, withdrawal records, calibrated sensitivity floor. Non-vacuity requires a calibration run over the monitored period. Disclosure: monitored period, sensitivity, and what is unmonitored |
| 9 — Irreducibility | Withdrawal escalation is an irreducible disposition and joins the reason distribution |
| 10 — Measured cost | Recurrence rate must be reported alongside coverage. CSR-PUB-0004's H6 failure is precisely a recurrence cost that coverage numbers hid |

After R6, row 4 (safe continuity — Paper 3's M1–M4) is the only §7.2 requirement with no mechanism.

---

## 11. Build order

1. Tables, config, backend interface — both backends
2. `record_reintegration` on the R5 success path + expiry check on trusted-use evaluation
3. `PROHIBITED_PATH` internal hook (cheapest real detector, no external dependency)
4. `RENEWED_DESIGNATION` internal hook
5. Transitive withdrawal reusing the existing CTE + circuit breaker
6. `POST /observe`, `POST /renew-trust`, `GET /recurrence-report`
7. Calibration harness + `POST /calibrate`
8. `gasc-audit` row 8 scoring reads `calibration_runs`

Steps 1–4 deliver a working recurrence control with **no new external dependency and no new attack surface**. Steps 5–8 are where the adversarial surface appears; build the circuit breaker in the same commit as the withdrawal, never after.
