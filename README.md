# GASC-Governor-Gateway

[![CI Status](https://github.com/andrebyrd-odingard/GASC-Governor-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/andrebyrd-odingard/GASC-Governor-Gateway/actions/workflows/ci.yml)

The **GASC-Governor-Gateway** is a lightweight, fail-closed policy enforcement sidecar for multi-agent shared state. It prevents cascading failures by enforcing **Transitive Taint Propagation (TTP)** in the GASC-ED v1.1 framework.

It implements the **GASC-ED v1.1 Engineering Architecture & Policy-as-Code Specification** and the **Containment Survivability Research (CSR) Program** findings, specifically CSR-PUB-0005.

## About the CSR Program

The **Containment Survivability Research (CSR) Program** is an independent, multi-stage research initiative authored by **Andre Byrd** under **Six Sense Enterprise Services LLC (Odingard Security)**.

The program was designed to rigorously study how contamination spreads in shared AI agent environments. It culminated in the **CSR-PUB-0005** capstone paper, which synthesized the findings into a unified framework for:
1. Defining transitive taint propagation.
2. Specifying "Containment Denial-of-Service" as an adversarial attack.
3. Measuring the cost of correctly isolating compromised agents.
4. Engineering "Governed Recovery" to safely rebuild state.

This repository is the practical software implementation of those findings.

## Core Capabilities

This gateway sits between your AI Agent orchestration frameworks and your shared memory graph. It natively intercepts state writes and enforces:

*   **Transitive Containment**: Automatically intercepts writes attempting to build on poisoned roots via dynamic graph-traversal blast-radius calculations.
*   **Verification Separation (OPA)**: Uses embedded Open Policy Agent (Rego) policies to ensure agents cannot authorize their own reintegration using evaluative outputs (e.g., planner scores or justifications).
*   **Cryptographic Binding**: Enforces ECDSA signature verification and JWT validation to guarantee identity and payload integrity.
*   **Historical Monotonicity**: Quarantine ledgers are append-only. Taint facts are never erased, ensuring true auditability.
*   **Fail-Closed Irreducibility**: Instead of fabricating a recovery that breaks safety invariants, the system escalates irreducible faults for human review.

## Operational Hardening (Phase 2)

Phase 2 added the concurrency and operational-hardening layer that makes the gateway safe under load and CI-gated:

*   **Transactional admission** with a shared/exclusive admission lock closing the race between `/submit-candidate` and `/designate`.
*   **Readiness probe, graceful drain, and backpressure** so the service refuses traffic before it degrades.
*   **Pluggable state backends**: SQLite, PostgreSQL, and in-memory.
*   **OPA policy evaluation** via a WASM bundle or a REST sidecar.
*   **Concurrency benchmark** with p50/p95/p99 reporting and CI latency gates.
*   **Continuous `gasc-audit` scoring** in CI.

The `main` branch passes the full CI matrix: Python tests, OPA policy tests, SQLite benchmarks, latency gates, and the GASC-Audit scoring step.

## Threat Model Boundary (What This Does NOT Do)

This architecture provides **provenance security and containment**, not content scanning.

*   We do **not** inspect `state_content` for prompt injections, malware, or policy violations. The state is treated as an opaque, cryptographically sealed envelope. We assume an external detection pipeline (e.g., OWASP Agent Memory Guard or human review) will independently discover poison and issue a designation event.
*   **External Side-Effects (Semantic Rollback Hazard):** GASC-ED governs internal agent state and memory isolation. It does **not** provide idempotency guarantees for external side-effects (e.g., financial transactions, API mutations). A malicious agent could exploit the reconstruct-forward capability to double-execute actions (semantic rollback attacks like ACRFence). Applications must enforce their own external effect ledgers and idempotency keys to safely consume reintegrated agent identities.

## Getting Started

### Option 1: Production Deployment (Docker Compose)

We provide a production-ready stack running the FastAPI Governor alongside a dedicated OPA REST sidecar.

```bash
docker-compose up --build
```

This requires configuring `JWT_SECRET` via environment variables.

### Option 2: Local Development (Python)

#### Prerequisites

*   Python 3.10+
*   [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/#1-download-opa) binary installed and accessible in the `bin/` directory.

#### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/andrebyrd-odingard/GASC-Governor-Gateway.git
    cd GASC-Governor-Gateway
    ```

2.  Download the OPA binary to the `bin/` directory:
    ```bash
    mkdir -p bin
    # For macOS ARM64:
    curl -L -o bin/opa https://openpolicyagent.org/downloads/latest/opa_darwin_arm64
    # For Linux:
    # curl -L -o bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
    chmod +x bin/opa
    ```

3.  Set up the Python virtual environment and install dependencies:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

## Audit & Conformance

This Gateway is designed to be evaluated by the `gasc-audit` CLI tool against the GASC-ED v1.1 rubric.

If you run the audit engine against the Gateway's own internally generated artifacts, the tool will return `overall_audit_passed: false`. By design, **6 out of 10 rows do not count toward conformance** in this scenario, scoring either as `NOT-EXERCISED` or `SELF-ATTESTED`.

Specifically, because the Gateway cannot independently verify its own snapshots (Rule 2), the audit engine correctly flags these rows as `SELF-ATTESTED`. This proves the audit rubric is not decorative — it actively prevents systems from grading their own homework. Passing a full audit requires an external orchestrator to supply a genuine independent snapshot.

## Testing and Validation

This repository includes a multi-layered test suite that verifies the core tenets of the GASC-ED v1.1 specification, including unit tests for JSON schemas and OPA policies, integration tests for the FastAPI gateway, and an end-to-end adversarial fault-injection scenario.

### Compliance & Non-Claims Disclaimer

As explicitly stated in CSR-PUB-0005:

*   **Conformance, Not Survivability:** This repository provides auditable controls, logs, and fail-closed gates that pass the GASC-ED v1.1 **conformance suite**. It does *not* claim empirical "containment survivability" out-of-the-box, which requires preregistered joint criteria over a specific operating envelope.
*   **Rule 2 (Second Source) & Rule 1 (Non-Vacuity):** To prevent self-attestation, any production audit must run against external graph snapshots and seeded incidents so the automated audit runner does not score rows as `NOT-EXERCISED` or `SELF-ATTESTED`.

### Run the Python Test Suite

```bash
source .venv/bin/activate
pytest tests/
```

### Run the OPA Policy Tests

```bash
bin/opa test policies/ -v
```

## Project Structure

*   `bin/`: Local OPA binary directory (created during setup; not committed).
*   `policies/`: Rego policies (`gasc_verification_separation.rego`, `gasc_quarantine_integrity.rego`) and their test suites.
*   `schemas/`: Strict JSON Schemas for `state_write_payload`, `quarantine_event`, and `governed_reconstruction_request`.
*   `src/`: Core services.
    *   `governor_service.py`: FastAPI governor API.
    *   `recovery_adapter.py`: Recovery and reconstruction adapter.
    *   `state_backend.py`, `sqlite_backend.py`, `postgres_backend.py`: Pluggable storage backends.
    *   `wasm_engine.py`: OPA/WASM and REST-sidecar policy evaluation.
    *   `r6_utils.py`: Recurrence-control utilities.
    *   `config.py`: Runtime configuration.
*   `migrations/`: Alembic migrations for PostgreSQL.
*   `benchmarks/`: Performance and recurrence-calibration harnesses.
*   `tests/`: Pytest suites for schemas, integration, concurrency, readiness, and adversarial fault injection.
*   `docs/`: Design documents for recovery semantics, recurrence control, and design comparisons.

## Roadmap

The `main` branch is the Phase 2 stable baseline. The next work stream centers on the remaining GASC-ED v1.1 rows and operational completeness:

1.  **R6 Recurrence Control** — trust expiry, renewal, transitive withdrawal, `/observe`, `/renew-trust`, `/calibrate`, and the seeded-recurrence calibration harness.
2.  **Compaction edge class and authenticated `/designate` webhook** — auditability and provenance for compaction events.
3.  **Real reconstruction backend** — an internal LLM-based adapter so governed reconstruction (Row 5) and irreducibility (Row 9) become exercisable instead of always failing closed.
4.  **Row 4 Safe Continuity** — the last §7.2 requirement with no mechanism after R6.

## License & Trademarks

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see the [LICENSE](LICENSE) file for details. This ensures that the Gateway remains open source and freely available, while preventing proprietary commercialization of network-hosted versions without contributing back.

**Trademark Notice**: "Odingard Security", "GASC-ED", and "Containment Survivability Research" are trademarks of Six Sense Enterprise Services LLC. Please see [TRADEMARK.md](TRADEMARK.md) for usage guidelines.
