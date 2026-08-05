# GASC-Governor-Gateway

[![CI Status](https://github.com/andrebyrd-odingard/GASC-Governor-Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/andrebyrd-odingard/GASC-Governor-Gateway/actions/workflows/ci.yml)

The **GASC-Governor-Gateway** is a lightweight, fail-closed policy enforcement sidecar that isolates AI agents and prevents cascading failures via Transitive Taint Propagation.

It implements the [GASC-ED v1.1 Engineering Architecture & Policy-as-Code Specification](https://ssrn.com/abstract=6976282) and enforces rules based on the **Containment Survivability Research (CSR) Program** (specifically CSR-PUB-0005).

## 🔬 About the CSR Program

The **Containment Survivability Research (CSR) Program** is an independent, multi-stage research initiative authored by **Andre Byrd** under **Six Sense Enterprise Services LLC (Odingard Security)**. 

The program was designed to rigorously study how contamination spreads in shared AI agent environments. It culminated in the **CSR-PUB-0005** capstone paper, which synthesized the findings into a unified framework for:
1. Defining transitive taint propagation.
2. Specifying "Containment Denial-of-Service" as an adversarial attack.
3. Measuring the cost of correctly isolating compromised agents.
4. Engineering "Governed Recovery" to safely rebuild state.

This repository is the practical software implementation of those findings.

## 🛡️ Core Capabilities

This gateway sits between your AI Agent orchestration frameworks and your shared memory graph. It natively intercepts state writes and enforces:

*   **Transitive Containment**: Automatically intercepts writes attempting to build on poisoned roots.
*   **Verification Separation (OPA)**: Uses embedded Open Policy Agent (Rego) policies to ensure agents cannot authorize their own reintegration using evaluative outputs (e.g., planner scores or justifications).
*   **Historical Monotonicity**: Quarantine ledgers are append-only. Taint facts are never erased, ensuring true auditability.
*   **Fail-Closed Irreducibility**: Instead of fabricating a recovery that breaks safety invariants, the system escalates irreducible faults for human review.

## 🚀 Getting Started

### Prerequisites

*   Python 3.10+
*   [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/latest/#1-download-opa) binary installed and accessible in the `bin/` directory.

### Installation

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

## 🧪 Testing and Validation

This repository includes a comprehensive, multi-layered test suite that verifies the core tenets of the GASC-ED v1.1 specification, including unit tests for JSON schemas and OPA policies, integration tests for the FastAPI gateway, and an End-to-End Adversarial Fault Injection scenario.

### ⚠️ Compliance & Non-Claims Disclaimer

As explicitly stated in CSR-PUB-0005:

*   **Conformance, Not Survivability:** This repository provides auditable controls, logs, and fail-closed gates that pass the GASC-ED v1.1 **conformance suite**. It does *not* claim empirical "containment survivability" out-of-the-box, which requires preregistered joint criteria over a specific operating envelope.
*   **Rule 2 (Second Source) & Rule 1 (Non-Vacuity):** To prevent self-attestation, any production audit must run against external graph snapshots and seeded incidents so the automated audit runner does not score rows as `NOT-EXERCISED` or `SELF-ATTESTED`.

### Run the Python Test Suite

The Python test suite covers schema validation, API integration, and adversarial injection (E2E):

```bash
source .venv/bin/activate
pytest tests/
```

### Run the OPA Policy Tests

You can independently verify the Rego policies using the OPA CLI:

```bash
bin/opa test policies/ -v
```

## 📂 Project Structure

*   `bin/`: Contains the executable for Open Policy Agent (`opa`).
*   `policies/`: Contains the Rego policies (`gasc_verification_separation.rego`, `gasc_quarantine_integrity.rego`) and their test suites.
*   `schemas/`: Contains the strict JSON Schemas for `state_write_payload`, `quarantine_event`, and `governed_reconstruction_request`.
*   `src/`: Contains the core `governor_service.py` (FastAPI) and the Python-based `gasc_audit_engine.py`.
*   `tests/`: Contains the pytest suites that validate schema compliance, integration pathways, and E2E fault injection limits.

## ⚖️ License & Trademarks

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** - see the [LICENSE](LICENSE) file for details. This ensures that the Gateway remains open source and freely available, while preventing proprietary commercialization of network-hosted versions without contributing back.

**Trademark Notice**: "Odingard Security", "GASC-ED", and "Containment Survivability Research" are trademarks of Six Sense Enterprise Services LLC. Please see [TRADEMARK.md](TRADEMARK.md) for usage guidelines.
