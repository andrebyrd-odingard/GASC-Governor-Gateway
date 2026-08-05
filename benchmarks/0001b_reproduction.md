# CSR-PUB-0001b Reproduction (SQLite Backend)

## Environment
- **CPU**: arm
- **Python**: 3.14.4
- **SQLite**: 3.53.0
- **Pragmas**: {"journal_mode": "WAL", "synchronous": "FULL"}

## Results (Medians over 20 trials, 400 writes)
| Metric | 0001b Baseline (Node.js) | GASC-ED (Python) |
|---|---|---|
| SHA-256 commitment | ≈0.002 ms | 0.015 ms |
| Record insert | ≈0.06 ms | 0.035 ms |
| Edge insert | ≈0.005 ms | 0.972 ms |
| Per-write @ 400 | 1.95 ms, 510 w/s | 1.091 ms, 917 w/s |
| Traversal (per node) | ≈4.8 µs | 14830.686 µs |
| Annotation writes (per node) | ≈2.4 µs | 32.413 µs |
| Storage | 7.1 MB @ 400 | 12.12 MB |

### Benchmark Analysis & Differences
- **Edge Insert vs Per-Write Speed:** The baseline (0001b) executed with a *no-clear read scope* (yielding ~167 dependencies per write by n=400), creating ~66,909 edges. Our harness creates only a handful of parents per node (~1,200 total edges). Therefore, the per-write latency appearing faster (1.091 ms vs 1.95 ms) is an artifact of the workload doing ~1% of the edge insertions. When examining the true cost per edge insertion, Python/SQLite is significantly slower (0.972 ms vs Node's 0.005 ms).
- **Storage:** The 12.12 MB size (1.7x the baseline's 7.1 MB) is due to schema differences: our implementation carries additional structural columns (like checkpoint tracking, external effects, and heavier JSON blob sizes for signatures and tokens) compared to the minimal 0001b ledger.
