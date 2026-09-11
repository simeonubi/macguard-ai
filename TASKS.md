# MacGuard AI — Development Roadmap & Tasks

This document tracks the staged engineering roadmap for MacGuard AI. It separates completed milestones from planned future phases to maintain clear boundaries between implemented code and target architecture.

---

## Progress Overview

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 0** | Foundation & Project Setup | **Completed** |
| **Phase 1** | Read-Only Storage Scanner | **Completed** |
| **Phase 2** | Storage Intelligence & Categorization | **Completed** |
| **Phase 3** | Safety Engine & Path Policies | **Completed** |
| **Phase 3.5** | Structured Recommendation Engine | **Completed** |
| **Phase 3.6** | Cryptographic HMAC Authorization Remediation | **Completed** |
| **Phase 4** | Local LLM & Ollama Explanation Layer | **Completed** |
| **Phase 5** | Human Approval Workflow | **Completed** |
| **Phase 6A** | Controlled Cleanup Executor (DRY-RUN ONLY) | **Completed** |
| **Phase 6B** | Controlled Trash-Based Execution | **Completed** |
| **Phase 6C** | Integrity Verification, Persistent Audit & Recovery | **Completed** |
| **Phase 7** | Product & Integration Layer (Streamlit UI & E2E) | **Completed** |
| **Phase 8** | Agentic Intelligence & Orchestration Layer | **Completed** |
| **Phase 9** | Production Hardening, Security Evaluation & Release Readiness | **Completed** |
| **Phase 10** | Product Polish, Presentation Guide & Final Validation | **Completed** |

---

## Phase 9 — Production Hardening, Security Evaluation & Release Readiness (Completed)

- [x] Comprehensive Architecture Audit and complete dependency mapping
- [x] Threat Model creation (`docs/THREAT_MODEL.md`) covering all 25 threats (T1–T25)
- [x] Agent Evaluation Framework (`app/evaluation/`):
  - [x] Evaluation models (`app/evaluation/models.py`)
  - [x] Deterministic 21-scenario suite (`app/evaluation/scenarios.py`)
  - [x] Evaluation metrics engine (`app/evaluation/metrics.py`)
  - [x] Evaluation runner (`app/evaluation/runner.py`)
  - [x] Markdown evaluation reporter (`app/evaluation/reporter.py`)
- [x] Path fuzzing & traversal security testing (`tests/test_path_fuzzing.py`)
- [x] Performance benchmarking & bounded heap scanner validation (`tests/test_performance_benchmarks.py`)
- [x] End-to-end sandbox mutation guard testing (`tests/test_mutation_guard.py`)
- [x] Formal reports & release artifacts:
  - [x] Agent Evaluation Report (`docs/AGENT_EVALUATION.md`)
  - [x] Security Audit Report (`docs/SECURITY_AUDIT.md`)
  - [x] Production Readiness Checklist (`docs/PRODUCTION_READINESS.md`)
  - [x] Version file (`VERSION` -> `0.9.0-rc1`)
  - [x] Project changelog (`CHANGELOG.md`)
- [x] Full regression test suite passing: 205/205 tests (0 failures)
- [x] Static security scan completed: zero dangerous primitives, zero permanent deletion, zero shell execution

---

## Phase 0 — Foundation & Setup

- [x] Initialize Python 3.11 virtual environment (`.venv`) and configure `requirements.txt`
- [x] Configure repository directory layout (`app/`, `tests/`, `docs/`, `scripts/`)
- [x] Configure `.gitignore` for Python, macOS, virtualenvs, and test caches
- [x] Establish automated test framework with `pytest`
- [x] Author core documentation: `README.md`, `ARCHITECTURE.md`, `SAFETY.md`, `TASKS.md`
- [x] Document environment template and configuration status (`.env.example`)

---

## Phase 1 — Read-Only Storage Scanner

- [x] Implement `DiskUsage` dataclass and `get_disk_usage()` using `psutil`
- [x] Implement `StorageItem` dataclass for file and directory representation
- [x] Implement `get_directory_size()` with recursive walk, symlink protection, and exception handling
- [x] Implement `get_top_directories()` for immediate subdirectory inspection
- [x] Implement `get_large_files()` for recursive largest-file discovery
- [x] Implement human-readable byte unit formatter (`format_bytes()`)
- [x] Implement command-line diagnostic tool (`app/cli.py`) with configurable root/home paths and limits
- [x] Wire top-level application entrypoint (`app/main.py`)
- [x] Enforce explicit read-only safety confirmation in CLI output (`"No files were modified."`)
- [x] Implement comprehensive unit tests (`tests/test_storage_scanner.py`, `tests/test_cli.py`)

---

## Phase 2 — Storage Intelligence & Categorization

- [x] Design structured storage models (`StorageCategory`, `RiskLevel`, `StorageCandidate` in `app/analysis/models.py`)
- [x] Implement deterministic classification rules (`app/analysis/rules.py`)
  - [x] Cache detection (`Library/Caches`, `.cache`, `_cacache`)
  - [x] Log detection (`Library/Logs`, `/var/log`, `.log`, `.crash`)
  - [x] Developer artifacts (Xcode `DerivedData`, Docker, `.venv`, `node_modules`, build artifacts)
  - [x] Application data analysis (`Library/Application Support`, sandboxed Containers)
  - [x] Media and document classification based on format extensions
  - [x] Fallback unclassified / unknown detection
- [x] Implement confidence scoring model for categorization rules
- [x] Implement deterministic risk classification engine (`LOW`, `MEDIUM`, `HIGH`, `UNKNOWN`)
- [x] Implement `StorageAnalyzer` (`app/analysis/storage_analyzer.py`) converting raw scan results to `StorageCandidate` objects
- [x] Generate conservative, non-destructive recommendation messages
- [x] Add comprehensive unit and rule tests in `tests/test_storage_analyzer.py`

---

## Phase 3 — Safety Engine & Path Policies

- [x] Implement strict path canonicalizer (`app/safety/canonicalizer.py`) to prevent traversal and symlink escapes
- [x] Implement system-critical path denylist (SIP, `/System`, `/usr`, `/Library`, `/Applications`, etc.)
- [x] Implement safe path allowlists for user caches and developer artifacts
- [x] Implement user home root and sensitive user directory protections (`.ssh`, `Documents`, `Desktop`, `Pictures`, etc.)
- [x] Implement containment and similar-prefix protection (`is_contained_within`)
- [x] Implement cryptographically random, tamper-evident human approval records (`ApprovalRecord` in `app/safety/approval.py`)
- [x] Implement approval validation with expiration, path, operation, risk, and signature checks
- [x] Add rigorous path containment, traversal escape, symlink resolution, and approval tests in `tests/test_safety.py`
- [x] Verify zero-filesystem-mutation safety invariant in automated test suite

---

## Phase 3.5 — Structured Recommendation Engine

- [x] Implement `RecommendationAction` and `SafetyStatus` enums (`app/analysis/recommendations.py`)
- [x] Implement frozen `StorageRecommendation` Pydantic model with confidence bounds
- [x] Implement `RecommendationEngine` with deterministic category and risk-level mapping
- [x] Enforce mandatory human approval requirement (`requires_approval = True`) on all recommendations
- [x] Enforce `MANUAL_REVIEW` / `NO_ACTION` for `HIGH` and `UNKNOWN` risk candidates
- [x] Add recommendation unit tests in `tests/test_recommendations.py`

---

## Phase 3.6 — Cryptographic HMAC Authorization Remediation

- [x] Implement `ApprovalKeyManager` managing a 256-bit runtime secret (`secrets.token_bytes(32)`)
- [x] Upgrade signature generation in `app/safety/approval.py` to genuine HMAC-SHA256
- [x] Enforce secret isolation (key is never exposed in models, serialized JSON, LLM context, or logs)
- [x] Enforce canonical payload formatting for deterministic signing and verification
- [x] Enforce constant-time signature comparison (`secrets.compare_digest`)
- [x] Add security tests proving unkeyed SHA-256 forgery attempts fail (`tests/test_safety.py`)
- [x] Add cross-key and application restart invalidation tests (`tests/test_safety.py`)
- [x] Update `SAFETY.md` with cryptographic authorization boundary documentation

---

## Phase 4 — Local LLM & Ollama Explanation Layer

- [x] Implement `AnalysisContext` and `LLMExplanation` structured Pydantic models (`app/llm/models.py`)
- [x] Implement configurable `OllamaClient` (`app/llm/ollama_client.py`) with typed error handling
- [x] Implement prompt module with system role bounds and XML injection delimiters (`app/llm/prompts.py`)
- [x] Implement defensive output safety validator (`validate_explanation_safety`) rejecting destructive command patterns
- [x] Implement `ExplanationService` with graceful deterministic offline fallback (`app/llm/explanation_service.py`)
- [x] Enforce strict secret isolation (approval HMAC keys never exposed to LLM context or prompts)
- [x] Add comprehensive mocked client, safety, prompt injection, and determinism tests in `tests/test_llm.py`

---

## Phase 5 — Human Approval System

- [x] Design structured review and audit models (`ReviewItem`, `ApprovalDecision`, `ApprovalAuditEvent`, `ApprovalStatus` in `app/safety/review.py`)
- [x] Implement `ApprovalService` (`app/safety/approval_service.py`) for workflow coordination
- [x] Enforce explicit human approval action with default rejection (`explicit_consent=True` required)
- [x] Implement runtime in-memory approval registry and replay protection (`CONSUMED` status prevents reuse)
- [x] Implement immutable audit logging tracking all approval lifecycle events with zero secrets
- [x] Implement interactive CLI review interface with granular item selection and confirmation prompts (`app/cli.py`)
- [x] Implement Streamlit review dashboard with explicit consent checkbox and approval cards (`app/ui/review.py`)
- [x] Enforce strict LLM isolation (LLM has zero approval authority and no access to `ApprovalKeyManager`)
- [x] Add comprehensive approval lifecycle, tampering, replay, and mutation safety tests in `tests/test_approval_workflow.py`


---

## Phase 6A — Controlled Cleanup Executor (DRY-RUN ONLY)

- [x] Design immutable execution models (`ExecutionAction.DRY_RUN`, `ExecutionStatus`, `ExecutionPlan`, `DryRunResult` in `app/execution/models.py`)
- [x] Implement `ExecutionPlanner` (`app/execution/planner.py`) with defense-in-depth policy and cryptographic re-validation
- [x] Enforce allowlist root protection (e.g. `~/Library/Caches` root cannot be targeted, only descendants)
- [x] Enforce risk gating (permanently block `HIGH` and `UNKNOWN` risk candidates)
- [x] Implement `DryRunExecutor` (`app/execution/executor.py`) simulating execution outcomes with zero filesystem mutations
- [x] Enforce non-consumption of human approval tokens during dry run
- [x] Add `--dry-run` flag to CLI (`app/cli.py`)
- [x] Add comprehensive execution plan, tampering, rejection, and zero-mutation tests in `tests/test_execution.py`

---

## Phase 6B — Controlled Trash-Based Execution (Completed)

- [x] Implement `TrashExecutor` (`app/execution/trash_executor.py`)
- [x] Implement macOS Trash integration (moving approved items strictly to `~/.Trash` with zero permanent deletion)
- [x] Implement thread-safe atomic execution claim (`ApprovalService.claim_for_execution`) with `threading.Lock`
- [x] Implement immediate pre-mutation revalidation (HMAC, risk, path canonicalization, `PathValidator`)
- [x] Implement symlink defense via `os.lstat()` failing closed on all symlink sources
- [x] Implement collision protection (isolated unique subfolders in Trash)
- [x] Enforce post-move verification (source absence, destination presence in Trash) before approval consumption
- [x] Add `--trash` flag with prominent safety warnings to CLI (`app/cli.py`)
- [x] Add comprehensive sandbox execution, concurrency, symlink, and collision tests in `tests/test_trash_executor.py`

---

## Phase 6C — Integrity Verification, Persistent Audit & Recovery (Completed)

- [x] Implement pre-execution integrity snapshot (`PathIntegritySnapshot` in `app/execution/integrity.py`)
- [x] Implement pre-execution integrity verification comparing metadata & SHA-256 digests
- [x] Implement post-execution integrity verification (source absence, controlled Trash presence, type/size/hash checks)
- [x] Implement persistent SQLite audit logger (`app/audit/models.py`, `app/audit/repository.py`)
- [x] Enforce parameterized SQL queries and zero secret/key/content storage in audit database
- [x] Implement execution ID correlation binding executions to approval records
- [x] Implement recovery-aware execution lifecycle (`IN_PROGRESS` detection and fail-closed refusal of automatic retries)
- [x] Implement CLI `--audit` diagnostic inspection command (`app/cli.py`)
- [x] Add comprehensive test suites:
  - `tests/test_integrity.py` (snapshotting, hash checks, symlink swaps, post-move verifications)
  - `tests/test_audit_repository.py` (SQLite schema init, parameterized operations, concurrent queries, lifecycle tracking)
  - `tests/test_execution_recovery.py` (interruption detection, fail-closed recovery)
  - `tests/test_execution_security.py` (symlink attacks Scenarios A-F, concurrent claim race conditions, secret key isolation)
- [x] Perform full repository-wide security scan verifying zero permanent deletion commands or leaks


---

## Phase 7 — Product & Integration Layer (Completed)

- [x] Design multi-page Streamlit application (`app/ui/app.py`, `app/ui/dashboard.py`, `app/ui/scan.py`, `app/ui/recommendations.py`, `app/ui/review.py`, `app/ui/execution.py`, `app/ui/audit.py`, `app/ui/settings.py`, `app/ui/components.py`, `app/ui/state.py`)
- [x] Implement three operating modes: `ANALYZE` (Read-only), `REVIEW` (Human confirmation), `CLEAN` (Controlled Trash execution)
- [x] Implement storage overview dashboard with live disk capacity metrics and category breakdown
- [x] Implement bounded, targeted storage scan workflow (`StorageScanner.get_common_user_storage_targets()`, `heapq` bounded large files)
- [x] Integrate deterministic analysis (`StorageAnalyzer`) and explainable recommendations (`RecommendationEngine`)
- [x] Integrate AI explanation engine (`ExplanationService`) with graceful offline fallback when Ollama is unreachable
- [x] Integrate human approval workflow (`ApprovalService`) with mandatory informed consent checkbox declaration
- [x] Enforce HMAC secret key isolation (zero secret keys in session state or UI components)
- [x] Integrate controlled Trash execution (`ExecutionPlanner`, `TrashExecutor`) with pre- and post-mutation integrity verification
- [x] Integrate persistent SQLite audit log viewer with multi-attribute filtering and crash anomaly detection
- [x] Add comprehensive end-to-end sandbox integration tests (`tests/test_ui_integration.py`)
- [x] Maintain 100% backwards compatibility with CLI diagnostics, review, dry-run, trash, and audit commands


---

## Phase 10 — Product Polish, Presentation Guide & Final Validation (Completed)

- [x] Executive Dashboard polish with physical disk state, quick action bar, onboarding welcome state, and presentation demo dataset loader
- [x] Enhanced Scan Storage visualizations with native Streamlit charts (category size distribution, risk tiers, largest consumers)
- [x] Smart Recommendations UI with risk color coding, safe terminology ("Eligible for controlled Trash review"), and on-demand local AI explanations
- [x] Human Review UI polish with mandatory informed consent declaration, individual candidate inspection, and strict rejection of "Approve All"
- [x] Controlled Execution workflow polish with clear safety sequence indicators, non-destructive dry-run simulations, and post-move SHA-256 integrity reporting
- [x] Conversational AI Agent UI with visible capability boundaries, zero execution authority, and safe prompt examples
- [x] Cryptographic Audit Log UI with multi-attribute filtering, raw JSON event inspector, and crash anomaly detection
- [x] Non-disableable safety policy information in Settings UI
- [x] Safe Presentation Demo Dataset Generator (`app/ui/demo.py`)
- [x] Complete 3–5 minute Demonstration Script & Presentation Guide (`docs/DEMO_GUIDE.md`)
- [x] Real isolated sandbox validation suite (`tests/test_sandbox_final_validation.py`)
- [x] Full automated test suite passing (245/245 tests, 100% pass rate)

---

## Future Enhancements & Optimization

- [ ] Multi-threaded / asynchronous filesystem scanning for improved scan throughput
- [ ] Implement SQLite metadata index with mtime-based incremental change detection
- [ ] Configurable scan exclusions (e.g., skip external network mounts, Time Machine snapshots)
- [ ] Package MacGuard AI for distribution (CLI entrypoint script / standalone launcher)

