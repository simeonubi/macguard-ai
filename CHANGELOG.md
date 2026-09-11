# Changelog

All notable changes to **MacGuard AI** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-11 — Whole-Disk Storage Intelligence & Analytics Platform

### Added
* **Bounded Whole-Home Storage Discovery (`app/tools/whole_home_scanner.py`, `app/models/scan_scope.py`):** Configurable `ScanScope` scanning (`HOME`, `DEV`, `APP_DATA`, `CACHE`, `CUSTOM`) with deterministic `TraversalLimits` (max depth, item count, timeout) and streaming min-heaps (`heapq`).
* **Smart Categorization Registry (`app/analysis/smart_categorizer.py`):** Deterministic 16-category classification engine (`CACHE`, `LOGS`, `DEVELOPMENT`, `DOCUMENTS`, `TRASH`, `DOWNLOADS`, `MEDIA`, `ARCHIVES`, `SYSTEM_DATA`, `MAIL_ATTACHMENTS`, `CLOUD_STORAGE`, `DISK_IMAGES`, `CODE_REPOSITORIES`, `VIRTUAL_MACHINES`, `APPLICATION_SUPPORT`, `UNKNOWN`) with confidence scoring.
* **Developer Storage Intelligence (`app/analysis/developer_analyzer.py`):** Deep inspection of developer environments (Xcode `DerivedData`, Docker raw images/layers, Python `.venv`, Node `node_modules`, Rust `target`, and ML model weights for Hugging Face, Ollama, PyTorch) with project manifest association and staleness indicators.
* **Large File Intelligence (`app/analysis/large_file_analyzer.py`):** Outlier detection and size ranking for large files across bounded scopes.
* **Storage History & Growth Trends (`app/analysis/storage_history.py`, `app/analysis/storage_trends.py`):** Persistent multi-scan snapshots and category growth velocity analytics (`GROWING`, `SHRINKING`, `STABLE`) backed by SQLite Schema v2 tables (`scan_snapshots`, `category_history`, `top_consumer_snapshots`).
* **Duplicate & Redundancy Intelligence (`app/analysis/duplicate_detector.py`):** Read-only duplicate cluster detection utilizing streaming two-stage hashing (size pre-filter ➔ 4KB partial hash ➔ full SHA-256) with APFS hardlink awareness (`st_nlink > 1`) and zero-wasted-byte accounting.
* **Duplicate-Aware & Trend Recommendations (`app/analysis/recommendations.py`):** Expanded 6-tier recommendation taxonomy (`REVIEW_FOR_CLEANUP`, `MANUAL_REVIEW`, `INFORMATIONAL`, `PROTECTED_SYSTEM`, `UNKNOWN_RISK`, `NO_ACTION`) with parent-child container deduplication and trend context.
* **Advisory Agentic Intelligence (`app/agent/`):** Conversational AI assistant with 10 allowlisted, read-only analytical tools (`get_storage_overview`, `list_top_directories`, `list_large_files`, `get_category_breakdown`, `get_recommendations`, `explain_candidate`, `get_storage_trends`, `compare_scans`, `get_duplicate_summary`, `get_developer_storage_breakdown`), zero execution authority, and 100% prompt injection resistance.
* **Streamlit UI Expansion (`app/ui/`):** 10 dedicated views including Developer Storage, Duplicate Explorer, and Storage Intelligence & History with two-phase navigation synchronization.
* **Performance & Security Hardening:** Validated memory footprint ($<150\text{ MB}$ RSS across 10k items), cooperative scan cancellation ($<100\text{ ms}$ latency), symlink loop defense, and extended adversarial attack resilience.
* **Expanded Automated Test Suite:** Expanded test suite to **592 passing unique tests** (73 security tests, 77 UI integration tests, 32 performance & hardening tests).

---

## [1.0.0] - 2026-09-09 — Final Production Release

### Added
* **Real-World Acceptance Test Suite (`tests/test_sandbox_final_validation.py`):** Verified all 18 safety gates on real filesystem targets in isolated sandboxes, validating pre/post SHA-256 snapshots, HMAC authorization, single-use token consumption, and SQLite audit logging.
* **Resilient Local AI Explanation Architecture (`app/llm/explanation_service.py`):** Added `explain_candidate_safe()` method with automatic fallback to deterministic rule rationales upon Ollama daemon timeouts (>30s) or connection errors, eliminating unhandled UI exceptions.
* **Comprehensive Documentation Suite:** Authoritative root-level documentation package:
  * `README.md`: High-level overview, architecture diagrams, and quickstart.
  * `ARCHITECTURE.md`: Complete component responsibilities, data flow, and HMAC lifecycle.
  * `SECURITY.md`: 12 core security invariants, threat boundaries, and fail-closed policies.
  * `USER_GUIDE.md`: Step-by-step user manual for all 4 operating modes, Dry Run, and Trash recovery.
  * `TESTING.md`: Test suite breakdown and verification commands.
  * `DEMO.md`: 3–5 minute live presentation script using Presentation Demo Data.
  * `CHANGELOG.md`: Complete version history through v1.0.0.

### Fixed & Hardened
* **Recommendations UI Schema Alignment (`app/ui/recommendations.py`):** Corrected data contract access from outer `StorageRecommendation` to inner `StorageCandidate` (`candidate.path`, `candidate.risk_level`, `candidate.category`), resolving runtime `AttributeError`.
* **Two-Phase Streamlit Navigation State Synchronization (`app/ui/state.py`):** Enforced strict separation between authoritative session state and widget-bound keys (`mode_radio`, `nav_selectbox`) to eliminate Streamlit session-state key collision crashes.
* **Controlled Execution Dry Run Lifecycle:** Validated that Dry Run simulations execute strictly non-destructively without mutating source files or consuming approval tokens.
* **Storage Visualizations Zero-Bound Y-Axis:** Adjusted Altair chart scale domains in `app/ui/scan.py` to prevent negative visual scale artifacts.
* **Test Suite Expansion:** Expanded automated test coverage to **255 passing tests** (100% pass rate).

---

## [1.0.0-rc1] - Product Polish & Presentation Release Candidate

### Added
* **Presentation Demo Dataset Generator (`app/ui/demo.py`):** Built-in synthetic dataset generator creating safe, zero-risk presentation state for live demos, technical interviews, and portfolio showcases without touching real user files.
* **Presentation Guide (`docs/DEMO_GUIDE.md`):** Complete 3–5 minute executive and technical demonstration script with visual timing diagram and step-by-step speaker cues.
* **Enhanced Storage Visualizations (`app/ui/scan.py`):** Native Streamlit visual charts for category storage breakdown (MB), risk tier distributions, and top storage consumers.
* **Explainable AI Integration on Findings (`app/ui/recommendations.py`):** On-demand local LLM explanation buttons providing contextual natural language reasoning for any flagged finding.
* **AI Agent Capability Boundary Box (`app/ui/agent_view.py`):** Prominent capability indicators and safe quick-prompt buttons enforcing zero-execution authority.
* **Human Review UX Boundary (`app/ui/review.py`):** Explicit informed consent checkbox declaration, granular candidate inspection cards, and strict rejection of "Approve All" bulk actions.
* **Controlled Execution Safety Banner (`app/ui/execution.py`):** Clear execution flow indicators (`Review ➔ Approve ➔ Dry Run ➔ Controlled Trash ➔ Integrity Verification ➔ Audit`), dry-run simulations, and SHA-256 verification results.

### Changed
* Standardized terminology across all UI views: replaced "safe to delete" with "Eligible for controlled Trash review".
* Polished Settings UI (`app/ui/settings.py`) with non-disableable safety policy information.

---

## [0.9.0-rc1] - Phase 9: Production Hardening & Security Evaluation

### Added
* **Formal Threat Model (`docs/THREAT_MODEL.md`):** Complete analysis of 25 threat vectors (T1–T25) covering path traversal, symlink attacks, TOCTOU race conditions, prompt injections, secret leakage, and cross-filesystem moves.
* **Agent Evaluation Framework (`app/evaluation/`):** Repeatable, deterministic agent evaluation framework with 21 scenarios covering legitimate queries, unsafe requests, prompt injections, secret extractions, tool abuse, and boundary attacks.
* **Evaluation Reporting (`docs/AGENT_EVALUATION.md`):** Automated metrics collection reporting 100% safety pass rate, 100% prompt injection resistance, 0 tool boundary violations, and 0 secret leakages.
* **Security Audit Report (`docs/SECURITY_AUDIT.md`):** Comprehensive audit report documenting full mitigation across all 25 threats with zero critical/high residual risks.
* **Production Readiness Checklist (`docs/PRODUCTION_READINESS.md`):** Multi-dimensional release readiness criteria across Security, Reliability, Performance, and UX.
* **Path Fuzzing Suite (`tests/test_path_fuzzing.py`):** Randomized and adversarial path input tests verifying canonicalization, unicode safety, traversal rejection, and containment.
* **Performance Benchmarks (`tests/test_performance_benchmarks.py`):** Synthetic benchmarks measuring storage scanner bounded heap scaling, analyzer throughput, and agent latency.
* **Mutation Guard Suite (`tests/test_mutation_guard.py`):** End-to-end sandbox tests proving that agent interactions cannot mutate the filesystem and only explicit human-approved Trash execution can modify target items.

---

## [0.8.0] - Phase 8: Agentic Intelligence & Orchestration Layer

### Added
* **Multi-Turn Agent Orchestrator (`app/agent/orchestrator.py`):** Conversational AI engine for storage analysis with deterministic fallback capabilities.
* **Read-Only Tool Registry (`app/agent/tools.py`):** Strictly allowlisted tool execution layer exposing only non-destructive diagnostic tools (`get_storage_overview`, `list_top_directories`, `list_large_files`, `get_category_breakdown`, `get_recommendations`, `explain_candidate`).
* **Prompt Injection Defense & Security Policies (`app/agent/policies.py`):** Multi-layer input validation, regex sanitization, and output bounds validation.
* **Streamlit Agent Chat Page (`app/ui/agent_view.py`):** Interactive UI for conversational storage queries.

---

## [0.7.0] - Phase 7: Product & UI Integration Layer

### Added
* Complete multi-page Streamlit web interface (`app/ui/`): Dashboard, Scan, Recommendations, Review, Execution, Agent, Audit, Settings.
* Persistent session state management with untrusted UI boundary enforcement.

---

## [0.6.0] - Phase 6: Execution Control, Trash & Audit Layer

### Added
* **Execution Planner (`app/execution/planner.py`):** Defensive execution planner validating allowlists and approvals.
* **Dry-Run Simulation Engine (`app/execution/executor.py`):** Non-destructive dry-run simulation.
* **Trash Executor (`app/execution/trash_executor.py`):** Controlled file move to macOS Trash (`~/.Trash`).
* **Physical Integrity Verifier (`app/execution/integrity.py`):** Pre/post-move SHA-256 integrity verification.
* **Persistent SQLite Audit Repository (`app/audit/repository.py`):** WAL-mode audit event logging.

---

## [0.5.0] - Phase 5: Cryptographic Approval & Safety Gates

### Added
* **HMAC-SHA256 Approval Engine (`app/safety/approval.py`):** 256-bit runtime secret key generation and token verification.
* **Path Allowlisting & Denylisting (`app/safety/path_validator.py`):** Comprehensive system protection rules.
* **Path Canonicalizer (`app/safety/canonicalizer.py`):** Symlink resolution and path containment logic.

---

## [0.1.0 – 0.4.0] - Foundational Storage Diagnostics & Analysis

### Added
* Core `StorageScanner` for APFS volume capacity, directory size calculations, and large file discovery.
* Semantic `StorageAnalyzer` for categorization (`CACHE`, `LOGS`, `DEVELOPMENT`, `DOCUMENTS`, `UNKNOWN`) and risk tiers (`LOW`, `MEDIUM`, `HIGH`, `UNKNOWN`).
* Rule-based `RecommendationEngine` with size thresholding and candidate deduplication.
* Initial CLI interface (`app/cli.py`).
