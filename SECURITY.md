# MacGuard AI — Security Policy & Specification

This document defines the formal security policy, threat boundaries, trust models, cryptographic authorization mechanisms, and verification invariants for **MacGuard AI v1.1.0**.

---

## 1. Security Philosophy & Invariant Flow

MacGuard AI operates under a defense-in-depth security model where intelligence is strictly decoupled from execution authority:

```text
       Analyze Broadly (Bounded Read-Only Whole-Home Discovery)
              ↓
       Assess Risk (Deterministic 16-Category Classification & Risk Tiers)
              ↓
       Analyze Redundancy (Streaming Two-Stage Hashing & Hardlink Accounting)
              ↓
       Track History (Immutable SQLite Storage Snapshots & Velocity)
              ↓
       Recommend Carefully (6-Tier Action Taxonomy & Size Thresholds)
              ↓
       Require Human Approval (Explicit, Granular Informed Consent)
              ↓
       Revalidate (Cryptographic HMAC Check & Allowlist Verification)
              ↓
       Move to Trash (Controlled Move Exclusively to ~/.Trash)
              ↓
       Verify (Post-Move Absence & Destination Hash Verification)
              ↓
       Audit (Immutable SQLite WAL Event Forensics)
```

---

## 2. Core Security Invariants

The application enforces 12 non-negotiable security invariants across all execution paths:

| # | Invariant | Enforcement Mechanism |
|---|---|---|
| **1** | **Zero Permanent Deletion Primitives** | Codebase contains **zero** instances of `os.remove`, `os.unlink`, `Path.unlink`, `Path.rmdir`, `shutil.rmtree`, or shell `rm`. All mutations route exclusively to macOS Trash (`~/.Trash`). |
| **2** | **Zero Subprocess / Shell Execution** | No `os.system`, `subprocess.Popen`, `subprocess.run`, or shell invocations exist in the entire application. |
| **3** | **Zero Agent Mutation Authority** | **The AI agent can inspect, explain, summarize, and prioritize storage findings. It cannot approve or execute cleanup.** |
| **4** | **Mandatory Human Approval** | Implicit, conversational, or bulk ("Approve All") authorizations are strictly prohibited. Every item requires conscious, individual human confirmation. |
| **5** | **Cryptographic HMAC-SHA256 Authorization** | Every approval is cryptographically signed using an ephemeral 256-bit runtime secret key (`ApprovalKeyManager`) binding canonical path, operation, risk level, and expiration. |
| **6** | **Strict Single-Use Replay Protection** | Tokens atomically transition from `PENDING` → `APPROVED` → `CONSUMED`. Re-execution of a consumed token is immediately blocked. |
| **7** | **Allowlist & Denylist Boundary Enforcement** | Mutations are confined to explicit allowlisted cache and log roots (`~/Library/Caches`, `~/Library/Logs`, `~/.cache`, `DerivedData`). System roots and user documents are permanently blocked. |
| **8** | **Anti-Symlink Traversal Protection** | File operations inspect targets using `os.lstat()`. Symlinks are strictly prohibited from being followed or targeted for mutation. |
| **9** | **Time-of-Check to Time-of-Use (TOCTOU) Protection** | Pre-execution verification re-evaluates the target allowlist, file existence, inode, size, and SHA-256 hash immediately prior to moving. |
| **10** | **Pre/Post Physical Integrity Verification** | Byte-exact SHA-256 hash digests are verified before and after moving to Trash. Content mismatch results in immediate failure. |
| **11** | **Controlled Trash Destination** | All moves target uniquely segregated subdirectories inside `~/.Trash/MacGuard_<approval_id>_<token>`. |
| **12** | **Persistent Tamper-Evident Audit Logging** | All scanning, recommendation, approval, dry-run, execution, and verification events are recorded in a local WAL-mode SQLite database with zero secret leakage. |

---

## 3. Trust Boundaries & Separation of Privilege

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              UNTRUSTED BOUNDARIES                               │
│                                                                                 │
│   ┌───────────────────────────┐         ┌───────────────────────────────────┐   │
│   │     Filesystem Inputs     │         │       Advisory AI / LLM           │   │
│   │ (Arbitrary paths, names,  │         │ (Conversational reasoning, prompts│   │
│   │  symlinks, metadata)      │         │  Ollama responses, embeddings)    │   │
│   └─────────────┬─────────────┘         └─────────────────┬─────────────────┘   │
└─────────────────┼─────────────────────────────────────────┼─────────────────────┘
                  │                                         │
                  ▼                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               TRUSTED CORE ENGINE                               │
│                                                                                 │
│   ┌───────────────────────────┐         ┌───────────────────────────────────┐   │
│   │   Deterministic Safety    │         │       Human Approval Gate         │   │
│   │  (PathValidator, Rules,   │         │ (Explicit Consent, 256-bit Key,   │   │
│   │   Integrity, Canonical)   │         │  HMAC-SHA256 Token Signature)     │   │
│   └─────────────┬─────────────┘         └─────────────────┬─────────────────┘   │
│                 │                                         │                     │
│                 ▼                                         ▼                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                   Execution Planner & Trash Executor                    │   │
│   │               (Revalidation, os.lstat, Moves to ~/.Trash)               │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│                                         ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                     SQLite WAL-Mode Audit Repository                    │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

1. **User Input & Prompts**: Untrusted. Prompt injections or simulated commands cannot bypass deterministic safety filters.
2. **Local LLM / Ollama**: Untrusted. Responses are validated against prohibited destructive shell patterns (`validate_explanation_safety`) and have zero tool execution access.
3. **Safety Engine & Key Manager**: Trusted. Computes cryptographic signatures and enforces allowlists.
4. **Execution Engine**: Trusted. Requires valid HMAC token and verified pre-execution snapshot before performing any Trash move.

---

## 4. Fail-Closed Policy

In accordance with safety engineering best practices, MacGuard AI implements a strict **fail-closed** architecture:

* **Unallowlisted Paths:** Refused with explicit policy rule violation.
* **Ambiguous / Unknown Risk:** Assigned `RiskLevel.UNKNOWN` and permanently blocked from cleanup approval.
* **Symlink Target:** Blocked from execution to prevent symlink race traversal attacks.
* **Invalid / Tampered HMAC Token:** Execution rejected (`ExecutionStatus.BLOCKED`).
* **Expired Approval Token:** Rejected if older than 15 minutes.
* **Pre-Execution Size / Hash Mismatch:** Execution halted before moving.
* **Post-Move Missing Destination:** Fails with integrity alert and audit event.
* **Ollama Daemon Timeout:** Degrades gracefully to offline deterministic explanation; zero UI or system failure.

---

## 5. Risk Classification Matrix

| Risk Level | Description | Cleanup Eligibility | Example Locations |
|---|---|---|---|
| **`LOW`** | Ephemeral, regenerable application caches and diagnostic logs older than threshold. | **Eligible for Human Review** | `~/Library/Caches/Google/Chrome`, Xcode `DerivedData`, `~/Library/Logs/DiagnosticReports` |
| **`MEDIUM`** | Developer artifacts and rebuildable dependencies requiring developer awareness. | **Manual Review Required (Caution)** | `node_modules`, Python `.venv`, Docker `disk.raw` |
| **`HIGH`** | System bundles, preferences, keychains, and personal user documents. | **Strictly Blocked** | `/System`, `/Library`, `~/Documents`, `~/Desktop`, `~/.ssh`, `~/.aws` |
| **`UNKNOWN`** | Ambiguous, unclassified, or unrecognized binary extensions. | **Strictly Blocked (Conservative)** | Unrecognized extensions outside known cache paths |

---

## 6. Extended Threat Model Considerations (T1–T29)

In addition to foundational threats T1–T25 documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), MacGuard AI v1.1 enforces specific protections against advanced storage intelligence threat vectors:

### Threat T26: Symlink Loop and Filesystem Boundary Evasion
* **Threat**: Malicious or circular symbolic links designed to trigger infinite recursion during whole-home scanning or escape bounded search paths.
* **Defense**: `WholeHomeScanner` enforces `followlinks=False`, records visited device/inode sets, enforces `TraversalLimits.max_depth` (default: 8) and `TraversalLimits.max_items` (default: 100,000), and rejects symlink traversal at every layer.

### Threat T27: Duplicate Evidence Manipulation & False Identity Deception
* **Threat**: Malicious crafted files designed to trick duplicate analysis into proposing deletion of genuine user documents or original source files.
* **Defense**: Duplicate detection provides **evidence only**, never independent deletion authority. Hardlink awareness (`st_nlink > 1`, matching `st_ino`) guarantees that APFS clones/hardlinks are detected as zero-wasted-byte items and cannot be misclassified as redundant physical waste.

### Threat T28: Historical Trend Manipulation & SQLite Snapshot Poisoning
* **Threat**: Malicious alteration of historical scan snapshots to hide anomalous growth or manipulate storage trend indicators.
* **Defense**: SQLite snapshots are managed through parameterized queries with strict Schema v2 constraints, timestamp validation, and WAL-mode database locking. Historical data remains strictly diagnostic.

### Threat T29: Developer Artifact Risk Confusion
* **Threat**: Misidentifying active developer environments (e.g., active project `.venv`, uncommitted git repositories, or production node dependencies) as disposable caches.
* **Defense**: `DeveloperStorageAnalyzer` inspects root manifests (`package.json`, `pyproject.toml`, `Cargo.toml`), assigns `RiskLevel.MEDIUM` (Manual Review Caution), and segregates developer environments from automated `LOW`-risk caches.

---

## 7. Security Suite & Verification

The core security invariants are validated by a dedicated **73-test security suite** (`tests/test_safety.py`, `tests/test_agent_security.py`, `tests/test_execution_security.py`, `tests/test_mutation_guard.py`, `tests/test_integrity.py`, `tests/test_path_fuzzing.py`, `tests/test_sandbox_final_validation.py`, `tests/test_trash_executor.py`):
* 100% pass rate.
* 0 dangerous AST primitives (`os.unlink`, `os.rmdir`, `shutil.rmtree`, `subprocess`, `os.system`, `eval`, `exec`).
* 100% prompt injection resistance.

---

## 8. Reporting a Vulnerability

If you discover a potential security flaw or unexpected safety boundary bypass in MacGuard AI, please report it responsibly:
1. Do not open public GitHub issues for security vulnerabilities.
2. Submit a private report detailing reproduction steps, target paths, and expected vs. actual behavior.
3. Reports are acknowledged within 24 hours and prioritized for immediate remediation.
