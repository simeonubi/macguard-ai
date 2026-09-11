# MacGuard AI — Safety Specification & Policy

This document defines the mandatory safety constraints, operating modes, risk tiers, and validation policies governing **MacGuard AI v1.1.0**.

---

## 1. Core Safety Objectives

1. **Zero Unintended Data Loss**: The primary directive of MacGuard AI is to prevent the loss of critical system files, user documents, credentials, or unrecoverable application state.
2. **User Sovereignty**: The user maintains total, transparent control over their filesystem. No mutating action may occur without informed, explicit human consent.
3. **Deterministic Safety Enforcement**: Safety rules are implemented in hardcoded, deterministic Python logic. AI models are treated as **untrusted proposal generators** and are strictly prevented from executing direct filesystem mutations.
4. **Fundamental Safety Axiom**:
   $$\text{DISCOVERY} \neq \text{AUTHORIZATION} \neq \text{RECOMMENDATION} \neq \text{APPROVAL} \neq \text{EXECUTION}$$

---

## 2. Four Segregated Operating Modes

MacGuard operates under four strictly segregated modes:

```text
┌─────────────────────────┐       ┌─────────────────────────┐       ┌─────────────────────────┐       ┌─────────────────────────┐
│         ANALYZE         │       │          AGENT          │ ───>  │         REVIEW          │ ───>  │          CLEAN          │
│       (Read-Only)       │       │    (Conversational AI)  │       │   (Human Confirmation)  │       │    (Controlled Trash)   │
│  - ScanScope Discovery  │       │  - Analytical Tools     │       │  - Inspect Recs & Risk  │       │  - Integrity Validation │
│  - 16 Smart Categories  │       │  - Trend & Delta Q&A    │       │  - Local AI Context     │       │  - Atomic Token Claim   │
│  - Developer Artifacts  │       │  - Injection Defense    │       │  - Explicit HMAC Sign   │       │  - Move to ~/.Trash     │
│  - Duplicate Explorer   │       │  - Zero Exec Authority  │       │  - ZERO Mutations       │       │  - Post-Move Verify     │
│  - Storage History      │       │                         │       │                         │       │  - SQLite Audit Logging │
└─────────────────────────┘       └─────────────────────────┘       └─────────────────────────┘       └─────────────────────────┘
```

### Mode 1: `ANALYZE` (Read-Only Diagnostics)
* **Behavior**: Scans disk mounts, inspects directory hierarchies via bounded `ScanScope`, identifies large files, classifies items into 16 categories, analyzes developer artifacts, detects duplicate clusters, and records historical snapshots.
* **Mutations**: **Strictly Forbidden**. Zero file deletions, modifications, moves, or attribute changes.
* **State**: Completely read-only.

### Mode 2: `AGENT` (Conversational Advisory Reasoning)
* **Behavior**: Answers user queries about storage consumers, growth trends, scan-to-scan comparisons, developer artifacts, and duplicate clusters using strictly allowlisted read-only analytical tools.
* **Mutations**: **Strictly Forbidden**. The agent has **zero tools** to delete, move, modify, or approve files.
* **State**: Completely read-only advisory.

### Mode 3: `REVIEW` (Human Confirmation & HMAC Gate)
* **Behavior**: Ingests findings, applies 6-tier recommendation taxonomy, calculates risk scores, presents candidate cards, requires informed consent confirmation, and issues cryptographic HMAC-SHA256 approval tokens upon individual user action.
* **Mutations**: **Strictly Forbidden**.
* **State**: Completely read-only with cryptographic authorization generation.

### Mode 4: `CLEAN` (Controlled Execution & Integrity Verification)
* **Behavior**: Executes non-destructive Dry Run simulations and controlled moves to macOS Trash (`~/.Trash`) on verified, allowlisted items bearing unconsumed, unexpired HMAC approval tokens.
* **Mutations**: Permitted **only** on items passing all safety checks, pre/post physical integrity checks, and bearing a verified human approval token.
* **State**: Audited, verified, and restricted Trash-only mutation.

---

## 3. Human Approval Protocol & Cryptographic Boundary

### Mandatory Explicit Approval
Before any file or directory is modified or moved:
1. The system must present the **canonical path**, **file size**, **semantic category**, and **risk classification**.
2. The user must provide a conscious, unambiguous approval action (e.g., clicking a specific item approval button). Bulk "Approve All" actions are strictly prohibited.

### Prohibition of Implicit Authorization
The agent must **never** interpret broad or conversational prompts as blanket approval. Examples of phrases that **DO NOT** constitute cleanup authorization:
* ❌ *"Clean up my Mac"*
* ❌ *"Free up 15 GB of space"*
* ❌ *"Delete old files"*
* ❌ *"Remove duplicate caches"*

Such prompts must only provide diagnostic answers and guide the user to the `REVIEW` stage.

### Cryptographic Authorization Boundary (HMAC-SHA256)
Human approvals are cryptographically sealed using **HMAC-SHA256** backed by a 256-bit runtime secret (`ApprovalKeyManager`):

1. **Exact Parameter Binding**: The signature covers `approval_id`, `canonical_path`, `operation`, `risk_level`, `expires_at`, and `approved` state.
2. **Replay Protection**: The `ApprovalService` maintains an in-memory registry. Once an approval is consumed for execution, its status is marked `CONSUMED` and cannot be replayed.
3. **Key Isolation**: The HMAC secret key is never serialized, logged, transmitted to the LLM, or exposed in UI models.
4. **Approval Lifecycle**:
   ```text
   PENDING ──(explicit human approval)──> APPROVED ──(HMAC verification)──> EXECUTING
      │                                       │                                │
      ├────(user cancels / rejects)─> REJECTED  └────(Dry Run: token untouched)   └────(Post-Move Verified)──> CONSUMED (No Replay)
      │                                                                                │
      └────(time > 15 minutes)───────> EXPIRED                                         └────(Integrity Mismatch)──> FAILED (Fail Closed)
   ```

---

## 4. Path Safety & Allowlisting

To eliminate the risk of destructive path traversal or accidental deletion, the execution engine enforces a multi-layered boundary check:

```text
Proposed Path
     │
     ▼
[Path Canonicalization]  ──> Resolve symlinks, .., unicode normalization
     │
     ▼
[Denylist Check]         ──> Immediate abort if matching OS / user data paths
     │
     ▼
[Allowlist Check]        ──> Immediate abort if NOT explicitly allowlisted
     │
     ▼
[Permission & Ownership] ──> Abort if root-owned, SIP-locked, or mismatched uid
     │
     ▼
[Human Approval Token]   ──> Abort if unapproved, expired, or consumed
     │
     ▼
[Pre-Execution Check]    ──> os.lstat non-following snapshot & SHA-256 verification
     │
     ▼
[Controlled Trash Move]  ──> Move exclusively into ~/.Trash/MacGuard_<approval_id>_<token>/
     │
     ▼
[Post-Move Verification] ──> Confirm source absent & destination SHA-256 matches
     │
     ▼
[Immutable Audit Record] ──> Record event to SQLite WAL database
```

---

## 5. Non-Deletion Rules & System Denylist

The following categories must **NEVER** be automatically targeted, recommended, or moved:

| Category | Forbidden Locations & Patterns |
| :--- | :--- |
| **macOS System & SIP Paths** | `/System`, `/usr`, `/bin`, `/sbin`, `/etc`, `/var`, `/private`, `/Library/Preferences` |
| **User Documents & Desktop** | `~/Documents/*`, `~/Desktop/*`, iCloud Drive paths |
| **Personal Media** | `~/Pictures/*`, `~/Movies/*`, `~/Music/*`, Photos Libraries |
| **Credentials & Secrets** | `~/.ssh/*`, `~/.gnupg/*`, `~/.aws/*`, `~/.config/gcloud/*`, `.env*`, `*.pem`, `*.key` |
| **Databases & State Stores** | `*.sqlite`, `*.db`, CoreData stores, PostgreSQL/MySQL data directories |
| **Browser User Profiles** | `~/Library/Application Support/Google/Chrome/Default/*`, Safari session stores, Firefox profiles |
| **System & Security Extensions**| `/Library/Extensions`, `/Library/SystemExtensions`, `/Library/LaunchDaemons` |
| **Arbitrary Hidden Files** | `~/.*` (except explicitly allowlisted package manager cache subdirectories) |
| **Root/Foreign Owned Files** | Any file where `stat.st_uid != current_user_uid` |

---

## 6. Risk Classification Framework

Every candidate item discovered during analysis must be classified into one of four risk tiers:

```text
  [ LOW ]      Recreatable caches, disposable temporary files, package download caches.
     │
 [ MEDIUM ]    Developer build artifacts, virtual environments, node modules (rebuild required).
     │
  [ HIGH ]     Application support data, downloads folder items, personal documents.
     │
 [ UNKNOWN ]   Unidentified files or ambiguous provenance.
               MUST BE TREATED CONSERVATIVELY AS HIGH / NEVER DELETE.
```

### Risk Tiers Defined

1. **`LOW` Risk**:
   * *Definition*: Ephemeral files that are guaranteed to be automatically recreated by their parent application without loss of user state.
   * *Examples*: Xcode `DerivedData`, npm cache, pip cache, Homebrew download cache.
   * *Eligibility*: **Eligible for human review and controlled Trash cleanup.**
2. **`MEDIUM` Risk**:
   * *Definition*: Developer artifacts whose deletion requires manual rebuilds or re-downloads, but which contain no unique user intellectual property.
   * *Examples*: `.venv` virtual environments, `node_modules`, Rust `target` builds.
   * *Eligibility*: **Manual Review Required (Caution).**
3. **`HIGH` Risk**:
   * *Definition*: Items in user-managed directories or system paths where intent cannot be proven automatically.
   * *Examples*: Documents, Desktop, Pictures, application support databases.
   * *Eligibility*: **Strictly Blocked by Safety Policy.**
4. **`UNKNOWN` Risk**:
   * *Definition*: Any item that does not match a verified, deterministic heuristic rule.
   * *Policy*: **Fail closed**. `UNKNOWN` items are permanently locked against automated cleanup proposals.

---

## 7. Controlled Trash-Based Execution Invariants

1. **No Permanent Deletion**: The implementation strictly forbids `os.remove`, `os.unlink`, `Path.unlink`, `Path.rmdir`, `shutil.rmtree`, and shell deletion commands (`rm`, `subprocess`, `os.system`).
2. **Controlled Trash Destination**: Target destinations are internally computed within `~/.Trash` (or an isolated sandbox Trash root during automated testing) and validated with `is_contained_within`. Destinations are never accepted from user input or LLM generation.
3. **Atomic Execution Claim**: `ApprovalService.claim_for_execution()` atomically transitions `APPROVED` records to `EXECUTION_CLAIMED` under a `threading.Lock` mutex to prevent concurrent double-execution.
4. **Immediate Pre-Mutation Revalidation**: Immediately before filesystem mutation, `TrashExecutor` re-verifies HMAC signatures, risk tier (`LOW` only), operation (`CLEAN` only), canonical source paths, Safety Engine allowlists, and inspects filesystem objects via `os.lstat()`.
5. **Symlink Defense**: Any source item that is a symbolic link or has been swapped with a symbolic link fails closed immediately (`stat.S_ISLNK` / `os.path.islink()`).
6. **Collision Protection**: Items are placed in isolated subfolders (`MacGuard_<approval_id>_<token>/`) to prevent overwriting existing Trash contents.
7. **Post-Move Verification**: Approvals transition to `CONSUMED` only after verifying source absence and destination presence inside `~/.Trash`.
8. **Sandbox Isolation in Tests**: All mutation unit and integration tests execute exclusively inside temporary directories (`tempfile.TemporaryDirectory()`). Real user directories are never modified during test runs.

---

## 8. Agentic Advisory Boundary Invariants

1. **"The Agent Has Intelligence, But Zero Authority"**:
   - `LLM ≠ Authority`
   - `Agent ≠ Executor`
   - `Recommendation ≠ Approval`
   - `Approval ≠ Execution`
2. **Zero Mutation Primitives**: The agent package contains zero imports of mutation tools, deletion primitives, or execution engines.
3. **Strictly Read-Only Allowlisted Tools**: The agent may only invoke explicitly allowlisted analytical tools (`get_storage_overview`, `list_top_directories`, `list_large_files`, `get_category_breakdown`, `get_recommendations`, `explain_candidate`, `get_storage_trends`, `compare_scans`, `get_duplicate_summary`, `get_developer_storage_breakdown`).
4. **Prompt & Metadata Injection Defenses**: Untrusted filesystem metadata is wrapped in `<storage_analysis_data>` delimiters with strict anti-injection system prompts. Malicious user instructions attempting safety circumvention are rejected.
5. **Secret Isolation**: Secrets, HMAC keys, and `ApprovalKeyManager` instances are never exposed to agent state, prompts, responses, or logs.
