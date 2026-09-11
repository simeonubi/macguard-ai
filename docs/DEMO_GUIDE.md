# MacGuard AI — Technical Demonstration & Presentation Guide

This guide outlines a structured **3–5 minute executive and technical demonstration** of MacGuard AI for portfolio reviews, interview showcases, and product presentations.

---

## Demonstration Script & Timing

```mermaid
timeline
    title MacGuard AI Demo Flow (3–5 Minutes)
    00:00 - 00:30 : Problem & Safety-First Thesis
    00:30 - 01:00 : Executive Dashboard & System State
    01:00 - 01:45 : Read-Only Diagnostic Scanner
    01:45 - 02:15 : Deterministic Recommendations
    02:15 - 02:45 : AI Agent & Capability Boundary
    02:45 - 03:15 : Human Review & HMAC Sealing
    03:15 - 03:45 : Non-Destructive Dry Run
    03:45 - 04:15 : Controlled Trash Move & Integrity Check
    04:15 - 05:00 : Audit Forensics & Architecture Summary
```

---

### Phase 1: Problem & Product Vision (00:00 – 00:30)
- **Speaker Script:**  
  *"Traditional macOS storage cleanup tools are risky: they often use black-box heuristics, hardcoded deletion scripts (`rm -rf`), and can accidentally delete active developer dependencies, virtual machines, or user documents. MacGuard AI is an AI-powered, safety-first storage intelligence tool that pairs deterministic security rules with local LLM reasoning to ensure zero unintended data loss."*
- **Key Message:** Zero permanent deletion. Zero-authority AI. Human-in-the-loop control.

---

### Phase 2: Executive Dashboard (00:30 – 01:00)
- **Action:** Open `http://localhost:8501` (Dashboard tab).
- **Highlights to Show:**
  - System Disk Physical State (Total Capacity, Used Space, Available Space, Allocation %).
  - Quick action buttons.
  - Category breakdown and Risk tier distribution.
  - Option to load the presentation demo dataset via **`🧪 Load Presentation Demo Data`** for zero-risk presentations.

---

### Phase 3: Diagnostic Scanning (01:00 – 01:45)
- **Action:** Navigate to **Scan Storage** (`Scan` tab) and run a diagnostic scan or load the demo dataset.
- **Highlights to Show:**
  - **Read-Only Guarantee:** Diagnostic scanning performs zero filesystem mutations.
  - **Hierarchical Deduplication:** Nested items inside parent directories are clearly tagged (`↳ Included in parent candidate`) to prevent double-counting storage sizes.
  - Interactive **Storage Visualizations** (Category MB distribution, Risk tier distribution, Largest consumers).

---

### Phase 4: Deterministic Recommendations (01:45 – 02:15)
- **Action:** Navigate to **Recommendations** tab.
- **Highlights to Show:**
  - Explainable recommendation cards with confidence scores, category, and rationale.
  - Clear visual risk tiers:
    - 🟢 `Eligible for controlled Trash review` (Caches, Logs)
    - 🟡 `Manual review required` (Developer node_modules, Python venvs, Docker images)
    - 🔴 `Safety Blocked` (User documents, System bundles)
  - Interactive sorting by size, risk tier, and category.
  - **Local AI Context Explanations:** Click *"Explain Finding with Local AI"* to show natural language reasoning.

---

### Phase 5: Conversational AI Agent (02:15 – 02:45)
- **Action:** Navigate to **AI Agent** (`Agent` tab).
- **Highlights to Show:**
  - **Zero Execution Authority**: The AI assistant can analyze, inspect, explain, and prioritize findings, but **cannot approve, delete, or move files**.
  - Click a quick safe prompt: *"What is consuming the most storage?"* or *"Which storage candidates should I review first?"*
  - Show the split presentation: **MacGuard Verified Storage Facts** (deterministic metric cards) vs **AI Explanation & Reasoning** vs **Recommended Next Step**.

---

### Phase 6: Human Review & Cryptographic Approval (02:45 – 03:15)
- **Action:** Navigate to **Human Review** (`Review` tab).
- **Highlights to Show:**
  - **Mandatory Informed Consent Declaration**: Individual approval buttons are disabled until the user explicitly checks the consent box.
  - **No "Approve All" / No Auto-Approval**: Every mutating action requires conscious per-item review.
  - Click **`✅ Approve Item`** on a low-risk cache item:
    - Generates a cryptographically signed HMAC-SHA256 authorization token bound to canonical path, operation, risk level, and 15-minute expiration.

---

### Phase 7: Dry Run & Controlled Execution (03:15 – 04:15)
- **Action:** Navigate to **Controlled Execution** (`Execution` tab).
- **Highlights to Show:**
  - **Safe Workflow Header**: `Review ➔ Approve ➔ Dry Run ➔ Controlled Trash ➔ Integrity Verification ➔ Audit`.
  - Click **`🧪 Dry Run Simulation`**:
    - Simulates space reclamation without touching the filesystem and without consuming the approval token.
  - Click **`🗑️ Safely Move to Trash`**:
    - Atomic token claim under thread lock.
    - Pre-move `os.lstat()` integrity snapshot.
    - Controlled move to isolated macOS Trash (`~/.Trash`).
    - Post-move verification (source absent, destination verified in Trash with matching SHA-256 hash).
    - Permanent consumption of approval token (prevents replay attacks).

---

### Phase 8: Cryptographic Audit Trail (04:15 – 04:45)
- **Action:** Navigate to **Audit Log** (`Audit` tab).
- **Highlights to Show:**
  - Complete, immutable forensic trail stored locally in SQLite.
  - Events tracked: `APPROVAL_REQUESTED`, `APPROVAL_APPROVED`, `EXECUTION_CLAIMED`, `TRASH_MOVE_SUCCEEDED`, `TRASH_VERIFICATION_SUCCEEDED`, `APPROVAL_CONSUMED`.
  - Zero cryptographic secrets, tokens, or raw file contents in audit logs.
  - Built-in crash recovery detection for incomplete operations.

---

### Phase 9: Wrap-Up & Key Architecture Highlights (04:45 – 05:00)
- **Summary Points:**
  - 100% automated test coverage (245 unit & integration tests, 60 focused security tests).
  - 0 calls to permanent deletion primitives (`os.remove`, `rm`, `unlink`, `shutil.rmtree`).
  - 0 subprocess or shell execution calls.
  - Full defense-in-depth safety engine.
