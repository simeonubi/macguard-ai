# MacGuard AI — User Guide & Operations Manual

Welcome to **MacGuard AI v1.1.0**, the safety-first storage intelligence and management platform for macOS. This guide explains how to explore storage, understand developer environments, inspect duplicate clusters, track historical trends, test cleanup simulations, and safely move unwanted files to macOS Trash.

---

## 1. First Launch & Interface Overview

To launch the MacGuard AI interactive web interface, open a terminal in the project directory and run:

```bash
streamlit run streamlit_app.py
```

The application opens in your default browser at `http://localhost:8501`.

### Interface Layout & Views
* **Sidebar Navigation**: Switch between the **4 Operating Modes** (`ANALYZE`, `AGENT`, `REVIEW`, `CLEAN`) and 10 dedicated workflow views:
  * **📊 Dashboard**: Storage overview, capacity gauges, and quick action launchpads.
  * **🔍 Scan Storage**: Granular storage scanning via configurable `ScanScope`.
  * **📦 Developer Storage**: Dedicated inspector for Xcode, Docker, Python virtualenvs, Node modules, Rust targets, and ML model caches.
  * **👥 Duplicate Explorer**: Read-only duplicate cluster visualizer with APFS hardlink awareness.
  * **📈 Storage Intelligence & History**: Multi-scan historical snapshots and growth trend analytics.
  * **💡 Recommendations**: Explainable findings using the 6-tier action taxonomy.
  * **🛡️ Human Review**: Informed Consent confirmation, candidate cards, and individual approval buttons.
  * **🗑️ Controlled Execution**: Dry Run simulation and verified Trash execution.
  * **🤖 AI Agent**: Interactive conversational storage reasoner with prominent capability boundary indicator.
  * **📜 Audit Log**: Searchable, filterable cryptographic event viewer.
  * **⚙️ Settings**: System diagnostics, non-disableable safety policy guarantees, and runtime engine health.
* **Presentation Demo Toggle**: Click **"🧪 Load Presentation Demo Data"** at any time to test and explore all features with simulated data without touching your real files.
* **Safety Policy Banner**: Always visible at the bottom of the sidebar, reminding users that permanent deletion is permanently disabled.

---

## 2. Operating Mode 1: `ANALYZE` (Storage Discovery & Diagnostics)

The `ANALYZE` mode provides deep, read-only visibility into your drive utilization. **Zero filesystem modifications occur in this mode.**

### 🔍 Scan Storage
1. Navigate to **🔍 Scan Storage** in the sidebar.
2. Select your **Scan Scope** (`HOME`, `DEV`, `APP_DATA`, `CACHE`, or `CUSTOM`).
3. Set your traversal limit (number of top items to discover).
4. Click **"🚀 Start Storage Scan"**.
5. Inspect interactive Altair charts showing storage distribution across 16 categories and risk tiers.

### 📦 Developer Storage
1. Navigate to **📦 Developer Storage**.
2. Inspect environment breakdowns for Xcode `DerivedData`, Docker containers/layers, Python `.venv` environments, Node `node_modules`, Rust `target` builds, and local ML model caches (Hugging Face, Ollama, PyTorch).
3. View project association manifests (`package.json`, `pyproject.toml`, `Cargo.toml`) and staleness indicators.

### 👥 Duplicate Explorer
1. Navigate to **👥 Duplicate Explorer**.
2. View duplicate clusters grouped by exact byte-for-byte SHA-256 hash.
3. Observe APFS hardlink badges (`st_nlink > 1`) and zero-wasted-byte indicators.
4. Note that duplicate inspection is strictly read-only diagnostics.

### 📈 Storage Intelligence & History
1. Navigate to **📈 Storage Intelligence & History**.
2. Compare previous scan snapshots persisted in the local SQLite database.
3. Track category growth trends with velocity indicators (`GROWING`, `SHRINKING`, `STABLE`).

---

## 3. Operating Mode 2: `AGENT` (Conversational Storage Assistant)

The `AGENT` mode allows you to explore and understand your storage using natural language.

### What the AI Agent CAN Do
* Provide conversational storage breakdowns (*"What are my largest cache folders?"*).
* Compare historical scans (*"How much did caches grow since last scan?"*).
* Summarize duplicate clusters (*"Which duplicate files waste the most space?"*).
* Explain developer tooling build artifacts (*"Why is Xcode DerivedData taking 15 GB?"*).
* Summarize risk tiers and recommend areas for manual inspection.

### What the AI Agent CANNOT Do
* **The agent cannot approve files for cleanup.**
* **The agent cannot delete, move, rename, or touch any file.**
* **The agent cannot execute shell commands or subprocesses.**
* **The agent cannot bypass allowlists or HMAC security tokens.**

---

## 4. Operating Mode 3: `REVIEW` (Recommendations & Human Approvals)

The `REVIEW` mode translates raw scan data into explainable findings and enforces mandatory human approval.

### Understanding Risk Levels & Recommendation Actions
* **🟢 LOW Risk (`REVIEW_FOR_CLEANUP`)**: Safe, rebuildable temporary items (e.g., Xcode DerivedData, browser cache). Eligible for human cleanup review.
* **🟡 MEDIUM Risk (`MANUAL_REVIEW`)**: Developer dependencies (`node_modules`, Python `.venv`) that can be regenerated from build manifests (`package.json`, `requirements.txt`), requiring developer awareness.
* **🔵 INFORMATIONAL (`INFORMATIONAL`)**: Large static files, duplicate clusters, or historical growth insights displayed for awareness only.
* **🔴 HIGH Risk (`PROTECTED_SYSTEM` / `NO_ACTION`)**: System bundles, user documents, and preferences. **Strictly blocked from automated cleanup by safety policy.**
* **⚪ UNKNOWN Risk (`UNKNOWN_RISK` / `NO_ACTION`)**: Unrecognized binary files. **Permanently blocked under fail-closed conservative rules.**

### Hierarchical Candidate Deduplication
If a container directory (e.g. `~/Library/Caches/trivy`) and a file inside it (e.g. `trivy/db/trivy.db`) are both flagged:
* The parent container is clearly tagged: `📂 Container Directory: Includes 1 nested candidate item(s)`.
* The child item is tagged: `↳ Contained in parent candidate`.
* This prevents double-counting reclaimable space.

### Granting Human Approval (No "Approve All")
1. Navigate to **🛡️ Human Review**.
2. Read and acknowledge the **Informed Consent Declaration**:  
   > *"I understand that approved items will be safely moved to macOS Trash (~/.Trash). No permanent deletion will occur."*
3. Review candidate cards in the **Eligible for Review** queue.
4. Click **"✅ Approve for Controlled Trash"** on the specific item you wish to approve.
5. The system cryptographically signs an **HMAC-SHA256 authorization token** valid for 15 minutes.

---

## 5. Operating Mode 4: `CLEAN` (Controlled Execution & Verification)

The `CLEAN` mode provides a verified, two-stage execution pipeline.

```text
Review Item ──> Grant Approval ──> Dry Run Simulation ──> Controlled Move to ~/.Trash ──> Verify SHA-256 ──> Audit
```

### Step 1: Run a Non-Destructive Dry Run
1. Navigate to **🗑️ Controlled Execution**.
2. Select your approved item from the queue.
3. Click **"🧪 Dry Run Simulation"**.
4. The system validates the allowlist, tests the execution plan, and displays the exact simulated reclaimable space.  
   **Result:** Zero files are modified, and your approval token remains valid (`APPROVED`).

### Step 2: Execute Controlled Move to macOS Trash
1. Click **"🗑️ Safely Move to Trash"**.
2. MacGuard performs the following automated safety checks:
   - Revalidates the path allowlist.
   - Atomically claims the HMAC token (transitioning it to `EXECUTING`).
   - Captures a pre-execution physical snapshot (`os.lstat`, file size, inode, SHA-256).
   - Moves the item exclusively into `~/.Trash/MacGuard_<approval_id>_<token>/`.
   - Verifies the source path no longer exists.
   - Verifies the destination file in `~/.Trash` matches the pre-move SHA-256 hash byte-for-byte.
   - Atomically transitions the token to `CONSUMED`.
   - Records the complete forensic timeline to the SQLite audit database.

---

## 6. Recovering Files from macOS Trash

Because MacGuard AI moves items to macOS Trash rather than permanently deleting them, **all cleanup operations are fully recoverable**:

1. Open **Finder** and click the **Trash** icon in your Dock.
2. Locate the folder named `MacGuard_<approval_id>_<token>`.
3. Right-click the item and select **"Put Back"**, or drag the item back to its original location.

---

## 7. Command-Line Interface (CLI) Reference

For terminal workflows or headless environments:

```bash
# 1. Read-only diagnostic overview of root and home directories
python -m app.cli

# 2. Interactive terminal review with non-destructive dry-run simulation
python -m app.cli --review

# 3. Interactive terminal review with controlled move to macOS Trash
python -m app.cli --trash

# 4. View persistent SQLite audit log entries
python -m app.cli --audit
```
