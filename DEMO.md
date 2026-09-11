# MacGuard AI — 3–5 Minute Presentation & Live Demonstration Script

This document provides a concise, step-by-step presentation script designed for portfolio walkthroughs, live technical interviews, and investor demonstrations for **MacGuard AI v1.1.0**.

> **Zero-Risk Guarantee**: This demonstration uses the built-in **Presentation Demo Dataset** (`app/ui/demo.py`). It simulates real-world developer storage findings, duplicate clusters, and historical trends in memory without scanning, moving, or modifying any real user files.

---

## Timing Overview

```text
┌──────────────┬───────────────────────────────┬────────────────────────────────────────┐
│    Timing    │ Segment                       │ Screen / View                          │
├──────────────┼───────────────────────────────┼────────────────────────────────────────┤
│ 0:00 – 0:30  │ Problem Statement             │ Slide / Verbal                         │
│ 0:30 – 1:00  │ Safety Architecture Overview  │ Dashboard (localhost:8501)             │
│ 1:00 – 1:45  │ Storage Scan & Developer View │ Scan Storage ➔ Developer Storage       │
│ 1:45 – 2:30  │ Duplicates & Storage Trends   │ Duplicate Explorer ➔ Storage History   │
│ 2:30 – 3:15  │ Recommendations & Explanations│ Recommendations (6 Tiers & Local AI)   │
│ 3:15 – 4:00  │ Human Approval & Dry Run      │ Human Review ➔ Controlled Execution    │
│ 4:00 – 4:30  │ Controlled Trash & Audit Log  │ Controlled Execution ➔ Audit Log       │
│ 4:30 – 5:00  │ Conversational AI Agent & Q&A │ AI Agent Chat (Analytical Tools)       │
└──────────────┴───────────────────────────────┴────────────────────────────────────────┘
```

---

## Demonstration Script

### Segment 1: The Problem (0:00 – 0:30)
* **What to Show**: Welcome screen / Streamlit Dashboard header (`http://localhost:8501`).
* **What to Say**:  
  > *"Traditional disk cleanup tools and emerging 'AI storage agents' are risky. Many hardcode permanent deletion (`rm -rf`) or give LLMs uncontrolled shell execution authority. A single hallucinated path or misclassified rule can permanently delete developer virtual environments, Docker images, or personal documents.  
  > MacGuard AI was built on a different premise: **AI should be advisory, and the human must remain the sole cryptographic authority over filesystem changes.**"*
* **Key Safety Message**: Zero permanent deletion; zero autonomous deletion authority.

---

### Segment 2: Safety Architecture Overview (0:30 – 1:00)
* **What to Show**: **Dashboard View**; click **"🧪 Load Presentation Demo Data"** in the sidebar.
* **What to Say**:  
  > *"MacGuard AI decouples intelligence from execution through four strictly segregated operating modes: **ANALYZE**, **AGENT**, **REVIEW**, and **CLEAN**.  
  > Notice the executive dashboard: it instantly provides total capacity, space used, and breaks down storage into verified risk categories. Let’s load the presentation demo dataset to walk through the entire v1.1 intelligence pipeline safely."*
* **Feature Demonstrated**: Instant presentation dataset population; capacity gauges; safe state initialization.

---

### Segment 3: Storage Scan & Developer Storage Intelligence (1:00 – 1:45)
* **What to Show**: **🔍 Scan Storage View** ➔ **📦 Developer Storage View**.
* **What to Say**:  
  > *"Under **Scan Storage**, MacGuard analyzes disk mounts using bounded `ScanScope` configurations and visualizes storage across 16 semantic categories with zero-bound Altair charts.  
  > In the **Developer Storage** view, we get specialized intelligence into developer artifacts: Xcode `DerivedData`, Docker container layers, Python `.venv` environments, Node `node_modules`, Rust `target` builds, and local ML model weights. MacGuard identifies project root manifests and staleness to help developers make informed decisions."*
* **Feature Demonstrated**: 16-category storage chart; developer environment breakdowns; project manifest associations.

---

### Segment 4: Duplicate Clusters & Storage History Trends (1:45 – 2:30)
* **What to Show**: **👥 Duplicate Explorer** ➔ **📈 Storage Intelligence & History**.
* **What to Say**:  
  > *"Next, the **Duplicate Explorer** detects duplicate clusters using two-stage streaming hashing (size pre-filter followed by full SHA-256). Notice the APFS hardlink badges: MacGuard understands that hardlinks share physical disk extents and correctly reports zero wasted bytes.  
  > Under **Storage Intelligence & History**, MacGuard tracks multi-scan storage snapshots in SQLite, computing category growth velocities (`GROWING`, `SHRINKING`, `STABLE`) so users can spot disk leaks over time."*
* **Feature Demonstrated**: Read-only duplicate clusters; APFS hardlink awareness; historical growth trends and scan deltas.

---

### Segment 5: Recommendations & Explainability (2:30 – 3:15)
* **What to Show**: **💡 Recommendations View**.
* **What to Say**:  
  > *"In the Recommendations view, deterministic rules classify findings into a 6-tier action taxonomy.  
  > Safe items like Xcode DerivedData are tagged as **Eligible for controlled Trash review**, while sensitive items like personal PDFs or system bundles are **Strictly Blocked**.  
  > If a user wants to understand why an item was flagged, they can click **'Explain Finding with Local AI'**. If the local Ollama daemon is offline or times out, MacGuard automatically degrades to its deterministic explanation engine with zero disruption to the UI."*
* **Feature Demonstrated**: 6-tier risk badges; container-parent hierarchy badges; on-demand Local AI explanation with timeout resilience.

---

### Segment 6: Human Approval & Dry Run Simulation (3:15 – 4:00)
* **What to Show**: **🛡️ Human Review View** ➔ **🗑️ Controlled Execution View**.
* **What to Say**:  
  > *"MacGuard strictly rejects 'Approve All' bulk actions. Under **Human Review**, the user must acknowledge the Informed Consent declaration and individually approve specific eligible items.  
  > When I click **'Approve for Controlled Trash'**, MacGuard generates an ephemeral **HMAC-SHA256 authorization token** backed by a 256-bit runtime secret key.  
  > Moving to **Controlled Execution**, we can run a **Dry Run Simulation**. This validates the plan against our allowlist and calculates reclaimable space, proving that zero files were modified and the token remains unconsumed."*
* **Feature Demonstrated**: Informed Consent checkbox; individual HMAC token generation; non-destructive Dry Run simulation.

---

### Segment 7: Controlled Trash & Audit Forensics (4:00 – 4:30)
* **What to Show**: **Controlled Execution** (Click **"Safely Move to Trash"**) ➔ **📜 Audit Log View**.
* **What to Say**:  
  > *"Now we execute the controlled move. Notice what happens:  
  > 1. MacGuard re-validates the allowlist immediately before moving.  
  > 2. It captures a pre-execution physical snapshot (inode, size, and SHA-256 hash).  
  > 3. The item is moved exclusively to `~/.Trash/`—never permanently deleted.  
  > 4. Post-move verification confirms source absence and byte-exact destination hash equality.  
  > 5. The token is marked `CONSUMED` to prevent replay attacks.  
  > Under the **Audit Log** tab, the complete forensic event timeline is immutably recorded in a local SQLite database."*
* **Feature Demonstrated**: Controlled move to Trash; post-move integrity verification; single-use token consumption; SQLite audit viewer.

---

### Segment 8: Conversational AI Agent & Wrap-Up (4:30 – 5:00)
* **What to Show**: **🤖 AI Agent View**.
* **What to Say**:  
  > *"Finally, under the **AI Agent** tab, users can chat naturally with MacGuard: 'What is consuming my storage?' or 'How did my caches grow since last scan?'.  
  > Notice the prominent **Capability Boundary Box**: the agent is strictly advisory and has zero tools to approve or delete files.  
  > MacGuard AI proves that agentic systems can be helpful, conversational, and powerful while maintaining absolute human authority and cryptographic safety."*
* **Feature Demonstrated**: Natural language storage query; historical trend Q&A; capability boundary indicator; prompt injection resistance.
