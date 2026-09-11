# MacGuard AI — Testing & Verification Guide

This document outlines the testing architecture, test suites, quality assurance methodology, and verification commands for **MacGuard AI v1.1.0**.

> **Canonical Test Status**: **592 passed / 0 failed / 0 skipped** across 38 test files in `tests/`  
> **Dedicated Security & Safety Suite**: **73 passed**  
> **UI Integration & Views Suite**: **77 passed**  
> **Performance & Hardening Suite**: **32 passed**  
> **Static AST Safety Scan**: **0 forbidden dangerous primitives across `app/`**  
> **Streamlit Health Check**: **HTTP 200 OK (`http://localhost:8501/_stcore/health`)**

---

## 1. Test Suite Hierarchy & Structure

MacGuard AI enforces a multi-tiered testing strategy ensuring that every safety gate, cryptographic invariant, analytical engine, and UI lifecycle flow is covered by automated regression tests:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              MACGUARD AI TEST SUITE (592 TESTS)                        │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Level 1: Core Analysis & Scanning (216 tests)                │  │
│  │   - Whole-Home Scanner & Scopes (test_whole_home_scanner.py, test_scan_scope.py) │  │
│  │   - Smart Categorizer (test_smart_categorizer.py, test_storage_analyzer.py)      │  │
│  │   - Developer Storage Analyzer (test_developer_analyzer.py)                      │  │
│  │   - Large File Analyzer (test_large_file_analyzer.py)                            │  │
│  │   - Duplicate Detection & Redundancy (test_duplicate_detector.py)                │  │
│  │   - Storage History & Trends (test_storage_history.py, test_storage_trends.py)   │  │
│  │   - Recommendation Engine & Trends (test_recommendations.py, rec_trends.py)      │  │
│  │   - Duplicate Recommendations (test_duplicate_recommendations.py)                │  │
│  │   - Legacy Scanner (test_storage_scanner.py)                                     │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Level 2: Security & Adversarial Suite (73 tests)             │  │
│  │   - TOCTOU symlink race attacks & Scenarios A–F (test_execution_security.py)     │  │
│  │   - Agent tool boundary & prompt injection defenses (test_agent_security.py)     │  │
│  │   - Zero-mutation guard under adversarial prompts (test_mutation_guard.py)       │  │
│  │   - Path traversal, unicode & malformed fuzzing (test_path_fuzzing.py)           │  │
│  │   - Pre/post byte-exact SHA-256 integrity verification (test_integrity.py)      │  │
│  │   - Secret key isolation & allowlist safety policies (test_safety.py)            │  │
│  │   - Controlled Trash execution invariants (test_trash_executor.py)               │  │
│  │   - Isolated sandbox final validation (test_sandbox_final_validation.py)         │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Level 3: Agent, LLM & Reasoning Tools (82 tests)             │  │
│  │   - Local Ollama Client & JSON schema validation (test_llm.py)                   │  │
│  │   - Advisory Agent v1.1 tools & trends (test_agent_v11.py)                       │  │
│  │   - Agent models, planner & tools (test_agent_models.py, test_agent_tools.py)    │  │
│  │   - Agent integration & safety evaluation (test_agent_safety_evaluation.py, etc.)│  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Level 4: UI & State Lifecycle Suite (77 tests)               │  │
│  │   - v1.1 Multi-view UI state & navigation (test_ui_v11.py)                       │  │
│  │   - Storage Intelligence UI (test_storage_intelligence_ui.py)                    │  │
│  │   - Two-phase navigation state synchronization (test_ui_integration.py)          │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Level 5: Performance & Hardening Suite (32 tests)            │  │
│  │   - v1.1 Memory scaling, timeouts & cancellation (test_performance_v11.py)       │  │
│  │   - Core benchmark suite (test_performance_benchmarks.py)                        │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                     Level 6: Approval, Execution & Audit (112 tests)             │  │
│  │   - Approval workflow & HMAC tokens (test_approval_workflow.py)                  │  │
│  │   - Execution planning & execution (test_execution.py, test_execution_recov.py)  │  │
│  │   - Audit repository SQLite persistence (test_audit_repository.py)               │  │
│  │   - CLI & Live E2E validation (test_cli.py, test_live_e2e_validation.py)        │  │
│  │   - Scan history integration (test_scan_history_integration.py)                 │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Test Execution Commands

### 1. Full Regression Suite (592 Tests)
Run the complete automated test suite:
```bash
PYTHONPATH=. .venv/bin/pytest
```

### 2. Dedicated Security & Safety Suite (73 Tests)
Run the dedicated security, fuzzing, integrity, and mutation guard tests:
```bash
PYTHONPATH=. .venv/bin/pytest \
  tests/test_safety.py \
  tests/test_agent_security.py \
  tests/test_execution_security.py \
  tests/test_mutation_guard.py \
  tests/test_integrity.py \
  tests/test_path_fuzzing.py \
  tests/test_sandbox_final_validation.py \
  tests/test_trash_executor.py -v
```

### 3. UI Integration Suite (77 Tests)
Run UI state lifecycle, routing, and error-handling tests:
```bash
PYTHONPATH=. .venv/bin/pytest \
  tests/test_ui_v11.py \
  tests/test_storage_intelligence_ui.py \
  tests/test_ui_integration.py -v
```

### 4. Performance & Hardening Suite (32 Tests)
Run memory scaling, cancellation latency, and timeout hardening tests:
```bash
PYTHONPATH=. .venv/bin/pytest \
  tests/test_performance_v11.py \
  tests/test_performance_benchmarks.py -v
```

### 5. Static AST Safety Scan
Run the static AST scan for forbidden dangerous primitives (`os.unlink`, `os.rmdir`, `shutil.rmtree`, `subprocess`, `os.system`, `eval`, `exec`, `shell=True`):
```bash
python3 -c '
import ast, os, sys
violations = []
for root, _, files in os.walk("app"):
    for f in files:
        if f.endswith(".py"):
            path = os.path.join(root, f)
            with open(path, "r", encoding="utf-8") as fp:
                tree = ast.parse(fp.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "subprocess":
                            violations.append((path, node.lineno, "import subprocess"))
                elif isinstance(node, ast.ImportFrom):
                    if node.module and "subprocess" in node.module:
                        violations.append((path, node.lineno, f"from {node.module}"))
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ("eval", "exec", "compile"):
                            violations.append((path, node.lineno, f"{node.func.id}()"))
                    elif isinstance(node.func, ast.Attribute):
                        attr = node.func.attr
                        if attr in ("unlink", "rmdir", "system", "popen"):
                            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                                violations.append((path, node.lineno, f"os.{attr}()"))
                        if attr == "rmtree":
                            violations.append((path, node.lineno, "shutil.rmtree()"))
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            violations.append((path, node.lineno, "shell=True"))
if violations:
    print(f"FAILED: Found {len(violations)} safety violations")
    sys.exit(1)
else:
    print("SUCCESS: 0 forbidden dangerous primitives found across app/")
'
```

### 6. Streamlit Health Check
Verify the Streamlit web application is running and healthy:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8501/_stcore/health
```
*(Expected response: `200`)*
