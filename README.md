# SecureXAI

Smart contract vulnerability detection and remediation platform for Solidity projects.

## Overview
This project aims to detect multiple classes of smart contract vulnerabilities using a hybrid workflow that combines:

- static analysis tools such as Semgrep, Slither, and Mythril
- structured vulnerability normalization
- severity scoring and line-level explanations
- manual remediation review and source validation
- a dashboard for comparison and reporting

## Goal
Build a practical system that ingests Solidity source code, analyzes it for security issues, explains the findings, and supports developer review.

## Research Outcomes

The literature survey identifies a gap between high-performing but narrow
detectors, explainable AI auditing systems, and traditional tools that are
useful but difficult to compare interactively. SecureXAI is designed to bring
these strengths together in one developer-facing workflow.

The intended outcomes are:

- multi-class vulnerability detection instead of reentrancy-only classification
- line-level evidence, explanations, confidence, and severity scoring
- side-by-side findings from SecureXAI, Semgrep, Slither, and Mythril
- normalized and deduplicated results across heterogeneous analyzers
- interactive benchmarking rather than offline-only comparison tables
- reviewed-source validation before adoption
- reproducible evaluation using precision, recall, F1-score, and ROC-AUC

The current MVP provides a FastAPI analysis endpoint, a transparent pattern
detector, Semgrep and Slither integration, structured findings, an interactive
frontend, reviewed-source validation, and JSON/HTML exports. CodeBERT training, multi-agent analysis, and
formal benchmark evaluation remain research extensions until they are measured.

An optional Layer 3 endpoint, `POST /api/v1/autofix`, uses Gemini to generate a
candidate from the combined findings, re-runs the analyzers, and returns a diff
for human review. It never applies generated source automatically.

The analyzer request accepts `solidity`, `vyper`, `rust`, and `move`. Solidity
uses the complete custom detector, Semgrep rules, and Slither support. Each
other language enters its own backend pipeline and bypasses the Solidity
detector and Slither entirely; those pipelines will receive language-specific
rules independently.

## Research Positioning

Unlike the reviewed reentrancy-focused hybrid deep-learning study, SecureXAI
targets multiple vulnerability classes. Unlike explanation-focused LLM or graph
systems, it links explanations to source lines and severity. Unlike studies
that compare tools only in offline experiments, it exposes analyzer outputs in
one interactive dashboard. These combined capabilities define the project's
research contribution; model accuracy claims will only be made after evaluation
on a documented dataset with a fixed train/test protocol.

## Planned Architecture
- Frontend: React + TypeScript dashboard
- Backend: FastAPI / Python service layer
- Detectors: Semgrep, Slither, Mythril, optional custom ML model
- Reporting: benchmark summary, findings, and severity

## Status
The MVP supports Solidity analysis with line-level findings, normalized
cross-tool results, severity filtering, and manual remediation validation,
and a rescan workflow that compares original and revised source. The API also
routes Vyper, Rust, and Move requests through separate placeholder pipelines.

## Run the Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API documentation.

## Run the Frontend

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal, usually `http://localhost:5173`.

Run the tests with:

```powershell
cd backend
pytest
```

## Getting Started
1. Clone the repository
2. Set up your Python environment
3. Install analysis tools
4. Start the backend and frontend services

## License
MIT
