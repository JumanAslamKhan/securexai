# SecureXAI Project Outcomes

## Research Gap Addressed

The reviewed literature tends to optimize one of three dimensions:

1. high detection performance for a narrow vulnerability class
2. explainable AI-based auditing
3. comparison with traditional analyzers

SecureXAI combines these dimensions into a single workflow for Solidity
developers and auditors.

## Target Outcomes

### 1. Multi-class detection

Detect reentrancy, access-control weaknesses, arithmetic issues, unchecked
external calls, dangerous operations, and additional classes added through
Semgrep, Slither, Mythril, and future ML models.

### 2. Actionable explanations

Every finding should include the responsible line or code region, category,
severity, confidence, explanation, recommendation, and detection source.

### 3. Tool benchmarking

The dashboard should compare findings from the custom detector, Semgrep,
Slither, and Mythril. Results should distinguish true positives, false
positives, duplicates, and tool-specific detections when ground truth is
available.

### 4. Assisted remediation

An LLM may explain a finding and propose a patch, but generated code must be
shown as a diff and checked by compilation and security analyzers before it is
accepted.

### 5. Reproducible evaluation

Evaluation should report precision, recall, F1-score, accuracy where
appropriate, ROC-AUC for classifiers, false-positive rate, runtime, and tool
coverage over a documented dataset.

## Current Baseline

The repository currently implements:

- a FastAPI analysis API
- a transparent Python pattern detector
- structured line-level findings
- severity and confidence fields
- a React client connected to the API
- CORS support for local development

These are implementation outcomes, not final research results. Numerical
performance claims should be added only after dataset-based experiments.

## Current Workflow

```mermaid
flowchart TD
	A[User loads or edits contract source] --> B[Select filename and language]
	B --> C[POST /api/v1/analyze]
	C --> D{Language?}
	D -->|Solidity| E[Run transparent pattern detector]
	E --> F[Run Semgrep and Slither]
	F --> G[Run trained ML classifier]
	G --> H[Merge and deduplicate findings]
	D -->|Vyper, Rust, or Move| I[Return language-specific pipeline placeholder]
	H --> J[Return findings and tool statuses]
	I --> J
	J --> K{Next action}
	K -->|Remediate a finding| L[POST /api/v1/remediate]
	L --> M[Show remediation guidance or patch]
	M --> N[User revises source]
	K -->|Generate report| O[POST /api/v1/report]
	O --> P[Show vulnerability report and allow JSON or HTML download]
	N --> Q{Source changed from analyzed version?}
	Q -->|Yes| R[POST /api/v1/validate-remediation]
	Q -->|No| S[Wait for source revision]
	R --> T[Reanalyze original and revised source]
	T --> U{Finding count and tool status}
	U -->|Fewer findings| V[Return improved]
	U -->|More findings| W[Return regressed]
	U -->|Same count| X[Return unchanged]
	U -->|Analyzer unavailable or errors| Y[Return inconclusive]
```

The current client workflow is analysis first, followed by optional
remediation, reporting, and revised-source validation. Validation compares
normalized finding counts and still requires human review.

## Planned Evidence

The project will support its claims with:

- labeled vulnerable and benign Solidity samples
- fixed train, validation, and test splits where ML is used
- tool version and configuration records
- normalized finding and ground-truth files
- benchmark tables and confusion matrices
- qualitative examples showing explanations and generated patches