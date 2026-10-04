# SecureXAI Backend

## Run locally

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API documentation is available at `http://127.0.0.1:8000/docs`.

## External Analyzers

SecureXAI runs the custom pattern detector, Semgrep, and Slither for Solidity
analysis requests. The API also accepts Vyper, Rust, and Move source through a
`language` field. Those languages enter separate pipelines and never run the
Solidity detector or Slither. The selected pipeline is returned in the API
response.

Activate it before starting the backend when possible:

```powershell
cd ..
.\.tools-venv\Scripts\Activate.ps1
cd backend
uvicorn app.main:app --reload
```

The API response includes `tool_runs`, showing whether each analyzer completed,
was unavailable, or returned an error.

## ML Analyzer Layer

The Solidity pipeline runs the custom detector, Semgrep, and Slither first.
The trained `securexai-ml` classifier then adds a second-layer prediction that
is normalized and deduplicated with the other findings. The model artifact is
generated locally and is intentionally excluded from Git:

```powershell
$datasetRoot = "$env:USERPROFILE\.cache\kagglehub\datasets\mdahhad0\smart-contract-vulnerability-dataset\versions\1"
$jsonl = Get-ChildItem "$datasetRoot\*.jsonl" | Select-Object -First 1
$csv = Get-ChildItem "$datasetRoot\*.csv" | Select-Object -First 1
python scripts\train_ml_model.py $jsonl.FullName $csv.FullName --output artifacts\securexai_ml.joblib
```

The trainer maps both files into shared vulnerability classes and uses a
grouped 80/20 split: vulnerable/fixed JSONL pairs stay together, and CSV rows
with the same filename stay together. This avoids the row-level leakage that
produced the earlier over-optimistic score.

Set `SECUREXAI_ML_MODEL_PATH` to use a different artifact. If no artifact is
available, the API reports the ML analyzer as `unavailable` and continues with
the deterministic analyzers.

After manually revising a source, call `POST /api/v1/validate-remediation` with
`original_source` and `revised_source`. SecureXAI rescans both versions and
returns `improved`, `unchanged`, `regressed`, or `inconclusive`.

## Layer 3 Gemini Candidate Generation

The optional `POST /api/v1/autofix` endpoint sends the current source and
combined analyzer findings to Gemini. It retries generation and re-analysis up
to five times, then returns a candidate source, remaining findings, tool
statuses, and a unified diff. It never changes the submitted source or applies
the candidate automatically.

Configure Gemini before starting the backend:

```powershell
$env:GEMINI_API_KEY = "your-google-ai-studio-api-key"
$env:GEMINI_MODEL = "gemini-3.8-flash"
$env:GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
```

## Layer 4 Final Report

`POST /api/v1/report` converts an `AnalysisResponse` into a deterministic final
report containing the risk summary, deduplicated recommendations, analyzer
completeness, and a deployment-review note. It does not call Gemini, so report
generation remains available when the AI provider is unavailable.

## Rate Limiting

Versioned API routes are limited to 60 requests per 60 seconds per client IP by
default. Configure the window before starting the backend:

```powershell
$env:SECUREXAI_RATE_LIMIT = "60"
$env:SECUREXAI_RATE_WINDOW_SECONDS = "60"
```

Limited responses return HTTP `429` with a `Retry-After` header. Health checks
are excluded from the limit.

## API Security

API-key protection is disabled by default for local development. To protect
versioned API routes and hide Swagger/ReDoc, configure the same key in the
backend and frontend:

```powershell
$env:SECUREXAI_API_KEY = "replace-with-a-local-secret"
# In frontend/.env.local:
# VITE_SECUREXAI_API_KEY=replace-with-a-local-secret
```

The frontend sends the key as `X-API-Key`; `/health` remains public.

## Test

```powershell
pytest
```
