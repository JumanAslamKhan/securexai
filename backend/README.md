# SecureXAI Backend

## Run locally

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Whole-contract Gemini repair allows up to 300 seconds by default. If the
provider is unavailable, the service returns a warning instead of a local
fallback report.

```powershell
$env:SECUREXAI_AI_REPAIR_TIMEOUT_SECONDS = "600"
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

After reviewing a remediation, call `POST /api/v1/validate-remediation` with
`original_source` and `revised_source`. SecureXAI rescans both versions and
returns `improved`, `unchanged`, `regressed`, or `inconclusive`; it never applies
the model output automatically.

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

Generated Solidity repairs are compiled with the local `solc` executable before
the response is shown. The response reports `compiled`, `error`, or
`unavailable`; compilation does not replace human review or the analyzer rescan.

## Gemini Remediation

Gemini is the repair and reporting provider. Generated repairs are never
auto-applied: they must compile and pass a server-side analyzer rescan without
increasing critical findings or the overall normalized risk profile. Repairs
that regress are returned as `rejected` for inspection and are not accepted.

## Test

```powershell
pytest
```
