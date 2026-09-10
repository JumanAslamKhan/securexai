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

## Rate Limiting

Versioned API routes are limited to 60 requests per 60 seconds per client IP by
default. Configure the window before starting the backend:

```powershell
$env:SECUREXAI_RATE_LIMIT = "60"
$env:SECUREXAI_RATE_WINDOW_SECONDS = "60"
```

Limited responses return HTTP `429` with a `Retry-After` header. Health checks
are excluded from the limit.

## Local LLM Remediation

Ollama is the default provider and uses the locally installed `llama3:latest`
model through `http://127.0.0.1:11434/v1`. No API key is required. Set
`OPENAI_MODEL=qwen2.5-coder:7b` after downloading that model for a
coding-focused provider. Generated patches are never auto-applied and must be
reviewed, compiled, and rescanned.

## Test

```powershell
pytest
```
