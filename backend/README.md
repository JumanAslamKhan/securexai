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

## Optional LLM Remediation

Copy `.env.example` to `.env` and set `OPENAI_API_KEY` to enable structured
remediation summaries and patch previews. Without a key, the local rule-guidance
provider is used. Generated patches are never auto-applied and must be reviewed,
compiled, and rescanned.

## Test

```powershell
pytest
```
