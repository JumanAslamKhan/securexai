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
`language` field. Tools that do not support the selected language are reported
as `skipped` rather than producing misleading results.

Activate it before starting the backend when possible:

```powershell
cd ..
.\.tools-venv\Scripts\Activate.ps1
cd backend
uvicorn app.main:app --reload
```

The API response includes `tool_runs`, showing whether each analyzer completed,
was unavailable, or returned an error.

## Test

```powershell
pytest
```
