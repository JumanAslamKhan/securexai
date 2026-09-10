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

## Test

```powershell
pytest
```
