## PromptGuard startup

Install backend dependencies and create the local environment file:

```bash
python3 -m pip install -r backend/requirements.txt
cp .env.example .env
```

Start the API from the repository root:

```bash
python3 backend/run.py
```

The launcher adds `backend/` to Python's import path, which matches the existing
`app.security.*` imports used by the repository.

Start the frontend in a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Provider selection:

- `TARGET_LLM_PROVIDER=mock` uses the offline provider.
- `TARGET_LLM_PROVIDER=gemini` uses Gemini and requires `GEMINI_API_KEY`.
- `GEMINI_MODEL` optionally selects the Gemini model.

API keys belong in the untracked root `.env` file and must never be placed in
`.env.example`, frontend code, logs, or API responses.