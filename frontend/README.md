# frontend/

HQC intelligence dashboard (Milestone 9): React + Vite + TypeScript. It is a presentation layer over the versioned API (`/api/v1`). It is **recommendation-only** and executes nothing.

```bash
npm ci        # exact versions from package-lock.json
npm run dev        # http://localhost:5173 (start the API on 127.0.0.1:8000 first)
npm run check      # typecheck + lint + tests (coverage) + production build
npm run gen:api    # regenerate src/api/schema.d.ts after `python scripts/export_frontend_contract.py`
```

See `docs/FRONTEND.md`.
