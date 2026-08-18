#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env — add LLM_API_KEY for full AI reports."
fi

python3 -m venv backend/.venv
# shellcheck disable=SC1091
source backend/.venv/bin/activate
pip install -q -r backend/requirements.txt

cd frontend
npm install
echo "Ready."
echo "  Backend:  cd backend && source .venv/bin/activate && PYTHONPATH=. uvicorn app.main:app --reload --port 8000"
echo "  Frontend: cd frontend && npm run dev"
