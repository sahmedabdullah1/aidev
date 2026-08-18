#!/usr/bin/env bash
# Test that the configured LLM responds (Groq / Ollama / other OpenAI-compatible).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
# shellcheck disable=SC1091
source .venv/bin/activate
export PYTHONPATH=.
python - <<'PY'
import asyncio
from app.config import get_settings
from app.analyzers.llm_client import chat_json, resolve_llm_settings

async def main():
    get_settings.cache_clear()
    s = resolve_llm_settings(get_settings())
    print(f"provider={s.llm_base_url}")
    print(f"model={s.llm_model}")
    print(f"key_set={bool(s.llm_api_key)}")
    if not s.llm_api_key:
        raise SystemExit(
            "Missing LLM_API_KEY / GROQ_API_KEY.\n"
            "1) Open https://console.groq.com/keys\n"
            "2) Create a free API key\n"
            "3) Put it in .env as LLM_API_KEY=gsk_...\n"
            "4) Re-run this script"
        )
    content = await chat_json(
        settings=s,
        system='Return JSON only: {"ok": true, "model_reply": "short phrase"}',
        user="Reply confirming you can analyze DevOps evidence.",
    )
    print("LLM OK:")
    print(content[:500])

asyncio.run(main())
PY
