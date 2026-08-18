"""LLM client — Groq (GPT-OSS) by default. No heuristic / hardcoded reports."""

from __future__ import annotations

import asyncio
from functools import lru_cache

from openai import APIStatusError, AsyncOpenAI, RateLimitError

from app.config import Settings, get_settings

# Groq retired Llama 3.3 70B / 3.1 8B on 2026-08-16. Prefer current catalog IDs.
GROQ_DEFAULT_MODEL = "openai/gpt-oss-120b"
GROQ_FALLBACK_MODELS = (
    "openai/gpt-oss-120b",
    "qwen/qwen3.6-27b",
    "openai/gpt-oss-20b",
)
GROQ_RETIRED_MODELS = {
    "llama-3.3-70b-versatile": GROQ_DEFAULT_MODEL,
    "llama-3.1-8b-instant": "openai/gpt-oss-20b",
    "llama3-70b-8192": GROQ_DEFAULT_MODEL,
    "llama3-8b-8192": "openai/gpt-oss-20b",
    "meta-llama/llama-4-scout-17b-16e-instruct": GROQ_DEFAULT_MODEL,
    "meta-llama/llama-4-maverick-17b-128e-instruct": GROQ_DEFAULT_MODEL,
    "qwen/qwen3-32b": "qwen/qwen3.6-27b",
}


class LLMNotConfiguredError(RuntimeError):
    pass


class LLMAnalysisError(RuntimeError):
    pass


def resolve_llm_settings(settings: Settings | None = None) -> Settings:
    """Prefer GROQ_API_KEY when LLM_API_KEY is empty. Remap retired Groq models."""
    s = settings or get_settings()
    updates: dict = {}
    if not s.llm_api_key and s.groq_api_key:
        updates["llm_api_key"] = s.groq_api_key
    key = updates.get("llm_api_key", s.llm_api_key)
    if key and "groq.com" not in (s.llm_base_url or "") and s.groq_api_key and not s.llm_api_key:
        updates["llm_base_url"] = "https://api.groq.com/openai/v1"
    base = updates.get("llm_base_url", s.llm_base_url) or ""
    on_groq = "groq.com" in base or bool(s.groq_api_key)
    model = s.llm_model
    if on_groq and model in GROQ_RETIRED_MODELS:
        updates["llm_model"] = GROQ_RETIRED_MODELS[model]
    elif key and model in {"", "gpt-4o-mini"} and on_groq:
        updates["llm_model"] = GROQ_DEFAULT_MODEL
    return s.model_copy(update=updates) if updates else s


def evidence_budget_chars(settings: Settings) -> int:
    """Keep prompts inside free-tier TPM limits (especially Groq)."""
    base = (settings.llm_base_url or "").lower()
    model = (settings.llm_model or "").lower()
    if "groq.com" in base:
        if "20b" in model or "8b" in model or "instant" in model:
            return 18_000
        if "scout" in model or "llama-4" in model or "qwen" in model or "gpt-oss" in model:
            return 24_000
        return 12_000
    if "localhost" in base or "11434" in base:
        return 90_000
    return min(settings.llm_evidence_max_chars, 20_000)

@lru_cache
def _client_key(api_key: str, base_url: str) -> tuple[str, str]:
    return api_key, base_url


def get_async_client(settings: Settings) -> AsyncOpenAI:
    s = resolve_llm_settings(settings)
    if not s.llm_api_key:
        raise LLMNotConfiguredError(
            "No LLM API key configured. Get a free Groq key at https://console.groq.com/keys "
            "and set LLM_API_KEY (or GROQ_API_KEY) in .env, then restart the API."
        )
    return AsyncOpenAI(api_key=s.llm_api_key, base_url=s.llm_base_url or None)


async def chat_json(
    *,
    settings: Settings,
    system: str,
    user: str,
    max_retries: int = 4,
) -> str:
    s = resolve_llm_settings(settings)
    client = get_async_client(s)
    last_err: Exception | None = None
    base = (s.llm_base_url or "").lower()
    max_tokens = min(s.llm_max_tokens, 8192)
    if "groq.com" in base and ("70b" in (s.llm_model or "").lower() or "120b" in (s.llm_model or "").lower()):
        max_tokens = min(max_tokens, 4096)

    models = [s.llm_model]
    if "groq.com" in base:
        for candidate in GROQ_FALLBACK_MODELS:
            if candidate not in models:
                models.append(candidate)
    model_idx = 0

    for attempt in range(max_retries):
        model = models[min(model_idx, len(models) - 1)]
        try:
            resp = await client.chat.completions.create(
                model=model,
                temperature=s.llm_temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            content = (resp.choices[0].message.content or "").strip()
            if not content:
                raise LLMAnalysisError("LLM returned an empty response")
            return content
        except RateLimitError as exc:
            last_err = exc
            await asyncio.sleep(2 ** attempt + 1)
        except APIStatusError as exc:
            last_err = exc
            if exc.status_code == 404 and model_idx < len(models) - 1:
                model_idx += 1
                continue
            if exc.status_code in {429, 500, 502, 503, 504}:
                await asyncio.sleep(2 ** attempt + 1)
                continue
            raise LLMAnalysisError(f"LLM API error {exc.status_code}: {exc.message}") from exc
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            await asyncio.sleep(1.5 * (attempt + 1))

    raise LLMAnalysisError(f"LLM analysis failed after retries: {last_err}")
