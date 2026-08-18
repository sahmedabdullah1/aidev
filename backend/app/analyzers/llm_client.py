"""LLM client — Groq (free Llama) by default. No heuristic / hardcoded reports."""

from __future__ import annotations

import asyncio
from functools import lru_cache

from openai import APIStatusError, AsyncOpenAI, RateLimitError

from app.config import Settings, get_settings


class LLMNotConfiguredError(RuntimeError):
    pass


class LLMAnalysisError(RuntimeError):
    pass


def resolve_llm_settings(settings: Settings | None = None) -> Settings:
    """Prefer GROQ_API_KEY when LLM_API_KEY is empty."""
    s = settings or get_settings()
    updates: dict = {}
    if not s.llm_api_key and s.groq_api_key:
        updates["llm_api_key"] = s.groq_api_key
    key = updates.get("llm_api_key", s.llm_api_key)
    if key and "groq.com" not in (s.llm_base_url or "") and s.groq_api_key and not s.llm_api_key:
        updates["llm_base_url"] = "https://api.groq.com/openai/v1"
    if key and s.llm_model in {"", "gpt-4o-mini"} and (s.groq_api_key or "groq.com" in (s.llm_base_url or "")):
        updates["llm_model"] = "llama-3.3-70b-versatile"
    return s.model_copy(update=updates) if updates else s


def evidence_budget_chars(settings: Settings) -> int:
    """Keep prompts inside free-tier TPM limits (especially Groq)."""
    base = (settings.llm_base_url or "").lower()
    model = (settings.llm_model or "").lower()
    if "groq.com" in base:
        if "8b" in model or "instant" in model:
            return 18_000
        if "scout" in model or "llama-4" in model:
            return 24_000
        # llama-3.3-70b free tier ~12k TPM (input+output) — keep evidence tiny
        return 5_500
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
    # Groq free 70B TPM is ~12k; reserve room for prompt by capping completion
    base = (s.llm_base_url or "").lower()
    model = (s.llm_model or "").lower()
    max_tokens = min(s.llm_max_tokens, 8192)
    if "groq.com" in base and "70b" in model:
        max_tokens = min(max_tokens, 2500)

    for attempt in range(max_retries):
        try:
            resp = await client.chat.completions.create(
                model=s.llm_model,
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
            # Retry transient 5xx / 429
            if exc.status_code in {429, 500, 502, 503, 504}:
                await asyncio.sleep(2 ** attempt + 1)
                continue
            raise LLMAnalysisError(f"LLM API error {exc.status_code}: {exc.message}") from exc
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            await asyncio.sleep(1.5 * (attempt + 1))

    raise LLMAnalysisError(f"LLM analysis failed after retries: {last_err}")
