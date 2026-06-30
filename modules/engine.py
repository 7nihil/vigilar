# ─────────────────────────────────────────────────────────────────
#  modules/engine.py  —  Async Multi-Provider LLM Engine
#
#  Supports: Ollama · OpenAI · Anthropic · Gemini · Groq · Mistral
#  Rate limiting: automatic retry + backoff on HTTP 429
# ─────────────────────────────────────────────────────────────────

import asyncio
import time
import aiohttp
from modules.config import PROVIDERS, DEFAULT_TEMPERATURE, DEFAULT_MAX_TOKENS

# ── Rate-limit settings ───────────────────────────────────────────
# Groq free tier = 30 RPM  →  2s between requests is safe
# Override at runtime with --delay flag (passed through send_single)
REQUEST_DELAY  = 2.0          # seconds between every request
MAX_RETRIES    = 3            # retries on 429
RETRY_BACKOFF  = [5, 15, 30]  # wait before retry 1, 2, 3


# ── Provider payload builders ─────────────────────────────────────

def _build_ollama_payload(model, system, messages, temperature):
    return {
        "model"   : model,
        "messages": [{"role": "system", "content": system}] + messages,
        "stream"  : False,
        "options" : {"temperature": temperature},
    }

def _build_openai_payload(model, system, messages, temperature, max_tokens):
    return {
        "model"      : model,
        "messages"   : [{"role": "system", "content": system}] + messages,
        "temperature": temperature,
        "max_tokens" : max_tokens,
    }

def _build_anthropic_payload(model, system, messages, temperature, max_tokens):
    return {
        "model"      : model,
        "system"     : system,
        "messages"   : messages,
        "temperature": temperature,
        "max_tokens" : max_tokens,
    }

def _build_gemini_payload(system, messages, temperature, max_tokens):
    contents = []
    for m in messages:
        role = "user" if m["role"] == "user" else "model"
        contents.append({"role": role, "parts": [{"text": m["content"]}]})
    return {
        "system_instruction": {"parts": [{"text": system}]},
        "contents"          : contents,
        "generationConfig"  : {
            "temperature"    : temperature,
            "maxOutputTokens": max_tokens,
        },
    }


def _extract_response(provider: str, chat_style: str, data: dict) -> str:
    try:
        if chat_style == "ollama":
            return data.get("message", {}).get("content", "") or data.get("response", "")
        elif chat_style == "openai":
            return data["choices"][0]["message"]["content"]
        elif chat_style == "anthropic":
            return data["content"][0]["text"]
        elif chat_style == "gemini":
            return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return f"[PARSE ERROR] Raw: {str(data)[:200]}"
    return ""


# ── Core async request with retry ────────────────────────────────

async def _async_request(
    session    : aiohttp.ClientSession,
    provider   : str,
    model      : str,
    system     : str,
    messages   : list,
    temperature: float = DEFAULT_TEMPERATURE,
    max_tokens : int   = DEFAULT_MAX_TOKENS,
    timeout    : int   = 60,
    delay      : float = REQUEST_DELAY,
) -> tuple[str, float]:
    """
    Fire one request with automatic retry on HTTP 429.
    Sleeps `delay` seconds before each attempt to respect rate limits.
    """
    cfg        = PROVIDERS[provider]
    chat_style = cfg["chat_style"]
    base_url   = cfg["base_url"]
    api_key    = cfg.get("api_key")

    headers = {"Content-Type": "application/json"}
    if api_key:
        if chat_style == "anthropic":
            headers["x-api-key"]         = api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {api_key}"

    if chat_style == "ollama":
        url = f"{base_url}/api/chat"
    elif chat_style == "anthropic":
        url = f"{base_url}/messages"
    elif chat_style == "gemini":
        url = f"{base_url}/models/{model}:generateContent?key={api_key}"
        headers.pop("Authorization", None)
    else:
        url = f"{base_url}/chat/completions"

    if chat_style == "ollama":
        payload = _build_ollama_payload(model, system, messages, temperature)
    elif chat_style == "anthropic":
        payload = _build_anthropic_payload(model, system, messages, temperature, max_tokens)
    elif chat_style == "gemini":
        payload = _build_gemini_payload(system, messages, temperature, max_tokens)
    else:
        payload = _build_openai_payload(model, system, messages, temperature, max_tokens)

    t0 = time.time()

    for attempt in range(MAX_RETRIES):
        # Rate-limit guard — wait before every attempt
        if delay > 0:
            await asyncio.sleep(delay)

        try:
            async with session.post(
                url, json=payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                elapsed = round(time.time() - t0, 2)

                if resp.status == 200:
                    data = await resp.json()
                    return _extract_response(provider, chat_style, data), elapsed

                elif resp.status == 429:
                    wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                    # Respect Retry-After header if present
                    try:
                        retry_after = int(resp.headers.get("Retry-After", wait))
                        wait = min(retry_after + 1, 30)  # cap at 30s
                    except (ValueError, TypeError):
                        pass
                    print(
                        f"\r  \033[93m[429] Rate limited — "
                        f"waiting {wait}s (retry {attempt+1}/{MAX_RETRIES})…\033[0m",
                        end="", flush=True,
                    )
                    await asyncio.sleep(wait)
                    continue

                else:
                    body = await resp.text()
                    return f"[HTTP {resp.status}] {body[:200]}", elapsed

        except asyncio.TimeoutError:
            return f"[TIMEOUT after {timeout}s]", float(timeout)
        except aiohttp.ClientError as e:
            return f"[CONNECTION ERROR: {e}]", round(time.time() - t0, 2)
        except Exception as e:
            return f"[ERROR: {e}]", round(time.time() - t0, 2)

    elapsed = round(time.time() - t0, 2)
    return f"[RATE LIMITED — all {MAX_RETRIES} retries failed]", elapsed


# ── Public async API ──────────────────────────────────────────────

async def send_single_async(
    provider   : str,
    model      : str,
    system     : str,
    user_prompt: str,
    timeout    : int   = 60,
    delay      : float = REQUEST_DELAY,
) -> tuple[str, float]:
    messages = [{"role": "user", "content": user_prompt}]
    async with aiohttp.ClientSession() as session:
        return await _async_request(
            session, provider, model, system, messages,
            timeout=timeout, delay=delay,
        )


async def send_chat_async(
    provider  : str,
    model     : str,
    system    : str,
    messages  : list,
    timeout   : int   = 60,
    delay     : float = REQUEST_DELAY,
) -> tuple[str, float]:
    async with aiohttp.ClientSession() as session:
        return await _async_request(
            session, provider, model, system, messages,
            timeout=timeout, delay=delay,
        )


async def benchmark_providers_async(
    targets    : list[tuple[str, str]],
    system     : str,
    user_prompt: str,
    timeout    : int   = 60,
    delay      : float = 0,   # benchmark fires in parallel — no per-request delay
) -> list[dict]:
    """Fire the same prompt at multiple providers IN PARALLEL."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            _async_request(
                session, provider, model, system,
                [{"role": "user", "content": user_prompt}],
                timeout=timeout, delay=delay,
            )
            for provider, model in targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    output = []
    for (provider, model), result in zip(targets, results):
        if isinstance(result, Exception):
            output.append({"provider": provider, "model": model,
                           "response": f"[EXCEPTION: {result}]", "elapsed": 0.0})
        else:
            response, elapsed = result
            output.append({"provider": provider, "model": model,
                           "response": response, "elapsed": elapsed})
    return output


# ── Sync wrappers ─────────────────────────────────────────────────

def send_single(provider, model, system, user_prompt, timeout=60, delay=REQUEST_DELAY):
    return asyncio.run(send_single_async(provider, model, system, user_prompt, timeout, delay))

def send_chat(provider, model, system, messages, timeout=60, delay=REQUEST_DELAY):
    return asyncio.run(send_chat_async(provider, model, system, messages, timeout, delay))

def benchmark_providers(targets, system, user_prompt, timeout=60):
    return asyncio.run(benchmark_providers_async(targets, system, user_prompt, timeout))