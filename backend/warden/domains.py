"""Shadow-AI domain registry. Maps host -> provider label shown in the UI."""
from __future__ import annotations

SHADOW_AI_DOMAINS: dict[str, str] = {
    "api.openai.com": "OpenAI",
    "chat.openai.com": "ChatGPT",
    "chatgpt.com": "ChatGPT",
    "api.anthropic.com": "Anthropic",
    "claude.ai": "Claude",
    "console.anthropic.com": "Anthropic Console",
    "generativelanguage.googleapis.com": "Google Gemini",
    "gemini.google.com": "Google Gemini",
    "api.cohere.ai": "Cohere",
    "api.mistral.ai": "Mistral",
    "api.perplexity.ai": "Perplexity",
    "api.together.xyz": "Together AI",
    "api.groq.com": "Groq",
    "api.deepseek.com": "DeepSeek",
    "api.x.ai": "xAI Grok",
    "openrouter.ai": "OpenRouter",
    "api.fireworks.ai": "Fireworks AI",
    "huggingface.co": "Hugging Face",
    "api-inference.huggingface.co": "Hugging Face Inference",
    "copilot.microsoft.com": "Microsoft Copilot",
    "api.replicate.com": "Replicate",
}


def lookup_provider(host: str) -> str | None:
    """Return provider label if host is a known shadow-AI endpoint."""
    if not host:
        return None
    host = host.lower().split(":", 1)[0]
    if host in SHADOW_AI_DOMAINS:
        return SHADOW_AI_DOMAINS[host]
    # Suffix match for subdomains (e.g. eu.api.openai.com)
    for known, label in SHADOW_AI_DOMAINS.items():
        if host.endswith("." + known) or host.endswith(known):
            return label
    return None


def is_shadow_ai(host: str) -> bool:
    return lookup_provider(host) is not None
