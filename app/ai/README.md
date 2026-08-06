# `app/ai/` — AI Provider Abstraction

Minimal adapter layer between the node and any OpenAI-compatible chat-completions endpoint. Used by:

- `app/chats/ai_assistant.py` — in-chat "/ai" assistant.
- `app/chats/translate.py` — on-demand message translation.
- `app/bots/bot_advanced.py` — AI-powered bot helpers.

The node never ships its own model. This module only wraps a remote HTTP API; the operator provides the URL + key.

## Files

| File          | Role                                                                          |
| ------------- | ----------------------------------------------------------------------------- |
| `provider.py` | Single-class adapter. Reads `AI_PROVIDER_URL` + `AI_PROVIDER_KEY` from config. Exposes `async chat(messages, model=None, stream=False)`. |

## Supported backends

Anything that speaks the OpenAI Chat Completions wire format — `POST /v1/chat/completions` with `{model, messages, stream}`:

- OpenAI (`api.openai.com`)
- Azure OpenAI (set `AI_PROVIDER_URL` to the deployment URL)
- Self-hosted **Qwen3-8B** (see `../../Qwen3-8B/`) via vLLM / llama.cpp `--api-like` mode
- Any other OpenAI-clone (LM Studio, Ollama with the OpenAI compatibility shim, llama-cpp-python server)

## Configuration

| Env var             | Purpose                                              |
| ------------------- | ---------------------------------------------------- |
| `AI_PROVIDER_URL`   | Base URL — e.g. `https://api.openai.com/v1/`.        |
| `AI_PROVIDER_KEY`   | Bearer token. Optional for local backends.           |
| `AI_DEFAULT_MODEL`  | Model name when the caller doesn't specify (e.g. `gpt-4o-mini`, `qwen3-8b`). |
| `AI_TIMEOUT_SECS`   | Per-call timeout (default 30).                        |

If `AI_PROVIDER_URL` is empty, AI features are disabled at startup — the "/ai" assistant route returns 503 and bots get a clear error instead of a timeout.

## Why it's minimal

The whole file is <200 lines on purpose. Providers churn faster than Vortex's release cadence; keeping the abstraction thin means we can swap backends without touching feature code.

---

## License

Vortex is **dual-licensed** under the **GNU Affero General Public License
v3.0-or-later** (see `LICENSE`) or a **commercial license** (see
`LICENSE-COMMERCIAL.md`).

```
Copyright (C) 2026 Andrey Karavaev, Boris Maltsev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

## Authors

**Boris Maltsev**

[![GitHub](https://img.shields.io/badge/GitHub-BorisMalts-181717?style=flat-square&logo=github)](https://github.com/BorisMalts)

**Andrey Karavaev**

[![GitHub](https://img.shields.io/badge/GitHub-Andre--wb-181717?style=flat-square&logo=github)](https://github.com/Andre-wb)
