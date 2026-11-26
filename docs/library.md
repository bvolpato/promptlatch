# Python library

Use PromptLatch without starting the proxy. Redact each prompt or request value in
the same process, immediately before passing it to your SDK or HTTP client. Install
the SDK you use separately; PromptLatch has no OpenAI, LiteLLM, LangChain, Anthropic,
or LlamaIndex SDK dependency.

Choose a helper for the shape of the value you send:

| Input | Helper | Result |
| --- | --- | --- |
| One prompt or text field | `redact_text(text)` | Redacted string |
| Chat messages, including nested tool data | `redact_messages(messages)` | Redacted message list |
| SDK keyword arguments | `redact_params(**params)` | Redacted dictionary ready to unpack into an SDK call |
| Raw mapping/list request body | `redact_payload(payload)` | Redacted structure with its shape preserved |

All four helpers are exported from `promptlatch`. They return the safe value. They do
not send the request or change an SDK client for you. **Pass the returned value to the
SDK call; never pass the original value after redaction.** If redaction raises an
error, do not retry by sending the original input.

## Redact a standalone prompt

Use `redact_text` when the prompt is assembled as a string, before passing it as
`input`, `prompt`, or another SDK field:

```python
from openai import OpenAI
from promptlatch import redact_text

client = OpenAI()
prompt = "Inspect this config: OPENAI_API_KEY=example-secret-value-123456"

response = client.responses.create(
    model="gpt-6-sol",
    input=redact_text(prompt),
)
```

## Redact a message array

Use `redact_messages` for chat-style `messages` arrays. It supports mapping-based
messages, `(role, content)` tuples, Pydantic/OpenAI message models, and LangChain
message objects:

```python
from openai import OpenAI
from promptlatch import redact_messages

client = OpenAI()
messages = [
    {"role": "system", "content": "Summarize the user's log."},
    {"role": "user", "content": "Authorization: Bearer FixtureToken000000000000000000000"},
]

safe_messages = redact_messages(messages)
response = client.chat.completions.create(
    model="gpt-6-sol",
    messages=safe_messages,
)
```

For non-Pydantic message objects, PromptLatch copies the object and redacts its
`content` field. For Pydantic messages, it recursively redacts fields, including
tool calls, and preserves the model type. Inputs are left unchanged.

## Redact SDK parameters or structured payloads

Use `redact_params` when assembling SDK keyword arguments. It returns a dictionary
you can unpack directly into the SDK call. A `messages` argument is treated as a
message array; other values, including `input`, `tools`, and nested parameter
objects, are scanned recursively.

```python
from openai import OpenAI
from promptlatch import redact_params

client = OpenAI()
safe_params = redact_params(
    model="gpt-6-sol",
    input="Summarize this: GITHUB_TOKEN=example-token-value-123456",
)
response = client.responses.create(**safe_params)
```

For raw JSON-compatible bodies, use `redact_payload` and pass its result to the
transport. It recursively scans strings in mappings and lists without reshaping the
request schema:

```python
import os
import httpx
from promptlatch import redact_payload

payload = {
    "model": "gpt-6-sol",
    "input": [
        {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": "OPENAI_API_KEY=example-secret-value-123456",
                }
            ],
        }
    ],
    "metadata": {"job": "support-triage"},
}
response = httpx.post(
    "https://api.openai.com/v1/responses",
    headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
    json=redact_payload(payload),
)
```

## Use with other SDKs

Call the same helpers at each SDK boundary. Keep provider authentication in the
SDK's normal environment/configuration; PromptLatch redacts prompt and payload
content, not credentials held in the SDK's transport configuration.

LiteLLM:

```python
from litellm import completion
from promptlatch import redact_params

response = completion(
    **redact_params(
        model="openai/gpt-6-sol",
        messages=[{"role": "user", "content": "GEMINI_API_KEY=example-key-value-123456"}],
    )
)
```

Anthropic:

```python
from anthropic import Anthropic
from promptlatch import redact_messages

client = Anthropic()
response = client.messages.create(
    model="claude-opus-4-8",
    max_tokens=1024,
    messages=redact_messages([{"role": "user", "content": "token=example-token-value-123456"}]),
)
```

LangChain:

```python
from langchain_openai import ChatOpenAI
from promptlatch import redact_messages

llm = ChatOpenAI(model="gpt-6-sol")
response = llm.invoke(
    redact_messages(
        [
            ("human", "Here is my token: example-token-value-123456"),
        ]
    )
)
```

## Inspect redaction results

`scan_text`, `scan_messages`, `scan_params`, and `scan_payload` return a
`RedactionResult` with `.value` and `.stats`. Use `.value` for the SDK call, and use
`.stats.redactions` or `.stats.rule_hits` for counts by rule. Stats do not contain
matched secret values.

```python
from promptlatch import scan_text

result = scan_text("OPENAI_API_KEY=example-secret-value-123456")
print(result.stats.redactions)
safe_text = result.value
```

## Configure custom rules

The default helpers use the default `RedactionConfig`. For per-application rules,
create a `PromptLatch` instance. An exact rule of 8 to 16 characters matches a secret
tail at the end of a longer token. See [custom rules](configuration.md#custom-rules).

```python
from promptlatch import PromptLatch
from promptlatch.config import RedactionConfig, RuleConfig

latch = PromptLatch(
    RedactionConfig(
        rules=[
            RuleConfig(type="exact", value="abcd1234", name="internal-token"),
        ]
    )
)
safe_prompt = latch.text("internal token: private-abcd1234")
```

Redaction copies mappings, lists, tuples, and Pydantic models rather than mutating
caller-owned values. A detected secret in a Pydantic model's extra field name or
mapping-key collision raises `ValueError`; fail closed and do not send the original
input. Unknown private token formats need a custom exact-tail or regex rule.
