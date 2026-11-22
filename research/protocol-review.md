# Protocol contract mismatches

## 1. Streamed `include_usage` chunks omit `usage` instead of emitting `null`

- **Location:** `internal/server/openai.go:80` and `internal/server/openai.go:166`.
- **Trigger:** `/v1/chat/completions` or `/v1/completions` with `stream:true` and `stream_options.include_usage:true`.
- **Actual:** `usage,omitempty` removes `usage` from the role/content/finish chunks. Only the additional final usage chunk contains the key.
- **Expected:** Every non-usage chunk must contain `"usage":null`; the additional chunk immediately before `data: [DONE]` must contain the usage object and `"choices":[]`. The `[DONE]` sentinel itself is correct.
- **Official contract:** [Chat Completions stream options](https://developers.openai.com/api/reference/resources/chat/create) and [Completions stream options](https://developers.openai.com/api/reference/resources/completions/create) both state that all other chunks include `usage` with a null value.

## 2. A completion prompt array is collapsed to one choice

- **Location:** `internal/server/openai.go:173-182`; prompt arrays are accepted at `internal/server/parse.go:174-184`.
- **Trigger:** For example, `POST /v1/completions` with `{"model":"qwen3:8b","prompt":["say hi","again"]}`.
- **Actual:** `body` always constructs `choices` with one element, whose index is zero. Streaming likewise emits only index zero.
- **Expected:** With the default `n:1`, two string prompts require two completion choices, one per prompt, with distinct `index` values `0` and `1`; streamed chunks must preserve those choice indexes. The two-prompt case already present at `internal/server/openai_test.go:157-166` checks only `choices[0]` and therefore does not catch the missing second choice.
- **Official contract:** [Create completion](https://developers.openai.com/api/reference/resources/completions/create) accepts an array of strings and specifies one completion per prompt when `n` is omitted.

## 3. Responses omit required top-level `access_programs` and `metadata` fields

- **Location:** `internal/server/openai.go:241-260`.
- **Trigger:** Every non-streaming `/v1/responses` result, every stored retrieval/cancellation result, and every `response.*` stream event carrying a `response` object.
- **Actual:** Both keys are absent because `responseObject` has no corresponding fields.
- **Expected:** The Response object must include `access_programs` (an object or `null`, normally `"access_programs":null` here) and `metadata` (an object or `null`, normally `"metadata":{}` when no metadata was supplied). This applies to completed, in-progress, retrieved, and cancelled Response objects.
- **Official contract:** The required Response fields are listed under [Create a model response](https://developers.openai.com/api/reference/resources/responses/methods/create), [Retrieve a model response](https://developers.openai.com/api/reference/resources/responses/methods/retrieve), and the [response streaming schemas](https://developers.openai.com/api/reference/resources/responses/streaming-events).

## 4. Responses text parts and text events lack required `logprobs` arrays

- **Location:** `internal/server/openai.go:219-223`, `internal/server/openai.go:324-327`, `internal/server/openai.go:331-334`, and `internal/server/openai.go:337-345`.
- **Trigger:** Every Responses output-text result and stream.
- **Actual:** `output_text` parts contain only `type`, `text`, and `annotations`. `response.output_text.delta` and `response.output_text.done` also omit their top-level `logprobs` key.
- **Expected:** When no token log probabilities are returned, each `output_text` part must still contain `"logprobs":[]`. The delta and done events must likewise include top-level `"logprobs":[]`, alongside `item_id`, `output_index`, `content_index`, `delta`/`text`, `sequence_number`, and `type`.
- **Official contract:** `ResponseOutputText`, `ResponseTextDeltaEvent`, and `ResponseTextDoneEvent` in the [Responses streaming event reference](https://developers.openai.com/api/reference/resources/responses/streaming-events) define these arrays as required and show empty arrays in their examples.

## 5. Responses usage omits required `cache_write_tokens`

- **Location:** `internal/server/openai.go:279-286`.
- **Trigger:** Every completed non-streaming Response, `response.completed` event, and fake retrieved/cancelled Response with usage.
- **Actual:** `input_tokens_details` is only `{"cached_tokens":0}`.
- **Expected:** The usage shape must include both required counters, for example `"input_tokens_details":{"cached_tokens":0,"cache_write_tokens":0}`. `output_tokens_details.reasoning_tokens` and the three token totals are otherwise shaped correctly.
- **Official contract:** `ResponseUsage.input_tokens_details` under [Create a model response](https://developers.openai.com/api/reference/resources/responses/methods/create) requires `cache_write_tokens` and `cached_tokens`.

## 6. Cancelled Responses use an invalid nested output-item status

- **Location:** `internal/server/openai.go:351-359`, reached by `cancelResponse` at `internal/server/openai.go:608-612`.
- **Trigger:** `POST /v1/responses/{id}/cancel`.
- **Actual:** The outer Response has `"status":"cancelled"`, but `full` passes that same value into the message item, producing `"output[0].status":"cancelled"`.
- **Expected:** `cancelled` is valid for the outer Response, not for a `ResponseOutputMessage`. For an output message interrupted by cancellation, the nested item status must be `"incomplete"` (the output-message enum is only `in_progress`, `completed`, or `incomplete`). The outer status remains `"cancelled"`.
- **Official contract:** [Cancel a response](https://developers.openai.com/api/reference/resources/responses/methods/cancel) defines the outer status and the nested `ResponseOutputMessage` status enum.

## 7. Embeddings lose token-array boundaries and undercount nested token inputs

- **Location:** `internal/server/parse.go:257-281` and `internal/server/embed.go:105-112`.
- **Trigger:** OpenAI-compatible embeddings requests using the documented token forms.
- **Actual:** `input:[1,2,3]` is converted to three strings and produces three embedding objects, although it is one tokenized input. `input:[[1,2,3]]` correctly produces one embedding by cardinality, but its serialized text is whitespace-counted as one word, yielding `"prompt_tokens":1` and `"total_tokens":1` instead of `3`.
- **Expected:** A flat number array is one input and must produce one embedding with index `0`. An array of token arrays produces one embedding per inner array. Usage must count the supplied tokens: both examples above have `prompt_tokens` and `total_tokens` equal to `3`.
- **Official contract:** [Create embeddings](https://developers.openai.com/api/reference/resources/embeddings/create) distinguishes `array of number` from `array of array of number` and defines usage as the number of input tokens.

## 8. Ollama unload requests are reported as loads

- **Location:** `internal/server/ollama.go:125-129`; the load decision is made without `keep_alive` at `internal/server/parse.go:164` and `internal/server/parse.go:185-188`.
- **Trigger:** `POST /api/generate` with an empty prompt and `"keep_alive":0`, or `POST /api/chat` with `"messages":[]` and `"keep_alive":0`.
- **Actual:** Both paths return `"done":true,"done_reason":"load"`.
- **Expected:** Generate must return an empty `response`, `done:true`, and `"done_reason":"unload"`; chat must return an empty assistant `message.content`, `done:true`, and `"done_reason":"unload"`. Ordinary empty-input requests without `keep_alive:0` correctly use `load`.
- **Official contract:** The generate and chat unload examples in [Ollama's API documentation](https://github.com/ollama/ollama/blob/main/docs/api.md#unload-a-model) specify `done_reason:"unload"`.

## 9. `/api/create` ignores `stream:false`

- **Location:** `internal/server/ollama.go:263-275`.
- **Trigger:** A create request such as `{"model":"mine","from":"qwen3:8b","stream":false}`.
- **Actual:** The handler always returns `Content-Type: application/x-ndjson` and writes the success object as an NDJSON record.
- **Expected:** With `stream:false`, return one ordinary JSON response with `Content-Type: application/json` and body `{"status":"success"}`. NDJSON is appropriate only for the default streaming mode.
- **Official contract:** [Create a model](https://docs.ollama.com/api/create) defines `stream` (default `true`) and provides separate `application/json` and `application/x-ndjson` success response forms.

## 10. Successful `/api/copy` responses have an empty body instead of the documented status object

- **Location:** `internal/server/ollama.go:278-292`.
- **Trigger:** A copy request whose source model exists.
- **Actual:** `c.empty(http.StatusOK)` returns HTTP 200 with `Content-Length: 0` and no JSON body.
- **Expected:** Under the current Ollama `StatusResponse` contract, success is HTTP 200 with an ordinary JSON body `{"status":"success"}`. The existing management test at `internal/server/ollama_test.go:180-182` checks only the status code, so the empty body is not detected.
- **Official contract:** [Copy a model](https://docs.ollama.com/api/copy) documents the 200 response as `StatusResponse` with the example `{"status":"success"}`.
