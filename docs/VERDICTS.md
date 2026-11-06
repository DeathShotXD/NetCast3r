# Evidence verdicts

A probe is not a verdict. NetCast3r records every request and response, then
labels what the response actually proves. The classifier lives in
`src/netcast3r/verdicts.py` and is attached to every lead case file.

## Why it exists

The Instant Gaming SSRF lead showed the failure mode:

- six metadata requests returned a Cloudflare `403` with no callback;
- one *different* request returned a `301` to `https://example.com/test`;
- the run log called the second request "supports" and the lead stayed open.

The `301` is an open redirect. It is not a server-side fetch. Reporting it as
SSRF would be wrong, and marking the SSRF lead "refuted" would also be wrong
because the edge blocked the test. The honest label is **edge-blocked**.

## Verdicts

| Verdict | Meaning | Proves the technique |
| --- | --- | --- |
| `supported` | A recorded body contains a cloud metadata document or a file-read body. | yes |
| `proven` | (open redirect) A recorded `Location` header leaves the target host. | yes, behaviour only |
| `redirect-only` | The target redirected a client to an external or metadata host. That is an open redirect, not SSRF. | no |
| `edge-blocked` | Every probe carried a CDN header or challenge body. | no |
| `blocked` | Every probe was refused, but the stored response cannot say whether the edge or the application refused it. | no |
| `inconclusive` | Responses exist but none decides the question. | no |
| `untested` | No probe is recorded. | no |
| `unavailable` | The classifier could not read the stored shape. This is a harness error, not a target result. | no |

## How each probe is labelled

The classifier reads the recorded result, never the model's prose:

- metadata marker in the body (`ami-id`, `iam/security-credentials`,
  `computemetadata`, `root:x:0:0`, ...) -> `metadata-response`
- edge header (`cf-ray`, `x-sucuri-id`, `x-iinfo`, ...) or a CDN `server`
  header, or a block status with a challenge body -> `edge-block`
- any other refusal status (`401`, `403`, `406`, `429`, `451`, `503`) ->
  `blocked-response`
- `3xx` with a `Location` on another host -> `external-redirect`
- `3xx` with a `Location` on a metadata host -> `metadata-redirect`
- transport failure -> `transport-error`
- `2xx` without a marker -> `body-returned`

## Proof survives redaction

The audit store redacts the raw body because a response can contain another
user's data or a credential. Losing the body would make a verdict impossible,
so every `http_probe` / `http_request` audit row also stores a small
non-secret digest (`signals`): which marker was seen, the `Location`, a body
hash, the body length, and the `server` header. The classifier reads that
digest when the body itself is redacted.

Old rows written before this digest existed can still be classified, but a
refusal with no stored digest is `blocked`, never `edge-blocked`: the harness
does not guess which layer refused the request.

## Where to see it

- Mission detail -> **Leads** -> the verdict block above the counts.
- `GET /api/v1/hypotheses/{id}/evidence` -> `verdict`.
- `GET /api/v1/hypotheses/{id}/evidence.md` -> a `## Verdict` section with the
  per-probe table.

## Rules

- A verdict never changes the hypothesis status, coverage, or the ledger.
- `edge-blocked` is not `refuted`. The application never saw the payload.
- `redirect-only` points at the related technique so the operator reports the
  right bug.
- Only `supported` (or `proven` for an open redirect) can justify promotion,
  and only after a reproducible retest.
