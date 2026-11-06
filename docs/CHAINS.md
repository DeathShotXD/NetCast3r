# File-read chains

A file read is not code execution. NetCast3r treats an LFI as a ladder: prove the
read, read the application source, look for a real execution sink, and stop at
the line where a write or an OS command needs an operator decision.

## Tools

| Tool | What it does | Risk |
| --- | --- | --- |
| `path_traversal_probe` | Sends plain, parent-directory, and encoded variants through one `{{path}}` parameter; classifies source, config, HTML, not-found, or error; reports depth and encoding. | medium |
| `source_disclosure_scan` | Fetches a bounded list of application source and config paths; scans each for credential-shaped values, SQL concatenation, cookie trust, upload, exec, and DB-exec sinks. Values are masked. | medium |
| `auth_cookie_probe` | Reads a login handler with a small set of cookie payloads, keeps the session cookie each response returns, and asks a protected page if the session became authenticated. | medium |
| `chain_run` | Runs the three steps in order and returns the ranked chain plus a `chain.plan` mission note. Uploads and OS commands are listed for approval only. | medium |

All four are scope-checked, audited, and read-only. They never write a file,
never authenticate with a discovered credential, and never run an OS command.

## The ladder

```
file parameter
  -> path_traversal_probe        read confirmed? depth / encoding
  -> source_disclosure_scan      source / config + secrets + sinks
  -> auth_cookie_probe           cookie trust -> authenticated session
  -> chain_run                   ranked candidates, approval boundary
```

## Verdicts

- `source-and-auth-bypass` - source disclosure plus a session bypass, no write.
- `chain-available-needs-approval` - a sink exists (upload, exec, DB command)
  but proving it would write or execute, so the chain stops.
- `source-disclosure` - source or config only.
- `read-only-no-source` - the parameter reads files but no source was reached.

## The approval boundary

`xp_cmdshell`, `sp_OACreate`, a webshell upload, or any OS command is a
real-world action. NetCast3r records the candidate and the exact reason it
stopped. It does not enable a database feature, upload a file, or execute a
command without an explicit operator approval bound to that tool call.

## Example

The EMTTS chain on `ep.gov.pk`:

1. `downloadPostApp.asp?file=../web.config` returned the config.
2. `downloadPostApp.asp?file=../HQ/check.asp` returned the login source.
3. The source trusted `uid`/`pwd` cookies and concatenated them into SQL.
4. `chain_run` then checked the protected page with no session first: it already
   returned the console, so the cookie injection was not credited as a bypass.
   The handler returned 500 for every credential, so the SQL injection stayed a
   code-level lead.
5. No upload handler existed in the console, so the chain ended at
   `source-disclosure`. The database command path was listed for approval and
   was not fired.

This baseline check is the point of the tool: a 200 is not a bypass until the
same page is tested without a session. The invalid bypass claim was rejected in
the ledger.

Credential values are masked everywhere in the record and the report.
