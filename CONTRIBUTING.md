# Contributing

Thanks for wanting to help. A few ground rules keep the project clean.

## Commits

- one change per commit, present tense: "add ...", "fix ...", "docs ..."
- keep the subject under 72 characters, no trailing period
- do not mix a refactor with a behaviour change
- run the tests before you commit

## Code

- Python 3.10 or later, standard library unless a dependency earns its place
- keep the deterministic path working when no provider is reachable
- never log or store a credential in full; redact on the way out
- plain ASCII in code, comments, and documents

## Tests

```
PYTHONPATH=src python3 -m unittest discover -s tests
```

Add a test for every behaviour change. The lab in `lab/` is the place to prove
a pipeline change without touching anything real.
