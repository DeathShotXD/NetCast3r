# Lab

The lab proves the pipeline without touching anything real and without any
provider key. It has two parts:

- `target_server.py` serves a small site whose JavaScript carries planted
  credentials and a source map.
- `verify_server.py` is a fake provider that answers the validation request
  for the lab token.

## Run it

```
bash lab/run_lab.sh
```

Or with Docker:

```
docker compose -f lab/docker-compose.yml up -d
```

Then, in another shell:

```
netcast3r run --input http://127.0.0.1:8099/ --out results \
  --patterns lab/patterns.toml --recipes lab/recipes.toml
```

The lab token `NC3RLABKEY123` is extracted, validated as verified, and written
into `results/report.md`.

## What it proves

- the crawler stays in scope and collects JavaScript
- the extractor finds the planted credential
- the assayer confirms it against the provider recipe
- the report is written with the value redacted
