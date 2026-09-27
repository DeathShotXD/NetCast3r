# NetCast3r

Cast a net over the web. NetCast3r crawls a target, reads its JavaScript,
hunts for secrets and logic holes, validates every credential it finds, and
writes a report you can submit.

This project is under active construction. The first milestone ships the recon
fabric, the scope engine, the egress layer, the provider bus, and a validation
engine that drives a single secret end to end.

## What it does

- Crawls a target and every endpoint it can reach, then collects the JavaScript
- Reads the JavaScript line by line to map the logic and surface weak spots
- Hunts for secrets, keys, tokens, and hardcoded credentials
- Validates each credential against its provider and reports what it can access
- Escalates to the highest provable impact when write access is enabled
- Writes a submission-ready report with proof and reproduction steps

## Scope files

Both scope files take one entry per line. Blank lines and lines starting with
`#` are ignored. The out-of-scope file wins over the in-scope file.

```
example.com            the host and all of its subdomains
*.example.com          subdomains only
https://example.com/p  scheme and path prefix
10.0.0.0/24            an IPv4 network
re:^api\.              a regular expression against the host
```

## Install

```
pipx install git+https://github.com/DeathShotXD/NetCast3r.git
netcast3r --version
```

## Usage

```
netcast3r recon --input target.com --scope scope.txt --out-of-scope oos.txt
netcast3r run   --input target.com --scope scope.txt --out-of-scope oos.txt
```

## Providers

NetCast3r talks to any OpenAI-compatible endpoint. OpenCode Zen and OpenRouter
are configured first by default; Ollama and custom endpoints are supported.

## Responsible use

NetCast3r is built for authorized testing only. Run it against systems you own
or have explicit written permission to assess.

## License

MIT. See [LICENSE](LICENSE).
