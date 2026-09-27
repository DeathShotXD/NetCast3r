# Maintenance plan

NetCast3r is maintained in small, focused commits. One change a day, each
commit doing a single thing and leaving the tree working.

This is a working plan, not a contract.

## Week 1

- Mon - source map reconstruction for minified JavaScript
- Tue - katana adapter that feeds the crawler
- Wed - wayback and gau adapters
- Thu - JavaScript in JavaScript recursion for chunk maps
- Fri - per-agent model routing from the config file
- Sat - provider health panel in the console
- Sun - README pass

## Week 2

- Mon - prospector model triage wired into the orchestrator
- Tue - secrets pattern set expanded by vendor
- Wed - assayer planning for types without a recipe
- Thu - read only validation for twenty providers
- Fri - chainer escalation steps from the knowledge base
- Sat - sentinel scoring and dedupe rules
- Sun - lab extended with more planted credentials

## Week 3

- Mon - exegete subagent fan out for large files
- Tue - concurrency limits per provider
- Wed - response caching
- Thu - report templates for HackerOne, Bugcrowd, and Intigriti
- Fri - redaction profiles for evidence
- Sat - JSON output mode
- Sun - docs pass

## Week 4

- Mon - interactive dashboard
- Tue - continuous monitoring between runs
- Wed - goldens and a benchmark for detection and validation accuracy
- Thu - CI that runs the tests on push
- Fri - assets and demo
- Sat - release checklist
- Sun - tag the release

## Commit conventions

- one change per commit, present tense
- subject under 72 characters, no trailing period
- do not mix refactors with behaviour changes
- run the tests before committing

## Daily checklist

1. Pick the next item.
2. Make the smallest change that completes it.
3. Run the tests and the lab.
4. Commit with a plain message.
5. Push to main.
