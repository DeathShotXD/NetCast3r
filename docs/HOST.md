# Host control

NetCast3r runs on the operator's machine and can drive it the way a coding
agent can: a shell and a filesystem, first class.

## Tools

| Tool | Risk | What it does |
| --- | --- | --- |
| `host_capabilities` | low | host, kernel, user, and which offensive/general tools are installed |
| `host_shell` | high | run one command, bounded, and return stdout/stderr/exit |
| `host_read` | medium | read a text file (binary is reported, not dumped) |
| `host_write` | high | create, overwrite, or append a file |
| `host_list` | low | list a directory |
| `host_find` | low | find files by glob |
| `host_stat` | low | existence, kind, size, mode, mtime |
| `host_processes` | low | list processes |
| `host_kill` | medium | signal a pid (TERM/KILL/INT) |

## The rules that are enforced

- **A shell is high risk.** `host_shell` and `host_write` run under the tool
  registry's risk gate: a supervised caller needs a single-use approval; an
  authorized autonomous mission runs them and the audit records
  `authorized:autonomous`. Every call is a tool call with its command, cwd, and
  exit code.
- **The framework protects itself.** NetCast3r's own secret store
  (`secrets.json`, the control-plane token) is refused by the path guard, so a
  prompt injected from a target cannot use the shell to read the control-plane
  token. Everything else on the host is the operator's to grant; hiding it would
  be theatre, since a shell can already reach it.
- **Bounded.** A wall-clock timeout on every command, with the whole process
  group killed on expiry, and an output cap on every stream.
- **No shell=False theatre.** `host_shell` is a real shell (`/bin/sh -lc`); the
  safety does not come from pretending otherwise, it comes from the risk gate,
  the audit, and the timeout.

## Surface

HTTP `POST /api/v1/host/shell`, `GET /api/v1/host/{read,list,find,stat,processes,capabilities}`,
`POST /api/v1/host/{write,kill}`. MCP `host_*`. The command center has a **Host
console** panel.

## Why this matters

The toolbox broker (see `docs/CAPABILITIES.md`) runs a curated set of external
tools with allowlisted arguments. The host shell is the escape hatch for
everything else: `msfconsole`, a custom PoC, `impacket`, a one-off `curl`. It is
what makes NetCast3r a complete harness rather than a fixed tool set, and it is
gated accordingly.
