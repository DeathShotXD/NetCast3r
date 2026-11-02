"""Source-to-sink call-chain analysis for Python.

Pattern matching finds a dangerous call. It cannot tell whether the argument
came from the network. This module follows a remote input through assignments,
branches, function arguments, and return values to a sink, and reports the
chain it actually traversed.

It is intentionally conservative. It only knows a small set of web sources
(``request``, ``input``, ``sys.argv``, environment variables) and a small set
of sinks (code execution, shell, SQL, SSRF, template injection, unsafe
deserialisation, file access, redirects). A chain is a lead for a human to
verify, never a finding. Safe parameterised SQL, safe YAML loaders, and an
untouched request object are not reported.

Only Python is analysed in this pass. The output shape is deliberately
language-neutral so a JavaScript/TypeScript or PHP front end can reuse it.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILES = 2000
MAX_BYTES = 1_500_000
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv",
             "__pycache__", "build", "dist", ".tox", ".mypy_cache",
             "site-packages"}
ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "route", "api_route",
                 "websocket", "head", "options"}
ROUTE_PARAM_NAMES = {"request", "req"}

CODE_SINKS = {"eval", "exec", "compile", "__import__"}
SHELL_SINKS = {"os.system", "os.popen", "subprocess.run", "subprocess.call",
               "subprocess.check_call", "subprocess.check_output",
               "subprocess.Popen", "asyncio.create_subprocess_shell"}
SQL_METHODS = {"execute", "executemany", "executescript"}
SSRF_SINKS = {"requests.get", "requests.post", "requests.put", "requests.patch",
              "requests.delete", "requests.request", "httpx.get", "httpx.post",
              "httpx.request", "urllib.request.urlopen", "urlopen",
              "aiohttp.ClientSession.get", "aiohttp.ClientSession.post"}
DESERIALIZE_SINKS = {"pickle.loads", "pickle.load", "marshal.loads",
                     "yaml.load", "dill.loads", "jsonpickle.decode"}
TEMPLATE_SINKS = {"render_template_string", "flask.render_template_string",
                  "Template", "jinja2.Template"}
FILE_SINKS = {"open", "io.open", "Path", "pathlib.Path", "send_file",
              "flask.send_file"}
REDIRECT_SINKS = {"redirect", "flask.redirect"}
SOURCE_ROOTS = {"request", "flask.request", "fastapi.Request", "req"}
SOURCE_CALLS = {"input", "sys.argv", "os.environ", "os.getenv"}
TAINT_PRESERVING = {"str", "bytes", "format", "join", "strip", "lstrip",
                    "rstrip", "lower", "upper", "replace", "encode", "decode",
                    "split", "partition", "removeprefix", "removesuffix",
                    "quote", "quote_plus", "unquote", "unquote_plus"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "safe_load"}


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: str
    route: str = ""
    params: list[str] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)


@dataclass
class Chain:
    sink: str
    severity: str
    line: int
    steps: list[str]
    route: str = ""
    confidence: str = "medium"
    note: str = ""

    def key(self) -> tuple:
        return (self.sink, self.line, self.route)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return ""


def _line(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 0) or 0)


def _route_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        dotted = _dotted(target)
        if not dotted:
            continue
        last = dotted.rsplit(".", 1)[-1].lower()
        if last not in ROUTE_METHODS:
            continue
        path = ""
        if isinstance(decorator, ast.Call) and decorator.args:
            first = decorator.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                path = first.value
        return f"{last.upper()} {path}".strip()
    return ""


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    names = [arg.arg for arg in (args.posonlyargs + args.args)]
    if names and names[0] in {"self", "cls"}:
        names = names[1:]
    return names


def _is_source_attr(dotted: str) -> bool:
    if not dotted:
        return False
    head = dotted.split(".", 1)[0]
    if head in SOURCE_ROOTS:
        return True
    return dotted in SOURCE_CALLS or any(
        dotted.startswith(f"{item}.") for item in SOURCE_CALLS)


def _source_path(node: ast.AST) -> list[str]:
    dotted = _dotted(node)
    if _is_source_attr(dotted):
        return [f"line {_line(node)}: remote input via {dotted or 'request'}"]
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        if _is_source_attr(name):
            return [f"line {_line(node)}: remote input via {name}"]
    return []


class _FunctionAnalysis:
    def __init__(self, info: FunctionInfo, known: dict[str, FunctionInfo],
                 returns: dict[str, list[str]]):
        self.info = info
        self.known = known
        self.returns = returns
        self.env: dict[str, list[str]] = {}
        self.sinks: list[Chain] = []
        self.calls: list[dict] = []
        self.return_path: list[str] = []
        self.route = info.route

    def run(self, param_paths: dict[str, list[str]]) -> dict:
        for name, path in param_paths.items():
            self.env[name] = list(path)
        # ``request`` is a Flask proxy, not always a parameter. A helper that
        # reads the global proxy is still reading remote input, so seed it in
        # every function. A local assignment with a safe value overwrites it.
        self.env.setdefault("request", [f"line {_line(self.info.node)}: "
                                        "request object"])
        self._statements(self.info.node.body)
        return {"sinks": self.sinks, "calls": self.calls,
                "return": self.return_path}

    # -- taint -------------------------------------------------------------
    def _taint(self, node: ast.AST | None) -> list[str]:
        if node is None:
            return []
        source = _source_path(node)
        if source:
            return source
        if isinstance(node, ast.Name):
            return list(self.env.get(node.id) or [])
        if isinstance(node, ast.Attribute):
            return self._taint(node.value)
        if isinstance(node, ast.Subscript):
            return self._taint(node.value)
        if isinstance(node, ast.Starred):
            return self._taint(node.value)
        if isinstance(node, ast.Await):
            return self._taint(node.value)
        if isinstance(node, ast.BinOp):
            return self._merge(self._taint(node.left), self._taint(node.right))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            paths: list[str] = []
            for item in node.elts:
                paths = self._merge(paths, self._taint(item))
            return paths
        if isinstance(node, ast.Dict):
            paths: list[str] = []
            for key, value in zip(node.keys, node.values):
                paths = self._merge(paths, self._taint(key))
                paths = self._merge(paths, self._taint(value))
            return paths
        if isinstance(node, ast.JoinedStr):
            paths: list[str] = []
            for value in node.values:
                paths = self._merge(paths, self._taint(value))
            return paths
        if isinstance(node, ast.FormattedValue):
            return self._taint(node.value)
        if isinstance(node, ast.IfExp):
            return self._merge(self._taint(node.body), self._taint(node.orelse))
        if isinstance(node, (ast.Compare, ast.BoolOp)):
            return []
        if isinstance(node, ast.NamedExpr):
            return self._taint(node.value)
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in self.returns:
                return self._append(self.returns[name], node)
            if name in TAINT_PRESERVING:
                paths: list[str] = []
                for arg in node.args:
                    paths = self._merge(paths, self._taint(arg))
                return paths
            if isinstance(node.func, ast.Attribute):
                return self._taint(node.func.value)
        return []

    @staticmethod
    def _merge(first: list[str], second: list[str]) -> list[str]:
        out = list(first)
        for item in second:
            if item not in out:
                out.append(item)
        return out

    @staticmethod
    def _append(path: list[str], node: ast.AST) -> list[str]:
        if not path:
            return []
        return list(path) + [f"line {_line(node)}: returned to the caller"]

    def _assign(self, target: ast.AST, path: list[str]) -> None:
        if not path:
            if isinstance(target, ast.Name):
                self.env.pop(target.id, None)
            return
        if isinstance(target, ast.Name):
            self.env[target.id] = list(path)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, path)

    # -- statements --------------------------------------------------------
    def _statements(self, body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                path = self._taint(value)
                self._expr(value)
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        self._assign(target, path)
                else:
                    self._assign(node.target, path)
            elif isinstance(node, ast.AugAssign):
                self._expr(node.value)
                left = self._taint(node.target)
                right = self._taint(node.value)
                path = self._merge(left, right)
                self._assign(node.target, path)
            elif isinstance(node, ast.Expr):
                self._expr(node.value)
            elif isinstance(node, ast.Return):
                path = self._taint(node.value)
                self._expr(node.value)
                if path:
                    self.return_path = self._merge(self.return_path, path)
            elif isinstance(node, ast.If):
                self._expr(node.test)
                base = dict(self.env)
                self._statements(node.body)
                body_env = dict(self.env)
                self.env = dict(base)
                self._statements(node.orelse)
                self.env = self._merge_env(body_env, self.env)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                self._expr(node.iter)
                item_path = self._taint(node.iter)
                self._assign(node.target, item_path)
                self._statements(node.body)
                self._statements(node.orelse)
            elif isinstance(node, (ast.While,)):
                self._expr(node.test)
                self._statements(node.body)
                self._statements(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self._expr(item.context_expr)
                self._statements(node.body)
            elif isinstance(node, ast.Try):
                self._statements(node.body)
                for handler in node.handlers:
                    self._statements(handler.body)
                self._statements(node.orelse)
                self._statements(node.finalbody)
            elif isinstance(node, ast.Match):
                self._expr(node.subject)
                for case in node.cases:
                    self._statements(case.body)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                   ast.ClassDef)):
                continue
            elif hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
                self._statements(node.body)
                for handler in node.handlers:
                    self._statements(handler.body)
                self._statements(node.orelse)
                self._statements(node.finalbody)

    @staticmethod
    def _merge_env(first: dict[str, list[str]],
                   second: dict[str, list[str]]) -> dict[str, list[str]]:
        merged = dict(first)
        for key, value in second.items():
            merged[key] = _FunctionAnalysis._merge(merged.get(key, []), value)
        return merged

    # -- expressions and sinks --------------------------------------------
    def _expr(self, node: ast.AST | None) -> None:
        if node is None:
            return
        if isinstance(node, ast.Call):
            self._call(node)
        for child in ast.iter_child_nodes(node):
            self._expr(child)

    def _call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        if not name:
            return
        tainted = []
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            path = self._taint(arg)
            if path:
                tainted.extend(path)
        last = name.rsplit(".", 1)[-1]
        sink = self._sink(name, last, node, tainted)
        if sink:
            self.sinks.append(sink)
        callee = self.known.get(last) or self.known.get(name)
        if callee and callee.qualname != self.info.qualname:
            params = list(callee.params)
            if isinstance(node.func, ast.Attribute) and params:
                params = params  # self was already removed by _param_names
            # Record the call even with no tainted argument: reachability is
            # what lets a helper that reads the global request proxy enter the
            # analysis at all.
            self.calls.append({"callee": last, "param": "", "path": []})
            for index, arg in enumerate(node.args):
                path = self._taint(arg)
                if path and index < len(params):
                    self.calls.append({"callee": last, "param": params[index],
                                       "path": list(path)})

    def _sink(self, name: str, last: str, node: ast.Call,
              tainted: list[str]) -> Chain | None:
        if not tainted and name not in CODE_SINKS:
            return None
        severity = ""
        note = ""
        if name.rsplit(".", 1)[-1] in CODE_SINKS or name in CODE_SINKS:
            severity, note = "critical", "code execution sink"
        elif name in SHELL_SINKS or name.endswith((".system", ".popen")):
            severity, note = "critical", "shell execution sink"
        elif last in SQL_METHODS and isinstance(node.func, ast.Attribute):
            first = node.args[0] if node.args else None
            if not self._taint(first):
                return None
            severity, note = "high", "SQL query built from remote input"
        elif name in SSRF_SINKS:
            severity, note = "high", "server-side request with remote target"
        elif name in TEMPLATE_SINKS:
            severity, note = "high", "template rendered from remote input"
        elif name in DESERIALIZE_SINKS:
            if name == "yaml.load":
                loader = ""
                if len(node.args) > 1:
                    loader = _dotted(node.args[1])
                for keyword in node.keywords:
                    if keyword.arg in {"Loader", "loader"}:
                        loader = _dotted(keyword.value)
                if loader.rsplit(".", 1)[-1] in SAFE_YAML_LOADERS:
                    return None
            severity, note = "high", "unsafe deserialisation of remote input"
        elif name in REDIRECT_SINKS:
            severity, note = "medium", "redirect target from remote input"
        elif name in FILE_SINKS:
            severity, note = "medium", "file path from remote input"
        else:
            return None
        if not tainted:
            return None
        steps = list(tainted) + [f"line {_line(node)}: {name}() sink"]
        confidence = "high" if len(steps) <= 3 else "medium"
        return Chain(sink=f"{name}()", severity=severity, line=_line(node),
                     steps=steps[-12:], route=self.route,
                     confidence=confidence, note=note)


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BYTES:
            return ""
        return path.read_text(errors="ignore")
    except OSError:
        return ""


def _files(root: Path) -> list[Path]:
    found: list[Path] = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in names:
            if name.endswith(".py"):
                found.append(Path(base) / name)
                if len(found) >= MAX_FILES:
                    return found
    return found


def analyze_text(text: str, filename: str = "<string>") -> dict:
    """Analyse one Python source file and return source-to-sink leads."""
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        return {"file": filename, "leads": [], "error": f"syntax error: {exc}"}
    funcs: list[FunctionInfo] = []
    known: dict[str, FunctionInfo] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = _route_of(node)
        info = FunctionInfo(
            name=node.name, qualname=f"{filename}:{node.name}",
            node=node, file=filename, route=route,
            params=_param_names(node))
        funcs.append(info)
        known.setdefault(node.name, info)
    if not funcs:
        return {"file": filename, "leads": [], "error": ""}

    routes = [info for info in funcs if info.route]
    param_paths: dict[str, dict[str, list[str]]] = {}
    # Only a route and the functions it actually calls are reachable from
    # remote input. Analysing every function in the tree turns ordinary
    # environment-variable use into a fake remote chain.
    reachable: set[str] = set()
    for info in routes:
        reachable.add(info.qualname)
        paths = param_paths.setdefault(info.qualname, {})
        for param in info.params:
            if param in ROUTE_PARAM_NAMES:
                paths[param] = [f"line {_line(info.node)}: route parameter {param}"]
        paths.setdefault("request", [f"line {_line(info.node)}: route request object"])
    returns: dict[str, list[str]] = {}
    leads: dict[tuple, Chain] = {}
    for _ in range(5):
        changed = False
        for info in funcs:
            if info.qualname not in reachable:
                continue
            analysis = _FunctionAnalysis(info, known, returns)
            result = analysis.run(param_paths.get(info.qualname) or {})
            for chain in result["sinks"]:
                old = leads.get(chain.key())
                if old is None or len(chain.steps) < len(old.steps):
                    leads[chain.key()] = chain
            if result["return"] and not returns.get(info.name):
                returns[info.name] = result["return"]
                changed = True
            for call in result["calls"]:
                target = known.get(call["callee"])
                if not target:
                    continue
                if target.qualname not in reachable:
                    reachable.add(target.qualname)
                    changed = True
                paths = param_paths.setdefault(target.qualname, {})
                current = paths.get(call["param"]) or []
                merged = _FunctionAnalysis._merge(current, call["path"])
                if merged != current:
                    paths[call["param"]] = merged
                    changed = True
        if not changed:
            break
    items = sorted(leads.values(), key=lambda item: (
        {"critical": 0, "high": 1, "medium": 2}.get(item.severity, 3),
        item.line))
    return {
        "file": filename,
        "leads": [{
            "sink": item.sink, "severity": item.severity,
            "line": item.line, "route": item.route,
            "confidence": item.confidence, "note": item.note,
            "steps": item.steps,
        } for item in items],
        "error": "",
    }


def scan(root: str | Path, max_files: int = MAX_FILES) -> dict:
    """Walk a source tree and return conservative source-to-sink leads."""
    base = Path(root)
    if not base.exists():
        raise ValueError(f"source path not found: {root}")
    if base.is_file():
        base_dir = base.parent
        files = [base] if base.suffix.lower() == ".py" else []
    else:
        base_dir = base
        files = _files(base)
    files = files[:max(1, min(int(max_files or MAX_FILES), MAX_FILES))]
    all_leads: list[dict] = []
    errors: list[dict] = []
    for path in files:
        text = _read(path)
        if not text:
            continue
        rel = str(path.relative_to(base_dir))
        result = analyze_text(text, rel)
        if result.get("error"):
            errors.append({"file": rel, "error": result["error"]})
        for lead in result["leads"]:
            lead["file"] = rel
            all_leads.append(lead)
    all_leads.sort(key=lambda item: (
        {"critical": 0, "high": 1, "medium": 2}.get(item["severity"], 3),
        item["file"], item.get("line", 0)))
    return {
        "root": str(base),
        "files": len(files),
        "leads": all_leads,
        "count": len(all_leads),
        "errors": errors[:20],
        "note": ("Static source-to-sink leads. A lead is not a finding: it "
                 "still needs a reachable route, a working request, and a "
                 "reviewer."),
    }
