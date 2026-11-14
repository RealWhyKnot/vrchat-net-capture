from __future__ import annotations

import ast
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from style_scan import Finding

STANDARD_MODULES = frozenset(sys.stdlib_module_names) | {"__future__"}
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


@dataclass(frozen=True, slots=True)
class LazyImport:
    line: int
    shown: str
    targets: tuple[str, ...]


@dataclass(slots=True)
class Module:
    path: str
    names: tuple[str, ...]
    package: str
    eager: list[str] = field(default_factory=list[str])
    lazy: list[LazyImport] = field(default_factory=list[LazyImport])


def is_type_checking(node: ast.If) -> bool:
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def read_module(path: str, packages: frozenset[str]) -> Module:
    pure = PurePosixPath(path)
    folders = pure.parent.parts
    start = next((index for index in range(len(folders)) if "/".join(folders[: index + 1]) in packages), 0)
    package = folders[start:]
    stem = () if pure.stem == "__init__" else (pure.stem,)
    names = dict.fromkeys(".".join((*parts, *stem)) for parts in (package, folders))
    usable = tuple(name for name in names if name and name not in STANDARD_MODULES)
    return Module(path, usable, ".".join(package))


def resolve(module: Module, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    base = module.package.split(".") if module.package else []
    base = base[: len(base) - node.level + 1]
    return ".".join([*base, node.module] if node.module else base)


def prefixes(name: str) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[:end]) for end in range(1, len(parts) + 1)]


def finishing_order(edges: dict[str, set[str]]) -> list[str]:
    seen: set[str] = set()
    order: list[str] = []
    for name in edges:
        pending = [(name, False)]
        while pending:
            current, finished = pending.pop()
            if finished:
                order.append(current)
            elif current not in seen:
                seen.add(current)
                pending.append((current, True))
                pending.extend((target, False) for target in edges[current] if target not in seen)
    return order


def components(edges: dict[str, set[str]]) -> dict[str, int]:
    reverse: dict[str, set[str]] = {name: set() for name in edges}
    for name, targets in edges.items():
        for target in targets:
            reverse[target].add(name)
    groups: dict[str, int] = {}
    for name in reversed(finishing_order(edges)):
        if name in groups:
            continue
        group = len(groups)
        queue = [name]
        groups[name] = group
        while queue:
            for target in reverse[queue.pop()]:
                if target not in groups:
                    groups[target] = group
                    queue.append(target)
    return groups


def reachability(edges: dict[str, set[str]], groups: dict[str, int]) -> dict[int, int]:
    representatives = {group: name for name, group in groups.items()}
    condensed: dict[str, set[str]] = {name: set() for name in representatives.values()}
    for name, targets in edges.items():
        condensed[representatives[groups[name]]].update(
            representatives[groups[target]] for target in targets if groups[target] != groups[name]
        )
    reachable: dict[int, int] = {}
    for name in finishing_order(condensed):
        group = groups[name]
        mask = 1 << group
        for target in condensed[name]:
            mask |= reachable[groups[target]]
        reachable[group] = mask
    return reachable


class Index:
    def __init__(self, modules: list[Module]) -> None:
        self.by_name: dict[str, list[Module]] = {}
        known: set[str] = set()
        for module in modules:
            for name in module.names:
                self.by_name.setdefault(name, []).append(module)
                known.update(prefixes(name))
        self.known = frozenset(known - STANDARD_MODULES)
        self.importers: dict[str, set[str]] = {}
        self.heavy: frozenset[str] = frozenset()
        self.dependencies: dict[str, set[str]] = {name: set() for name in self.known}
        self.groups: dict[str, int] = {}
        self.reachable: dict[int, int] = {}

    def targets(self, module: Module, node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
        if isinstance(node, ast.Import):
            return tuple(self.local_name(module, alias.name) for alias in node.names)
        base = resolve(module, node)
        if not node.level:
            base = self.local_name(module, base)
        return tuple(f"{base}.{alias.name}" if f"{base}.{alias.name}" in self.known else base for alias in node.names)

    def local_name(self, module: Module, name: str) -> str:
        sibling = f"{module.package}.{name}"
        if name.split(".", maxsplit=1)[0] not in STANDARD_MODULES and name not in self.known and sibling in self.known:
            return sibling
        return name

    def own_prefixes(self, name: str) -> list[str]:
        return [prefix for prefix in prefixes(name) if prefix in self.known]

    def link(self) -> None:
        direct: set[str] = set()
        for name, modules in self.by_name.items():
            for target in (target for module in modules for target in module.eager):
                own = self.own_prefixes(target)
                if not own and target.split(".", maxsplit=1)[0] not in STANDARD_MODULES:
                    direct.add(name)
                for prefix in own:
                    self.importers.setdefault(prefix, set()).add(name)
                if target in self.known and target not in prefixes(name)[:-1]:
                    self.dependencies[name].add(target)
        self.heavy = self.spread(direct)
        self.groups = components(self.dependencies)
        self.reachable = reachability(self.dependencies, self.groups)

    def spread(self, start: set[str]) -> frozenset[str]:
        found = set(start)
        queue = deque(start)
        while queue:
            for importer in self.importers.get(queue.popleft(), ()):
                if importer not in found:
                    found.add(importer)
                    queue.append(importer)
        return frozenset(found)

    def is_heavy(self, name: str) -> bool:
        own = self.own_prefixes(name)
        if not own:
            return name.split(".", maxsplit=1)[0] not in STANDARD_MODULES
        return any(prefix in self.heavy for prefix in own)

    def reaches(self, name: str, module: Module) -> bool:
        if name not in self.known:
            return False
        mask = self.reachable[self.groups[name]]
        return any(mask & (1 << self.groups[target]) for target in module.names)


def collect(module: Module, index: Index, node: ast.AST, *, lazy: bool) -> None:
    if isinstance(node, ast.If) and not lazy and is_type_checking(node):
        for other in node.orelse:
            collect(module, index, other, lazy=lazy)
        return
    if isinstance(node, ast.Import | ast.ImportFrom):
        targets = index.targets(module, node)
        if lazy:
            shown = ", ".join(alias.name for alias in node.names)
            module.lazy.append(LazyImport(node.lineno, shown, targets))
        else:
            module.eager.extend(targets)
        return
    inner = lazy or isinstance(node, FUNCTIONS)
    for child in ast.iter_child_nodes(node):
        collect(module, index, child, lazy=inner)


def check_imports(sources: dict[str, str]) -> list[Finding]:
    packages = frozenset(
        str(PurePosixPath(path).parent) for path in sources if PurePosixPath(path).name == "__init__.py"
    )
    trees: dict[str, ast.Module] = {}
    modules: list[Module] = []
    for path, text in sources.items():
        try:
            trees[path] = ast.parse(text, filename=path)
        except SyntaxError:
            continue
        modules.append(read_module(path, packages))
    index = Index(modules)
    for module in modules:
        collect(module, index, trees[module.path], lazy=False)
    index.link()
    findings: list[Finding] = []
    for module in modules:
        for item in module.lazy:
            if any(index.is_heavy(target) or index.reaches(target, module) for target in item.targets):
                continue
            findings.append(
                Finding(module.path, item.line, f"import of {item.shown} inside a function; it's light (PY-14)")
            )
    return findings
