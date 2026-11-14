from __future__ import annotations

import argparse
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from style_configs import LINT_DIR, check_config
from style_imports import check_imports
from style_scan import Finding
from style_sources import check_generated, check_source, language_of

if TYPE_CHECKING:
    from types import TracebackType

VENDORED_FILE = "vendored-paths.txt"
LOCAL_FILE = "vendored-paths.local.txt"
APPROVED_FILE = "approved-suppressions.local.txt"
SUPPRESSION = "lint suppression (GEN-4)"
ATTRIBUTE_SPAN = 6
SEGMENT = r"(?!\.+/)[A-Za-z0-9_.@+-]+/"
LEAF = r"(?!\.+$)[A-Za-z0-9_.@+-]+"
ENTRY = re.compile(rf"/(?:{SEGMENT})+|/(?:{SEGMENT})*{LEAF}|{SEGMENT}")
APPROVED_ENTRY = re.compile(rf"(/(?:{SEGMENT})*{LEAF})[ \t]+([A-Za-z][A-Za-z0-9_]*)")


@dataclass(frozen=True, slots=True)
class VendoredPaths:
    names: frozenset[str]
    prefixes: tuple[str, ...]
    files: frozenset[str]

    def covers(self, path: str) -> bool:
        if path in self.files or path.startswith(self.prefixes):
            return True
        return any(part in self.names for part in path.split("/")[:-1])


@dataclass(frozen=True, slots=True)
class Approval:
    number: int
    path: str
    rule: str


def read_approvals(path: Path) -> list[Approval]:
    approvals: list[Approval] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        entry = raw.strip()
        if not entry:
            continue
        match = APPROVED_ENTRY.fullmatch(entry)
        if match is None:
            message = f"{path.name}:{number}: {entry!r} isn't a /path/file from the repo root and a rule id"
            raise ValueError(message)
        approvals.append(Approval(number, match.group(1).lstrip("/"), match.group(2)))
    return approvals


def attribute_text(root: Path, finding: Finding) -> str:
    try:
        lines = (root / finding.path).read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[max(finding.line - 1, 0) : finding.line - 1 + ATTRIBUTE_SPAN])


def apply_approvals(root: Path, findings: list[Finding], approvals: list[Approval]) -> list[Finding]:
    kept = list(findings)
    for approval in approvals:
        rule = re.compile(
            rf'^[^\n]*?\bSuppressMessage(?:Attribute)?\s*\(\s*"[^"\n]*"\s*,\s*"{re.escape(approval.rule)}\b',
        )
        approved = next(
            (
                finding
                for finding in kept
                if finding.path == approval.path
                and finding.message == SUPPRESSION
                and rule.search(attribute_text(root, finding))
            ),
            None,
        )
        if approved is None:
            message = f"{approval.path} has no {approval.rule} suppression left; remove this line (GEN-4)"
            kept.append(Finding(f"{LINT_DIR}/{APPROVED_FILE}", approval.number, message))
        else:
            kept.remove(approved)
    return sorted(kept)


def read_entries(path: Path) -> list[str]:
    entries: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        entry = raw.strip()
        if not entry:
            continue
        if not ENTRY.fullmatch(entry):
            message = (
                f"{path.name}:{number}: {entry!r} isn't a folder name/, a /path/ or a /path/file from the repo root"
            )
            raise ValueError(message)
        entries.append(entry)
    return entries


def vendored_paths(entries: list[str]) -> VendoredPaths:
    names = {entry.strip("/") for entry in entries if not entry.startswith("/")}
    rooted = [entry.lstrip("/") for entry in entries if entry.startswith("/")]
    prefixes = tuple(entry for entry in rooted if entry.endswith("/"))
    files = frozenset(entry for entry in rooted if not entry.endswith("/"))
    return VendoredPaths(frozenset(names), prefixes, files)


def unfolded(shared: list[str], local: list[str]) -> list[Finding]:
    return [
        Finding(f"{LINT_DIR}/{LOCAL_FILE}", 0, f"{entry} isn't in {VENDORED_FILE} yet. Run Install-Lint again (GEN-1)")
        for entry in local
        if entry not in shared
    ]


def tracked_files(root: Path) -> list[str]:
    git = shutil.which("git")
    if git is None:
        message = "git isn't on PATH"
        raise OSError(message)
    result = subprocess.run(
        [git, "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=True,
        timeout=120,
    )
    return [entry for entry in result.stdout.decode("utf-8", errors="replace").split("\0") if entry]


def check_repo(root: Path, vendored: VendoredPaths) -> list[Finding]:
    own = [path for path in tracked_files(root) if not vendored.covers(path)]
    tracked = frozenset(own)
    findings: list[Finding] = []
    python: dict[str, str] = {}
    for path in own:
        full = root / path
        if not full.is_file():
            continue
        findings.extend(check_config(path, root))
        findings.extend(check_generated(path, tracked))
        try:
            text = full.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as error:
            findings.append(Finding(path, 0, f"can't read: {error.strerror}"))
            continue
        findings.extend(check_source(path, text))
        if language_of(path, text) == "python":
            python[path] = text
    findings.extend(check_imports(python))
    return sorted(findings)


def report_unhandled(error_type: type[BaseException], error: BaseException, traceback: TracebackType | None) -> None:
    logging.getLogger(__name__).error("Style check failed", exc_info=(error_type, error, traceback))
    sys.stderr.write("Style check failed; fix the error above and run it again.\n")


def unslashed(root: Path, path: Path, entries: list[str]) -> list[Finding]:
    folders = {entry for entry in entries if not entry.endswith("/") and (root / entry.lstrip("/")).is_dir()}
    if not folders:
        return []
    name = path.relative_to(root).as_posix()
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    return [
        Finding(name, number, f"{line.strip()} is a folder; end it with /")
        for number, line in enumerate(lines, 1)
        if line.strip() in folders
    ]


def main() -> int:
    sys.excepthook = report_unhandled
    parser = argparse.ArgumentParser(
        description="Check a repo for comments, lint suppressions, long files and nested lint configs.",
    )
    parser.add_argument("root", nargs="?", default=".", help="repo root (default: the current folder)")
    args = parser.parse_args()
    root = Path(str(args.root)).resolve()
    list_path = Path(__file__).resolve().with_name(VENDORED_FILE)
    if not list_path.is_file():
        sys.stderr.write(f"{VENDORED_FILE} is missing next to {Path(__file__).name}. Run Install-Lint again.\n")
        return 2
    lint = root / LINT_DIR
    local_path = lint / LOCAL_FILE
    approved_path = lint / APPROVED_FILE
    try:
        shared = read_entries(list_path)
        local = read_entries(local_path) if local_path.is_file() else []
        approvals = read_approvals(approved_path) if approved_path.is_file() else []
    except (OSError, ValueError) as error:
        sys.stderr.write(f"can't read the lists in {LINT_DIR}: {error}\n")
        return 2
    try:
        findings = check_repo(root, vendored_paths(shared + local))
    except (subprocess.CalledProcessError, OSError) as error:
        sys.stderr.write(f"can't list the files in {root} with git: {error}\n")
        return 2
    findings = apply_approvals(root, findings, approvals)
    findings += unslashed(root, local_path, local)
    if list_path.parent == lint:
        findings = sorted(findings + unfolded(shared, local))
    for finding in findings:
        sys.stdout.write(finding.render() + "\n")
    if findings:
        sys.stdout.write(f"{len(findings)} findings\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
