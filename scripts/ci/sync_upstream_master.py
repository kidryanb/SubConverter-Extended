#!/usr/bin/env python3
"""Merge upstream/master without hiding source conflicts.

Only fork-owned automation files may keep their current contents when they
conflict. Every other conflict aborts the merge before anything can be pushed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence


PROTECTED_CONFLICT_PATHS = frozenset(
    {
        ".github/upstream-subconverter.seen",
        ".github/upstream-subconverter.skipped.json",
        ".github/workflows/build-personal-image.yml",
        ".github/workflows/sync-upstream-parser.yml",
        ".github/workflows/sync-upstream.yml",
        "scripts/sync_upstream_parser.py",
        "tests/test_sync_upstream_parser.py",
    }
)
MERGE_ARGUMENTS = ("merge", "--no-commit", "--no-ff")


class SyncError(RuntimeError):
    """Raised when the upstream merge cannot be completed safely."""


def run_git(
    repository: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise SyncError(f"git {' '.join(arguments)} failed: {details}")
    return result


def git_output(repository: Path, arguments: Sequence[str]) -> str:
    return run_git(repository, arguments).stdout.strip()


def merge_in_progress(repository: Path) -> bool:
    return (
        run_git(
            repository,
            ("rev-parse", "-q", "--verify", "MERGE_HEAD"),
            check=False,
        ).returncode
        == 0
    )


def abort_merge(repository: Path) -> None:
    if not merge_in_progress(repository):
        return
    result = run_git(repository, ("merge", "--abort"), check=False)
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise SyncError(f"unable to abort failed merge: {details}")


def conflicted_paths(repository: Path) -> tuple[str, ...]:
    output = run_git(
        repository,
        ("diff", "--name-only", "--diff-filter=U", "-z"),
    ).stdout
    return tuple(path for path in output.split("\0") if path)


def resolve_protected_conflicts(repository: Path, conflicts: Sequence[str]) -> None:
    unexpected = sorted(set(conflicts) - PROTECTED_CONFLICT_PATHS)
    if unexpected:
        abort_merge(repository)
        joined = ", ".join(unexpected)
        raise SyncError(f"upstream merge has non-protected conflicts: {joined}")

    for path in conflicts:
        exists_in_head = (
            run_git(repository, ("cat-file", "-e", f"HEAD:{path}"), check=False).returncode
            == 0
        )
        if exists_in_head:
            run_git(
                repository,
                ("restore", "--source=HEAD", "--staged", "--worktree", "--", path),
            )
        else:
            run_git(repository, ("rm", "-f", "--ignore-unmatch", "--", path))

    remaining = conflicted_paths(repository)
    if remaining:
        abort_merge(repository)
        raise SyncError(
            "protected conflict resolution left unresolved paths: "
            + ", ".join(remaining)
        )


def write_changed_output(path: Path | None, changed: bool) -> None:
    assignment = f"changed={'true' if changed else 'false'}\n"
    if path is None:
        print(assignment, end="")
        return
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(assignment)


def sync_upstream(
    repository: Path,
    *,
    upstream_ref: str,
    target_branch: str,
    origin: str,
    push: bool,
) -> bool:
    repository = repository.resolve()
    branch = git_output(repository, ("branch", "--show-current"))
    if branch != target_branch:
        raise SyncError(
            f"expected branch {target_branch!r}, but repository is on {branch!r}"
        )
    if git_output(repository, ("status", "--porcelain")):
        raise SyncError("working tree must be clean before syncing upstream")

    before = git_output(repository, ("rev-parse", "HEAD"))
    merge_result = run_git(
        repository,
        (*MERGE_ARGUMENTS, upstream_ref),
        check=False,
    )
    if merge_result.stdout:
        print(merge_result.stdout, end="")
    if merge_result.stderr:
        print(merge_result.stderr, end="", file=sys.stderr)

    try:
        if merge_result.returncode != 0:
            if not merge_in_progress(repository):
                details = merge_result.stderr.strip() or merge_result.stdout.strip()
                raise SyncError(f"upstream merge failed before conflict resolution: {details}")
            conflicts = conflicted_paths(repository)
            if not conflicts:
                abort_merge(repository)
                raise SyncError("upstream merge failed without conflicted paths")
            resolve_protected_conflicts(repository, conflicts)

        if merge_in_progress(repository):
            run_git(repository, ("commit", "--no-edit"))

        after = git_output(repository, ("rev-parse", "HEAD"))
        changed = before != after
        if changed and push:
            run_git(repository, ("push", origin, f"HEAD:{target_branch}"))
        return changed
    except Exception:
        if merge_in_progress(repository):
            abort_merge(repository)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--upstream-ref", default="upstream/master")
    parser.add_argument("--target-branch", default="master")
    parser.add_argument("--origin", default="origin")
    parser.add_argument("--push", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    output_path = args.github_output
    if output_path is None and os.environ.get("GITHUB_OUTPUT"):
        output_path = Path(os.environ["GITHUB_OUTPUT"])

    try:
        changed = sync_upstream(
            args.repository,
            upstream_ref=args.upstream_ref,
            target_branch=args.target_branch,
            origin=args.origin,
            push=args.push,
        )
        write_changed_output(output_path, changed)
    except (OSError, SyncError, subprocess.SubprocessError) as error:
        print(f"upstream sync error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
