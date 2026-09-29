from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "sync_upstream_master.py"
WORKFLOW = ROOT / ".github" / "workflows" / "sync-upstream.yml"
EXPECTED_PROTECTED_PATHS = frozenset(
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


def load_sync_module():
    spec = importlib.util.spec_from_file_location("sync_upstream_master", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load upstream sync helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class UpstreamSyncWorkflowContractTests(unittest.TestCase):
    def test_workflow_uses_guarded_merge_helper(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        helper = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("python3 scripts/ci/sync_upstream_master.py", workflow)
        self.assertIn('(\"merge\", \"--no-commit\", \"--no-ff\")', helper)
        self.assertNotIn("-X ours", workflow)
        self.assertNotIn("-X ours", helper)

        helper_start = workflow.index("python3 scripts/ci/sync_upstream_master.py")
        validation_start = workflow.index("- name: Validate synced master")
        push_start = workflow.index("- name: Push validated master")
        dispatch_start = workflow.index("- name: Trigger image build")
        helper_call = workflow[helper_start:validation_start]
        self.assertNotIn("--push", helper_call)
        self.assertIn("--upstream-ref upstream/master", helper_call)
        self.assertIn("--target-branch master", helper_call)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', helper_call)
        self.assertIn(
            "python3 -m unittest discover -s tests -p 'test_*.py' -v",
            workflow,
        )
        self.assertIn("bash tests/ci_delivery_scripts_test.sh", workflow)
        self.assertIn("git diff --check HEAD^1..HEAD", workflow)
        self.assertIn("git push origin HEAD:master", workflow)
        self.assertLess(helper_start, validation_start)
        self.assertLess(validation_start, push_start)
        self.assertLess(push_start, dispatch_start)

    def test_only_fork_automation_paths_are_protected(self) -> None:
        module = load_sync_module()
        self.assertEqual(EXPECTED_PROTECTED_PATHS, module.PROTECTED_CONFLICT_PATHS)
        self.assertNotIn("Dockerfile", module.PROTECTED_CONFLICT_PATHS)
        self.assertNotIn("CMakeLists.txt", module.PROTECTED_CONFLICT_PATHS)
        self.assertNotIn(
            "src/config/proxy_provider_interval.h",
            module.PROTECTED_CONFLICT_PATHS,
        )


class UpstreamSyncRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.origin = self.root / "origin.git"
        self.repository = self.root / "work"
        self.output = self.root / "github-output.txt"

        self.git(self.root, "init", "--bare", str(self.origin))
        self.git(self.root, "init", "-b", "master", str(self.repository))
        self.git(self.repository, "config", "user.name", "Sync Contract Test")
        self.git(self.repository, "config", "user.email", "sync-test@example.invalid")
        self.write("shared.txt", "base\n")
        self.write(".github/upstream-subconverter.applied.json", "base applied\n")
        self.write(".github/workflows/sync-upstream.yml", "base workflow\n")
        self.write("src/config/proxy_provider_interval.h", "base interval\n")
        self.git(self.repository, "add", ".")
        self.git(self.repository, "commit", "-m", "base")
        self.git(self.repository, "remote", "add", "origin", str(self.origin))
        self.git(self.repository, "push", "-u", "origin", "master")

    def git(
        self,
        repository: Path,
        *arguments: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def write(self, relative_path: str, content: str) -> None:
        path = self.repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def commit_changes(self, message: str, changes: dict[str, str]) -> str:
        for path, content in changes.items():
            self.write(path, content)
        self.git(self.repository, "add", ".")
        self.git(self.repository, "commit", "-m", message)
        return self.git(self.repository, "rev-parse", "HEAD").stdout.strip()

    def create_divergence(
        self,
        *,
        upstream_changes: dict[str, str],
        fork_changes: dict[str, str],
    ) -> tuple[str, str]:
        self.git(self.repository, "checkout", "-b", "upstream/master")
        upstream = self.commit_changes("upstream", upstream_changes)
        self.git(self.repository, "checkout", "master")
        fork = self.commit_changes("fork", fork_changes)
        self.git(self.repository, "push", "origin", "master")
        return upstream, fork

    def run_sync(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repository",
                str(self.repository),
                "--upstream-ref",
                "upstream/master",
                "--target-branch",
                "master",
                "--origin",
                "origin",
                "--push",
                "--github-output",
                str(self.output),
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_unprotected_conflict_aborts(self, path: str) -> None:
        _, fork = self.create_divergence(
            upstream_changes={path: "upstream\n"},
            fork_changes={path: "fork\n"},
        )

        result = self.run_sync()

        self.assertNotEqual(0, result.returncode)
        self.assertIn(f"non-protected conflicts: {path}", result.stderr)
        self.assertEqual(fork, self.origin_master())
        self.assertEqual(
            fork,
            self.git(self.repository, "rev-parse", "HEAD").stdout.strip(),
        )
        self.assertFalse(self.merge_head_exists())
        self.assertEqual(
            "",
            self.git(self.repository, "status", "--porcelain").stdout,
        )
        self.assertFalse(self.output.exists())

    def merge_head_exists(self) -> bool:
        return (
            self.git(
                self.repository,
                "rev-parse",
                "-q",
                "--verify",
                "MERGE_HEAD",
                check=False,
            ).returncode
            == 0
        )

    def origin_master(self) -> str:
        return self.git(
            self.repository,
            "--git-dir",
            str(self.origin),
            "rev-parse",
            "refs/heads/master",
        ).stdout.strip()

    def test_up_to_date_repository_is_a_safe_noop(self) -> None:
        before = self.git(self.repository, "rev-parse", "HEAD").stdout.strip()
        self.git(self.repository, "branch", "upstream/master", before)

        result = self.run_sync()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("changed=false\n", self.output.read_text(encoding="utf-8"))
        self.assertEqual(before, self.origin_master())
        self.assertFalse(self.merge_head_exists())

    def test_unknown_conflict_aborts_without_push(self) -> None:
        interval = "src/config/proxy_provider_interval.h"
        self.assert_unprotected_conflict_aborts(interval)

    def test_unlisted_applied_cursor_conflict_aborts_without_push(self) -> None:
        self.assert_unprotected_conflict_aborts(
            ".github/upstream-subconverter.applied.json"
        )

    def test_mixed_protected_and_unknown_conflicts_abort_atomically(self) -> None:
        protected = ".github/workflows/sync-upstream.yml"
        _, fork = self.create_divergence(
            upstream_changes={protected: "upstream workflow\n", "shared.txt": "upstream\n"},
            fork_changes={protected: "fork workflow\n", "shared.txt": "fork\n"},
        )

        result = self.run_sync()

        self.assertNotEqual(0, result.returncode)
        self.assertIn("non-protected conflicts: shared.txt", result.stderr)
        self.assertEqual(fork, self.origin_master())
        self.assertEqual("fork workflow\n", (self.repository / protected).read_text())
        self.assertEqual("fork\n", (self.repository / "shared.txt").read_text())
        self.assertFalse(self.merge_head_exists())
        self.assertEqual("", self.git(self.repository, "status", "--porcelain").stdout)

    def test_protected_conflict_keeps_fork_and_pushes_merge(self) -> None:
        protected = ".github/workflows/sync-upstream.yml"
        self.create_divergence(
            upstream_changes={
                protected: "upstream workflow\n",
                "upstream-only.txt": "new upstream content\n",
            },
            fork_changes={protected: "fork workflow\n"},
        )

        result = self.run_sync()

        self.assertEqual(0, result.returncode, result.stderr)
        head = self.git(self.repository, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(head, self.origin_master())
        self.assertEqual("fork workflow\n", (self.repository / protected).read_text())
        self.assertEqual(
            "new upstream content\n",
            (self.repository / "upstream-only.txt").read_text(),
        )
        self.assertEqual("changed=true\n", self.output.read_text(encoding="utf-8"))
        parents = self.git(
            self.repository,
            "rev-list",
            "--parents",
            "-n",
            "1",
            "HEAD",
        ).stdout.split()
        self.assertEqual(3, len(parents))

    def test_fast_forward_candidate_becomes_a_merge_commit(self) -> None:
        before = self.git(self.repository, "rev-parse", "HEAD").stdout.strip()
        self.git(self.repository, "checkout", "-b", "upstream/master")
        upstream = self.commit_changes(
            "upstream ahead",
            {"upstream-only.txt": "new upstream content\n"},
        )
        self.git(self.repository, "checkout", "master")

        result = self.run_sync()

        self.assertEqual(0, result.returncode, result.stderr)
        head = self.git(self.repository, "rev-parse", "HEAD").stdout.strip()
        self.assertNotEqual(before, head)
        self.assertNotEqual(upstream, head)
        self.assertEqual(head, self.origin_master())
        parents = self.git(
            self.repository,
            "rev-list",
            "--parents",
            "-n",
            "1",
            "HEAD",
        ).stdout.split()
        self.assertEqual([head, before, upstream], parents)
        self.assertEqual("changed=true\n", self.output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
