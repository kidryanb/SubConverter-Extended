from __future__ import annotations

import argparse
import importlib.util
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cleanup_container_registry",
    ROOT / "scripts" / "ci" / "cleanup_container_registry.py",
)
CLEANUP = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = CLEANUP
SPEC.loader.exec_module(CLEANUP)


class ContainerRegistryCleanupCredentialTests(unittest.TestCase):
    def run_prune_all(self, docker_tags: dict[str, str]) -> int:
        args = argparse.Namespace(
            github_owner="owner",
            repository="repository",
            dockerhub_namespace="namespace",
            current_tag=[],
            current_prefix=[],
            prune_orphans=False,
            prune_all=True,
            apply=True,
        )
        client = mock.Mock()
        client.reachable.return_value = set()

        with (
            mock.patch.object(CLEANUP, "parse_args", return_value=args),
            mock.patch.object(CLEANUP, "dockerhub_tags", return_value=docker_tags),
            mock.patch.object(CLEANUP, "list_github_versions", return_value=[]),
            mock.patch.object(CLEANUP, "GhcrManifestClient", return_value=client),
            mock.patch.dict(
                CLEANUP.os.environ,
                {"GITHUB_TOKEN": "github-token"},
                clear=True,
            ),
        ):
            return CLEANUP.main()

    def test_apply_without_dockerhub_targets_does_not_require_credentials(self) -> None:
        with (
            mock.patch.object(CLEANUP, "dockerhub_token") as token,
            mock.patch.object(CLEANUP, "delete_dockerhub_tags") as delete,
        ):
            self.assertEqual(self.run_prune_all({}), 0)

        token.assert_not_called()
        delete.assert_not_called()

    def test_apply_with_only_protected_dockerhub_tags_does_not_require_credentials(
        self,
    ) -> None:
        with (
            mock.patch.object(CLEANUP, "dockerhub_token") as token,
            mock.patch.object(CLEANUP, "delete_dockerhub_tags") as delete,
        ):
            self.assertEqual(
                self.run_prune_all({"latest": "sha256:" + "0" * 64}),
                0,
            )

        token.assert_not_called()
        delete.assert_not_called()

    def test_apply_with_dockerhub_target_still_requires_credentials(self) -> None:
        with self.assertRaisesRegex(
            CLEANUP.CleanupError,
            "Docker Hub credentials are required for deletion",
        ):
            self.run_prune_all({"ci-expired": "sha256:" + "1" * 64})


if __name__ == "__main__":
    unittest.main()
