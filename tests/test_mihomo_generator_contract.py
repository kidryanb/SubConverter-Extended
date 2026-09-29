import json
import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
BUILD_ENTRYPOINTS = (
    "Dockerfile",
    "bridge/build.sh",
    "docker/Dockerfile.debian",
    "docker/Dockerfile.armv7-cross",
    "scripts/build-local-msys2.ps1",
    "scripts/build-windows-amd64.sh",
    ".github/workflows/codeql.yml",
)
GENERATORS = (
    "generate_proxy_validation.go",
    "generate_schemes.go",
    "generate_param_compat.go",
)


class MihomoGeneratorContractTests(unittest.TestCase):
    def test_all_build_entrypoints_share_the_generated_manifest(self) -> None:
        for relative_path in BUILD_ENTRYPOINTS:
            content = (REPOSITORY / relative_path).read_text(encoding="utf-8")
            commands = content.replace("\\\n", " ").replace("`\n", " ").splitlines()
            with self.subTest(path=relative_path):
                for generator in GENERATORS:
                    invocations = [
                        line
                        for line in commands
                        if f"go run ../scripts/{generator}" in line
                    ]
                    self.assertEqual(1, len(invocations), f"unexpected {generator} invocation count")
                    self.assertIn("-manifest mihomo_capabilities.json", invocations[0])
                    self.assertIn("-o ", invocations[0])

    def test_proxy_generator_creates_the_manifest_consumed_downstream(self) -> None:
        source = (REPOSITORY / "scripts/generate_proxy_validation.go").read_text(
            encoding="utf-8"
        )
        self.assertIn('flag.String("manifest"', source)
        self.assertIn("writeCapabilityManifest(*manifestPath, manifest)", source)

        dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "COPY --from=go-builder /build/bridge/mihomo_capabilities.json "
            "/src/bridge/mihomo_capabilities.json",
            dockerfile,
        )

    def test_committed_outputs_match_the_pinned_mihomo_module(self) -> None:
        go_mod = (REPOSITORY / "bridge/go.mod").read_text(encoding="utf-8")
        match = re.search(r"github\.com/metacubex/mihomo\s+(\S+)", go_mod)
        self.assertIsNotNone(match)
        version = match.group(1)

        manifest = json.loads(
            (REPOSITORY / "bridge/mihomo_capabilities.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(version, manifest["module_version"])
        for relative_path in (
            "bridge/proxy_validation_generated.go",
            "src/parser/mihomo_schemes.h",
            "src/parser/param_compat.h",
        ):
            content = (REPOSITORY / relative_path).read_text(encoding="utf-8")
            self.assertIn(f"Based on Mihomo version: {version}", content)

if __name__ == "__main__":
    unittest.main()
