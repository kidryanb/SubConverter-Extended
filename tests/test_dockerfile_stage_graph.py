import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
FROM_PATTERN = re.compile(
    r"^FROM(?:\s+--\S+)*\s+(\S+)(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE,
)


class DockerfileStageGraphTests(unittest.TestCase):
    def test_sanitizer_stage_graph_is_local_and_unambiguous(self) -> None:
        stages = []
        for line in (REPOSITORY / "Dockerfile").read_text(encoding="utf-8").splitlines():
            match = FROM_PATTERN.match(line)
            if match:
                stages.append(tuple(value.lower() if value else None for value in match.groups()))

        aliases = [alias for _, alias in stages if alias]
        self.assertEqual(len(aliases), len(set(aliases)), "Dockerfile stage aliases must be unique")
        self.assertIn(("${debian_image}", "builder-base"), stages)
        self.assertIn(("builder-base", "sanitizer-bootstrap"), stages)
        self.assertIn(("sanitizer-bootstrap", "builder"), stages)
        self.assertLess(aliases.index("builder-base"), aliases.index("sanitizer-bootstrap"))
        self.assertLess(aliases.index("sanitizer-bootstrap"), aliases.index("builder"))


if __name__ == "__main__":
    unittest.main()
