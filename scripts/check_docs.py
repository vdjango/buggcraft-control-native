"""Check local references and numbered documentation without network access."""
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def main():
    files = [ROOT/"README.md", ROOT/"AGENTS.md", *sorted((ROOT/"docs").rglob("*.md")),
             ROOT/".agents/skills/multiplayer-control-native/SKILL.md"]
    failures = []
    for path in files:
        if path.parent == ROOT/"docs" and not re.match(r"\d{2}-.+\.md$", path.name):
            failures.append(f"Unnumbered: {path.name}")
        content = path.read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)]+)\)", content):
            target = unquote(target.split("#", 1)[0])
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            if not (path.parent/target).exists():
                failures.append(f"{path.relative_to(ROOT)}: broken link {target}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"OK {len(files)} Markdown files; local links and numbering")


if __name__ == "__main__":
    main()
