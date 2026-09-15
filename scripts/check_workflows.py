"""Reject malformed YAML and duplicate keys in GitHub workflow files."""
from pathlib import Path
import yaml


def check(node, path):
    if isinstance(node, yaml.MappingNode):
        seen = set()
        for key, value in node.value:
            if key.value in seen:
                raise ValueError(f"{path}:{key.start_mark.line + 1}: duplicate {key.value}")
            seen.add(key.value)
            check(value, path)
    elif isinstance(node, yaml.SequenceNode):
        for value in node.value:
            check(value, path)


paths = sorted(Path('.github/workflows').glob('*.yml'))
for path in paths:
    check(yaml.compose(path.read_text(encoding='utf-8')), path)
print(f"Validated YAML and key uniqueness in {len(paths)} workflows")
