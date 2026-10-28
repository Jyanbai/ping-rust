#!/usr/bin/env python3
"""Compare new-build vs v0.2.1 outputs. info must be byte-identical; exports
must be semantically identical (YAML/JSON parse). Never prints file contents."""
import json, pathlib, re, sys
import yaml

new_dir, old_dir = map(pathlib.Path, sys.argv[1:3])
failures, text_diffs = [], []
for new in sorted(new_dir.iterdir()):
    old = old_dir / new.name
    a, b = new.read_text(), old.read_text()
    if a == b:
        continue
    if new.name == "info":
        new_lines, old_lines = a.splitlines(), b.splitlines()
        new_versions = [line for line in new_lines if line.startswith("shoes：")]
        old_versions = [line for line in old_lines if line.startswith("shoes：")]
        expected_old = "shoes：shoes（CLI 未提供版本参数）"
        if (
            len(new_versions) != 1
            or len(old_versions) != 1
            or old_versions[0] != expected_old
            or not re.fullmatch(r"shoes：shoes \S+", new_versions[0])
        ):
            failures.append(f"{new.name}: unexpected version probe difference")
        elif [line for line in new_lines if not line.startswith("shoes：")] != [
            line for line in old_lines if not line.startswith("shoes：")
        ]:
            failures.append(f"{new.name}: text differs outside version probe")
        else:
            print("expected version probe difference: old CLI fallback vs shoes --version")
        continue
    body_a, _, rc_a = a.rpartition("exit=")
    body_b, _, rc_b = b.rpartition("exit=")
    if rc_a != rc_b:
        failures.append(f"{new.name}: exit code differs")
        continue
    try:
        same = yaml.safe_load(body_a) == yaml.safe_load(body_b)
    except yaml.YAMLError:
        same = False
    if not same:
        failures.append(f"{new.name}: semantic difference")
    else:
        changed = sum(1 for x, y in zip(body_a.splitlines(), body_b.splitlines()) if x != y)
        text_diffs.append(f"{new.name}: {changed} line(s) differ in formatting only")
for line in text_diffs:
    print("format-only:", line)
if failures:
    print("\n".join(failures))
    sys.exit(1)
print(f"compared {len(list(new_dir.iterdir()))} outputs: semantically identical")
