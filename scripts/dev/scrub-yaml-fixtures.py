#!/usr/bin/env python3
"""Replace random credentials in raw YAML fixtures with fixed test values.

Usage: scrub-yaml-fixtures.py RUN_A RUN_B
RUN_A and RUN_B are two independent `regenerate_yaml_fixtures` outputs. Every
JSON string leaf of the state files that differs between the two runs is a
randomly generated value; each one is replaced in RUN_A (state files and
compat/config.yaml) by a deterministic, length- and character-class
preserving test value.
"""
import json
import pathlib
import sys

INPUTS = ["compat/state.json", "chain-v2/state.json"]
TEXT = INPUTS + ["compat/config.yaml"]
HEX = set("0123456789abcdef")


def leaves(value, path=()):
    if isinstance(value, dict):
        for key in sorted(value):
            yield from leaves(value[key], path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, path + (index,))
    elif isinstance(value, str):
        yield path, value


def replacement(token, seed):
    hex_only = set(token.lower()) <= HEX | set("-")
    out = []
    for index, char in enumerate(token):
        n = (seed * 31 + index * 7) % 997
        if char.isdigit():
            out.append("0123456789"[n % 10])
        elif char.islower():
            out.append(("abcdef" if hex_only else "abcdefghijklmnopqrstuvwxyz")[n % (6 if hex_only else 26)])
        elif char.isupper():
            out.append(("ABCDEF" if hex_only else "ABCDEFGHIJKLMNOPQRSTUVWXYZ")[n % (6 if hex_only else 26)])
        else:
            out.append(char)
    if not hex_only and len(token) >= 22:
        # Keep base64 canonical: the last data character carries no spare bits.
        last = max(i for i, c in enumerate(out) if c.isalnum())
        out[last] = "A"
    return "".join(out)


def main():
    run_a, run_b = map(pathlib.Path, sys.argv[1:3])
    tokens = {}
    for relative in INPUTS:
        a = dict(leaves(json.loads((run_a / relative).read_text())))
        b = dict(leaves(json.loads((run_b / relative).read_text())))
        for path, value in a.items():
            if b.get(path) != value and value not in tokens:
                tokens[value] = replacement(value, len(tokens) + 1)
    for relative in TEXT:
        file = run_a / relative
        text = file.read_text()
        for token in sorted(tokens, key=len, reverse=True):
            text = text.replace(token, tokens[token])
        file.write_text(text)
    print(f"scrubbed {len(tokens)} random values")


if __name__ == "__main__":
    main()
