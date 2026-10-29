"""Bounded failure output for generated test configurations (stdlib only)."""

import json
import re


SENSITIVE = re.compile(r"key|password|secret|token|decryption|user|id", re.I)


def redact_config(config):
    secrets = []

    def remember(value):
        if isinstance(value, str):
            secrets.extend([value, *value.splitlines()])
        elif isinstance(value, dict):
            for child in value.values():
                remember(child)
        elif isinstance(value, list):
            for child in value:
                remember(child)

    def redact(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if SENSITIVE.search(key):
                    remember(child)
                    value[key] = "[REDACTED]"
                else:
                    redact(child)
        elif isinstance(value, list):
            for child in value:
                redact(child)

    try:
        value = json.loads(config)
    except ValueError:
        # Generated YAML uses block mappings. Consume a sensitive field's whole
        # indented value, including PEM blocks, rather than just its first line.
        lines = config.splitlines()
        safe = []
        index = 0
        while index < len(lines):
            line = lines[index]
            match = re.match(r'''^(\s*(?:- )?["']?([\w-]+)["']?\s*:)\s*(.*)$''', line)
            if match and SENSITIVE.search(match.group(2)):
                scalar = match.group(3)
                try:
                    scalar = json.loads(scalar)
                except ValueError:
                    scalar = scalar.strip("'").replace("''", "'")
                remember(scalar)
                safe.append(match.group(1) + " [REDACTED]")
                indent = len(line) - len(line.lstrip())
                index += 1
                while index < len(lines) and (
                    not lines[index].strip()
                    or len(lines[index]) - len(lines[index].lstrip()) > indent
                ):
                    remember(lines[index].strip())
                    index += 1
            else:
                safe.append(line)
                index += 1
        return "\n".join(safe), secrets
    else:
        redact(value)
        return json.dumps(value, ensure_ascii=False, indent=2), secrets


def failure_details(stderr, config, known_secrets=()):
    config, secrets = redact_config(config)
    for secret in sorted(set([*secrets, *known_secrets]), key=len, reverse=True):
        if secret:
            stderr = stderr.replace(secret, "[REDACTED]")

    def sanitize(text):
        text = re.sub(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+", "[URL REDACTED]", text)
        text = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[ID REDACTED]", text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP REDACTED]", text)
        return text[:8192] + ("\n[truncated]" if len(text) > 8192 else "")

    return f"stderr:\n{sanitize(stderr)}\nvalidated config (redacted):\n{sanitize(config)}"
