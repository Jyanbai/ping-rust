# YAML golden and compatibility fixtures

Baseline written by ping-rust main @ `7f80a37` (serde_yaml 0.9.34) with fixed
test credentials. They are asserted by `src/config/yaml_fixture_tests.rs`.

- `compat/state.json`, `compat/config.yaml`, `compat/profiles/*.yaml`: managed
  state, aggregate shoes config and per-node files as the old release writes
  them (every protocol preset plus ShadowTLS v3, AnyTLS-Reality and SOCKS5
  without auth).
- `chain-v2/state.json`, `chain-v2/config.yaml`: a typical Chain 2.0 topology
  (two chains, a pool, CIDR / hostname / block / round-robin rules).
- `golden/clients.json`, `golden/clients/*.clash-meta.yaml`: Clash Meta
  (Mihomo), sing-box and NekoBox exports.
- Every `*.json` next to a YAML file is its parser-independent
  `serde_json::Value`; tests compare values, not text.

All credentials are fake. Regenerate (only on purpose):

```sh
PING_RUST_YAML_FIXTURE_OUT=/tmp/a cargo test regenerate_yaml_fixtures -- --ignored
PING_RUST_YAML_FIXTURE_OUT=/tmp/b cargo test regenerate_yaml_fixtures -- --ignored
python3 scripts/dev/scrub-yaml-fixtures.py /tmp/a /tmp/b
# copy compat/state.json, compat/config.yaml, chain-v2/state.json from /tmp/a, then
PING_RUST_YAML_FIXTURE_OUT=$PWD/tests/fixtures/yaml cargo test derive_yaml_fixtures -- --ignored
```
