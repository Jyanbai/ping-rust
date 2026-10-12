//! The single YAML entry point of ping-rust.
//!
//! Backed by serde-saphyr (pure safe Rust). The parse options are pinned to
//! the behavior ping-rust relied on with serde_yaml 0.9 so that files written
//! by older releases read back identically. No other module may use
//! serde-saphyr directly; dynamic YAML values are `serde_json::Value`.

use std::{borrow::Cow, collections::BTreeMap};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub type Error = serde_saphyr::Error;
pub type SerializeError = serde_saphyr::ser::Error;

fn parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        // YAML 1.2 core schema like serde_yaml 0.9: only `true`/`false` are
        // booleans; `yes`/`no`/`on`/`off` stay strings.
        strict_booleans: true,
        // serde_yaml 0.9 never expands `<<` merge keys implicitly.
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        // Reject duplicate mapping keys (serde_yaml 0.9 did for structs and
        // its own Mapping; serde_json::Value targets used to keep the last).
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        // Never treat a leading `0` as octal. serde_yaml 0.9 read plain
        // `0123` as the string "0123"; `legacy_compatible_input` keeps that.
        legacy_octal_numbers: false,
        // Error messages must not echo YAML source lines (credentials).
        with_snippet: false,
        // Comments are never consumed by ping-rust.
        emit_comments: false,
    }
}

fn serializer_options() -> serde_saphyr::SerializerOptions {
    serde_saphyr::ser_options! {
        // Keep every scalar on one line like serde_yaml; no `>` folding of
        // long strings and no `|` literal blocks.
        prefer_block_scalars: false,
        // Quote YAML 1.1 ambiguous spellings (`yes`, `on`, `0x1F`, ...) so
        // any reader keeps them as strings.
        yaml_12: false,
    }
}

pub fn from_str<T: DeserializeOwned>(input: &str) -> Result<T, Error> {
    serde_saphyr::from_str_with_options(&legacy_compatible_input(input), parse_options())
}

pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, Error> {
    match std::str::from_utf8(input) {
        Ok(text) => from_str(text),
        // Not UTF-8: let serde-saphyr report the encoding error.
        Err(_) => serde_saphyr::from_slice_with_options(input, parse_options()),
    }
}

pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, SerializeError> {
    serde_saphyr::to_string_with_options(&value, serializer_options())
}

/// Converts a serializable value into a dynamic YAML value.
pub fn to_value<T: Serialize>(value: T) -> serde_json::Result<Value> {
    serde_json::to_value(value)
}

// ---- serde_yaml 0.9 plain-scalar compatibility -------------------------
//
// serde-saphyr resolves a few plain scalars as numbers that serde_yaml 0.9
// resolved as strings (and therefore wrote unquoted): `1_000`, `0X1F`,
// `0O17`, `007`, `1e999`, `.iNf`, ... Before parsing, every such plain
// scalar is rewritten as a single-quoted scalar, so files written by older
// releases read back exactly as before. The rules below are a port of
// serde_yaml 0.9.34 `visit_untagged_scalar` (MIT OR Apache-2.0).

fn legacy_parse_null(s: &str) -> bool {
    matches!(s, "~" | "null" | "Null" | "NULL")
}

fn legacy_parse_bool(s: &str) -> bool {
    matches!(s, "true" | "True" | "TRUE" | "false" | "False" | "FALSE")
}

fn legacy_digits_but_not_number(s: &str) -> bool {
    let s = s.strip_prefix(['-', '+']).unwrap_or(s);
    s.len() > 1 && s.starts_with('0') && s[1..].bytes().all(|b| b.is_ascii_digit())
}

fn legacy_unsigned_int(s: &str) -> bool {
    let unpositive = s.strip_prefix('+').unwrap_or(s);
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpositive.strip_prefix(prefix) {
            if rest.starts_with(['+', '-']) {
                return false;
            }
            if u128::from_str_radix(rest, radix).is_ok() {
                return true;
            }
        }
    }
    if unpositive.starts_with(['+', '-']) || legacy_digits_but_not_number(s) {
        return false;
    }
    s.parse::<u128>().is_ok()
}

fn legacy_negative_int(s: &str) -> bool {
    for (prefix, radix) in [("-0x", 16), ("-0o", 8), ("-0b", 2)] {
        if let Some(rest) = s.strip_prefix(prefix) {
            if i128::from_str_radix(&format!("-{rest}"), radix).is_ok() {
                return true;
            }
        }
    }
    !legacy_digits_but_not_number(s) && s.parse::<i128>().is_ok()
}

fn legacy_float(s: &str) -> bool {
    let unpositive = match s.strip_prefix('+') {
        Some(rest) if rest.starts_with(['+', '-']) => return false,
        Some(rest) => rest,
        None => s,
    };
    matches!(unpositive, ".inf" | ".Inf" | ".INF")
        || matches!(s, "-.inf" | "-.Inf" | "-.INF" | ".nan" | ".NaN" | ".NAN")
        || unpositive.parse::<f64>().is_ok_and(f64::is_finite)
}

/// serde_yaml 0.9 resolved this untagged plain scalar as a string.
fn legacy_resolves_to_string(s: &str) -> bool {
    !(s.is_empty()
        || legacy_parse_null(s)
        || legacy_parse_bool(s)
        || legacy_unsigned_int(s)
        || legacy_negative_int(s)
        || (!legacy_digits_but_not_number(s) && legacy_float(s)))
}

/// serde-saphyr (with `parse_options`) would not resolve it as a string.
fn saphyr_resolves_to_non_string(s: &str) -> bool {
    if !s.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '+' | '-' | '.')) {
        return false;
    }
    let probe = format!("v: {s}\n");
    !matches!(
        serde_saphyr::from_str_with_options::<BTreeMap<String, Value>>(&probe, parse_options())
            .ok()
            .and_then(|mut map| map.remove("v")),
        Some(Value::String(ref value)) if value == s
    )
}

fn legacy_compatible_input(input: &str) -> Cow<'_, str> {
    use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};

    let mut edits = Vec::new();
    for item in Parser::new_from_str(input) {
        let Ok((event, span)) = item else {
            // Let the real parse report the syntax error.
            return Cow::Borrowed(input);
        };
        let Event::Scalar(value, ScalarStyle::Plain, _, None) = &event else {
            continue;
        };
        if !legacy_resolves_to_string(value) || !saphyr_resolves_to_non_string(value) {
            continue;
        }
        let (Some(start), Some(end)) = (span.start.byte_offset(), span.end.byte_offset()) else {
            continue;
        };
        if input.get(start..end) == Some(value.as_ref()) {
            edits.push((start, end));
        }
    }
    if edits.is_empty() {
        return Cow::Borrowed(input);
    }
    let mut output = String::with_capacity(input.len() + edits.len() * 2);
    let mut cursor = 0;
    for (start, end) in edits {
        output.push_str(&input[cursor..start]);
        output.push('\'');
        output.push_str(&input[start..end].replace('\'', "''"));
        output.push('\'');
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    Cow::Owned(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(tag = "type", rename_all = "lowercase")]
    enum Tagged {
        Socks { username: String, password: String },
    }

    #[test]
    fn yaml_1_2_booleans_and_nulls() {
        let value: Value =
            from_str("a: no\nb: on\nc: yes\nd: off\ne: true\nf: False\ng: ~\nh: null\n").unwrap();
        assert_eq!(
            value,
            serde_json::json!({"a": "no", "b": "on", "c": "yes", "d": "off", "e": true, "f": false, "g": null, "h": null})
        );
    }

    #[test]
    fn merge_keys_are_ordinary_keys() {
        let value: Value = from_str("a: &x {k: 1}\nb:\n  <<: *x\n  j: 2\n").unwrap();
        assert_eq!(
            value,
            serde_json::json!({"a": {"k": 1}, "b": {"<<": {"k": 1}, "j": 2}})
        );
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert!(from_str::<Value>("a: 1\na: 2\n").is_err());
        assert!(
            from_str::<Tagged>("type: socks\nusername: a\nusername: b\npassword: c\n").is_err()
        );
    }

    #[test]
    fn errors_do_not_echo_source_lines() {
        let error = from_str::<Tagged>("type: socks\nusername: a\npassword: [hunter2-secret\n")
            .unwrap_err();
        assert!(!error.to_string().contains("hunter2-secret"), "{error}");
    }

    #[test]
    fn numbers_keep_serde_yaml_0_9_resolution() {
        let value: Value =
            from_str("a: 0x1F\nb: 0o17\nc: 0b11\nd: 123\ne: -5\nf: 1.5\ng: 1e3\n").unwrap();
        assert_eq!(
            value,
            serde_json::json!({"a": 31, "b": 15, "c": 3, "d": 123, "e": -5, "f": 1.5, "g": 1000.0})
        );
    }

    #[test]
    fn legacy_plain_strings_read_back_as_strings() {
        // serde_yaml 0.9 wrote these strings without quotes.
        let legacy = "a: 1_000\nb: 0X1F\nc: 007\nd: 1e999\ne: .iNf\nf: -0012\ng: [1_0, 0O7]\nh: {x: 0B1}\n1_0: key\n";
        let value: Value = from_str(legacy).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "a": "1_000", "b": "0X1F", "c": "007", "d": "1e999", "e": ".iNf",
                "f": "-0012", "g": ["1_0", "0O7"], "h": {"x": "0B1"}, "1_0": "key"
            })
        );
        let typed: Tagged = from_str("type: socks\nusername: 0X1F\npassword: 1_000\n").unwrap();
        assert_eq!(
            typed,
            Tagged::Socks {
                username: "0X1F".to_owned(),
                password: "1_000".to_owned()
            }
        );
        let typed: Tagged = from_slice(b"type: socks\nusername: '007'\npassword: 1e999\n").unwrap();
        assert_eq!(
            typed,
            Tagged::Socks {
                username: "007".to_owned(),
                password: "1e999".to_owned()
            }
        );
    }

    #[test]
    fn special_strings_round_trip_exactly() {
        for text in [
            "no",
            "on",
            "yes",
            "off",
            "y",
            "n",
            "null",
            "Null",
            "~",
            "",
            "0x1F",
            "0X1F",
            "007",
            "0123",
            "1_000",
            "1e3",
            "1e999",
            ".inf",
            ".iNf",
            "true",
            "a:b",
            "a: b",
            "#lead",
            "pass#word",
            "a #b",
            "::/0",
            "*.example.com",
            "- x",
            "it's",
            "\"q\"",
            "12:30",
            "2001-12-14",
            " sp",
            "x\ny",
        ] {
            let yaml =
                to_string(&serde_json::json!({ "v": text, "list": [text], text: 1 })).unwrap();
            let back: Value = from_str(&yaml).unwrap();
            assert_eq!(
                back,
                serde_json::json!({ "v": text, "list": [text], text: 1 }),
                "{yaml}"
            );
            let typed: Tagged = from_str(
                &to_string(
                    &serde_json::json!({ "type": "socks", "username": text, "password": text }),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                typed,
                Tagged::Socks {
                    username: text.to_owned(),
                    password: text.to_owned()
                }
            );
        }
    }

    #[test]
    fn long_and_multiline_strings_stay_inline() {
        let long = "x ".repeat(80);
        let yaml = to_string(&serde_json::json!({ "v": long, "m": "a\nb" })).unwrap();
        assert!(!yaml.contains(": >") && !yaml.contains(": |"), "{yaml}");
        let back: Value = from_str(&yaml).unwrap();
        assert_eq!(back, serde_json::json!({ "v": long, "m": "a\nb" }));
    }
}
