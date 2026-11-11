//! `tests/support/shoes_e2e.rs` 的单元测试。放在主程序里，只跑一次，不随每个集成测试重复。
//! 环境变量通过 `Lookup` 传入固定值，不修改进程环境，可以和其他测试并行。

use crate::shoes_e2e::{
    shoes_binary_or_with, shoes_binary_with, skip_message, REQUIRE_E2E, SHOES_E2E_BIN, TEST_SHOES,
};
use std::{ffi::OsString, path::Path};

const INSTALLED: &str = "/usr/local/bin/shoes";

fn fixed<'a>(values: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
    move |name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| OsString::from(*value))
    }
}

#[test]
fn missing_variable_skips_when_not_required() {
    let unset: [(&str, &str); 0] = [];
    let not_one = [(REQUIRE_E2E, "0")];
    for values in [&unset[..], &not_one[..]] {
        let lookup = fixed(values);
        let skipped = shoes_binary_with("demo", &[SHOES_E2E_BIN], &lookup);
        assert!(skipped.is_none());
        let fallback = shoes_binary_or_with("demo", &[TEST_SHOES], INSTALLED, &lookup);
        assert_eq!(fallback, Path::new(INSTALLED));
    }
    assert_eq!(
        skip_message("demo", &[SHOES_E2E_BIN]),
        "SKIPPED(e2e): demo：未设置 PING_RUST_SHOES_E2E_BIN，需要 shoes 的部分未运行"
    );
    let both = skip_message("demo", &[TEST_SHOES, SHOES_E2E_BIN]);
    assert!(both.contains("未设置 PING_RUST_TEST_SHOES 或 PING_RUST_SHOES_E2E_BIN，"));
}

#[test]
#[should_panic(expected = "PING_RUST_REQUIRE_E2E=1，但没有设置 PING_RUST_SHOES_E2E_BIN")]
fn missing_variable_panics_when_required() {
    let values = [(REQUIRE_E2E, "1")];
    let lookup = fixed(&values);
    shoes_binary_with("demo", &[SHOES_E2E_BIN], &lookup);
}

#[test]
#[should_panic(expected = "PING_RUST_REQUIRE_E2E=1，但没有设置 PING_RUST_TEST_SHOES")]
fn installed_fallback_is_refused_when_required() {
    let values = [(REQUIRE_E2E, "1")];
    let lookup = fixed(&values);
    shoes_binary_or_with("demo", &[TEST_SHOES], INSTALLED, &lookup);
}

#[test]
#[should_panic(expected = "不是存在的文件")]
fn configured_path_must_exist() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("shoes");
    let values = [(SHOES_E2E_BIN, missing.to_str().unwrap())];
    let lookup = fixed(&values);
    shoes_binary_with("demo", &[SHOES_E2E_BIN], &lookup);
}

#[test]
#[should_panic(expected = "不是存在的文件")]
fn configured_directory_is_not_a_binary() {
    let directory = tempfile::tempdir().unwrap();
    let values = [(TEST_SHOES, directory.path().to_str().unwrap())];
    let lookup = fixed(&values);
    shoes_binary_or_with("demo", &[TEST_SHOES], INSTALLED, &lookup);
}

#[test]
fn first_configured_variable_wins() {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("shoes");
    std::fs::write(&binary, b"").unwrap();
    let missing = directory.path().join("missing");
    let both = [TEST_SHOES, SHOES_E2E_BIN];

    let first = [
        (TEST_SHOES, binary.to_str().unwrap()),
        (SHOES_E2E_BIN, missing.to_str().unwrap()),
    ];
    let lookup = fixed(&first);
    let found = shoes_binary_with("demo", &both, &lookup);
    assert_eq!(found.as_deref(), Some(binary.as_path()));

    let second = [(SHOES_E2E_BIN, binary.to_str().unwrap())];
    let lookup = fixed(&second);
    let found = shoes_binary_with("demo", &both, &lookup);
    assert_eq!(found.as_deref(), Some(binary.as_path()));
    let found = shoes_binary_or_with("demo", &both, "/unused", &lookup);
    assert_eq!(found, binary);
}
