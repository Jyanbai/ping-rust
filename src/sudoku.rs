use anyhow::{bail, Result};
use clap::ValueEnum;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

macro_rules! transport_cost {
    () => { "上行约 4 倍（无 padding），10% padding 约 4.5 倍，单次写入最多约 9 倍；下行约 1.33 倍。关闭原始 TCP splice，每条连接多占约 64 KiB 缓冲。只支持 TCP，没有 UDP/QUIC 掩码；在 TCP 内转发的 UDP 仍可用。客户端需要 Xray ≥ v26.3.27 或 v2rayN 等基于它的客户端。" };
}

pub const COST: &str = concat!(
    "Sudoku 是混淆，不是加密或认证，传输安全仍由 VLESS Encryption 提供。",
    transport_cost!()
);
pub const PLAIN_WARNING: &str = "警告：VLESS-Sudoku 没有任何加密和认证。Sudoku 只是混淆，不是加密或身份验证；下行打包编码没有密钥，上行的置换种子空间有限。普通 VLESS 不加密，UUID、目标地址、非 HTTPS 内容都能在链路上被还原。需要加密时请使用 VLESS-ENC + Sudoku 或 VLESS-REALITY。";
pub const PLAIN_COST: &str = transport_cost!();

pub fn warn_plain() {
    eprintln!("{PLAIN_WARNING}\n{PLAIN_COST}");
}

pub const UNSUPPORTED: &str =
    "该客户端导出不支持 Xray FinalMask Sudoku，请用分享链接导入 v2rayN 或 Xray ≥ v26.3.27";

pub fn generate_password() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 24)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SudokuAscii {
    #[default]
    PreferEntropy,
    Entropy,
    PreferAscii,
    Ascii,
}

impl SudokuAscii {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreferEntropy => "prefer_entropy",
            Self::Entropy => "entropy",
            Self::PreferAscii => "prefer_ascii",
            Self::Ascii => "ascii",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SudokuConfig {
    pub password: String,
    #[serde(default)]
    pub ascii: SudokuAscii,
    #[serde(default)]
    pub padding_min: u8,
    #[serde(default)]
    pub padding_max: u8,
}

impl SudokuConfig {
    pub fn generated() -> Self {
        Self {
            password: generate_password(),
            ascii: SudokuAscii::default(),
            padding_min: 0,
            padding_max: 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.padding_min > 100 || self.padding_max > 100 {
            bail!("Sudoku padding 必须在 0–100 范围内");
        }
        if self.padding_max < self.padding_min {
            bail!("Sudoku padding-max 不能小于 padding-min");
        }
        Ok(())
    }

    pub fn finalmask(&self) -> serde_json::Value {
        serde_json::json!({"tcp": [{"type": "sudoku", "settings": {
            "password": self.password, "ascii": self.ascii.as_str(),
            "paddingMin": self.padding_min, "paddingMax": self.padding_max
        }}]})
    }

    pub fn description(&self) -> String {
        format!(
            "外观：Sudoku（{}、padding {}–{}%）",
            self.ascii.as_str(),
            self.padding_min,
            self.padding_max
        )
    }
}

#[derive(Clone, Debug, Default, clap::Args)]
pub struct SudokuOptions {
    /// 开启可选的 Sudoku TCP 外观（默认关闭）
    #[arg(id = "sudoku_enabled", long = "sudoku", long_help = COST)]
    pub enabled: bool,
    /// Sudoku 共享密码，按原样使用；省略时安全随机生成 24 位字母数字
    #[arg(id = "sudoku_password", long = "sudoku-password")]
    pub password: Option<String>,
    /// Sudoku ASCII 模式（使用默认熵布局）
    #[arg(id = "sudoku_ascii", long = "sudoku-ascii", value_enum)]
    pub ascii: Option<SudokuAscii>,
    /// Sudoku 最小 padding 百分比
    #[arg(id = "sudoku_padding_min", long = "sudoku-padding-min", value_parser = clap::value_parser!(u8).range(0..=100))]
    pub padding_min: Option<u8>,
    /// Sudoku 最大 padding 百分比，不能小于 min
    #[arg(id = "sudoku_padding_max", long = "sudoku-padding-max", value_parser = clap::value_parser!(u8).range(0..=100))]
    pub padding_max: Option<u8>,
}

impl SudokuOptions {
    pub fn validate_for(&self, protocol: crate::config::Protocol) -> Result<()> {
        use crate::config::Protocol;
        let parameters = self.password.is_some()
            || self.ascii.is_some()
            || self.padding_min.is_some()
            || self.padding_max.is_some();
        if protocol != Protocol::VlessSudoku {
            if self.enabled && protocol != Protocol::VlessEnc {
                bail!("Sudoku 参数仅适用于 VLESS-ENC 或 VLESS-Sudoku");
            }
            if parameters && !self.enabled {
                bail!("VLESS-ENC 的 Sudoku 参数需要 --sudoku，其他协议不支持 Sudoku 参数");
            }
        }
        self.config_for(protocol)?;
        Ok(())
    }

    pub fn config_for(&self, protocol: crate::config::Protocol) -> Result<Option<SudokuConfig>> {
        let mut options = self.clone();
        options.enabled |= protocol == crate::config::Protocol::VlessSudoku;
        options.config()
    }
    pub fn config(&self) -> Result<Option<SudokuConfig>> {
        if !self.enabled {
            return Ok(None);
        }
        let config = SudokuConfig {
            password: self.password.clone().unwrap_or_else(generate_password),
            ascii: self.ascii.unwrap_or_default(),
            padding_min: self.padding_min.unwrap_or_default(),
            padding_max: self.padding_max.unwrap_or_default(),
        };
        config.validate()?;
        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn options(args: &[&str]) -> Result<SudokuOptions> {
        let cli = Cli::try_parse_from(
            ["prs", "add", "vless-enc"]
                .into_iter()
                .chain(args.iter().copied()),
        )?;
        let Some(Command::Add(args)) = cli.command else {
            panic!()
        };
        Ok(args.vless_enc.sudoku)
    }

    #[test]
    fn sudoku_cli_help_explains_all_costs_and_restricts_protocol() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        let help = cli
            .find_subcommand_mut("add")
            .unwrap()
            .render_long_help()
            .to_string();
        for required in [
            "混淆",
            "不是加密或认证",
            "VLESS Encryption",
            "4 倍",
            "4.5 倍",
            "9 倍",
            "1.33 倍",
            "TCP splice",
            "64 KiB",
            "UDP/QUIC",
            "TCP 内转发的 UDP 仍可用",
            "v26.3.27",
        ] {
            assert!(help.contains(required), "{required}");
        }
        let sudoku = options(&["--sudoku"]).unwrap();
        assert!(sudoku
            .validate_for(crate::config::Protocol::VlessEnc)
            .is_ok());
        assert!(sudoku
            .validate_for(crate::config::Protocol::Socks5)
            .is_err());
    }

    #[test]
    fn sudoku_cli_defaults_validation_and_password_preservation() {
        assert!(options(&[]).unwrap().config().unwrap().is_none());
        let config = options(&["--sudoku"]).unwrap().config().unwrap().unwrap();
        assert_eq!(config.ascii, SudokuAscii::PreferEntropy);
        assert_eq!((config.padding_min, config.padding_max), (0, 0));
        assert_eq!(config.password.len(), 24);
        assert!(config.password.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(config.password, SudokuConfig::generated().password);
        for (arg, expected) in [
            ("prefer-entropy", "prefer_entropy"),
            ("entropy", "entropy"),
            ("prefer-ascii", "prefer_ascii"),
            ("ascii", "ascii"),
        ] {
            let config = options(&[
                "--sudoku",
                "--sudoku-password",
                "  pass+%字  ",
                "--sudoku-ascii",
                arg,
                "--sudoku-padding-min",
                "10",
                "--sudoku-padding-max",
                "100",
            ])
            .unwrap()
            .config()
            .unwrap()
            .unwrap();
            assert_eq!(config.password, "  pass+%字  ");
            assert_eq!(config.ascii.as_str(), expected);
            assert_eq!((config.padding_min, config.padding_max), (10, 100));
        }
        for args in [
            vec!["--sudoku", "--sudoku-padding-min", "101"],
            vec!["--sudoku", "--sudoku-padding-max", "101"],
            vec!["--sudoku", "--sudoku-padding-min", "-1"],
            vec!["--sudoku", "--sudoku-ascii", "bad"],
        ] {
            assert!(options(&args).is_err(), "{args:?}");
        }
        // VLESS-Sudoku can omit --sudoku, so the shared semantic validator
        // now enforces this requirement for VLESS-ENC after clap parsing.
        for args in [
            vec!["--sudoku-password", "pass"],
            vec!["--sudoku-ascii", "ascii"],
            vec!["--sudoku-padding-min", "0"],
        ] {
            assert!(
                options(&args)
                    .unwrap()
                    .validate_for(crate::config::Protocol::VlessEnc)
                    .is_err(),
                "{args:?}"
            );
        }
        assert!(options(&[
            "--sudoku",
            "--sudoku-padding-min",
            "10",
            "--sudoku-padding-max",
            "9"
        ])
        .unwrap()
        .config()
        .is_err());
        let mask = SudokuConfig {
            padding_min: 101,
            ..SudokuConfig::generated()
        };
        assert!(mask.validate().is_err());
        let mask = SudokuConfig {
            padding_max: 101,
            ..SudokuConfig::generated()
        };
        assert!(mask.validate().is_err());
    }
}
