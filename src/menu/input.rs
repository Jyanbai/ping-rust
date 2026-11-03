//! 菜单共享的纯文本输入。取消与 EOF 分开，调用方只吞掉当前操作的取消。
use std::{
    fmt::Display,
    io::{self, BufRead, Write},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use console::Term;

#[derive(Debug)]
pub(crate) struct MenuEof;
impl Display for MenuEof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("输入已结束")
    }
}
impl std::error::Error for MenuEof {}

#[derive(Debug)]
struct MenuBack;
impl Display for MenuBack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("已返回")
    }
}
impl std::error::Error for MenuBack {}

pub(crate) fn is_back(error: &anyhow::Error) -> bool {
    error.is::<MenuBack>()
}

fn line(reader: &mut impl BufRead) -> Result<String> {
    let mut value = String::new();
    if reader.read_line(&mut value).context("读取输入失败")? == 0 {
        return Err(MenuEof.into());
    }
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn text_prompt(writer: &mut impl Write, prompt: &str, default: Option<&str>) -> Result<()> {
    match default {
        Some(value) => write!(writer, "{prompt}（默认：{value}，输入 0 返回）：")?,
        None => write!(writer, "{prompt}（输入 0 返回）：")?,
    }
    writer.flush().context("输出输入提示失败")
}

fn parse_text<T>(
    value: &str,
    default: Option<&str>,
    allow_empty: bool,
    parse: &impl Fn(&str) -> Result<T>,
) -> Result<T> {
    if value.trim() == "0" {
        return Err(MenuBack.into());
    }
    let value = if value.is_empty() {
        default.unwrap_or(value)
    } else {
        value
    };
    if !allow_empty && value.trim().is_empty() {
        bail!("请输入内容");
    }
    if value.trim() == "0" {
        bail!("0 用于返回，请输入其他内容");
    }
    parse(value)
}

pub(crate) fn read_text<T>(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    prompt: &str,
    default: Option<&str>,
    allow_empty: bool,
    parse: impl Fn(&str) -> Result<T>,
) -> Result<T> {
    loop {
        text_prompt(writer, prompt, default)?;
        let value = line(reader)?;
        match parse_text(&value, default, allow_empty, &parse) {
            Ok(value) => return Ok(value),
            Err(error) if is_back(&error) => return Err(error),
            Err(error) => writeln!(writer, "错误！{error:#}")?,
        }
    }
}

pub(crate) fn read_confirm(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    prompt: &str,
    default: bool,
) -> Result<bool> {
    loop {
        write!(
            writer,
            "{prompt} [{}]（输入 0 返回）：",
            if default { "Y/n" } else { "y/N" }
        )?;
        writer.flush()?;
        match line(reader)?.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            "" => return Ok(default),
            "0" => return Err(MenuBack.into()),
            _ => writeln!(writer, "错误！请输入 y、yes、n、no 或 0")?,
        }
    }
}

/// 仅用于 0 本身有意义的数字参数，回车保留当前值。
pub(crate) fn read_number<T>(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    prompt: &str,
    current: T,
) -> Result<T>
where
    T: FromStr + Display + Copy,
    T::Err: Display,
{
    loop {
        write!(
            writer,
            "{prompt}（当前：{current}，直接回车保持当前值，0 为合法值）："
        )?;
        writer.flush()?;
        let value = line(reader)?;
        if value.trim().is_empty() {
            return Ok(current);
        }
        match value.trim().parse() {
            Ok(value) => return Ok(value),
            Err(error) => writeln!(writer, "错误！请输入有效数字：{error}")?,
        }
    }
}

pub(crate) fn read_menu_choice(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    max: usize,
) -> Result<String> {
    write!(writer, "请选择 [0-{max}]: ")?;
    writer.flush().context("输出菜单提示失败")?;
    line(reader)
}

pub(crate) fn text(
    prompt: impl AsRef<str>,
    default: Option<&str>,
    allow_empty: bool,
) -> Result<String> {
    validated_text(prompt, default, allow_empty, |v| Ok(v.to_owned()))
}

pub(crate) fn validated_text<T>(
    prompt: impl AsRef<str>,
    default: Option<&str>,
    allow_empty: bool,
    parse: impl Fn(&str) -> Result<T>,
) -> Result<T> {
    read_text(
        &mut io::stdin().lock(),
        &mut io::stdout(),
        prompt.as_ref(),
        default,
        allow_empty,
        parse,
    )
}

pub(crate) fn checked_text(
    prompt: impl AsRef<str>,
    default: Option<&str>,
    allow_empty: bool,
    validate: impl Fn(&str) -> Result<()>,
) -> Result<String> {
    validated_text(prompt, default, allow_empty, |value| {
        if !value.is_empty() {
            validate(value)?;
        }
        Ok(value.to_owned())
    })
}

pub(crate) fn file_path(prompt: &str) -> Result<String> {
    checked_text(prompt, None, false, |value| {
        std::fs::File::open(value)
            .and_then(|file| {
                if file.metadata()?.is_file() {
                    Ok(())
                } else {
                    Err(io::Error::other("路径不是文件"))
                }
            })
            .context("无法读取文件，请检查路径及权限")
    })
}

pub(crate) fn confirm(prompt: impl AsRef<str>, default: bool) -> Result<bool> {
    read_confirm(
        &mut io::stdin().lock(),
        &mut io::stdout(),
        prompt.as_ref(),
        default,
    )
}

pub(crate) fn number<T>(prompt: impl AsRef<str>, current: T) -> Result<T>
where
    T: FromStr + Display + Copy,
    T::Err: Display,
{
    read_number(
        &mut io::stdin().lock(),
        &mut io::stdout(),
        prompt.as_ref(),
        current,
    )
}

pub(crate) fn port(prompt: impl AsRef<str>, default: Option<u16>) -> Result<u16> {
    let default = default.map(|v| v.to_string());
    validated_text(prompt, default.as_deref(), false, |v| {
        v.trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .context("请输入 1 到 65535 的端口")
    })
}

/// 注入的 reader 在终端环境由 SecureReader 提供不回显的整行输入。
pub(crate) fn read_password(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    prompt: &str,
    allow_empty: bool,
) -> Result<String> {
    read_text(reader, writer, prompt, None, allow_empty, |value| {
        Ok(value.to_owned())
    })
}

struct SecureReader {
    term: Term,
    line: io::Cursor<Vec<u8>>,
}

impl io::Read for SecureReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for SecureReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.line.position() as usize == self.line.get_ref().len() {
            if !self.term.is_term() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let mut value = self.term.read_secure_line()?;
            value.push('\n');
            self.line = io::Cursor::new(value.into_bytes());
        }
        self.line.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.line.consume(amount);
    }
}

pub(crate) fn password(prompt: impl AsRef<str>, allow_empty: bool) -> Result<String> {
    let mut reader = SecureReader {
        term: Term::stderr(),
        line: io::Cursor::new(Vec::new()),
    };
    read_password(&mut reader, &mut io::stdout(), prompt.as_ref(), allow_empty).map_err(|error| {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof)
        {
            MenuEof.into()
        } else {
            error
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn text(input: &str, default: Option<&str>) -> (Result<String>, String) {
        let mut output = Vec::new();
        let result = read_text(
            &mut Cursor::new(input),
            &mut output,
            "名称",
            default,
            false,
            |value| {
                if value.contains('/') {
                    anyhow::bail!("名称不能包含斜杠");
                }
                Ok(value.to_owned())
            },
        );
        (result, String::from_utf8(output).unwrap())
    }

    #[test]
    fn text_default_required_back_invalid_and_eof() {
        assert_eq!(text("\n", Some("当前名称")).0.unwrap(), "当前名称");
        let (result, output) = text("\n新名称\n", None);
        assert_eq!(result.unwrap(), "新名称");
        assert_eq!(output.matches("名称（输入 0 返回）：").count(), 2);
        assert!(output.contains("错误！请输入内容"));
        assert!(is_back(&text("0\n", Some("原名称")).0.unwrap_err()));
        let (result, output) = text("bad/name\n正确名称\n", None);
        assert_eq!(result.unwrap(), "正确名称");
        assert!(output.contains("错误！名称不能包含斜杠"));
        assert!(text("", None).0.unwrap_err().is::<MenuEof>());
    }

    #[test]
    fn zero_default_cannot_create_a_name_and_numbered_eof_is_typed() {
        let (result, output) = text("\n新名称\n", Some("0"));
        assert_eq!(result.unwrap(), "新名称");
        assert!(output.contains("错误！0 用于返回，请输入其他内容"));
        let mut output = Vec::new();
        assert_eq!(
            read_menu_choice(&mut Cursor::new("2\n"), &mut output, 10).unwrap(),
            "2"
        );
        assert_eq!(String::from_utf8(output).unwrap(), "请选择 [0-10]: ");
        assert!(read_menu_choice(&mut Cursor::new(""), &mut Vec::new(), 10)
            .unwrap_err()
            .is::<MenuEof>());
    }

    #[test]
    fn plain_text_input_transcripts() {
        let mut output = Vec::new();
        assert_eq!(
            read_menu_choice(&mut Cursor::new("2\n"), &mut output, 10).unwrap(),
            "2"
        );
        writeln!(output, "[注入输入：2]").unwrap();
        assert!(is_back(
            &read_text(
                &mut Cursor::new("0\n"),
                &mut output,
                "新配置名称",
                Some("example-node"),
                false,
                |v| Ok(v.to_owned())
            )
            .unwrap_err()
        ));
        writeln!(output, "[注入输入：0；返回上一级]").unwrap();
        println!(
            "记录一（输入模块，注入 I/O）：\n{}",
            String::from_utf8(output).unwrap()
        );

        let mut output = Vec::new();
        assert!(!read_confirm(
            &mut Cursor::new("\n"),
            &mut output,
            "确认删除 example-node？",
            false
        )
        .unwrap());
        writeln!(output, "[注入输入：回车；确认结果：否]").unwrap();
        println!(
            "记录二（输入模块，注入 I/O）：\n{}",
            String::from_utf8(output).unwrap()
        );

        let mut output = Vec::new();
        let port = read_text(
            &mut Cursor::new("65536\n443\n"),
            &mut output,
            "新端口",
            Some("443"),
            false,
            |v| v.parse::<u16>().context("请输入 1 到 65535 的端口"),
        )
        .unwrap();
        assert_eq!(port, 443);
        writeln!(output, "[依次注入：65536、443；读取结果：443]").unwrap();
        println!(
            "记录三（输入模块，注入 I/O）：\n{}",
            String::from_utf8(output).unwrap()
        );
    }

    #[test]
    fn confirm_yes_no_default_back_and_retry() {
        for (value, expected) in [
            ("y\n", true),
            ("yes\n", true),
            ("n\n", false),
            ("no\n", false),
            ("\n", false),
        ] {
            let mut output = Vec::new();
            assert_eq!(
                read_confirm(&mut Cursor::new(value), &mut output, "确认删除？", false).unwrap(),
                expected
            );
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "确认删除？ [y/N]（输入 0 返回）："
            );
        }
        assert!(read_confirm(&mut Cursor::new("\n"), &mut Vec::new(), "启用？", true).unwrap());
        assert!(is_back(
            &read_confirm(&mut Cursor::new("0\n"), &mut Vec::new(), "删除？", false).unwrap_err()
        ));
        let mut output = Vec::new();
        assert!(read_confirm(
            &mut Cursor::new("maybe\nyes\n"),
            &mut output,
            "继续？",
            false
        )
        .unwrap());
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("错误！请输入 y、yes、n、no 或 0"));
        assert!(
            read_confirm(&mut Cursor::new(""), &mut Vec::new(), "继续？", false)
                .unwrap_err()
                .is::<MenuEof>()
        );
    }

    #[test]
    fn zero_is_a_number_and_enter_keeps_current_value() {
        for (value, expected) in [("0\n", 0), ("\n", 4), ("bad\n0\n", 0)] {
            let mut output = Vec::new();
            assert_eq!(
                read_number(
                    &mut Cursor::new(value),
                    &mut output,
                    "Max connections",
                    4u32
                )
                .unwrap(),
                expected
            );
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("Max connections（当前：4，直接回车保持当前值，0 为合法值）："));
            assert!(!output.contains("输入 0 返回"));
        }
    }

    #[test]
    fn password_rules_use_same_parser_without_writing_secret() {
        let mut output = Vec::new();
        assert_eq!(
            read_password(
                &mut Cursor::new("\n"),
                &mut output,
                "密码（留空安全随机生成）",
                true
            )
            .unwrap(),
            ""
        );
        assert!(is_back(
            &read_password(&mut Cursor::new("0\n"), &mut output, "密码", true).unwrap_err()
        ));
        assert!(
            read_password(&mut Cursor::new(""), &mut output, "密码", true)
                .unwrap_err()
                .is::<MenuEof>()
        );
        let secret = "fixture-only-password";
        assert_eq!(
            read_password(
                &mut Cursor::new(format!("{secret}\n")),
                &mut output,
                "密码",
                true
            )
            .unwrap(),
            secret
        );
        assert!(!String::from_utf8(output).unwrap().contains(secret));
    }
}
