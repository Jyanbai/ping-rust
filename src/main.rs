mod chain_proxy;
mod cli;
mod client;
mod config;
mod deployment;
mod fast_add;
mod github_api;
mod h2mux;
mod install_self;
mod installer;
mod menu;
mod operations;
mod performance;
mod self_update;
mod service;
mod shoes_compat;
mod sni;
mod sni_probe;
mod socks5_secure;
mod sudoku;
mod utils;
mod vless_encryption;
mod yaml;

// 需要 shoes 的测试共用的路径读取；集成测试通过 #[path] 引用同一份源码。
#[cfg(test)]
#[path = "../tests/support/shoes_e2e.rs"]
mod shoes_e2e;
#[cfg(test)]
mod shoes_e2e_tests;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    listen_for_interrupts().await?;
    if cli::is_version_request(std::env::args()) {
        let (stdout, stderr) = cli::version_output();
        println!("{stdout}");
        eprintln!("{stderr}");
        return Ok(());
    }
    let cli = cli::Cli::parse();
    if !cli.is_socks5_secure_dry_run() && std::path::Path::new(utils::STATE_FILE).exists() {
        if let Ok(state) = config::load_state() {
            for profile in &state.profiles {
                if let Some(warning) = profile.socks5_risk_warning() {
                    eprintln!("{warning}");
                }
            }
        }
    }
    let securing_socks5 = matches!(&cli.command, Some(cli::Command::Socks5 { .. }));
    let result = cli::run(cli).await;
    if let Some(error) = result.as_ref().err().filter(|error| is_interrupted(error)) {
        if securing_socks5 {
            eprintln!("{error:#}");
        }
        restore_cursor_and_exit();
    }
    result
}

#[cfg(unix)]
async fn listen_for_interrupts() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut signals = signal(SignalKind::interrupt())?;
    tokio::spawn(async move {
        while signals.recv().await.is_some() {
            handle_interrupt();
        }
    });
    Ok(())
}

#[cfg(not(unix))]
async fn listen_for_interrupts() -> Result<()> {
    use std::future::Future;

    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    // Poll once before entering blocking terminal prompts to install the handler.
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(result) = interrupt.as_mut().poll(cx) {
            return std::task::Poll::Ready(result);
        }
        std::task::Poll::Ready(Ok(()))
    })
    .await?;
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            handle_interrupt();
        }
    });
    Ok(())
}

fn handle_interrupt() {
    if !socks5_secure::INTERRUPT.defer_signal() {
        restore_cursor_and_exit();
    }
}

fn is_interrupted(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
    })
}

fn restore_cursor_and_exit() -> ! {
    sni::cleanup_on_interrupt();
    let _ = restore_cursor(&mut std::io::stdout());
    std::process::exit(130)
}

fn restore_cursor(output: &mut impl std::io::Write) -> std::io::Result<()> {
    output.write_all(b"\x1b[?25h\n")?;
    output.flush()
}

#[cfg(test)]
mod signal_tests {
    #[test]
    fn interrupt_restores_cursor_and_starts_a_new_line() {
        let mut output = Vec::new();
        super::restore_cursor(&mut output).unwrap();
        assert_eq!(output, b"\x1b[?25h\n");
    }
}
