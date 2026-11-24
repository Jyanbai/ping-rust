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
use socks5_secure::ShutdownSignal;

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
    let securing_socks5 = matches!(&cli.command, Some(cli::Command::Socks5 { .. }));
    #[cfg(unix)]
    if securing_socks5 {
        listen_for_termination()?;
    }
    if !cli.is_socks5_secure_dry_run() && std::path::Path::new(utils::STATE_FILE).exists() {
        if let Ok(state) = config::load_state() {
            for profile in &state.profiles {
                if let Some(warning) = profile.socks5_risk_warning() {
                    eprintln!("{warning}");
                }
            }
        }
    }
    let result = cli::run(cli).await;
    if let Some(error) = result.as_ref().err().filter(|error| is_interrupted(error)) {
        if securing_socks5 {
            eprintln!("{error:#}");
        }
        exit_after_signal(interrupted_exit_code(error));
    }
    result
}

#[cfg(unix)]
async fn listen_for_interrupts() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupts = signal(SignalKind::interrupt())?;
    tokio::spawn(async move {
        while interrupts.recv().await.is_some() {
            handle_interrupt(ShutdownSignal::Interrupt);
        }
    });
    Ok(())
}

#[cfg(unix)]
fn listen_for_termination() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminations = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        while terminations.recv().await.is_some() {
            handle_interrupt(ShutdownSignal::Terminate);
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
            handle_interrupt(ShutdownSignal::Interrupt);
        }
    });
    Ok(())
}

fn handle_interrupt(signal: ShutdownSignal) {
    if !socks5_secure::INTERRUPT.defer_signal(signal) {
        exit_after_signal(signal.exit_code());
    }
}

fn is_interrupted(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
    })
}

fn interrupted_exit_code(error: &anyhow::Error) -> i32 {
    error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()?
                .get_ref()?
                .downcast_ref::<ShutdownSignal>()
        })
        .copied()
        .unwrap_or(ShutdownSignal::Interrupt)
        .exit_code()
}

fn restore_cursor_and_exit() -> ! {
    exit_after_signal(ShutdownSignal::Interrupt.exit_code())
}

fn exit_after_signal(code: i32) -> ! {
    sni::cleanup_on_interrupt();
    let _ = restore_cursor(&mut std::io::stdout());
    std::process::exit(code)
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
