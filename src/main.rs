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
mod utils;
mod vless_encryption;
mod yaml;

use anyhow::Result;
use clap::Parser;
use std::future::Future;

#[tokio::main]
async fn main() -> Result<()> {
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
            restore_cursor_and_exit();
        }
    });
    if cli::is_version_request(std::env::args()) {
        let (stdout, stderr) = cli::version_output();
        println!("{stdout}");
        eprintln!("{stderr}");
        return Ok(());
    }
    let result = cli::run(cli::Cli::parse()).await;
    if result.as_ref().is_err_and(is_interrupted) {
        restore_cursor_and_exit();
    }
    result
}

fn is_interrupted(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
    })
}

fn restore_cursor_and_exit() -> ! {
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
