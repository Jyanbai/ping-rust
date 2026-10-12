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
mod yaml;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    if cli::is_version_request(std::env::args()) {
        let (stdout, stderr) = cli::version_output();
        println!("{stdout}");
        eprintln!("{stderr}");
        return Ok(());
    }
    cli::run(cli::Cli::parse()).await
}
