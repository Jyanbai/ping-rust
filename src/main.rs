mod cli;
mod client;
mod config;
mod installer;
mod menu;
mod operations;
mod self_update;
mod service;
mod utils;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    cli::run(cli::Cli::parse()).await
}
