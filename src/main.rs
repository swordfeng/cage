use clap::Parser;
use scopeguard::defer;
use std::process;

mod cli;
mod config;
mod platform;
mod policy;

const BUNDLED_CONFIG: &str = include_str!("../config/cage.toml");

fn main() {
    let args = cli::Args::parse();

    if let Err(e) = run(args) {
        eprintln!("cage error: {}", e);
        process::exit(1);
    }
}

fn run(args: cli::Args) -> anyhow::Result<()> {
    todo!("T1.1 complete: Project scaffold with module structure")
}
