use clap::Parser;

fn main() -> anyhow::Result<()> {
    gatir::cli::run(gatir::cli::Cli::parse())
}
