use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "magpie", version, about = "Fast git secret scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Scan a git repository for secrets
    Scan {
        /// Path to the git repository (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,

        /// Force a full scan (ignore .magpie-state)
        #[arg(long)]
        full: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}
