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

    /// Scan staged changes for secrets (pre-commit hook)
    Watch {
        /// Path to the git repository (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// List detectable patterns (the magpie is attracted to shiny things)
    Shiny {
        /// Path to the git repository (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },

    /// Local findings dashboard
    Nest {
        #[command(subcommand)]
        action: Option<NestAction>,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum NestAction {
    /// Clear all stored scan data
    Reset {
        /// Path to the git repository (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show dashboard
    Show {
        /// Path to the git repository (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}
