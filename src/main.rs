use clap::Parser;
use std::process;

mod cli;

fn main() {
    let args = cli::Cli::parse();

    match args.command {
        cli::Commands::Scan { path, format } => {
            let result = match magpie::run_scan(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };

            let output = match format {
                cli::OutputFormat::Text => magpie::output::text::render(&result),
                cli::OutputFormat::Json => magpie::output::json::render(&result),
            };
            print!("{output}");

            let has_high = result.findings.iter().any(|f| {
                f.confidence == magpie::models::Confidence::High
            });
            if has_high {
                process::exit(1);
            }
        }
    }
}
