use clap::Parser;
use std::process;

mod cli;

fn main() {
    let args = cli::Cli::parse();

    match args.command {
        cli::Commands::Scan { path, format, full } => {
            let (result, head_oid) = match magpie::run_scan(&path, full) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(2);
                }
            };

            let output = match format {
                cli::OutputFormat::Text => magpie::output::text::render(&result),
                cli::OutputFormat::Json => magpie::output::json::render(&result),
            };
            print!("{output}");

            if let Err(e) = magpie::state::write(&path, head_oid) {
                eprintln!("warning: could not write .magpie-state: {e}");
            }

            let has_high = result.findings.iter().any(|f| {
                f.confidence == magpie::models::Confidence::High
            });
            if has_high {
                process::exit(1);
            }
        }
    }
}
