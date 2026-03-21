use clap::Parser;
use std::path::PathBuf;
use std::process;

mod cli;

fn main() {
    let args = cli::Cli::parse();

    match args.command {
        cli::Commands::Scan { path, format, full } => {
            let (result, head_oid, root) = match magpie::run_scan(&path, full) {
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

            if let Err(e) = magpie::state::write(&root, head_oid) {
                eprintln!("warning: could not write .magpie-state: {e}");
            }

            if let Err(e) = magpie::nest::persist(&root, &result, Some(&head_oid.to_string())) {
                eprintln!("warning: could not write to nest database: {e}");
            }

            let has_high = result.findings.iter().any(|f| {
                f.confidence == magpie::models::Confidence::High
            });
            if has_high {
                process::exit(1);
            }
        }

        cli::Commands::Watch { path, format } => {
            let root = magpie::resolve_root(&path).ok();

            let result = match magpie::run_watch(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(2);
                }
            };

            if result.findings.is_empty() && result.files_scanned == 0 {
                println!("nothing staged");
                if let Some(ref root) = root {
                    if let Err(e) = magpie::nest::persist(root, &result, None) {
                        eprintln!("warning: could not write to nest database: {e}");
                    }
                }
                return;
            }

            let output = match format {
                cli::OutputFormat::Text => magpie::output::text::render(&result),
                cli::OutputFormat::Json => magpie::output::json::render(&result),
            };
            print!("{output}");

            if let Some(ref root) = root {
                if let Err(e) = magpie::nest::persist(root, &result, None) {
                    eprintln!("warning: could not write to nest database: {e}");
                }
            }

            let has_high = result.findings.iter().any(|f| {
                f.confidence == magpie::models::Confidence::High
            });
            if has_high {
                process::exit(1);
            }
        }

        cli::Commands::Nest { action } => {
            let path = match &action {
                Some(cli::NestAction::Reset { path }) => path.clone(),
                Some(cli::NestAction::Show { path }) => path.clone(),
                None => PathBuf::from("."),
            };
            let root = match magpie::resolve_root(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(2);
                }
            };

            match action {
                Some(cli::NestAction::Reset { .. }) => {
                    if let Err(e) = magpie::nest::reset(&root) {
                        eprintln!("Error: {e}");
                        process::exit(2);
                    }
                    println!("Database cleared.");
                }
                _ => {
                    if let Err(e) = magpie::nest::init_db(&root) {
                        eprintln!("Error: {e}");
                        process::exit(2);
                    }
                    match magpie::nest::dashboard(&root) {
                        Ok(output) => print!("{output}"),
                        Err(e) => {
                            eprintln!("Error: {e}");
                            process::exit(2);
                        }
                    }
                }
            }
        }
    }
}
