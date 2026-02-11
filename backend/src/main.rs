use std::fs::File;
use std::io::{self, BufReader, BufRead};
use std::path::Path;
use clap::Parser;

mod models;
mod log_parser;
mod threat_detection;
mod sequential_analysis;
mod parallel_analysis;
mod distributed_analysis;
mod utils;
mod server;
mod rules_engine;
mod log_processor;
mod ai_module;
mod parser_config;

use models::{LogEntry, Metrics};
use log_parser::parse_log_entry;
use parser_config::load_parsing_rules;



use utils::Timer;
use rules_engine::RulesEngine;
use log_processor::{process_sequential, process_parallel, process_distributed};
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser, default_value_t = String::from("analysis"))]
    mode: String,

    #[clap(long, value_parser)]
    log_file: Option<String>,

    #[clap(long, value_parser, default_value_t = String::from("rules.json"))]
    rules_file: String,

    #[clap(long, value_parser, default_value_t = 4)]
    workers: usize,
}

fn read_log_file(filename: &Path) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(|line| line.ok()).collect())
}

fn read_rules_file_content(filename: &Path) -> io::Result<String> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut content = String::new();
    for line in reader.lines() {
        content.push_str(&line?);
        content.push('\n');
    }
    Ok(content)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let args = Args::parse();

    match args.mode.as_str() {
        "analysis" => {
            let log_file = args.log_file.expect("Log file must be provided for analysis mode.");
            println!("Loading log file: {}", log_file);
            let log_lines = read_log_file(Path::new(&log_file))?;
            println!("Loaded {} log entries.", log_lines.len());

            println!("Loading rules file: {}", args.rules_file);
            let rules_json = read_rules_file_content(Path::new(&args.rules_file))?;
            let mut rules_engine = RulesEngine::new();
            rules_engine.load_rules(&rules_json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            println!("Loaded {} rules.", rules_engine.rules.len());

            let mut metrics: Metrics;

            let timer = Timer::new();

            match args.mode.as_str() {
                "sequential" => {
                    println!("Running sequential analysis...");
                    let parsed_logs: Vec<LogEntry> = log_lines.iter()
                        .filter_map(|line| parse_log_entry(line))
                        .collect();
                    metrics = process_sequential(parsed_logs, Arc::new(Mutex::new(rules_engine)));
                    let elapsed_time_ms = timer.elapsed_millis();
                    metrics.execution_time_ms = elapsed_time_ms;
                    metrics.logs_per_second = (metrics.total_logs_processed as f64 / elapsed_time_ms as f64) * 1000.0;
                },
                "parallel" => {
                    println!("Running parallel analysis...");
                    let parsed_logs: Vec<LogEntry> = log_lines.iter()
                        .filter_map(|line| parse_log_entry(line))
                        .collect();
                    metrics = process_parallel(parsed_logs, Arc::new(Mutex::new(rules_engine)));
                    let elapsed_time_ms = timer.elapsed_millis();
                    metrics.execution_time_ms = elapsed_time_ms;
                    metrics.logs_per_second = (metrics.total_logs_processed as f64 / elapsed_time_ms as f64) * 1000.0;
                },
                "distributed" => {
                    println!("Running distributed analysis with {} workers...", args.workers);
                    let parsed_logs: Vec<LogEntry> = log_lines.iter()
                        .filter_map(|line| parse_log_entry(line))
                        .collect();
                    metrics = process_distributed(parsed_logs, Arc::new(Mutex::new(rules_engine)));
                    let elapsed_time_ms = timer.elapsed_millis();
                    metrics.execution_time_ms = elapsed_time_ms;
                    metrics.logs_per_second = (metrics.total_logs_processed as f64 / elapsed_time_ms as f64) * 1000.0;
                },
                _ => {
                    eprintln!("Invalid analysis mode: {}. Please choose from 'sequential', 'parallel', or 'distributed'.", args.mode);
                    std::process::exit(1);
                }
            }

            println!("\n--- Analysis Results ({}) ---", metrics.mode);
            println!("Total logs processed: {}", metrics.total_logs_processed);
            // println!("Execution time: {} ms", metrics.execution_time_ms);
            // println!("Logs per second: {:.2}", metrics.logs_per_second);
            println!("Total alerts generated: {}", metrics.alerts_generated.len());

            if !metrics.alerts_generated.is_empty() {
                println!("\n--- Alerts ---");
                for alert in metrics.alerts_generated {
                    println!("  - [{:?}] {}: {}", alert.alert_type, alert.timestamp, alert.description);
                }
            }
        },
        "server" => {
            println!("Starting web server on 127.0.0.1:8080...");
            let rules_engine = Arc::new(Mutex::new(RulesEngine::new()));

            let parsing_rules_path = "parsing_rules.json";
            let parsing_rules = match load_parsing_rules(parsing_rules_path) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Failed to load parsing rules: {}. Exiting.", e);
                    std::process::exit(1);
                }
            };

            server::run_server(rules_engine, parsing_rules).await?;
        },
        _ => {
            eprintln!("Invalid mode: {}. Please choose from 'analysis' or 'server'.", args.mode);
            std::process::exit(1);
        }
    }

    Ok(())
}
