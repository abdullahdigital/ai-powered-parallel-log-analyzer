use crate::models::{LogEntry, Alert, Metrics, ParsingRule};
use crate::rules_engine::RulesEngine;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc, TimeZone, NaiveDateTime};
use regex::Regex;
use std::collections::HashMap;

pub fn parse_log_content(content: String, parsing_rules: Arc<Mutex<Vec<ParsingRule>>>) -> Vec<LogEntry> {
    let mut log_entries = Vec::new();
    let rules_locked = parsing_rules.lock().unwrap();

    for line in content.lines() {
        let mut parsed_entry = LogEntry {
            raw_log: line.to_string(),
            timestamp: None,
            ip_address: None,
            user_id: None,
            event_type: None,
            level: None,
            message: None,
            extra: HashMap::new(),
        };

        for rule in rules_locked.iter() {
            if let Ok(regex) = Regex::new(&rule.pattern) {
                if let Some(captures) = regex.captures(line) {
                    for (field_name, capture_name) in &rule.field_map {
                        if let Some(captured_value) = captures.name(capture_name).map(|m| m.as_str().to_string()) {
                            match field_name.as_str() {
                                "timestamp" => {
                                    let common_formats = [
                                        "%Y-%m-%dT%H:%M:%S%.3fZ", // RFC3339 with milliseconds
                                        "%Y-%m-%dT%H:%M:%S%:z",    // RFC3339 with timezone
                                        "%Y-%m-%d %H:%M:%S",      // Common YYYY-MM-DD HH:MM:SS
                                        "%b %d %H:%M:%S",          // Syslog-like (e.g., "Jan 01 12:34:56")
                                        "%Y/%m/%d %H:%M:%S",      // YYYY/MM/DD HH:MM:SS
                                    ];

                                    for format in common_formats.iter() {
                                        if let Ok(ts) = DateTime::parse_from_str(&captured_value, format) {
                                            parsed_entry.timestamp = Some(ts.with_timezone(&Utc));
                                            break;
                                        } else if let Ok(ts) = NaiveDateTime::parse_from_str(&captured_value, format) {
                                            parsed_entry.timestamp = Some(Utc.from_utc_datetime(&ts));
                                            break;
                                        }
                                    }
                                },
                                "ip_address" => parsed_entry.ip_address = Some(captured_value),
                                "user_id" => parsed_entry.user_id = Some(captured_value),
                                "event_type" => parsed_entry.event_type = Some(captured_value),
                                "level" => parsed_entry.level = Some(captured_value),
                                "message" => parsed_entry.message = Some(captured_value),
                                _ => {
                                    parsed_entry.extra.insert(field_name.clone(), captured_value);
                                }
                            }
                        }
                    }
                    break; // Apply the first matching rule
                }
            }
        }
        log_entries.push(parsed_entry);
    }
    log_entries
}


use std::time::Instant;

pub fn process_sequential(
    log_entries: Vec<LogEntry>,
    rules_engine: Arc<Mutex<RulesEngine>>,
) -> Metrics {
    let start_time = Instant::now();
    let mut alerts = Vec::new();
    let mut processed_logs_count = 0;
    let rules_engine_locked = rules_engine.lock().unwrap();
    for entry in &log_entries {
        processed_logs_count += 1;
        alerts.extend(rules_engine_locked.evaluate_log_entry(entry));
    }
    let duration = start_time.elapsed();
    let execution_time_ms = duration.as_secs_f64() * 1000.0;
    let logs_per_second = if execution_time_ms > 0.001 {
        (processed_logs_count as f64 / execution_time_ms) * 1000.0
    } else {
        processed_logs_count as f64 / duration.as_secs_f64().max(0.000001)
    };

    Metrics {
        total_logs_processed: processed_logs_count,
        execution_time_ms,
        logs_per_second,
        alerts_generated: alerts,
        mode: "Sequential".to_string(),
    }
}

use rayon::prelude::*;

pub fn process_parallel(
    log_entries: Vec<LogEntry>,
    rules_engine: Arc<Mutex<RulesEngine>>,
) -> Metrics {
    let start_time = Instant::now();
    let alerts: Vec<Alert> = log_entries.par_iter().flat_map(|entry| {
        let rules_engine_locked = rules_engine.lock().unwrap();
        rules_engine_locked.evaluate_log_entry(entry)
    }).collect();

    let duration = start_time.elapsed();
    let execution_time_ms = duration.as_secs_f64() * 1000.0;
    let logs_per_second = if execution_time_ms > 0.001 {
        (log_entries.len() as f64 / execution_time_ms) * 1000.0
    } else {
        log_entries.len() as f64 / duration.as_secs_f64().max(0.000001)
    };

    Metrics {
        total_logs_processed: log_entries.len(),
        execution_time_ms,
        logs_per_second,
        alerts_generated: alerts,
        mode: "Parallel".to_string(),
    }
}

pub fn process_distributed(
    log_entries: Vec<LogEntry>,
    rules_engine: Arc<Mutex<RulesEngine>>,
) -> Metrics {
    let start_time = Instant::now();
    // Fall back to sequential for now, but with proper timing
    let mut metrics = process_sequential(log_entries, rules_engine);
    
    metrics.mode = "Distributed".to_string();
    metrics.execution_time_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    metrics
}
