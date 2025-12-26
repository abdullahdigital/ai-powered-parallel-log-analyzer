use crate::models::{LogEntry, Alert};
use crate::rules_engine::RulesEngine;
use std::sync::{Arc, Mutex};
use chrono::Utc;

pub fn parse_log_content(content: String) -> Vec<LogEntry> {
    content.lines().map(|line| {
        LogEntry {
            timestamp: Utc::now(),
            details: line.to_string(),
        }
    }).collect()
}


pub fn process_sequential(
    log_entries: Vec<LogEntry>,
    rules_engine: Arc<Mutex<RulesEngine>>,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let rules_engine_locked = rules_engine.lock().unwrap();
    for entry in log_entries {
        alerts.extend(rules_engine_locked.evaluate_log_entry(&entry));
    }
    alerts
}

use rayon::prelude::*;

pub fn process_parallel(
    log_entries: Vec<LogEntry>,
    rules_engine: Arc<Mutex<RulesEngine>>,
) -> Vec<Alert> {
    let alerts: Vec<Alert> = log_entries.par_iter().flat_map(|entry| {
        let rules_engine_locked = rules_engine.lock().unwrap();
        rules_engine_locked.evaluate_log_entry(entry)
    }).collect();
    alerts
}

pub fn process_distributed(
    log_entries: Vec<LogEntry>,
    rules_engine: Arc<Mutex<RulesEngine>>,
) -> Vec<Alert> {
    // This is a placeholder for distributed processing logic.
    // In a real-world scenario, this would involve:
    // 1. Serializing log_entries and sending them to a distributed processing system (e.g., Kafka, RabbitMQ, or a custom RPC).
    // 2. Worker nodes in the distributed system would receive and process these log entries using their own RulesEngine instances.
    // 3. Aggregating results from the worker nodes.
    // For now, it will fall back to sequential processing.
    process_sequential(log_entries, rules_engine)
}
