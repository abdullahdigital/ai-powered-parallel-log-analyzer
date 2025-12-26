use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AlertType {
    BruteForce,
    HighFrequencyRequest,
    SuspiciousActivity,
    Custom(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Alert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub alert_type: AlertType,
    pub description: String,
    pub log_entry_sample: Option<LogEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metrics {
    pub total_logs_processed: usize,
    pub alerts_generated: Vec<Alert>,
    pub mode: String, // Sequential, Parallel, Distributed
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub pattern: String, // Regex pattern to match against log entry details
    pub description: String,
    pub alert_type: AlertType,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    LogChunk(Vec<LogEntry>),
    Rules(Vec<Rule>),
    StartAnalysis,
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MasterMessage {
    AnalysisResult(Metrics),
    Error(String),
    Ack,
}
