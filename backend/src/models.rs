use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};


use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub raw_log: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub ip_address: Option<String>,
    pub user_id: Option<String>,
    pub level: Option<String>,
    pub message: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AlertType {
    BruteForce,
    HighFrequencyRequest,
    SuspiciousIp,
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
    pub execution_time_ms: f64,
    pub logs_per_second: f64,
    pub alerts_generated: Vec<Alert>,
    pub mode: String, // Sequential, Parallel, Distributed
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RuleType {
    BruteForce,
    HighFrequencyRequest,
    SuspiciousIp,
    Custom(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub pattern: String, // Regex pattern to match against log entry details
    pub description: String,
    pub alert_type: AlertType,
    pub enabled: bool,
    pub rule_type: RuleType,
    pub time_window_seconds: Option<u64>,
    pub threshold: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParsingRule {
    pub name: String,
    pub pattern: String, // Regex pattern
    pub field_map: HashMap<String, String>, // Maps regex capture group names to LogEntry fields
    pub default: bool, // If true, this rule is applied if no other rule matches
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AiExplanation {
    pub explanation: String,
    pub suggested_rules: Vec<Rule>,
}
