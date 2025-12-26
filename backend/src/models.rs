use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_id: Option<String>,
    pub event_type: String,
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
    pub execution_time_ms: u128,
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
