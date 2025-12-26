use crate::models::{LogEntry, Alert, Metrics, Rule};
use crate::threat_detection::ThreatDetector;

pub fn run_sequential_analysis(parsed_logs: Vec<LogEntry>, rules: Vec<Rule>) -> Metrics {
    let mut alerts: Vec<Alert> = Vec::new();
    let mut threat_detector = ThreatDetector::new(rules);
    let mut processed_logs_count = 0;

    for log_entry in parsed_logs {
        processed_logs_count += 1;
        if let Some(alert) = threat_detector.detect_threats(&log_entry) {
            alerts.push(alert);
        }
    }

    Metrics {
        total_logs_processed: processed_logs_count,
        alerts_generated: alerts,
        mode: "Sequential".to_string(),
    }
}
