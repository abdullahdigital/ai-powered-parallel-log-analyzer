use crate::models::{LogEntry, Alert, Metrics, Rule};

use crate::threat_detection::ThreatDetector;

use rayon::prelude::*;
use std::sync::{Arc, Mutex};

pub fn run_parallel_analysis(parsed_logs: Vec<LogEntry>, rules: Vec<Rule>) -> Metrics {
    let alerts: Arc<Mutex<Vec<Alert>>> = Arc::new(Mutex::new(Vec::new()));
    let processed_logs_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let threat_detector = Arc::new(Mutex::new(ThreatDetector::new(rules)));

    parsed_logs.par_iter().for_each(|log_entry| {
        let mut detector_lock = threat_detector.lock().unwrap();
        let mut alerts_lock = alerts.lock().unwrap();
        let mut count_lock = processed_logs_count.lock().unwrap();

        *count_lock += 1;
        if let Some(alert) = detector_lock.detect_threats(log_entry) {
            alerts_lock.push(alert);
        }
    });

    let final_processed_logs_count = *processed_logs_count.lock().unwrap();
    let final_alerts = alerts.lock().unwrap().clone();

    Metrics {
        total_logs_processed: final_processed_logs_count,
        execution_time_ms: 0.0,
        logs_per_second: 0.0,
        alerts_generated: final_alerts,
        mode: "Parallel".to_string(),
    }
}
