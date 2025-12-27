use crate::models::{LogEntry, Alert, AlertType, Rule, RuleType};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use uuid::Uuid;

pub struct ThreatDetector {
    rules: Vec<Rule>,
    // State for brute-force detection: (ip_address, user_id) -> (failed_attempts, last_attempt_time)
    brute_force_attempts: HashMap<(String, String), (usize, DateTime<Utc>)>, 
    // State for high-frequency request detection: ip_address -> (request_count, last_request_time)
    high_frequency_requests: HashMap<String, (usize, DateTime<Utc>)>, 
    // State for suspicious IP behavior: ip_address -> (event_counts, last_event_time)
    suspicious_ip_behavior: HashMap<String, (HashMap<String, usize>, DateTime<Utc>)>, 
}

impl ThreatDetector {
    pub fn new(rules: Vec<Rule>) -> Self {
        ThreatDetector {
            rules,
            brute_force_attempts: HashMap::new(),
            high_frequency_requests: HashMap::new(),
            suspicious_ip_behavior: HashMap::new(),
        }
    }

    pub fn detect_threats(&mut self, log_entry: &LogEntry) -> Option<Alert> {
        let mut generated_alerts: Vec<Alert> = Vec::new();

        // Clone rules to iterate over them, allowing mutable access to self within the loop
        let rules_clone = self.rules.clone();

        for rule in rules_clone {
            match rule.rule_type {
                RuleType::BruteForce => {
                    if let Some(alert) = self.check_brute_force(log_entry, &rule) {
                        generated_alerts.push(alert);
                    }
                }
                RuleType::HighFrequencyRequest => {
                    if let Some(alert) = self.check_high_frequency_request(log_entry, &rule) {
                        generated_alerts.push(alert);
                    }
                }
                RuleType::SuspiciousIp => {
                    if let Some(alert) = self.check_suspicious_ip_behavior(log_entry, &rule) {
                        generated_alerts.push(alert);
                    }
                }
                RuleType::Custom(_) => {
                    // Custom rules logic would go here
                }
            }
        }
        generated_alerts.into_iter().next()
    }

    fn check_brute_force(&mut self, log_entry: &LogEntry, rule: &Rule) -> Option<Alert> {
        if log_entry.event_type.as_deref() == Some("login_failed") {
            if let (Some(ip_address), Some(user_id), Some(time_window_seconds), Some(threshold)) = (&log_entry.ip_address, &log_entry.user_id, rule.time_window_seconds, rule.threshold) {
                let key = (ip_address.clone(), user_id.clone());
                let (attempts, last_attempt_time) = self.brute_force_attempts.entry(key.clone()).or_insert((0, log_entry.timestamp.unwrap_or_else(|| Utc::now())));

                if log_entry.timestamp.unwrap_or_else(|| Utc::now()) - *last_attempt_time < Duration::seconds(time_window_seconds as i64) {
                    *attempts += 1;
                } else {
                    *attempts = 1;
                }
                *last_attempt_time = log_entry.timestamp.unwrap_or_else(|| Utc::now());

                if *attempts >= threshold {
                    self.brute_force_attempts.remove(&key);
                    return Some(Alert {
                        id: Uuid::new_v4().to_string(),
                        timestamp: log_entry.timestamp.unwrap_or_else(|| Utc::now()),
                        alert_type: AlertType::BruteForce,
                        description: format!("Brute-force attempt detected from IP {} for user {}", ip_address, user_id),
                        log_entry_sample: Some(log_entry.clone()),
                    });
                }
            }
        }
        None
    }

    fn check_high_frequency_request(&mut self, log_entry: &LogEntry, rule: &Rule) -> Option<Alert> {
        if let (Some(ip_address), Some(time_window_seconds), Some(threshold)) = (&log_entry.ip_address, rule.time_window_seconds, rule.threshold) {
            let key = ip_address.clone();
            let (count, last_request_time) = self.high_frequency_requests.entry(key.clone()).or_insert((0, log_entry.timestamp.unwrap_or_else(|| Utc::now())));

            if log_entry.timestamp.unwrap_or_else(|| Utc::now()) - *last_request_time < Duration::seconds(time_window_seconds as i64) {
                *count += 1;
            } else {
                *count = 1;
            }
            *last_request_time = log_entry.timestamp.unwrap_or_else(|| Utc::now());

            if *count >= threshold {
                self.high_frequency_requests.remove(&key);
                return Some(Alert {
                    id: Uuid::new_v4().to_string(),
                    timestamp: log_entry.timestamp.unwrap_or_else(|| Utc::now()),
                    alert_type: AlertType::HighFrequencyRequest,
                    description: format!("High-frequency requests detected from IP {}", ip_address),
                    log_entry_sample: Some(log_entry.clone()),
                });
            }
        }
        None
    }

    fn check_suspicious_ip_behavior(&mut self, log_entry: &LogEntry, rule: &Rule) -> Option<Alert> {
        if let (Some(ip_address), Some(time_window_seconds), Some(threshold)) = (&log_entry.ip_address, rule.time_window_seconds, rule.threshold) {
            let key = ip_address.clone();
            let (event_counts, last_event_time) = self.suspicious_ip_behavior.entry(key.clone()).or_insert_with(|| (HashMap::new(), log_entry.timestamp.unwrap_or_else(|| Utc::now())));

            if log_entry.timestamp.unwrap_or_else(|| Utc::now()) - *last_event_time < Duration::seconds(time_window_seconds as i64) {
                if let Some(event_type) = log_entry.event_type.clone() {
                    *event_counts.entry(event_type).or_insert(0) += 1;
                }
            } else {
                event_counts.clear();
                if let Some(event_type_str) = log_entry.event_type.clone() {
                    *event_counts.entry(event_type_str).or_insert(0) = 1;
                }
            }
            *last_event_time = log_entry.timestamp.unwrap_or_else(|| Utc::now());

            // Example: If an IP has more than 'threshold' unique event types in the time window
            if event_counts.len() >= threshold {
                self.suspicious_ip_behavior.remove(&key);
                return Some(Alert {
                    id: Uuid::new_v4().to_string(),
                    timestamp: log_entry.timestamp.unwrap_or_else(|| Utc::now()),
                    alert_type: AlertType::SuspiciousIp,
                    description: format!("Suspicious IP behavior detected from IP {}: multiple event types", ip_address),
                    log_entry_sample: Some(log_entry.clone()),
                });
            }
        }
        None
    }
}
