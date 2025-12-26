use crate::models::{LogEntry, Rule, Alert, AlertType};
use regex::Regex;
use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RulesEngine {
    pub rules: Vec<Rule>,
}

impl RulesEngine {
    pub fn new() -> Self {
        RulesEngine {
            rules: Vec::new(),
        }
    }

    pub fn load_rules(&mut self, rules_json: &str) -> Result<(), String> {
        match serde_json::from_str(rules_json) {
            Ok(rules) => {
                self.rules = rules;
                Ok(())
            },
            Err(e) => Err(format!("Failed to parse rules JSON: {}", e)),
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn evaluate_log_entry(&self, log_entry: &LogEntry) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for rule in &self.rules {
            if !rule.enabled { continue; }

            let re = match Regex::new(&rule.pattern) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Invalid regex pattern for rule {}: {}", rule.name, e);
                    continue;
                }
            };

            if re.is_match(&log_entry.details) {
                alerts.push(Alert {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    alert_type: rule.alert_type.clone(),
                    description: format!("Rule '{}' triggered: {}", rule.name, rule.description),
                    log_entry_sample: Some(log_entry.clone()),
                });
            }
        }
        alerts
    }
}
