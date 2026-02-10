use crate::models::{LogEntry, Rule, Alert};
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

    pub fn add_rule(&mut self, mut rule: Rule) {
        // Automatically generate sequential ID if needed
        let next_index = self.rules.len() + 1;
        rule.id = format!("rule_{:03}", next_index);
        
        self.rules.push(rule);
        
        // Persist to file
        if let Err(e) = self.save_rules() {
            eprintln!("Warning: Failed to persist rules: {}", e);
        }
    }

    pub fn save_rules(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.rules)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        let mut file = std::fs::File::create("rules.json")
            .map_err(|e| format!("File creation error: {}", e))?;
        
        use std::io::Write;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("File write error: {}", e))?;
        
        Ok(())
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

            if re.is_match(&log_entry.raw_log) {
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
