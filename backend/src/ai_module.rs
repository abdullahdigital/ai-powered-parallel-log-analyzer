use crate::models::{LogEntry, Rule};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AiExplanation {
    pub explanation: String,
    pub suggested_rules: Vec<Rule>,
}

pub fn explain_log_entry(log_entry: &LogEntry) -> AiExplanation {
    let mut explanation = String::new();
    let mut suggested_rules = Vec::new();

    let raw_log = &log_entry.raw_log;

    if raw_log.contains("ERROR") || raw_log.contains("failed") {
        explanation.push_str("This log entry indicates an error or a failure event. It's critical and requires immediate attention.");
        if raw_log.contains("authentication") {
            explanation.push_str(" Specifically, it seems to be an authentication failure, possibly due to incorrect credentials or an unauthorized access attempt.");
            suggested_rules.push(Rule { 
                id: "auth_fail_rule".to_string(), 
                name: "Authentication Failure".to_string(),
                pattern: "authentication failed".to_string(), 
                description: "Alert on repeated authentication failures.".to_string(),
                rule_type: crate::models::RuleType::BruteForce,
                time_window_seconds: Some(300),
                threshold: Some(5),
                alert_type: crate::models::AlertType::BruteForce,
                enabled: true,
            });
        } else if raw_log.contains("connection refused") {
            explanation.push_str(" The error suggests a connection issue, where a client was unable to establish a connection to a service.");
            suggested_rules.push(Rule { 
                id: "conn_refused_rule".to_string(), 
                name: "Connection Refused".to_string(),
                pattern: "connection refused".to_string(), 
                description: "Alert on connection refused errors.".to_string(),
                rule_type: crate::models::RuleType::Custom("connection_error".to_string()),
                time_window_seconds: None,
                threshold: None,
                alert_type: crate::models::AlertType::Custom("ConnectionError".to_string()),
                enabled: true,
            });
        }
    } else if raw_log.contains("WARN") || raw_log.contains("warning") {
        explanation.push_str("This log entry indicates a warning. While not critical, it suggests a potential issue that might lead to problems if not addressed.");
    } else if raw_log.contains("INFO") || raw_log.contains("success") {
        explanation.push_str("This is an informational log entry, indicating a normal operation or a successful event.");
        if raw_log.contains("login successful") {
            explanation.push_str(" A user has successfully logged in.");
        }
    } else if raw_log.contains("denied") || raw_log.contains("unauthorized") {
        explanation.push_str("This log entry indicates an access control issue, where an operation was denied due to insufficient permissions or unauthorized access.");
        suggested_rules.push(Rule { 
            id: "access_denied_rule".to_string(), 
            name: "Access Denied/Unauthorized".to_string(),
            pattern: "access denied|unauthorized".to_string(), 
            description: "Alert on access denied or unauthorized attempts.".to_string(),
            rule_type: crate::models::RuleType::Custom("access_control".to_string()),
            time_window_seconds: None,
            threshold: None,
            alert_type: crate::models::AlertType::Custom("AccessControl".to_string()),
            enabled: true,
        });
    }

    if explanation.is_empty() {
        explanation.push_str(&format!("This log entry: \"{}\" does not match any specific known patterns, but appears to be a general system message.", raw_log));
    }

    AiExplanation {
        explanation,
        suggested_rules,
    }
}

pub fn generate_rule_from_description(description: &str) -> Option<Rule> {
    let lower_desc = description.to_lowercase();
    if lower_desc.contains("alert on") && lower_desc.contains("if log contains") {
        let parts: Vec<&str> = lower_desc.split("if log contains").collect();
        if parts.len() > 1 {
            let pattern_str = parts[1].trim().trim_matches('\'').to_string();
            if !pattern_str.is_empty() {
                return Some(Rule {
                    id: format!("generated_rule_{}", uuid::Uuid::new_v4()),
                    name: format!("Generated Rule: {}", pattern_str),
                    pattern: pattern_str,
                    description: description.to_string(),
                    rule_type: crate::models::RuleType::Custom("generated".to_string()),
                    time_window_seconds: None,
                    threshold: None,
                    alert_type: crate::models::AlertType::Custom("GeneratedAlert".to_string()),
                    enabled: true,
                });
            }
        }
    }
    None
}
