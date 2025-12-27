use crate::models::LogEntry;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub fn parse_log_entry(line: &str) -> Option<LogEntry> {
    // Example log format: [2023-10-27T10:00:00Z] INFO 192.168.1.1 user_id=testuser event=login_failed details={"reason":"bad_password"}
    let parts: Vec<&str> = line.splitn(3, "] ").collect();
    if parts.len() < 3 { return None; }

    let timestamp_str = &parts[0][1..]; // Remove leading '['
    let timestamp = match DateTime::parse_from_rfc3339(timestamp_str) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => return None,
    };

    let mut sub_parts = parts[2].split_whitespace();
    let ip_address = sub_parts.next()?.to_string();

    let mut user_id: Option<String> = None;
    let mut event_type: Option<String> = None;
    let mut details_str: Option<String> = None;

    for part in sub_parts {
        if part.starts_with("user_id=") {
            user_id = Some(part.trim_start_matches("user_id=").to_string());
        } else if part.starts_with("event=") {
            event_type = Some(part.trim_start_matches("event=").to_string());
        } else if part.starts_with("details=") {
            details_str = Some(part.trim_start_matches("details=").to_string());
        }
    }

    Some(LogEntry {
        timestamp: Some(timestamp),
        ip_address: Some(ip_address),
        user_id,
        event_type: event_type,
        level: None,
        message: details_str,
        raw_log: line.to_string(),
        extra: HashMap::new(),
    })
}
