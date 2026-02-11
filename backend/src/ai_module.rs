use crate::models::{Rule, Metrics, AiExplanation};
use std::process::{Command, Stdio};



pub fn explain_alert(alert: serde_json::Value) -> Option<String> {
    // Use environment variables or sensible defaults for path portability
    let script_path = std::env::var("AI_EXPL_SCRIPT_PATH").unwrap_or_else(|_| "../ai_modules/alert_explainer.py".to_string());
    let python_path = std::env::var("PYTHON_INTERPRETER_PATH").unwrap_or_else(|_| "python3".to_string());
    
    let alert_json = alert.to_string();

    let output = Command::new(python_path)
        .arg(script_path)
        .arg(&alert_json)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                let out_str = String::from_utf8_lossy(&out.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&out_str) {
                    return json.get("explanation").and_then(|v| v.as_str()).map(|s| s.to_string());
                }
                None
            } else {
                let err_str = String::from_utf8_lossy(&out.stderr);
                eprintln!("AI Alert Explanation Error: {}", err_str);
                None
            }
        }
        Err(e) => {
            eprintln!("Failed to execute AI explainer: {}", e);
            None
        }
    }
}

pub fn generate_rule_from_description(description: &str) -> Result<Rule, String> {
    let script_path = std::env::var("AI_GEN_SCRIPT_PATH").unwrap_or_else(|_| "../ai_modules/rule_generator.py".to_string());
    let python_path = std::env::var("PYTHON_INTERPRETER_PATH").unwrap_or_else(|_| "python3".to_string());
    println!("DEBUG: AI Rule Generator using Python: {}", python_path);

    let output = Command::new(python_path)
        .arg(script_path)
        .arg(description)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                let out_str = String::from_utf8_lossy(&out.stdout);
                
                if let Ok(result) = serde_json::from_str::<serde_json::Value>(&out_str) {
                    if result["status"] == "success" {
                        return serde_json::from_value::<Rule>(result["rule"].clone())
                            .map_err(|e| format!("Serialization error: {}", e));
                    } else {
                        return Err(result["message"].as_str().unwrap_or("Unknown AI error").to_string());
                    }
                }
                Err("Failed to parse AI output as JSON".to_string())
            } else {
                let err_str = String::from_utf8_lossy(&out.stderr);
                Err(format!("Python execution failed: {}", err_str))
            }
        }
        Err(e) => Err(format!("Failed to spawn Python process: {}", e))
    }
}

// Keep legacy functions if they are used elsewhere, but marked as candidates for removal
pub fn explain_metrics(_metrics: &Vec<Metrics>) -> AiExplanation {
    AiExplanation {
        explanation: "Legacy metrics explanation is being replaced by per-alert explanation.".to_string(),
        suggested_rules: vec![],
    }
}
