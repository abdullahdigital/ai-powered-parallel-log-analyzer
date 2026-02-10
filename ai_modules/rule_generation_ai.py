import json

def generate_rule_from_natural_language(description: str) -> dict:
    """
    Generates a structured rule (JSON) from a natural language description.
    This is a placeholder for an actual AI model integration.
    """
    # In a real application, this would involve a call to an NLP model (e.g., OpenAI, Gemini, etc.)
    # that can parse the natural language and extract rule parameters.
    # For demonstration purposes, we'll use a simple heuristic or a mock response.

    rule = {
        "id": f"generated-{hash(description)}",
        "name": "Generated Rule",
        "pattern": ".*", # Default catch-all if no specific pattern derived
        "description": description,
        "alert_type": "Custom",
        "enabled": True,
        "rule_type": "Custom",
        "threshold": 1,
        "time_window_seconds": 60,
    }

    description_lower = description.lower()

    if "failed logins" in description_lower or "brute force" in description_lower:
        rule["name"] = "BruteForceAttempt"
        rule["rule_type"] = "BruteForce"
        rule["alert_type"] = "BruteForce"
        rule["pattern"] = "failed login|authentication failure"
        rule["threshold"] = 5 # Default threshold for brute force
        if "more than" in description_lower:
            try:
                parts = description_lower.split("more than")
                threshold_str = parts[1].strip().split(" ")[0]
                rule["threshold"] = int(threshold_str)
            except (ValueError, IndexError):
                pass # Keep default
        if "in" in description_lower and "minutes" in description_lower:
            try:
                parts = description_lower.split("in")
                time_str = parts[1].strip().split(" ")[0]
                rule["time_window_seconds"] = int(time_str) * 60
            except (ValueError, IndexError):
                pass # Keep default

    elif "high frequency request" in description_lower or "unusual number of requests" in description_lower:
        rule["name"] = "HighFrequencyRequest"
        rule["rule_type"] = "HighFrequencyRequest"
        rule["alert_type"] = "HighFrequencyRequest"
        rule["pattern"] = "request processed"
        rule["threshold"] = 100 # Default threshold for high frequency
        if "more than" in description_lower:
            try:
                parts = description_lower.split("more than")
                threshold_str = parts[1].strip().split(" ")[0]
                rule["threshold"] = int(threshold_str)
            except (ValueError, IndexError):
                pass # Keep default
        if "in" in description_lower and ("seconds" in description_lower or "minutes" in description_lower):
            try:
                parts = description_lower.split("in")
                time_str = parts[1].strip().split(" ")[0]
                if "minutes" in description_lower:
                    rule["time_window_seconds"] = int(time_str) * 60
                else:
                    rule["time_window_seconds"] = int(time_str)
            except (ValueError, IndexError):
                pass # Keep default

    elif "suspicious ip" in description_lower or "malicious ip" in description_lower:
        rule["name"] = "SuspiciousIpAccess"
        rule["rule_type"] = "SuspiciousIp"
        rule["alert_type"] = "SuspiciousIp"
        rule["pattern"] = "suspicious|malicious"
        rule["threshold"] = 1 # Even one access from suspicious IP is an alert
        rule["time_window_seconds"] = 3600 # Monitor for an hour

    return rule

if __name__ == '__main__':
    import sys
    
    # Check if input is provided via stdin
    if not sys.stdin.isatty():
        try:
            line = sys.stdin.read().strip()
            if line:
                # The Rust backend might send just the description string or a JSON object.
                # Let's assume it sends the raw description string for simplicity based on previous api.rs,
                # or we can handle JSON.
                # If the input starts with '{', assume JSON.
                description = line
                if line.startswith('{'):
                    try:
                        data = json.loads(line)
                        if "description" in data:
                            description = data["description"]
                    except:
                        pass # Treat as raw string
                
                rule = generate_rule_from_natural_language(description)
                print(json.dumps(rule))
            else:
                 print(json.dumps({"error": "No input provided"}))
        except Exception as e:
            print(json.dumps({"error": f"Error processing input: {str(e)}"}))
    else:
        # Example Usage if run directly
        print(json.dumps({
            "name": "Example Rule",
            "description": "Run via stdin to generate rules.",
            "rule_type": "Custom",
            "threshold": 1,
            "time_window_seconds": 60
        }))
