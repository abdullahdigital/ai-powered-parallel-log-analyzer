import sys
import json
from gemini_client import get_gemini_client

def explain_alert(alert_json):
    """
    Takes an Alert JSON object and generates a concise security explanation.
    """
    model = get_gemini_client()
    
    try:
        alert_data = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
        
        raw_log = alert_data.get("log_entry_sample", {}).get("raw_log", "No raw log available")
        description = alert_data.get("description", "Unknown alert")
        alert_type = alert_data.get("alert_type", "General")

        prompt = f"""
        You are a Security Operations Center (SOC) Analyst. 
        Explain the following alert to a junior developer in 2-3 concise sentences.
        
        ALERT TYPE: {alert_type}
        SYSTEM DESCRIPTION: {description}
        RAW LOG SAMPLE: {raw_log}
        
        Focus on:
        1. What exactly happened.
        2. Why it is a security risk.
        3. What is the immediate recommended action.
        
        Keep it professional and technical yet accessible.
        """

        response = model.generate_content(prompt)
        return {"status": "success", "explanation": response.text.strip()}

    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        alert_payload = sys.argv[1]
        result = explain_alert(alert_payload)
        print(json.dumps(result))
    else:
        print(json.dumps({"status": "error", "message": "No alert data provided"}))
