import json

def generate_explanation(metrics: list[dict]) -> str:
    """
    Generates a natural language explanation and recommendations based on the provided metrics.
    """
    if not metrics:
        return "No metrics provided for explanation."

    latest_metrics = metrics[-1]
    explanation_parts = []

    explanation_parts.append(f"The latest log analysis run in '{latest_metrics.get('mode', 'N/A')}' mode processed "
                             f"{latest_metrics.get('total_logs_processed', 0):,} logs in "
                             f"{latest_metrics.get('execution_time_ms', 0):.2f} milliseconds, achieving a rate of "
                             f"{latest_metrics.get('logs_per_second', 0):.2f} logs per second.")

    alerts = latest_metrics.get('alerts_generated', [])
    if alerts:
        explanation_parts.append(f"During this run, {len(alerts)} alerts were generated. "
                                 "These indicate potential security incidents or anomalies.")
        for i, alert in enumerate(alerts[:3]): # Limit to first 3 alerts for brevity
            explanation_parts.append(f"- Alert {i+1}: A '{alert.get('alert_type', 'N/A')}' alert was triggered "
                                     f"due to '{alert.get('description', 'N/A')}' at {alert.get('timestamp', 'N/A')}.")
        if len(alerts) > 3:
            explanation_parts.append(f"  (and {len(alerts) - 3} more alerts...)")
    else:
        explanation_parts.append("No alerts were generated in this analysis run, indicating a clean scan or that current rules did not detect any threats.")

    recommendations = []
    if latest_metrics.get('logs_per_second', 0) < 1000:
        recommendations.append("Consider optimizing log parsing and analysis logic for better performance, especially in sequential mode.")
    if len(alerts) > 5:
        recommendations.append("Review the generated alerts immediately to understand the nature of potential threats and take corrective actions.")
    if latest_metrics.get('mode') == 'sequential' and latest_metrics.get('total_logs_processed', 0) > 10000:
        recommendations.append("For large log volumes, consider utilizing parallel or distributed analysis modes to significantly reduce processing time.")

    if recommendations:
        explanation_parts.append("\nRecommendations:")
        for i, rec in enumerate(recommendations):
            explanation_parts.append(f"{i+1}. {rec}")

    return "\n".join(explanation_parts)

if __name__ == '__main__':
    import sys
    
    # Check if input is provided via stdin
    if not sys.stdin.isatty():
        try:
            input_data = sys.stdin.read()
            if input_data:
                metrics = json.loads(input_data)
                # Ensure metrics is a list, if single dict provided, wrap it
                if isinstance(metrics, dict):
                    metrics = [metrics]
                
                explanation = generate_explanation(metrics)
                
                # Output as JSON object with explanation field to match Rust expectation
                # The Rust side expects a JSON that can be deserialized into AiExplanation
                # or just the raw string?
                # Rust `AiExplanation` struct: { explanation: String, suggested_rules: Vec<Rule> }
                # The python script currently returns a string string.
                # I should wrap it in the expected JSON structure.
                
                response = {
                    "explanation": explanation,
                    "suggested_rules": [] 
                }
                print(json.dumps(response))
            else:
                 print(json.dumps({"explanation": "No input data provided.", "suggested_rules": []}))
        except Exception as e:
            print(json.dumps({"explanation": f"Error processing input: {str(e)}", "suggested_rules": []}))
    else:
        # Keep example usage for manual testing if needed, or just print usage
        print(json.dumps({"explanation": "Please provide metrics JSON via stdin.", "suggested_rules": []}))
