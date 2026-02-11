import datetime
import random
import os

def generate_normal_log_entry(timestamp, log_id):
    levels = ["INFO", "DEBUG", "SUCCESS"]
    messages = [
        "User session started.",
        "System heartbeat check: OK.",
        "Database connection pool: 12/20 active.",
        "Background task worker-1 completed successfully.",
        "Static asset served: /images/logo.png.",
        "DNS lookup for api.internal.svc took 4ms.",
        "Cache hit ratio: 94.2%.",
        "Load balancer health check passed.",
        "Memory usage within normal bounds (42%).",
        "Configuration reloaded successfully.",
    ]
    
    level = random.choice(levels)
    message = random.choice(messages)
    
    # Format: YYYY-MM-DD HH:MM:SS LEVEL Message
    return f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {level} {message}"

def generate_logs(file_path, num_entries):
    print(f"Generating {num_entries} normal log entries to {file_path}...")
    with open(file_path, "w") as f:
        start_time = datetime.datetime.now() - datetime.timedelta(hours=5)
        for i in range(num_entries):
            # Add a small random delay for each log
            start_time += datetime.timedelta(milliseconds=random.randint(10, 1000))
            f.write(generate_normal_log_entry(start_time, i + 1) + "\n")
    print(f"Finished generating {num_entries} log entries.")

if __name__ == "__main__":
    output_path = "logs.log"
    generate_logs(output_path, 10000)
