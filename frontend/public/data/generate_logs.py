import datetime
import random
import os
import argparse

def generate_log_entry(timestamp, log_id):
    levels = ["INFO", "WARN", "ERROR", "DEBUG"]
    
    # Normal and Malicious messages to test rules
    messages = [
        "User logged in successfully.",
        "Resource accessed.",
        "Database query executed.",
        "API call received.",
        "System health check.",
        "File download initiated.",
        "Configuration updated.",
        "Service restarted.",
        # Malicious entries to trigger alerts
        "Failed password for user root",
        "authentication failure for user admin",
        "Permission denied for user guest accessing /etc/passwd",
        "access denied to /var/www/html/config.php",
        "SELECT * FROM users WHERE '1'='1'",
        "OR '1'='1' --",
        "Nmap scan detected",
        "port scan from malicious-ip.com",
        "high traffic alert detected on eth0",
        "Possible DoS attack in progress",
    ]
    
    ip_addresses = [f"192.168.1.{i}" for i in range(1, 255)] + [f"10.0.0.{i}" for i in range(1, 255)]
    user_ids = [f"user_{i:04d}" for i in range(1, 100)]

    level = random.choice(levels)
    message = random.choice(messages)
    ip_address = random.choice(ip_addresses)
    user_id = random.choice(user_ids) if random.random() > 0.2 else "N/A"

    return f"{timestamp.isoformat()}Z {level} {ip_address} {user_id} {message} (LogID:{log_id})"

def generate_log_file(file_path, num_entries):
    print(f"Generating {num_entries} log entries to {file_path}...")
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    with open(file_path, "w") as f:
        start_time = datetime.datetime.now() - datetime.timedelta(days=1)
        for i in range(num_entries):
            time_offset_seconds = random.uniform(0, 24 * 60 * 60)
            timestamp = start_time + datetime.timedelta(seconds=time_offset_seconds)
            f.write(generate_log_entry(timestamp, i + 1) + "\n")
            if (i + 1) % 10000 == 0:
                print(f"Generated {i + 1}/{num_entries} entries...")
    print(f"Finished generating {num_entries} log entries.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate dummy logs for testing.")
    parser.add_argument("--entries", type=int, default=1000, help="Number of logs to generate (default: 1000 to stay under 256KB limit)")
    parser.add_argument("--output", type=str, default="test_malicious_large.log", help="Output file path")
    
    args = parser.parse_args()
    
    generate_log_file(args.output, args.entries)

