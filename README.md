# Distributed Log Analysis & Threat Detection Engine

This project implements a distributed log analysis and threat detection engine with a Rust backend and an Astro frontend. It supports sequential, parallel, and distributed master-worker execution modes for log processing, along with AI-assisted explanation and rule generation.

## Project Structure

- `backend/`: Contains the Rust backend code.
  - `src/`: Rust source files for log parsing, threat detection, analysis modes, and utilities.
  - `rules.json`: Configuration file for threat detection rules.
- `frontend/`: Contains the Astro frontend code.
  - `src/components/`: Astro and React components for the UI.
  - `src/layouts/`: Astro layouts.
  - `src/pages/`: Astro pages.
  - `public/data/`: Example log files and metrics data.
- `generate_logs.py`: Python script to generate example log data.
- `README.md`: This file.

## Features

### Backend (Rust)
- **Execution Modes**: Sequential, Parallel (using Rayon), and Distributed Master-Worker for scalable log processing.
- **Concurrency**: Utilizes Tokio for asynchronous networking and `Arc<Mutex>` for thread-safe shared state.
- **Modular Design**: Well-organized codebase with clear separation of concerns.
- **Threat Detection**: Configurable threat detection rules loaded from `rules.json`.
- **AI-Assisted Analysis**: Rust-only AI for log explanation and rule generation.
- **Error Handling**: Robust error handling using Rust's `Result` type.

### Frontend (Astro + React)
- **Modern UI**: Built with Astro for static content and React for interactive components (Astro Islands Architecture).
- **Log Analysis Dashboard**: Displays performance metrics (execution time, logs per second, alerts generated) and active rules.
- **Log Upload**: Allows users to upload log files for analysis.
- **AI Explanation**: Provides natural language explanations and recommendations based on analysis results.

## Setup and Installation

### Prerequisites
- Rust (latest stable version)
- Node.js (LTS version) and npm/yarn

### 1. Clone the Repository

```bash
git clone <repository_url>
cd project
```

### 2. Generate Example Logs (Optional)

If you want to generate a large example log file for testing, you can use the provided Python script:

```bash
python generate_logs.py
```
This will create `frontend/public/data/example_log.txt` with 500k-1M log entries. You can also upload your own log files.

### 3. Backend Setup (Rust)

Navigate to the `backend` directory and build the Rust project. The backend will automatically load rules from `backend/rules.json` on startup.

```bash
cd backend
cargo build --release
```

To run the backend server:

```bash
cargo run --release
```

The backend will expose an API for the frontend to interact with, typically on `http://127.0.0.1:8080`.

### 4. Frontend Setup (Astro)

Open a new terminal, navigate to the `frontend` directory, and install dependencies:

```bash
cd frontend
npm install
```

To start the Astro development server:

```bash
npm run dev
```

This will typically start the server at `http://localhost:4321`. Open this URL in your browser to access the dashboard.

## Rules Management

Threat detection rules are defined in `backend/rules.json`. This file is loaded by the backend at startup. You can modify this file to add, remove, or update rules. Each rule is a JSON object with the following structure:

```json
[
  {
    "id": "unique_rule_id",
    "name": "Rule Name",
    "pattern": ".*regex_pattern.*",
    "description": "A description of what this rule detects.",
    "alert_type": "BruteForce", // or HighFrequencyRequest, SuspiciousActivity, Custom("YourType")
    "enabled": true
  }
]
```

- `id`: A unique identifier for the rule.
- `name`: A human-readable name for the rule.
- `pattern`: A regular expression that will be matched against the `details` field of incoming log entries. Ensure your regex is valid.
- `description`: A brief explanation of what the rule is designed to detect.
- `alert_type`: The type of alert to generate when this rule is triggered. Can be one of `BruteForce`, `HighFrequencyRequest`, `SuspiciousActivity`, or `Custom("YourType")`.
- `enabled`: A boolean indicating whether the rule is active (`true`) or disabled (`false`).

After modifying `rules.json`, you must restart the backend server for the changes to take effect.

## Usage

1. **Start the Backend**: In a terminal, navigate to the `backend` directory and run `cargo run --release`.
2. **Start the Frontend**: In a separate terminal, navigate to the `frontend` directory and run `npm run dev`.
3. **Access the Dashboard**: Open your web browser and go to `http://localhost:4321`.
4. **Upload Log Files**: Use the "Upload Log File" button to select and upload a `.log` or `.txt` file. The backend will process it and display initial alerts.
5. **Analyze Logs**: Use the "Run Sequential", "Run Parallel", and "Run Distributed" buttons to re-analyze the loaded log data using different processing modes. Performance metrics and alerts will be updated in real-time.
   - **Note on Distributed Mode**: The current implementation of "Run Distributed" is a placeholder and will fall back to sequential processing. True distributed processing would require integration with a distributed system.
6. **Get AI Explanation**: Click the "Get AI Explanation" button to receive an AI-generated summary and recommendations based on the log analysis.

## For Users Unfamiliar with Rust/Commands

If you're new to Rust or command-line operations, here are some basic tips:

- **Installing Rust**: Follow the instructions on the official Rust website: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
- **Installing Node.js**: Download and install the LTS version from the official Node.js website: [https://nodejs.org/](https://nodejs.org/)
- **Terminal/Command Prompt**: You'll need to use a terminal (Linux/macOS) or Command Prompt/PowerShell (Windows) to run commands.
- **`cd` command**: Use `cd <directory_name>` to change your current directory. For example, `cd backend` will move you into the `backend` folder.
- **`git clone`**: This command downloads the project from its repository. Replace `<repository_url>` with the actual URL of this project.
- **`cargo build --release`**: This command compiles the Rust backend code. `--release` optimizes it for performance.
- **`cargo run --release`**: This command compiles (if not already built) and runs the Rust backend application.
- **`npm install`**: This command downloads and installs all necessary JavaScript dependencies for the frontend.
- **`npm run dev`**: This command starts the frontend development server, making the web interface accessible in your browser.

## Contributing

Feel free to fork the repository and contribute. Please follow standard coding practices and submit pull requests.

## License

[Specify your license here, e.g., MIT, Apache 2.0, etc.]
