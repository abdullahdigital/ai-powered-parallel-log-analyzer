# --- Builder Stage ---
FROM rust:1.81-slim-bullseye AS builder

WORKDIR /app
COPY backend/Cargo.toml backend/Cargo.lock ./backend/
COPY backend/src ./backend/src

# Pre-build dependencies for caching
WORKDIR /app/backend
RUN cargo build --release

# --- Final Stage ---
FROM python:3.11-slim-bullseye

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust backend
COPY --from=builder /app/backend/target/release/log_analysis_engine ./log_analyzer

# Setup Python environment
COPY ai_modules/requirements.txt ./ai_modules/
RUN pip install --no-cache-dir -r ai_modules/requirements.txt

# Copy AI scripts
COPY ai_modules/*.py ./ai_modules/

# Copy initial rules
COPY backend/rules.json ./rules.json

# Expose backend port
EXPOSE 8080

# Environment variables (to be provided at runtime or defaults)
ENV GEMINI_API_KEY=""
ENV PYTHON_INTERPRETER_PATH="python3"
ENV AI_EXPL_SCRIPT_PATH="./ai_modules/alert_explainer.py"
ENV AI_GEN_SCRIPT_PATH="./ai_modules/rule_generator.py"

CMD ["./log_analyzer", "--mode", "server"]
