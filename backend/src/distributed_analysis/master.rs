use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::models::{LogEntry, Alert, Metrics, Rule, WorkerMessage, MasterMessage};
use std::time::Instant;
use chrono::{Utc};

const WORKER_PORT: u16 = 8081;

pub async fn run_master(log_lines: Vec<String>, rules: Vec<Rule>, num_workers: usize) -> Result<Metrics, Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", WORKER_PORT)).await?;
    println!("Master listening on port {}", WORKER_PORT);

    let mut worker_handles = Vec::new();
    let mut worker_streams = Vec::new();

    for i in 0..num_workers {
        println!("Waiting for worker {}", i + 1);
        let (stream, _) = listener.accept().await?;
        worker_streams.push(stream);
        println!("Worker {} connected", i + 1);
    }

    // Send rules to all workers
    for stream in &mut worker_streams {
        let rules_message = WorkerMessage::Rules(rules.clone());
        let serialized_rules = serde_json::to_vec(&rules_message)?;
        stream.write_all(&(serialized_rules.len() as u32).to_le_bytes()).await?;
        stream.write_all(&serialized_rules).await?;
    }

    let chunk_size = (log_lines.len() + num_workers - 1) / num_workers;
    let mut all_alerts: Vec<Alert> = Vec::new();
    let mut total_processed_logs = 0;

    let mut handles = Vec::new();

    for (i, mut stream) in worker_streams.into_iter().enumerate() {
        let start_index = i * chunk_size;
        let end_index = (start_index + chunk_size).min(log_lines.len());
        let chunk = log_lines[start_index..end_index].to_vec();

        let handle = tokio::spawn(async move {
            let log_entries_chunk: Vec<LogEntry> = chunk.into_iter().map(|line| LogEntry {
                timestamp: Utc::now(), // Assign current UTC timestamp
                details: line,
            }).collect();
            let log_chunk_message = WorkerMessage::LogChunk(log_entries_chunk);
            let serialized_chunk = serde_json::to_vec(&log_chunk_message)?;
            stream.write_all(&(serialized_chunk.len() as u32).to_le_bytes()).await?;
            stream.write_all(&serialized_chunk).await?;

            // Read ACK response from worker for LogChunk
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut buffer = vec![0u8; len];
            stream.read_exact(&mut buffer).await?;
            let worker_ack: MasterMessage = serde_json::from_slice(&buffer)?;
            match worker_ack {
                MasterMessage::Ack => println!("Worker acknowledged log chunk."),
                _ => return Err(Box::<dyn std::error::Error + Send + Sync>::from("Unexpected worker response after log chunk.")),
            }

            // Store the stream to send shutdown later
            Ok(stream)
        }) as tokio::task::JoinHandle<Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>>>;
        handles.push(handle);
    }

    let mut worker_streams_for_shutdown = Vec::new();
    for handle in handles {
        worker_streams_for_shutdown.push(handle.await??);
    }

    // Now send shutdown messages and collect final results
    let mut final_handles = Vec::new();
    for mut stream in worker_streams_for_shutdown {
        let handle = tokio::spawn(async move {
            let shutdown_message = WorkerMessage::Shutdown;
            let serialized_shutdown = serde_json::to_vec(&shutdown_message)?;
            stream.write_all(&(serialized_shutdown.len() as u32).to_le_bytes()).await?;
            stream.write_all(&serialized_shutdown).await?;

            // Read final analysis result from worker
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            let mut buffer = vec![0u8; len];
            stream.read_exact(&mut buffer).await?;
            let worker_result: MasterMessage = serde_json::from_slice(&buffer)?;

            Ok(worker_result)
        });
        final_handles.push(handle);
    }

    for handle in final_handles {
        match handle.await? {
            Ok(MasterMessage::AnalysisResult(metrics)) => {
                all_alerts.extend(metrics.alerts_generated);
                total_processed_logs += metrics.total_logs_processed;
            },
            Ok(MasterMessage::Error(e)) => eprintln!("Worker error during shutdown: {}", e),
            _ => eprintln!("Unexpected worker response during shutdown."),
        }
    }

    let elapsed_time = start_time.elapsed();
    let execution_time_ms = elapsed_time.as_millis();
    let logs_per_second = if execution_time_ms > 0 {
        (total_processed_logs as f64 / execution_time_ms as f64) * 1000.0
    } else {
        0.0
    };

    Ok(Metrics {
        total_logs_processed: total_processed_logs,
        execution_time_ms,
        logs_per_second,
        alerts_generated: all_alerts,
        mode: "Distributed".to_string(),
    })}
