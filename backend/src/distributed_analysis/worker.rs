use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use crate::models::{Metrics, Alert, WorkerMessage, MasterMessage};
use std::sync::{Arc, Mutex};
use std::error::Error;

pub async fn run_worker(worker_id: usize) -> Result<(), Box<dyn Error>> {
    let addr = format!("127.0.0.1:{}", 8081 + worker_id as u16);
    let listener = TcpListener::bind(&addr).await?;
    println!("Worker {} listening on {}", worker_id, addr);

    let mut threat_detector: Option<ThreatDetector> = None;
    let mut processed_logs_count = 0;
    let mut generated_alerts: Vec<Alert> = Vec::new();

    loop {
        let (mut socket, _) = listener.accept().await?;
        println!("Worker {} accepted connection from master", worker_id);

        let mut len_bytes = [0u8; 4];
        socket.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut buffer = vec![0u8; len];
        socket.read_exact(&mut buffer).await?;

        let message: WorkerMessage = serde_json::from_slice(&buffer)?;

        match message {
            WorkerMessage::LogChunk(log_entries) => {
                println!("Worker {} received log chunk of {} entries", worker_id, log_entries.len());
                processed_logs_count += log_entries.len();
                if let Some(detector) = &mut threat_detector {
                    for log_entry in log_entries {
                        if let Some(alert) = detector.detect_threats(&log_entry) {
                            generated_alerts.push(alert);
                        }
                    }
                }
                let response = MasterMessage::Ack;
                let serialized_response = serde_json::to_vec(&response)?;
                socket.write_all(&(serialized_response.len() as u32).to_le_bytes()).await?;
                socket.write_all(&serialized_response).await?;
            },
            WorkerMessage::Rules(rules) => {
                println!("Worker {} received {} rules", worker_id, rules.len());
                threat_detector = Some(ThreatDetector::new(rules));
                let response = MasterMessage::Ack;
                let serialized_response = serde_json::to_vec(&response)?;
                socket.write_all(&(serialized_response.len() as u32).to_le_bytes()).await?;
                socket.write_all(&serialized_response).await?;
            },
            WorkerMessage::StartAnalysis => {
                println!("Worker {} received start analysis command", worker_id);
                // This message is now redundant as analysis happens on LogChunk receipt
                let response = MasterMessage::Ack;
                let serialized_response = serde_json::to_vec(&response)?;
                socket.write_all(&(serialized_response.len() as u32).to_le_bytes()).await?;
                socket.write_all(&serialized_response).await?;
            },
            WorkerMessage::Shutdown => {
                println!("Worker {} received shutdown command. Sending results and exiting.", worker_id);
                let metrics = Metrics {
                    total_logs_processed: processed_logs_count,
                    execution_time_ms: 0, // Worker doesn't track overall time
                    logs_per_second: 0.0, // Worker doesn't track overall rate
                    alerts_generated: generated_alerts,
                    mode: "Distributed Worker".to_string(),
                };
                let response = MasterMessage::AnalysisResult(metrics);
                let serialized_response = serde_json::to_vec(&response)?;
                socket.write_all(&(serialized_response.len() as u32).to_le_bytes()).await?;
                socket.write_all(&serialized_response).await?;
                break;
            },
        }
    }

    Ok(())
}
