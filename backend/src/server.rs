use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web::web::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::models::{LogEntry, Rule, Metrics};
use crate::rules_engine::RulesEngine;
use crate::log_processor::{process_sequential, process_parallel, process_distributed, parse_log_content};
use crate::ai_module::{explain_log_entry, generate_rule_from_description, AiExplanation};

pub struct AppState {
    pub rules_engine: Arc<Mutex<RulesEngine>>,
}

#[post("/api/logs/upload")]
pub async fn upload_log_endpoint(log_content: Bytes, data: web::Data<AppState>) -> impl Responder {
    let log_string = match String::from_utf8(log_content.to_vec()) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid UTF-8 sequence: {}", e)),
    };

    let log_entries = parse_log_content(log_string);
    let rules_engine_arc = Arc::clone(&data.rules_engine);
    let alerts = process_sequential(log_entries, rules_engine_arc);
    HttpResponse::Ok().json(alerts)
}


#[post("/api/rules/load")]
pub async fn load_rules_endpoint(rules_json: web::Json<String>, data: web::Data<AppState>) -> impl Responder {
    let mut rules_engine = data.rules_engine.lock().unwrap();
    match rules_engine.load_rules(&rules_json.into_inner()) {
        Ok(_) => HttpResponse::Ok().body("Rules loaded successfully"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to load rules: {}", e)),
    }
}

#[get("/api/rules")]
pub async fn get_rules_endpoint(data: web::Data<AppState>) -> impl Responder {
    let rules_engine = data.rules_engine.lock().unwrap();
    HttpResponse::Ok().json(&rules_engine.rules)
}

#[post("/api/rules/add")]
pub async fn add_rule_endpoint(rule: web::Json<Rule>, data: web::Data<AppState>) -> impl Responder {
    let mut rules_engine = data.rules_engine.lock().unwrap();
    rules_engine.add_rule(rule.into_inner());
    HttpResponse::Ok().body("Rule added successfully")
}

#[post("/api/analyze/sequential")]
pub async fn analyze_sequential_endpoint(log_entries: web::Json<Vec<LogEntry>>, data: web::Data<AppState>) -> impl Responder {
    let rules_engine_arc = Arc::clone(&data.rules_engine);
    let alerts = process_sequential(log_entries.into_inner(), rules_engine_arc);
    HttpResponse::Ok().json(alerts)
}

#[post("/api/analyze/parallel")]
pub async fn analyze_parallel_endpoint(log_entries: web::Json<Vec<LogEntry>>, data: web::Data<AppState>) -> impl Responder {
    let rules_engine_arc = Arc::clone(&data.rules_engine);
    let alerts = process_parallel(log_entries.into_inner(), rules_engine_arc);
    HttpResponse::Ok().json(alerts)
}

#[post("/api/analyze/distributed")]
pub async fn analyze_distributed_endpoint(log_entries: web::Json<Vec<LogEntry>>, data: web::Data<AppState>) -> impl Responder {
    let rules_engine_arc = Arc::clone(&data.rules_engine);
    let alerts = process_distributed(log_entries.into_inner(), rules_engine_arc);
    HttpResponse::Ok().json(alerts)
}

#[post("/api/ai/explain")]
pub async fn explain_log_endpoint(log_entry: web::Json<LogEntry>) -> impl Responder {
    let explanation = explain_log_entry(&log_entry.into_inner());
    HttpResponse::Ok().json(explanation)
}

#[post("/api/ai/generate-rule")]
pub async fn generate_rule_endpoint(description: web::Json<String>) -> impl Responder {
    match generate_rule_from_description(&description.into_inner()) {
        Some(rule) => HttpResponse::Ok().json(rule),
        None => HttpResponse::InternalServerError().body("Failed to generate rule"),
    }
}

pub async fn run_server(rules_engine: Arc<Mutex<RulesEngine>>) -> std::io::Result<()> {
    // Load rules from rules.json at startup
    let rules_path = "backend/rules.json";
    let rules_content = std::fs::read_to_string(rules_path)
        .expect(&format!("Failed to read rules file: {}", rules_path));
    {
        let mut rules_engine_locked = rules_engine.lock().unwrap();
        rules_engine_locked.load_rules(&rules_content)
            .expect("Failed to load rules from JSON");
    }

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { rules_engine: Arc::clone(&rules_engine) }))
            .service(load_rules_endpoint)
            .service(get_rules_endpoint)
            .service(add_rule_endpoint)
            .service(analyze_sequential_endpoint)
            .service(analyze_parallel_endpoint)
            .service(analyze_distributed_endpoint)
            .service(explain_log_endpoint)
            .service(generate_rule_endpoint)
            .service(upload_log_endpoint)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
