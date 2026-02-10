use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web::web::Bytes;
use actix_cors::Cors;

use std::sync::{Arc, Mutex};

use crate::models::{LogEntry, Rule, ParsingRule};
use crate::rules_engine::RulesEngine;
use crate::log_processor::{process_sequential, process_parallel, process_distributed, parse_log_content};
// ai_module functions are used via crate::ai_module::prefix

pub struct AppState {
    pub rules_engine: Arc<Mutex<RulesEngine>>,
    pub parsing_rules: Arc<Mutex<Vec<ParsingRule>>>,
}

#[post("/api/logs/upload")]
pub async fn upload_log_endpoint(log_content: Bytes, data: web::Data<AppState>) -> impl Responder {
    let log_string = match String::from_utf8(log_content.to_vec()) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid UTF-8 sequence: {}", e)),
    };

    let log_entries = parse_log_content(log_string, Arc::clone(&data.parsing_rules));
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

// ... imports

#[post("/api/ai/explain-alert")]
pub async fn explain_alert_endpoint(alert: web::Json<serde_json::Value>) -> impl Responder {
    match crate::ai_module::explain_alert(alert.into_inner()) {
        Some(explanation) => HttpResponse::Ok().json(explanation),
        None => HttpResponse::InternalServerError().body("Failed to generate AI explanation"),
    }
}

#[post("/api/ai/generate-rule")]
pub async fn generate_rule_endpoint(req: web::Json<serde_json::Value>) -> impl Responder {
    let description = if let Some(desc) = req.get("description").and_then(|v| v.as_str()) {
        desc.to_string()
    } else if let Some(desc_str) = req.as_str() {
        desc_str.to_string()
    } else {
        return HttpResponse::BadRequest().body("Invalid input. Expected JSON with 'description' field or a raw string.");
    };

    match crate::ai_module::generate_rule_from_description(&description) {
        Ok(rule) => HttpResponse::Ok().json(rule),
        Err(e) => HttpResponse::InternalServerError().body(format!("AI Error: {}", e)),
    }
}

pub async fn run_server(rules_engine: Arc<Mutex<RulesEngine>>, parsing_rules: Vec<ParsingRule>) -> std::io::Result<()> {
    // Load rules from rules.json at startup
    let rules_path = "rules.json";
    let rules_content = std::fs::read_to_string(rules_path)
        .expect(&format!("Failed to read rules file: {}", rules_path));
    {
        let mut rules_engine_locked = rules_engine.lock().unwrap();
        rules_engine_locked.load_rules(&rules_content)
            .expect("Failed to load rules from JSON");
    }

    let parsing_rules_arc = Arc::new(Mutex::new(parsing_rules));

    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin() // Temporarily allow any origin for debugging
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![actix_web::http::header::AUTHORIZATION, actix_web::http::header::ACCEPT])
            .allowed_header(actix_web::http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(actix_web::middleware::Logger::default()) // Enable request logging
            .wrap(cors)
            .app_data(web::Data::new(AppState { 
                rules_engine: Arc::clone(&rules_engine),
                parsing_rules: Arc::clone(&parsing_rules_arc),
            }))
            .service(load_rules_endpoint)
            .service(get_rules_endpoint)
            .service(add_rule_endpoint)
            .service(analyze_sequential_endpoint)
            .service(analyze_parallel_endpoint)
            .service(analyze_distributed_endpoint)
            .service(explain_alert_endpoint)
            .service(generate_rule_endpoint)
            .service(upload_log_endpoint)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
