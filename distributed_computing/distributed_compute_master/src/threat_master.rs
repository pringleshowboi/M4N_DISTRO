// src/threat_master.rs
// Add-on threat intelligence master - runs alongside compute master

use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::collections::HashMap;

slint::include_modules!();

// Import from the compute module that's being generated
pub mod compute {
    tonic::include_proto!("compute");
}

use compute::{
    CameraInfo, ThreatDetection,
    master_monitor_server::{MasterMonitor, MasterMonitorServer},
};

// In-memory database
#[derive(Debug, Clone)]
pub struct ThreatDatabase {
    pub threats: Vec<ThreatDetection>,
    pub cameras: HashMap<String, CameraInfo>,
}

impl ThreatDatabase {
    pub fn new() -> Self {
        Self {
            threats: Vec::new(),
            cameras: HashMap::new(),
        }
    }

    pub fn add_threat(&mut self, threat: ThreatDetection) {
        self.threats.push(threat);
        if self.threats.len() > 500 {
            self.threats.remove(0);
        }
    }

    pub fn update_camera(&mut self, camera: CameraInfo) {
        self.cameras.insert(camera.camera_id.clone(), camera);
    }

    pub fn get_recent_threats(&self, window_ms: i64) -> Vec<&ThreatDetection> {
        let now = chrono::Utc::now().timestamp_millis();
        self.threats.iter()
            .filter(|t| now - t.timestamp < window_ms)
            .collect()
    }
}

// Threat Master Service
pub struct ThreatMasterService {
    db: Arc<RwLock<ThreatDatabase>>,
    alert_tx: mpsc::Sender<ThreatDetection>,
    ui_weak: slint::Weak<ThreatDashboard>,
}

impl ThreatMasterService {
    pub fn new(
        db: Arc<RwLock<ThreatDatabase>>,
        alert_tx: mpsc::Sender<ThreatDetection>,
        ui_weak: slint::Weak<ThreatDashboard>,
    ) -> Self {
        Self { db, alert_tx, ui_weak }
    }

    async fn update_dashboard(&self) {
        let db = self.db.read().await;
        
        let total_threats = db.threats.len();
        let critical_threats = db.threats.iter()
            .filter(|t| t.severity == "critical")
            .count();
        let active_cameras = db.cameras.len();

        // Convert to Slint types
        let threats_slint: Vec<ThreatEvent> = db.threats.iter()
            .rev()
            .take(50)
            .map(|t| ThreatEvent {
                id: t.detection_id.clone().into(),
                camera_id: t.camera_id.clone().into(),
                threat_type: t.threat_type.clone().into(),
                severity: t.severity.clone().into(),
                confidence: t.confidence as f32,
                timestamp: format_timestamp(t.timestamp).into(),
                location: t.camera_id.clone().into(),
                description: t.description.clone().into(),
            })
            .collect();

        let cameras_slint: Vec<CameraFeed> = db.cameras.values()
            .map(|c| {
                let recent_threats = db.threats.iter()
                    .filter(|t| t.camera_id == c.camera_id)
                    .filter(|t| {
                        let now = chrono::Utc::now().timestamp_millis();
                        now - t.timestamp < 60000 // Last minute
                    })
                    .count();
                
                let threat_level = if recent_threats > 5 {
                    "critical"
                } else if recent_threats > 2 {
                    "high"
                } else if recent_threats > 0 {
                    "medium"
                } else {
                    "low"
                };

                CameraFeed {
                    camera_id: c.camera_id.clone().into(),
                    location: c.location.clone().into(),
                    status: "active".to_string().into(),
                    fps: c.fps as f32,
                    threat_level: threat_level.to_string().into(),
                    last_detection: "Just now".to_string().into(),
                    active_threats: recent_threats as i32,
                }
            })
            .collect();

        let metrics = SystemMetrics {
            total_cameras: db.cameras.len() as i32,
            active_cameras: active_cameras as i32,
            total_threats: total_threats as i32,
            critical_threats: critical_threats as i32,
            processing_fps: 10.0,
            ai_workers: db.cameras.len() as i32,
        };

        let ui_clone = self.ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_clone.upgrade() {
                ui.set_metrics(metrics);
                ui.set_threats(std::rc::Rc::new(slint::VecModel::from(threats_slint)).into());
                ui.set_cameras(std::rc::Rc::new(slint::VecModel::from(cameras_slint)).into());
            }
        });
    }
}

#[tonic::async_trait]
impl MasterMonitor for ThreatMasterService {
    async fn report_threat(
        &self,
        request: Request<ThreatDetection>,
    ) -> Result<Response<compute::Acknowledgment>, Status> {
        let threat = request.into_inner();

        println!("🚨 THREAT: {} - {} ({}%)", 
            threat.threat_type,
            threat.severity,
            (threat.confidence * 100.0) as i32
        );

        {
            let mut db = self.db.write().await;
            db.add_threat(threat.clone());
        }

        let _ = self.alert_tx.send(threat).await;
        self.update_dashboard().await;

        Ok(Response::new(compute::Acknowledgment {
            success: true,
            message: "Threat logged".to_string(),
        }))
    }

    async fn analyze_geospatial(
        &self,
        request: Request<compute::GeospatialAnalysisRequest>,
    ) -> Result<Response<compute::GeospatialAnalysisResult>, Status> {
        let _req = request.into_inner();
        
        // Placeholder implementation
        Ok(Response::new(compute::GeospatialAnalysisResult {
            clusters: vec![],
            hot_zones: vec![],
            movement_tracks: vec![],
        }))
    }

    async fn analyze_network(
        &self,
        request: Request<compute::NetworkAnalysisRequest>,
    ) -> Result<Response<compute::NetworkAnalysisResult>, Status> {
        let _req = request.into_inner();
        
        // Placeholder implementation
        Ok(Response::new(compute::NetworkAnalysisResult {
            patterns: vec![],
            anomalies: vec![],
            threat_network: None,
            predictions: vec![],
        }))
    }

    async fn generate_response(
        &self,
        request: Request<ThreatDetection>,
    ) -> Result<Response<compute::ResponsePlan>, Status> {
        let _threat = request.into_inner();
        
        // Placeholder implementation
        Ok(Response::new(compute::ResponsePlan {
            plan_id: "plan_001".to_string(),
            priority: "high".to_string(),
            actions: vec![],
            alerts: vec![],
            resource_allocations: vec![],
            estimated_response_time: 300,
        }))
    }
}

fn format_timestamp(timestamp_ms: i64) -> String {
    let dt = chrono::DateTime::from_timestamp_millis(timestamp_ms)
        .unwrap_or_else(|| chrono::Utc::now().into());
    dt.format("%H:%M:%S").to_string()
}

// Main entry point for threat master
pub async fn run_threat_intelligence(
    rt: Arc<tokio::runtime::Runtime>,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("🛡️  Starting Threat Intelligence System...");
    
    let ui = ThreatDashboard::new()?;
    let ui_weak = ui.as_weak();
    
    let db = Arc::new(RwLock::new(ThreatDatabase::new()));
    let (alert_tx, mut alert_rx) = mpsc::channel::<ThreatDetection>(100);

    // Start gRPC server
    let service = ThreatMasterService::new(
        Arc::clone(&db),
        alert_tx,
        ui_weak.clone(),
    );

    let addr = "0.0.0.0:50053".parse()?;
    println!("🎯 Threat Master listening on {}", addr);

    let rt_server = Arc::clone(&rt);
    rt_server.spawn(async move {
        Server::builder()
            .add_service(MasterMonitorServer::new(service))
            .serve(addr)
            .await
            .expect("Failed to start threat master");
    });

    // Alert processing
    let ui_alert = ui_weak.clone();
    rt.spawn(async move {
        while let Some(threat) = alert_rx.recv().await {
            if threat.severity == "critical" {
                println!("🚨🚨🚨 CRITICAL ALERT: {}", threat.description);
            }
        }
    });

    // UI Callbacks
    ui.on_start_detection(move || {
        println!("▶ AI Detection Started");
    });

    ui.on_stop_detection(move || {
        println!("⏸ AI Detection Stopped");
    });

    ui.on_add_camera(move |location| {
        println!("➕ Add camera at: {}", location);
    });

    ui.on_export_threats(move || {
        println!("💾 Exporting threats...");
    });

    ui.on_acknowledge_threat(move |threat_id| {
        println!("✓ Acknowledged: {}", threat_id);
    });

    ui.set_ai_detection_active(false);
    ui.set_metrics(SystemMetrics {
        total_cameras: 0,
        active_cameras: 0,
        total_threats: 0,
        critical_threats: 0,
        processing_fps: 0.0,
        ai_workers: 0,
    });

    ui.run()?;

    Ok(())
}