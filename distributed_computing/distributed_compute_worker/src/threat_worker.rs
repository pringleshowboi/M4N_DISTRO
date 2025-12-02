// src/threat_worker.rs
// Add-on threat intelligence master - runs alongside compute master

use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::collections::HashMap;

slint::include_modules!();

pub mod threat {
    tonic::include_proto!("threat");
}

use threat::{
    CameraInfo, ThreatDetection, CameraStatus,
    RegisterCameraRequest, RegisterCameraResponse,
    ThreatReport, ThreatReportResponse,
    StatusUpdate, StatusUpdateResponse,
    threat_master_server::{ThreatMaster, ThreatMasterServer},
};

// In-memory database
#[derive(Debug, Clone)]
pub struct ThreatDatabase {
    pub threats: Vec<ThreatDetection>,
    pub cameras: HashMap<String, CameraStatus>,
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

    pub fn update_camera(&mut self, status: CameraStatus) {
        self.cameras.insert(status.camera_id.clone(), status);
    }
}

// Threat Master Service
pub struct ThreatMasterService {
    db: Arc<RwLock<ThreatDatabase>>,
    alert_tx: mpsc::Sender<ThreatDetection>,
    ui_weak: slint::Weak<crate::ThreatDashboard>,
}

impl ThreatMasterService {
    pub fn new(
        db: Arc<RwLock<ThreatDatabase>>,
        alert_tx: mpsc::Sender<ThreatDetection>,
        ui_weak: slint::Weak<crate::ThreatDashboard>,
    ) -> Self {
        Self { db, alert_tx, ui_weak }
    }

    async fn update_dashboard(&self) {
        let db = self.db.read().await;
        
        let total_threats = db.threats.len();
        let critical_threats = db.threats.iter()
            .filter(|t| t.severity == "critical")
            .count();
        let active_cameras = db.cameras.values()
            .filter(|c| c.is_active)
            .count();

        // Convert to Slint types
        let threats_slint: Vec<crate::ThreatEvent> = db.threats.iter()
            .rev()
            .take(50)
            .map(|t| crate::ThreatEvent {
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

        let cameras_slint: Vec<crate::CameraFeed> = db.cameras.values()
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

                crate::CameraFeed {
                    camera_id: c.camera_id.clone().into(),
                    location: c.camera_id.clone().into(),
                    status: if c.is_active { "active" } else { "inactive" }.to_string().into(),
                    fps: c.current_fps as f32,
                    threat_level: threat_level.to_string().into(),
                    last_detection: "Just now".to_string().into(),
                    active_threats: c.detections_count,
                }
            })
            .collect();

        let metrics = crate::SystemMetrics {
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
impl ThreatMaster for ThreatMasterService {
    async fn register_camera(
        &self,
        request: Request<RegisterCameraRequest>,
    ) -> Result<Response<RegisterCameraResponse>, Status> {
        let req = request.into_inner();
        let camera_info = req.camera_info.ok_or_else(|| 
            Status::invalid_argument("Camera info required")
        )?;

        println!("📹 Camera registered: {}", camera_info.camera_id);

        let status = CameraStatus {
            camera_id: camera_info.camera_id.clone(),
            is_active: true,
            current_fps: camera_info.fps,
            detections_count: 0,
            last_frame_time: chrono::Utc::now().timestamp_millis(),
        };

        {
            let mut db = self.db.write().await;
            db.update_camera(status);
        }

        self.update_dashboard().await;

        Ok(Response::new(RegisterCameraResponse {
            success: true,
            message: "Camera registered successfully".to_string(),
        }))
    }

    async fn report_threat(
        &self,
        request: Request<ThreatReport>,
    ) -> Result<Response<ThreatReportResponse>, Status> {
        let report = request.into_inner();
        let threat = report.detection.ok_or_else(||
            Status::invalid_argument("Detection required")
        )?;

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

        Ok(Response::new(ThreatReportResponse {
            accepted: true,
            message: "Threat logged".to_string(),
        }))
    }

    async fn update_status(
        &self,
        request: Request<StatusUpdate>,
    ) -> Result<Response<StatusUpdateResponse>, Status> {
        let update = request.into_inner();
        let status = update.status.ok_or_else(||
            Status::invalid_argument("Status required")
        )?;

        {
            let mut db = self.db.write().await;
            db.update_camera(status);
        }

        self.update_dashboard().await;

        Ok(Response::new(StatusUpdateResponse {
            received: true,
        }))
    }

    type StreamThreatsStream = mpsc::Receiver<Result<ThreatDetection, Status>>;

    async fn stream_threats(
        &self,
        _request: Request<CameraInfo>,
    ) -> Result<Response<Self::StreamThreatsStream>, Status> {
        let (tx, rx) = mpsc::channel(100);
        Ok(Response::new(rx))
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
    
    let ui = crate::ThreatDashboard::new()?;
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
            .add_service(ThreatMasterServer::new(service))
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
    ui.set_metrics(crate::SystemMetrics {
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