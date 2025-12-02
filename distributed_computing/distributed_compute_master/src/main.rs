// src/main.rs (Master Node: UPDATED with Camera Frame Display)

slint::include_modules!();

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tonic::{transport::{Server, Channel}, Request, Response, Status};
use uuid::Uuid;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};
use sysinfo::System;

pub mod compute {
    tonic::include_proto!("compute"); 
}

use compute::{
    Resources, 
    worker_client::WorkerClient, 
    TaskRequest,
    master_monitor_server::{MasterMonitor, MasterMonitorServer},
    WorkerLoad, 
    ReportStatus,
    ThreatDetection,
    CameraInfo,
    GeospatialAnalysisRequest,
    GeospatialAnalysisResult,
    NetworkAnalysisRequest,
    NetworkAnalysisResult,
    ResponsePlan,
    ThreatCluster,
    GeoLocation,
};

#[derive(Debug, Clone)]
struct WorkerInfo {
    ip_address: String,
    capacity: Resources, 
    current_load: WorkerLoad,
    last_heartbeat: std::time::Instant,
}

#[derive(Debug)]
struct WorkerClientHandle {
    client: WorkerClient<Channel>,
    ip_address: String,
}

#[derive(Debug)]
struct AppState {
    log: String,
    status: String,
    worker_registry: HashMap<String, WorkerInfo>,
    client_pool: HashMap<String, WorkerClientHandle>,
    system: System,
    threat_database: ThreatDatabase,
    camera_registry: HashMap<String, CameraInfo>,
    active_response_plans: HashMap<String, ResponsePlan>,
    // NEW: Store latest camera frame
    latest_camera_frame: Option<Vec<u8>>,
    latest_camera_id: String,
}

#[derive(Debug, Clone)]
struct ThreatDatabase {
    threats: Vec<ThreatDetection>,
    geospatial_cache: HashMap<String, GeospatialAnalysisResult>,
    network_cache: HashMap<String, NetworkAnalysisResult>,
}

impl ThreatDatabase {
    fn new() -> Self {
        Self {
            threats: Vec::new(),
            geospatial_cache: HashMap::new(),
            network_cache: HashMap::new(),
        }
    }
    
    fn add_threat(&mut self, threat: ThreatDetection) {
        self.threats.push(threat);
        if self.threats.len() > 1000 {
            self.threats.remove(0);
        }
    }
    
    #[allow(dead_code)]
    fn get_recent_threats(&self, window_ms: i64) -> Vec<&ThreatDetection> {
        let now = chrono::Utc::now().timestamp_millis();
        self.threats.iter()
            .filter(|t| now - t.timestamp < window_ms)
            .collect()
    }
}

impl AppState {
    fn new() -> Self {
        AppState {
            log: String::from("System started. Ready to connect.\n"),
            status: String::from("Disconnected"),
            worker_registry: HashMap::new(),
            client_pool: HashMap::new(),
            system: System::new_all(),
            threat_database: ThreatDatabase::new(),
            camera_registry: HashMap::new(),
            active_response_plans: HashMap::new(),
            latest_camera_frame: None,
            latest_camera_id: String::from("No camera"),
        }
    }
    
    fn add_threat(&mut self, threat: ThreatDetection) {
        // NEW: Update camera frame if this is a frame update
        if threat.threat_type == "frame_update" && !threat.frame_snapshot.is_empty() {
            self.latest_camera_frame = Some(threat.frame_snapshot.clone());
            self.latest_camera_id = threat.camera_id.clone();
        }
        
        self.threat_database.add_threat(threat.clone());
        
        // Only log actual threats, not frame updates
        if threat.threat_type != "frame_update" {
            self.append_log(&format!("🚨 THREAT: {} - {}\n", 
                threat.threat_type, 
                severity_to_string(threat.severity)
            ));
        }
    }
    
    fn append_log(&mut self, message: &str) {
        self.log.push_str(message);
    }
    
    fn set_status(&mut self, status: &str) {
        self.status = status.to_string();
    }
}

struct MasterMonitorService {
    app_state: Arc<Mutex<AppState>>,
    ui_weak: slint::Weak<AppWindow>,
}

#[tonic::async_trait]
impl MasterMonitor for MasterMonitorService {
    async fn report_load(
        &self,
        request: Request<WorkerLoad>,
    ) -> Result<Response<ReportStatus>, Status> {
        let load = request.into_inner();
        let worker_id = load.worker_id.clone();
        
        let mut state_guard = self.app_state.lock().unwrap();
        
        if let Some(info) = state_guard.worker_registry.get_mut(&worker_id) {
            info.current_load = load.clone();
            info.last_heartbeat = std::time::Instant::now();

            let ui_update = self.ui_weak.clone();
            let workers_data = get_workers_slint_data(
                &state_guard.worker_registry,
                &state_guard.camera_registry 
            );
            
            drop(state_guard);
            
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_update.upgrade() {
                    ui.set_workers(std::rc::Rc::new(slint::VecModel::from(workers_data)).into());
                }
            });

            Ok(Response::new(ReportStatus {
                accepted: true,
                message: format!("Load from {} accepted.", worker_id),
            }))
        } else {
            state_guard.append_log(&format!("!! Unregistered worker reported load: {}\n", worker_id));
            
            Ok(Response::new(ReportStatus {
                accepted: false,
                message: "Worker not registered.".to_string(),
            }))
        }
    }
    
    async fn report_threat(
        &self,
        request: Request<ThreatDetection>,
    ) -> Result<Response<ReportStatus>, Status> {
        let threat = request.into_inner();
        let severity = threat.severity;
        let is_frame_update = threat.threat_type == "frame_update";
        
        // NEW: Update UI with camera frame
        if is_frame_update && !threat.frame_snapshot.is_empty() {
            let frame_data = threat.frame_snapshot.clone();
            let camera_id = threat.camera_id.clone();
            let ui_weak = self.ui_weak.clone();
            
            // Convert JPEG bytes to Slint Image
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    // Try loading from memory
                    match image::load_from_memory(&frame_data) {
                        Ok(dynamic_img) => {
                            // Convert to RGBA for Slint
                            let rgba = dynamic_img.to_rgba8();
                            let width = rgba.width();
                            let height = rgba.height();
                            
                            // Get raw bytes directly
                            let raw_bytes = rgba.into_raw();
                            
                            // Create Slint SharedPixelBuffer directly from raw bytes
                            // The bytes are already in RGBA format, 4 bytes per pixel
                            let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                                &raw_bytes,
                                width,
                                height,
                            );
                            
                            ui.set_camera_frame(slint::Image::from_rgba8(buffer));
                            ui.set_camera_id(camera_id.into());
                        }
                        Err(e) => {
                            eprintln!("Failed to decode camera frame: {}", e);
                        }
                    }
                }
            });
        }
        
        {
            let mut state = self.app_state.lock().unwrap();
            state.add_threat(threat.clone());
        }
        
        if severity >= 3 && !is_frame_update {
            let _ = self.generate_response_plan(threat).await;
        }
        
        Ok(Response::new(ReportStatus {
            accepted: true,
            message: "Threat logged".to_string(),
        }))
    }
    
    async fn request_geospatial_analysis(
        &self,
        request: Request<GeospatialAnalysisRequest>,
    ) -> Result<Response<GeospatialAnalysisResult>, Status> {
        let req = request.into_inner();
        
        Ok(Response::new(GeospatialAnalysisResult {
            analysis_id: req.analysis_id,
            tracks: vec![],
            clusters: vec![],
            hot_zones: vec![],
            recommended_response: None,
        }))
    }
    
    async fn request_network_analysis(
        &self,
        request: Request<NetworkAnalysisRequest>,
    ) -> Result<Response<NetworkAnalysisResult>, Status> {
        let req = request.into_inner();
        
        Ok(Response::new(NetworkAnalysisResult {
            analysis_id: req.analysis_id,
            patterns: vec![],
            anomalies: vec![],
            network: None,
            predictions: vec![],
        }))
    }
    
    async fn get_response_plan(
        &self,
        request: Request<ThreatDetection>,
    ) -> Result<Response<ResponsePlan>, Status> {
        let threat = request.into_inner();
        let plan = self.generate_response_plan(threat).await?;
        Ok(Response::new(plan))
    }
    
    type StreamAllThreatsStream = tokio_stream::wrappers::ReceiverStream<Result<ThreatDetection, Status>>;
    
    async fn stream_all_threats(
        &self,
        _request: Request<CameraInfo>,
    ) -> Result<Response<Self::StreamAllThreatsStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(100);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
    
    type StreamActivePlansStream = tokio_stream::wrappers::ReceiverStream<Result<ResponsePlan, Status>>;
    
    async fn stream_active_plans(
        &self,
        _request: Request<CameraInfo>,
    ) -> Result<Response<Self::StreamActivePlansStream>, Status> {
        let (_tx, rx) = tokio::sync::mpsc::channel(100);
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

impl MasterMonitorService {
    async fn generate_response_plan(
        &self,
        threat: ThreatDetection,
    ) -> Result<ResponsePlan, Status> {
        Ok(ResponsePlan {
            plan_id: uuid::Uuid::new_v4().to_string(),
            threat_level: threat.severity,
            immediate_actions: vec![],
            allocations: vec![],
            camera_adjustments: vec![],
            alerts: vec![],
            estimated_response_time_seconds: 300.0,
        })
    }
}

fn severity_to_string(severity: i32) -> String {
    match severity {
        0 => "INFO",
        1 => "LOW",
        2 => "MEDIUM",
        3 => "HIGH",
        4 => "CRITICAL",
        _ => "UNKNOWN",
    }.to_string()
}

fn get_workers_slint_data(
    registry: &HashMap<String, WorkerInfo>, 
    camera_registry: &HashMap<String, CameraInfo>
) -> Vec<WorkerNode> {
    registry.iter().map(|(id, info)| {
        let load = &info.current_load;
        let worker_status = if info.last_heartbeat.elapsed() > Duration::from_secs(10) {
            "Inactive".to_string()
        } else {
            "Active".to_string()
        };
        
        let has_camera_flag = camera_registry.contains_key(id);

        WorkerNode {
            id: id.clone().into(),
            ip: info.ip_address.clone().into(),
            status: worker_status.into(),
            cpu_usage: (load.cpu_load_percent * 100.0) as f32,
            ram_usage: (load.ram_used_bytes as f32 / info.capacity.ram_bytes as f32 * 100.0),
            gpu_usage: (load.gpu_vram_used_bytes as f32 / info.capacity.gpu_vram_bytes as f32 * 100.0),
            has_camera: has_camera_flag,
            location: "Unknown".to_string().into(),
        }
    }).collect()
}

fn find_worker(
    registry: &HashMap<String, WorkerInfo>, 
    required: &Resources
) -> Option<String> {
    let mut best_worker_id: Option<String> = None;
    let mut lowest_gpu_vram_used: u64 = u64::MAX;

    for (id, info) in registry.iter() {
        let capacity = &info.capacity;
        let load = &info.current_load;
        
        let is_active = info.last_heartbeat.elapsed() < Duration::from_secs(10);
        let cpu_ok = capacity.cpu_cores >= required.cpu_cores;
        let ram_ok = capacity.ram_bytes >= required.ram_bytes;
        let gpu_capacity_ok = if required.gpu_vram_bytes > 0 {
            capacity.gpu_vram_bytes >= required.gpu_vram_bytes
        } else {
            true
        };

        if !is_active || !cpu_ok || !ram_ok || !gpu_capacity_ok {
            continue;
        }

        let remaining_vram = capacity.gpu_vram_bytes.saturating_sub(load.gpu_vram_used_bytes);
        let vram_available_ok = remaining_vram >= required.gpu_vram_bytes;

        if vram_available_ok && load.gpu_vram_used_bytes < lowest_gpu_vram_used {
            lowest_gpu_vram_used = load.gpu_vram_used_bytes;
            best_worker_id = Some(id.clone());
        }
    }
    
    best_worker_id
}

fn update_gui_weak(ui_weak: &slint::Weak<AppWindow>, log: String, status: String) {
    let ui_clone = ui_weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui_clone.upgrade() {
            ui.set_connection_status(status.into());
            ui.set_log_text(log.into());
        }
    });
}

async fn dispatch_task(
    state: Arc<Mutex<AppState>>,
    ui_weak: slint::Weak<AppWindow>, 
    target_ip: String,
    task_request: TaskRequest,
) -> Result<(), tonic::Status> {
    
    let client_handle = {
        let state_guard = state.lock().unwrap();
        state_guard.client_pool.get(&target_ip).map(|h| h.client.clone())
    };

    if client_handle.is_none() {
        let mut state_guard = state.lock().unwrap();
        state_guard.append_log(&format!("Error: No client found for dispatch IP: {}\n", target_ip));
        let log = state_guard.log.clone();
        let status = state_guard.status.clone();
        drop(state_guard);
        update_gui_weak(&ui_weak, log, status);
        return Err(tonic::Status::unavailable("Client not in pool"));
    }
    
    let mut client = client_handle.unwrap();
    let task_id = task_request.task_id.clone();
    
    {
        let mut state_guard = state.lock().unwrap();
        state_guard.append_log(&format!("-> Dispatching Task {} to {}.\n", task_id, target_ip));
        let log = state_guard.log.clone();
        let status = state_guard.status.clone();
        drop(state_guard);
        update_gui_weak(&ui_weak, log, status);
    }

    match client.execute_task(task_request).await {
        Ok(response) => {
            let task_result = response.into_inner();
            let mut state_guard = state.lock().unwrap();
            state_guard.append_log(&format!("<- Task {} completed by {}: {}\n", 
                task_result.task_id, 
                task_result.worker_id, 
                String::from_utf8_lossy(&task_result.output_data)
            ));
            let log = state_guard.log.clone();
            let status = state_guard.status.clone();
            drop(state_guard);
            update_gui_weak(&ui_weak, log, status);
            Ok(())
        }
        Err(e) => {
            let mut state_guard = state.lock().unwrap();
            state_guard.append_log(&format!("!! Task {} failed on {}: {:?}\n", task_id, target_ip, e));
            let log = state_guard.log.clone();
            let status = state_guard.status.clone();
            drop(state_guard);
            update_gui_weak(&ui_weak, log, status);
            Err(e)
        }
    }
}

async fn local_resource_monitor_task(
    state: Arc<Mutex<AppState>>, 
    ui_weak: slint::Weak<AppWindow>
) {
    loop {
        {
            let mut state_guard = state.lock().unwrap();
            state_guard.system.refresh_all();
            
            let stats = ResourceStats {
                cpu_usage: state_guard.system.global_cpu_usage(),
                cpu_cores: state_guard.system.cpus().len() as i32,
                gpu_usage: 0.0, 
                gpu_vram_used: 0.0,
                gpu_vram_total: 0.0, 
                ram_used: (state_guard.system.used_memory() / 1024 / 1024) as f32,
                ram_total: (state_guard.system.total_memory() / 1024 / 1024) as f32,
                storage_used: 0.0,
                storage_total: 0.0,
            };

            let ui_update = ui_weak.clone();
            drop(state_guard);

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_update.upgrade() {
                    ui.set_resource_stats(stats);
                }
            });
        }
        sleep(Duration::from_secs(1)).await;
    }
}

fn run_gui_app(rt: Arc<tokio::runtime::Runtime>) -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let ui_handle = ui.as_weak();
    let ui_handle2 = ui.as_weak(); 
    let ui_handle3 = ui.as_weak();
    let ui_monitor = ui.as_weak();
    
    let app_state = Arc::new(Mutex::new(AppState::new()));
    let state_callback = Arc::clone(&app_state);
    let state_monitor = Arc::clone(&app_state);

    rt.spawn(local_resource_monitor_task(Arc::clone(&app_state), ui_handle.clone()));

    let rt_server = Arc::clone(&rt);
    rt_server.spawn(async move {
        let monitor_addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
        println!("Master Monitor Server listening on {}", monitor_addr);

        let monitor_service = MasterMonitorService {
            app_state: state_monitor,
            ui_weak: ui_monitor,
        };

        Server::builder()
            .add_service(MasterMonitorServer::new(monitor_service))
            .serve(monitor_addr)
            .await
            .expect("Failed to start Master Monitor Server");
    });

    let rt_connect = Arc::clone(&rt);
    ui.on_connect_requested(move |ip_address| {
        let ui_weak = ui_handle.clone();
        let state = Arc::clone(&state_callback);
        let rt = Arc::clone(&rt_connect);

        let target_address = if ip_address.contains(':') {
            ip_address.to_string()
        } else {
            format!("{}:50051", ip_address)
        };

        rt.spawn(async move {
            let update_gui_inner = |ui_weak: slint::Weak<AppWindow>, log: String, status: String| {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_connection_status(status.into());
                        ui.set_log_text(log.into());
                    }
                });
            };

            {
                let mut state_guard = state.lock().unwrap();
                state_guard.append_log(&format!("Attempting gRPC connection to: {}\n", target_address));
                state_guard.set_status("Connecting...");
                update_gui_inner(ui_weak.clone(), state_guard.log.clone(), state_guard.status.clone());
            }

            let endpoint = format!("http://{}", target_address);
            
            match WorkerClient::connect(endpoint.clone()).await {
                Ok(client) => {
                    let log_status;
                    let connection_status;

                    {
                        let mut state_guard = state.lock().unwrap();
                        state_guard.append_log(&format!("Successfully connected to worker at {}\n", target_address));
                        state_guard.set_status("Connected");
                        
                        state_guard.client_pool.insert(target_address.clone(), WorkerClientHandle {
                            client: client.clone(),
                            ip_address: target_address.clone(),
                        });
                        
                        log_status = state_guard.log.clone();
                        connection_status = state_guard.status.clone();
                    }
                    
                    update_gui_inner(ui_weak.clone(), log_status, connection_status);
                    
                    let mut registration_client = client.clone();

                    match registration_client.register_worker(Resources {
                        cpu_cores: 0,
                        ram_bytes: 0,
                        gpu_vram_bytes: 0,
                        gpu_model: String::new(),
                    }).await {
                        Ok(response) => {
                            let (log_final, status_final);
                            
                            {
                                let worker_status = response.into_inner();
                                let mut state_guard = state.lock().unwrap();
                                state_guard.append_log(&format!("Worker Status: {}\n", worker_status.message));
                                
                                if let Some(capacity) = worker_status.capacity {
                                    let initial_load = WorkerLoad {
                                        worker_id: target_address.clone(),
                                        cpu_load_percent: 0.0,
                                        ram_used_bytes: 0,
                                        gpu_vram_used_bytes: 0,
                                        active_tasks: 0,
                                    };
                                    
                                    state_guard.worker_registry.insert(target_address.clone(), WorkerInfo {
                                        ip_address: target_address.clone(),
                                        capacity,
                                        current_load: initial_load,
                                        last_heartbeat: std::time::Instant::now(),
                                    });
                                    let worker_count = state_guard.worker_registry.len();
                                    state_guard.append_log(&format!("-> Registered 1 Worker (Total: {})\n", worker_count));
                                }
                                
                                log_final = state_guard.log.clone();
                                status_final = state_guard.status.clone();
                            }

                            update_gui_inner(ui_weak.clone(), log_final, status_final);
                        }
                        Err(e) => {
                            let (log_err, status_err);
                            {
                                let mut state_guard = state.lock().unwrap();
                                state_guard.append_log(&format!("Registration failed: {:?}\n", e));
                                log_err = state_guard.log.clone();
                                status_err = state_guard.status.clone();
                            }
                            update_gui_inner(ui_weak.clone(), log_err, status_err);
                        }
                    }
                }
                Err(e) => {
                    let (log_err, status_err);
                    {
                        let mut state_guard = state.lock().unwrap();
                        state_guard.append_log(&format!("Connection failed: {:?}\n", e));
                        state_guard.set_status("Error");
                        log_err = state_guard.log.clone();
                        status_err = state_guard.status.clone();
                    }
                    update_gui_inner(ui_weak.clone(), log_err, status_err);
                }
            }
        });
    });

    let state_for_task = Arc::clone(&app_state);
    let rt_for_task = Arc::clone(&rt);
    ui.on_send_test_task(move || {
        let ui_weak = ui_handle2.clone(); 
        let state = Arc::clone(&state_for_task);
        let rt = Arc::clone(&rt_for_task);

        rt.spawn(async move {
            let required_resources = Resources {
                cpu_cores: 2,
                ram_bytes: 2_000_000_000,
                gpu_vram_bytes: 4_000_000_000,
                gpu_model: "Any GPU".to_string(),
            };
            
            let target_ip = {
                let state_guard = state.lock().unwrap();
                find_worker(&state_guard.worker_registry, &required_resources) 
            };

            if let Some(ip) = target_ip {
                let task_request = TaskRequest {
                    task_id: format!("{}", Uuid::new_v4()),
                    task_type: 0,
                    required_resources: Some(required_resources),
                    job_data: b"Stream Marvel Rivals for cousin".to_vec(),
                };
                
                let _ = dispatch_task(state.clone(), ui_weak.clone(), ip, task_request).await; 
            } else {
                let mut state_guard = state.lock().unwrap();
                state_guard.append_log("!! Scheduler: No worker found with sufficient AND available resources for GPU gaming task (4GB VRAM).\n");
                let log = state_guard.log.clone();
                let status = state_guard.status.clone();
                drop(state_guard);
                update_gui_weak(&ui_weak, log, status);
            }
        });
    });
    
    let state_for_refresh = Arc::clone(&app_state);
    ui.on_refresh_stats(move || {
        let state_guard = state_for_refresh.lock().unwrap();
        
        let workers_data = get_workers_slint_data(
            &state_guard.worker_registry,
            &state_guard.camera_registry
        );
        
        let log = state_guard.log.clone();
        let status = state_guard.status.clone();
        
        let ui_clone = ui_handle3.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_clone.upgrade() {
                ui.set_workers(std::rc::Rc::new(slint::VecModel::from(workers_data)).into());
                ui.set_connection_status(status.into());
                ui.set_log_text(log.into());
            }
        });
    });

    let initial_state = app_state.lock().unwrap();
    ui.set_connection_status(initial_state.status.clone().into());
    ui.set_log_text(initial_state.log.clone().into());
    drop(initial_state);

    ui.run()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    
    let rt_arc = Arc::new(rt);

    run_gui_app(rt_arc).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}