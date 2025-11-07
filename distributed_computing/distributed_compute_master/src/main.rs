// src/main.rs (Master Node: Slint + gRPC Client + Scheduler)

// This macro will find the generated Rust code for the UI
slint::include_modules!(); 

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tonic::transport::Channel;
use uuid::Uuid;

// --- 1. Import Generated gRPC Code ---
pub mod compute {
    tonic::include_proto!("compute"); 
}

// Import the types directly from the compute module
use compute::{
    Resources, 
    worker_client::WorkerClient, 
    TaskRequest,
};

// --- Worker Registry Structures ---

/// Holds connection and capacity information for a worker.
#[derive(Debug, Clone)]
struct WorkerInfo {
    ip_address: String,
    capacity: Resources, 
}

/// Helper struct combining client and address for thread-safe access.
struct WorkerClientHandle {
    client: WorkerClient<Channel>,
    ip_address: String,
}

// --- Application State ---
struct AppState {
    log: String,
    status: String,
    worker_registry: HashMap<String, WorkerInfo>, 
    client_pool: HashMap<String, WorkerClientHandle>,
}

impl AppState {
    fn new() -> Self {
        AppState {
            log: String::from("System started. Ready to connect.\n"),
            status: String::from("Disconnected"),
            worker_registry: HashMap::new(),
            client_pool: HashMap::new(),
        }
    }

    fn append_log(&mut self, message: &str) {
        self.log.push_str(message);
        self.log.push_str("\n");
    }

    fn set_status(&mut self, new_status: &str) {
        self.status = new_status.to_string();
    }
}

// --- Resource Scheduler Logic ---

/// Resource Scheduler: Finds a worker that meets the required resources.
fn find_worker(
    registry: &HashMap<String, WorkerInfo>, 
    required: &Resources
) -> Option<String> {
    registry.iter()
        .filter(|(_, info)| {
            let capacity = &info.capacity;
            
            // Checks if worker capacity meets required resources
            let cpu_ok = capacity.cpu_cores >= required.cpu_cores;
            let ram_ok = capacity.ram_bytes >= required.ram_bytes;
            let gpu_ok = if required.gpu_vram_bytes > 0 {
                capacity.gpu_vram_bytes >= required.gpu_vram_bytes && 
                !capacity.gpu_model.is_empty()
            } else {
                true
            };
            
            cpu_ok && ram_ok && gpu_ok
        })
        .map(|(ip, _)| ip.clone())
        .next()
}

// --- Task Dispatch Logic ---

// Helper function to update the GUI log safely using weak reference
fn update_gui_weak(ui_weak: &slint::Weak<crate::AppWindow>, log: String, status: String) {
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
    ui_weak: slint::Weak<crate::AppWindow>,  // Changed to weak reference
    target_ip: String,
    task_request: TaskRequest,
) -> Result<(), tonic::Status> {
    
    // Get client handle from pool
    let client_handle = {
        let state_guard = state.lock().unwrap();
        state_guard.client_pool.get(&target_ip).map(|h| h.client.clone())
    };

    if client_handle.is_none() {
        let mut state_guard = state.lock().unwrap();
        state_guard.append_log(&format!("Error: No client found for dispatch IP: {}", target_ip));
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
        state_guard.append_log(&format!("-> Dispatching Task {} to {}.", task_id, target_ip));
        let log = state_guard.log.clone();
        let status = state_guard.status.clone();
        drop(state_guard);
        update_gui_weak(&ui_weak, log, status);
    }

    match client.execute_task(task_request).await {
        Ok(response) => {
            let task_result = response.into_inner();
            let mut state_guard = state.lock().unwrap();
            state_guard.append_log(&format!("<- Task {} completed by {}: {}", 
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
            state_guard.append_log(&format!("!! Task {} failed on {}: {:?}", task_id, target_ip, e));
            let log = state_guard.log.clone();
            let status = state_guard.status.clone();
            drop(state_guard);
            update_gui_weak(&ui_weak, log, status);
            Err(e)
        }
    }
}


// --- Main Application Function ---

fn run_gui_app(rt: Arc<tokio::runtime::Runtime>) -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let ui_handle = ui.as_weak();
    let ui_handle2 = ui.as_weak();  // Second weak reference for second callback
    
    // State shared across threads
    let app_state = Arc::new(Mutex::new(AppState::new()));
    let state_callback = Arc::clone(&app_state);

    // --- 1. Connect/Register Worker Callback ---
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
            // Helper function that takes a weak reference
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
                state_guard.append_log(&format!("Attempting gRPC connection to: {}", target_address));
                state_guard.set_status("Connecting...");
                update_gui_inner(ui_weak.clone(), state_guard.log.clone(), state_guard.status.clone());
            }

            let endpoint = format!("http://{}", target_address);
            
            match WorkerClient::connect(endpoint.clone()).await {
                Ok(client) => {
                    let mut state_guard = state.lock().unwrap();
                    state_guard.append_log(&format!("Successfully connected to worker at {}", target_address));
                    state_guard.set_status("Connected");
                    
                    // Add client handle to the pool
                    state_guard.client_pool.insert(target_address.clone(), WorkerClientHandle {
                        client: client.clone(),
                        ip_address: target_address.clone(),
                    });
                    
                    update_gui_inner(ui_weak.clone(), state_guard.log.clone(), state_guard.status.clone());
                    
                    // Clone the client before dropping the guard
                    let mut registration_client = client.clone();
                    drop(state_guard);

                    // --- Registration RPC ---
                    match registration_client.register_worker(compute::Resources {
                        cpu_cores: 0,
                        ram_bytes: 0,
                        gpu_vram_bytes: 0,
                        gpu_model: String::new(),
                    }).await {
                        Ok(response) => {
                            let worker_status = response.into_inner();
                            let mut state_guard = state.lock().unwrap();
                            state_guard.append_log(&format!("Worker Status: {}", worker_status.message));
                            
                            // Save Worker Info (Resources) to Registry
                            if let Some(capacity) = worker_status.capacity {
                                state_guard.worker_registry.insert(target_address.clone(), WorkerInfo {
                                    ip_address: target_address.clone(),
                                    capacity,
                                });
                                let worker_count = state_guard.worker_registry.len();
                                state_guard.append_log(&format!("-> Registered 1 Worker (Total: {})", worker_count));
                            }
                            update_gui_inner(ui_weak.clone(), state_guard.log.clone(), state_guard.status.clone());
                        }
                        Err(e) => {
                            let mut state_guard = state.lock().unwrap();
                            state_guard.append_log(&format!("Registration failed: {:?}", e));
                            update_gui_inner(ui_weak.clone(), state_guard.log.clone(), state_guard.status.clone());
                        }
                    }
                }
                Err(e) => {
                    let mut state_guard = state.lock().unwrap();
                    state_guard.append_log(&format!("Connection failed: {:?}", e));
                    state_guard.set_status("Error");
                    update_gui_inner(ui_weak.clone(), state_guard.log.clone(), state_guard.status.clone());
                }
            }
        });
    });

    // --- 2. Send Test Task Callback (Scheduler Demo) ---
    let state_for_task = Arc::clone(&app_state);
    let rt_for_task = Arc::clone(&rt);
    ui.on_send_test_task(move || {
        let ui_weak = ui_handle2.clone();  // Use second weak reference
        let state = Arc::clone(&state_for_task);
        let rt = Arc::clone(&rt_for_task);

        rt.spawn(async move {
            let required_resources = Resources {
                cpu_cores: 0, 
                ram_bytes: 3_000_000_000,
                gpu_vram_bytes: 0,
                gpu_model: "".to_string(),
            };
            
            // 1. Run Scheduler
            let target_ip = {
                let state_guard = state.lock().unwrap();
                find_worker(&state_guard.worker_registry, &required_resources)
            };

            // 2. Dispatch Task
            if let Some(ip) = target_ip {
                let task_request = TaskRequest {
                    task_id: format!("{}", Uuid::new_v4()),
                    required_resources: Some(required_resources),
                    job_data: b"Data for 3GB RAM task".to_vec(),
                };
                
                // Dispatch the task to the chosen worker (pass weak reference)
                let _ = dispatch_task(state.clone(), ui_weak.clone(), ip, task_request).await; 
            } else {
                let mut state_guard = state.lock().unwrap();
                state_guard.append_log("!! Scheduler: No worker found with sufficient resources for 3GB RAM task.");
                let log = state_guard.log.clone();
                let status = state_guard.status.clone();
                drop(state_guard);
                update_gui_weak(&ui_weak, log, status);
            }
        });
    });


    // --- 3. Initial GUI Data Binding & Run ---
    let initial_state = app_state.lock().unwrap();
    ui.set_connection_status(initial_state.status.clone().into());
    ui.set_log_text(initial_state.log.clone().into());
    drop(initial_state);

    ui.run()
}


// The actual main entry point for the executable
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the Tokio multi-threaded runtime.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    
    // Wrap the runtime in an Arc for thread safety and easy sharing
    let rt_arc = Arc::new(rt);

    // Map the slint::PlatformError to Box<dyn Error>
    run_gui_app(rt_arc).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}