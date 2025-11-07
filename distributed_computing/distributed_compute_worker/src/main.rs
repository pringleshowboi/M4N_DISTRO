// src/main.rs (Worker Node: gRPC Server)

use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

pub mod compute {
    tonic::include_proto!("compute");
}

use compute::{
    worker_server::{Worker, WorkerServer},
    Resources, TaskRequest, TaskResult, WorkerRegistrationStatus,
};

// --- Worker Node Implementation (The gRPC Server) ---

#[derive(Debug, Default)]
pub struct WorkerService {
    worker_id: String,
    capacity: Resources,
}

impl WorkerService {
    fn new(id: &str, capacity: Resources) -> Self {
        WorkerService {
            worker_id: id.to_string(),
            capacity,
        }
    }

    /// Helper to get actual system resources (Placeholder for now)
    fn get_system_resources() -> Resources {
        // NOTE: Use a crate like `sysinfo` for production
        Resources {
            cpu_cores: 8,
            ram_bytes: 32_000_000_000,
            gpu_vram_bytes: 8_000_000_000,
            gpu_model: "NVIDIA RTX 3070".to_string(),
        }
    }
}

#[tonic::async_trait]
impl Worker for WorkerService {
    /// Implementation of the registration call (Master -> Worker Client)
    async fn register_worker(
        &self,
        _request: Request<Resources>,
    ) -> Result<Response<WorkerRegistrationStatus>, Status> {
        
        println!("\n*** Master Node connected and requested registration ***");
        println!("Worker ID: {}", self.worker_id);
        println!("Capacity: {:?}", self.capacity);

        // Crucial: Return the worker's capacity to the master
        let reply = WorkerRegistrationStatus {
            registered: true,
            message: format!("Worker {} registered successfully.", self.worker_id).into(),
            capacity: Some(self.capacity.clone()), 
        };

        Ok(Response::new(reply))
    }

    /// Implementation of the task execution call (Master -> Worker Client)
    async fn execute_task(
        &self,
        request: Request<TaskRequest>,
    ) -> Result<Response<TaskResult>, Status> {
        let task = request.into_inner();
        
        println!("\n--- Received Task ---");
        println!("Task ID: {}", task.task_id);
        
        println!("Simulating computation...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let result = TaskResult {
            task_id: task.task_id,
            success: true,
            output_data: b"Task completed successfully!".to_vec(),
            worker_id: self.worker_id.clone(),
        };
        
        println!("Task {} completed.", result.task_id);
        
        Ok(Response::new(result))
    }
}

// --- Main Server Setup ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse()?;
    
    let worker_id = format!("{}", Uuid::new_v4());
    let worker_capacity = WorkerService::get_system_resources();
    
    let worker_service = WorkerService::new(&worker_id, worker_capacity.clone());
    
    println!("Worker Node ID: {}", worker_id);
    println!("Capacity: {:?}", worker_capacity);
    println!("Listening for Master Node connection at {}", addr);
    
    Server::builder()
        .max_frame_size(Some(4 * 1024 * 1024))
        .add_service(WorkerServer::new(worker_service))
        .serve(addr)
        .await?;

    Ok(())
}