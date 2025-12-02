// distributed_compute_worker/src/camera_worker.rs

use nokhwa::{
    pixel_format::RgbFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};
use image::{ImageBuffer, Rgb, ImageFormat};
use std::io::Cursor;
use uuid::Uuid;

pub mod compute {
    tonic::include_proto!("compute");
}

use compute::{
    ThreatDetection, BoundingBox, GeoLocation,
    master_monitor_client::MasterMonitorClient,
};

pub async fn start_camera_mode() -> Result<(), Box<dyn std::error::Error>> {
    let worker_id = std::env::var("WORKER_ID")
        .unwrap_or_else(|_| format!("worker-{}", Uuid::new_v4()));
    let master_address = std::env::var("MASTER_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string());
    let camera_type = std::env::var("CAMERA_TYPE")
        .unwrap_or_else(|_| "webcam".to_string());

    println!("🎥 Starting Camera Worker");
    println!("   Worker ID: {}", worker_id);
    println!("   Master: {}", master_address);
    println!("   Camera Type: {}", camera_type);

    match camera_type.as_str() {
        "webcam" => start_webcam_stream(worker_id, master_address).await,
        "ip" => start_ip_camera_stream(worker_id, master_address).await,
        "raspi" => start_raspi_camera_stream(worker_id, master_address).await,
        _ => {
            eprintln!("Unknown camera type: {}", camera_type);
            eprintln!("Supported: webcam, ip, raspi");
            std::process::exit(1);
        }
    }
}

// WEBCAM Implementation
async fn start_webcam_stream(
    worker_id: String,
    master_address: String,
) -> Result<(), Box<dyn std::error::Error>> {
    
    println!("📹 Opening webcam...");
    
    let camera_index = CameraIndex::Index(0);
    let requested = RequestedFormat::new::<RgbFormat>(
        RequestedFormatType::AbsoluteHighestFrameRate
    );
    
    let mut camera = match Camera::new(camera_index, requested) {
        Ok(cam) => {
            println!("✓ Webcam opened successfully");
            cam
        }
        Err(e) => {
            eprintln!("❌ Failed to open webcam: {}", e);
            eprintln!("   Troubleshooting:");
            eprintln!("   - Check webcam is connected");
            eprintln!("   - Close other apps using camera");
            eprintln!("   - Linux: sudo usermod -a -G video $USER");
            return Err(e.into());
        }
    };

    let camera_id = format!("webcam-{}", worker_id);
    let master_url = format!("http://{}", master_address);
    
    let mut master_client = match MasterMonitorClient::connect(master_url.clone()).await {
        Ok(client) => {
            println!("✓ Connected to master at {}", master_address);
            client
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to master: {}", e);
            return Err(e.into());
        }
    };

    let mut frame_number = 0i64;

    println!("🎬 Starting frame capture...");

    loop {
        // Capture frame
        let frame = match camera.frame() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("⚠️  Frame capture error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        // Decode to RGB
        let decoded = frame.decode_image::<RgbFormat>()
            .expect("Failed to decode");
        let width = decoded.width();
        let height = decoded.height();
        
        // Convert to JPEG
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_raw(
            width,
            height,
            decoded.into_raw(),
        ).expect("Failed to create image buffer");

        let mut jpeg_data = Vec::new();
        img.write_to(&mut Cursor::new(&mut jpeg_data), ImageFormat::Jpeg)
            .expect("Failed to encode JPEG");

        // Send frame preview every 30 frames (~3 seconds at 10 FPS)
        if frame_number % 30 == 0 {
            let frame_update = ThreatDetection {
                detection_id: format!("frame-{}", frame_number),
                camera_id: camera_id.clone(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                threat_type: "frame_update".to_string(),
                confidence: 1.0,
                severity: 0, // INFO
                bbox: None,
                estimated_location: Some(GeoLocation {
                    latitude: -33.9249,
                    longitude: 18.4241,
                    address: "Cape Town".to_string(),
                    zone_id: "zone-1".to_string(),
                }),
                frame_snapshot: jpeg_data.clone(),
                description: format!("Frame preview {}", frame_number),
            };
            
            match master_client.report_threat(frame_update).await {
                Ok(_) => println!("📸 Frame {} sent", frame_number),
                Err(e) => eprintln!("⚠️  Failed to send frame: {}", e),
            }
        }

        // Simulate AI detection (replace with real model)
        let detections = simulate_threat_detection(
            &camera_id,
            &jpeg_data,
            frame_number,
        );

        // Report threats to master
        for detection in detections {
            match master_client.report_threat(detection.clone()).await {
                Ok(_) => println!("🚨 Threat reported: {} (severity: {})", detection.threat_type, detection.severity),
                Err(e) => eprintln!("⚠️  Failed to report threat: {}", e),
            }
        }

        frame_number += 1;

        // Limit to ~10 FPS to avoid overwhelming master
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

// IP CAMERA Implementation (Placeholder)
async fn start_ip_camera_stream(
    worker_id: String,
    master_address: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("📹 IP Camera streaming (placeholder)");
    println!("   Worker ID: {}", worker_id);
    println!("   Master: {}", master_address);
    
    println!("⚠️  IP camera support not yet implemented");
    println!("   Use CAMERA_TYPE=webcam for now");
    
    std::thread::sleep(std::time::Duration::from_secs(60));
    Ok(())
}

// RASPBERRY PI Camera Implementation (Placeholder)
async fn start_raspi_camera_stream(
    worker_id: String,
    master_address: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("📹 Raspberry Pi camera streaming (placeholder)");
    println!("   Worker ID: {}", worker_id);
    println!("   Master: {}", master_address);
    
    println!("⚠️  Raspberry Pi camera support not yet implemented");
    println!("   Use CAMERA_TYPE=webcam for now");
    
    std::thread::sleep(std::time::Duration::from_secs(60));
    Ok(())
}

// Simulated AI detection (replace with YOLO/TensorFlow)
fn simulate_threat_detection(
    camera_id: &str,
    jpeg_data: &[u8],
    frame_number: i64,
) -> Vec<ThreatDetection> {
    let mut detections = Vec::new();
    
    // Simulate detection every 10 frames
    if frame_number % 10 == 0 && rand::random::<f32>() > 0.6 {
        detections.push(ThreatDetection {
            detection_id: Uuid::new_v4().to_string(),
            camera_id: camera_id.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            threat_type: "person".to_string(),
            confidence: 0.85 + (rand::random::<f64>() * 0.14),
            severity: 1, // LOW
            bbox: Some(BoundingBox {
                x: 100,
                y: 100,
                width: 200,
                height: 300,
            }),
            estimated_location: Some(GeoLocation {
                latitude: -33.9249,
                longitude: 18.4241,
                address: "Cape Town".to_string(),
                zone_id: "zone-1".to_string(),
            }),
            frame_snapshot: jpeg_data.to_vec(),
            description: "Person detected in frame".to_string(),
        });
    }

    // Simulate critical threat (rare)
    if rand::random::<f32>() > 0.98 {
        detections.push(ThreatDetection {
            detection_id: Uuid::new_v4().to_string(),
            camera_id: camera_id.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            threat_type: "weapon".to_string(),
            confidence: 0.82,
            severity: 4, // CRITICAL
            bbox: Some(BoundingBox {
                x: 250,
                y: 150,
                width: 100,
                height: 80,
            }),
            estimated_location: Some(GeoLocation {
                latitude: -33.9249,
                longitude: 18.4241,
                address: "Cape Town".to_string(),
                zone_id: "zone-1".to_string(),
            }),
            frame_snapshot: jpeg_data.to_vec(),
            description: "⚠️ WEAPON DETECTED".to_string(),
        });
    }

    detections
}