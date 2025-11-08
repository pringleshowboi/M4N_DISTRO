// build.rs

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- 1. gRPC Code Generation ---
    // Don't add Debug or Default - they conflict with prost::Message
    tonic_prost_build::configure()
        .compile_protos(&["proto/resource_manager.proto"], &["proto"])?;

    Ok(())
}