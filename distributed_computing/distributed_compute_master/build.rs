// build.rs

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- 1. gRPC Code Generation ---
    tonic_prost_build::configure()
        .compile_protos(
            &["proto/resource_manager.proto"], // Only this file now
            &["proto"]
        )?;

    // --- 2. Slint UI Code Generation ---
    slint_build::compile("src/ui/appwindow.slint")?;

    Ok(())
}