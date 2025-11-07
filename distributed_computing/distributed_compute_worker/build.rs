// build.rs (Master Node) - with optional derives

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // --- 1. gRPC Code Generation ---
    tonic_build::configure()
        .build_server(false)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile(
            &["proto/resource_manager.proto"],
            &["proto"],
        )?;

    // --- 2. Slint UI Code Generation ---
    slint_build::compile("src/ui/appwindow.slint")?;

    Ok(())
}