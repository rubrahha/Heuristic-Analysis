#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use tauri_plugin_shell::ShellExt;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // ── 1. Boot up the Python AI Brain ──
            match app.shell().sidecar("BrainEngine") {
                Ok(cmd) => {
                    cmd.spawn().expect("Failed to spawn Python Brain");
                    println!("BrainEngine started successfully.");
                }
                Err(e) => println!("Failed to find BrainEngine: {}", e),
            }

            // ── 2. Boot up the C++ Kernel Sensor ──
            match app.shell().sidecar("HeuristicSensor") {
                Ok(cmd) => {
                    cmd.spawn().expect("Failed to spawn C++ Sensor");
                    println!("HeuristicSensor started successfully.");
                }
                Err(e) => println!("Failed to find HeuristicSensor: {}", e),
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}