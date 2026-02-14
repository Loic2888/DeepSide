// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod dll_loader {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    use std::ffi::CString;
    use std::path::Path;

    pub fn preload_onnx() {
        println!("Attempting to preload ONNX Runtime DLL...");
        
        // Define paths where the custom DLL might be located
        // Order matters: check the specific bundled location first
        let paths = [
            "src-tauri/resources/lib/onnxruntime.dll", // Explicit path from root context
            "resources/lib/onnxruntime.dll",           // From src-tauri context
            "target/debug/onnxruntime.dll",            // Build dir
            "onnxruntime.dll",                         // CWD
        ];

        for p in paths {
            if Path::new(p).exists() {
                println!("   Found candidate at: {}", p);
                if let Ok(c_path) = CString::new(p) {
                    unsafe {
                        let handle = LoadLibraryA(c_path.as_ptr() as *const u8);
                        if !handle.is_null() {
                            println!("✅ SUCCESSFULLY PRELOADED ONNX Runtime (v1.20) from: {}", p);
                            // Set environment variable to help ort find it too (just in case)
                            if let Ok(abs_path) = std::fs::canonicalize(p) {
                                std::env::set_var("ORT_DYLIB_PATH", abs_path);
                            }
                            return;
                        } else {
                            println!("❌ LoadLibraryA returned 0 (Failed) for: {}", p);
                        }
                    }
                }
            }
        }
        println!("⚠️ WARNING: Could not preload custom ONNX Runtime DLL. System version might be used.");
    }
}

fn main() {
    #[cfg(windows)]
    dll_loader::preload_onnx();

    deepside_lib::run()
}
