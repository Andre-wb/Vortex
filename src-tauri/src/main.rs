// Vortex Desktop — Tauri entry point
// Wraps the existing web app in a native window with tray icon,
// native notifications, auto-start, global shortcuts, file picker,
// clipboard, window controls, badge, deep links, and theme detection.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

// ---------------------------------------------------------------------------
// Native file picker
// ---------------------------------------------------------------------------

#[tauri::command]
async fn pick_files(app: AppHandle) -> Result<Vec<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();

    app.dialog()
        .file()
        .pick_files(move |paths| {
            let result = paths
                .map(|list| {
                    list.into_iter()
                        .filter_map(|p| p.into_path().ok())
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let _ = tx.send(result);
        });

    rx.recv().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

#[tauri::command]
fn write_clipboard(app: AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

#[tauri::command]
fn read_clipboard(app: AppHandle) -> Result<String, String> {
    app.clipboard().read_text().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Window controls
// ---------------------------------------------------------------------------

#[tauri::command]
fn minimize_window(app: AppHandle) -> Result<(), String> {
    let window = app.get_webview_window("main").ok_or("window not found")?;
    window.minimize().map_err(|e| e.to_string())
}

#[tauri::command]
fn maximize_window(app: AppHandle) -> Result<(), String> {
    let window = app.get_webview_window("main").ok_or("window not found")?;
    if window.is_maximized().unwrap_or(false) {
        window.unmaximize().map_err(|e| e.to_string())
    } else {
        window.maximize().map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn close_window(app: AppHandle) -> Result<(), String> {
    let window = app.get_webview_window("main").ok_or("window not found")?;
    window.close().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Badge count (macOS dock / Windows taskbar via notification plugin)
// ---------------------------------------------------------------------------

#[tauri::command]
fn set_badge(app: AppHandle, count: u32) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use tauri::plugin::PluginApi;
        // On macOS we update the dock badge via the notification plugin API.
        // tauri-plugin-notification exposes set_badge on the AppHandle.
        // The method signature differs across minor versions; fall back to
        // emitting an event to the frontend if the method is unavailable.
        let badge_str = if count == 0 {
            String::new()
        } else {
            count.to_string()
        };
        // Best-effort: use objc runtime directly when available.
        set_dock_badge_macos(&badge_str);
    }
    #[cfg(target_os = "windows")]
    {
        // Windows taskbar badge: emit event so JS overlay can handle it,
        // because the Win32 API requires a COM ITaskbarList3 call.
        let _ = app.emit("badge-count", count);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        // Linux — emit event for frontend fallback
        let _ = app.emit("badge-count", count);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_dock_badge_macos(label: &str) {
    use std::ffi::CString;
    // Safety: calling Objective-C runtime functions via raw FFI.
    // This is the standard pattern for Tauri macOS badge support.
    #[allow(non_camel_case_types)]
    type id = *mut std::os::raw::c_void;
    extern "C" {
        fn objc_getClass(name: *const std::os::raw::c_char) -> id;
        fn sel_registerName(name: *const std::os::raw::c_char) -> id;
        fn objc_msgSend(receiver: id, op: id, ...) -> id;
    }
    unsafe {
        let ns_app_class = CString::new("NSApplication").unwrap();
        let ns_string_class = CString::new("NSString").unwrap();

        let shared_app_sel = CString::new("sharedApplication").unwrap();
        let dock_tile_sel = CString::new("dockTile").unwrap();
        let set_badge_sel = CString::new("setBadgeLabel:").unwrap();
        let string_with_utf8_sel = CString::new("stringWithUTF8String:").unwrap();

        let app_class = objc_getClass(ns_app_class.as_ptr());
        let shared_app = objc_msgSend(app_class, sel_registerName(shared_app_sel.as_ptr()));
        let dock_tile = objc_msgSend(shared_app, sel_registerName(dock_tile_sel.as_ptr()));

        let ns_string_cls = objc_getClass(ns_string_class.as_ptr());
        let label_cstr = CString::new(label).unwrap_or_default();
        let ns_label = objc_msgSend(
            ns_string_cls,
            sel_registerName(string_with_utf8_sel.as_ptr()),
            label_cstr.as_ptr(),
        );
        objc_msgSend(dock_tile, sel_registerName(set_badge_sel.as_ptr()), ns_label);
    }
}

// ---------------------------------------------------------------------------
// System theme detection
// ---------------------------------------------------------------------------

fn detect_theme() -> &'static str {
    // Tauri itself reports the system theme; we read it from the window.
    // At setup time we emit the current theme and register a listener.
    // The actual watch is done in setup() via a background thread.
    "unknown"
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        // --- plugins ---
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        // --- commands ---
        .invoke_handler(tauri::generate_handler![
            pick_files,
            write_clipboard,
            read_clipboard,
            minimize_window,
            maximize_window,
            close_window,
            set_badge,
        ])
        // --- setup ---
        .setup(|app| {
            println!("Vortex Desktop started");

            let app_handle = app.handle().clone();

            // --- Deep link: handle vortex:// protocol ---
            // On macOS/Windows Tauri registers the custom scheme via tauri.conf.json.
            // We listen for the open-url event emitted by the OS.
            let deep_link_handle = app_handle.clone();
            app.listen("deep-link://new-url", move |event| {
                let url = event.payload().to_string();
                let _ = deep_link_handle.emit("vortex-deep-link", url);
            });

            // --- System theme detection ---
            // Poll every 2 seconds — a lightweight approach that avoids
            // platform-specific native API bindings at the cost of a small delay.
            let theme_handle = app_handle.clone();
            std::thread::spawn(move || {
                let mut last_theme = String::new();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let current_theme = detect_current_theme();
                    if current_theme != last_theme {
                        last_theme = current_theme.clone();
                        let _ = theme_handle.emit("theme-changed", &last_theme);
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Returns "dark" or "light" based on current OS preference.
fn detect_current_theme() -> String {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("defaults")
            .args(["read", "-g", "AppleInterfaceStyle"])
            .output()
        {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout);
                if s.trim().eq_ignore_ascii_case("dark") {
                    return "dark".to_string();
                }
            }
        }
        return "light".to_string();
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        // Registry value 0 = dark mode
        if let Ok(output) = Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                "/v",
                "AppsUseLightTheme",
            ])
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.contains("0x0") {
                return "dark".to_string();
            }
        }
        return "light".to_string();
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "light".to_string()
    }
}
