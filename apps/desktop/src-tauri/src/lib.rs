mod commands;

use std::path::PathBuf;
use std::sync::Arc;

use commands::AppState;
use nettrace_engine::Engine;

/// First command-line argument that points to an existing file (file association / "Open with").
fn file_from_args() -> Option<PathBuf> {
    std::env::args_os().skip(1).map(PathBuf::from).find(|p| p.is_file())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState { engine: Arc::new(Engine::new()), initial_file: std::sync::Mutex::new(file_from_args()) })
        .invoke_handler(tauri::generate_handler![
            commands::open_capture,
            commands::close_capture,
            commands::capture_library,
            commands::capture_interfaces,
            commands::start_capture,
            commands::stop_capture,
            commands::initial_file,
            commands::capture_summary,
            commands::index_progress,
            commands::apply_view,
            commands::view_len,
            commands::get_rows,
            commands::find_row,
            commands::packet_detail,
            commands::validate_filter,
            commands::list_fields,
            commands::set_coloring_rules,
            commands::list_flows,
            commands::get_flow,
            commands::get_sequence,
            commands::get_hosts,
            commands::get_conversations,
            commands::get_protocol_hierarchy,
            commands::get_io_graph,
            commands::get_packet_lengths,
            commands::get_timeline,
            commands::get_indicators,
            commands::search,
            commands::export_view,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
