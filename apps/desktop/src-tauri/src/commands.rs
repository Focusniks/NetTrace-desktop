//! IPC commands. Each one is a thin adapter over `nettrace_engine::Engine`;
//! work runs on the blocking thread pool so the webview never waits on the
//! main thread.

use std::path::PathBuf;
use std::sync::Arc;

use nettrace_engine::{
    Engine, EngineError, FlowQuery, IoGraphRequest, SearchHit, SearchRequest, SortSpec, TimelineRequest,
};
use nettrace_model::{
    CaptureInfo, CaptureInterface, CaptureSummary, LiveOptions, ConversationKind, ConversationRow, FieldInfo, FilterError, FlowPage, FlowSummary,
    HostRow, IndexProgress, Indicator, IoGraph, PacketDetail, PacketLengths, PacketRow, ProtocolNode, SequencePage,
    StreamRef, Timeline, ViewInfo,
};
use tauri::{AppHandle, Emitter, State};

pub struct AppState {
    pub engine: Arc<Engine>,
    /// File passed on the command line (file association), consumed once by the UI.
    pub initial_file: std::sync::Mutex<Option<PathBuf>>,
}

type CmdResult<T> = Result<T, EngineError>;

async fn blocking<T, F>(state: &State<'_, AppState>, f: F) -> CmdResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Engine) -> CmdResult<T> + Send + 'static,
{
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || f(&engine))
        .await
        .map_err(|e| EngineError::new("internal", e.to_string()))?
}

pub const PROGRESS_EVENT: &str = "index-progress";

#[tauri::command]
pub async fn open_capture(app: AppHandle, state: State<'_, AppState>, path: String) -> CmdResult<CaptureInfo> {
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err(EngineError::new("io", "file not found"));
    }
    blocking(&state, move |e| {
        e.open(
            &path,
            Arc::new(move |p: IndexProgress| {
                let _ = app.emit(PROGRESS_EVENT, p);
            }),
        )
    })
    .await
}

#[tauri::command]
pub async fn capture_library(state: State<'_, AppState>) -> CmdResult<String> {
    blocking(&state, |e| e.capture_library()).await
}

#[tauri::command]
pub async fn capture_interfaces(state: State<'_, AppState>) -> CmdResult<Vec<CaptureInterface>> {
    blocking(&state, |e| e.capture_interfaces()).await
}

/// Starts a live capture; packets stream to the UI through `index-progress` events.
#[tauri::command]
pub async fn start_capture(app: AppHandle, state: State<'_, AppState>, options: LiveOptions) -> CmdResult<CaptureInfo> {
    blocking(&state, move |e| {
        e.start_capture(
            &options,
            Arc::new(move |p: IndexProgress| {
                let _ = app.emit(PROGRESS_EVENT, p);
            }),
        )
    })
    .await
}

#[tauri::command]
pub async fn stop_capture(state: State<'_, AppState>) -> CmdResult<()> {
    blocking(&state, |e| e.stop_capture()).await
}

#[tauri::command]
pub async fn close_capture(state: State<'_, AppState>) -> CmdResult<()> {
    state.engine.close();
    Ok(())
}

#[tauri::command]
pub async fn initial_file(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let taken = state.initial_file.lock().map(|mut g| g.take()).unwrap_or(None);
    Ok(taken.map(|p| p.display().to_string()))
}

#[tauri::command]
pub async fn capture_summary(state: State<'_, AppState>) -> CmdResult<CaptureSummary> {
    blocking(&state, |e| e.summary()).await
}

#[tauri::command]
pub async fn index_progress(state: State<'_, AppState>) -> CmdResult<IndexProgress> {
    blocking(&state, |e| e.progress()).await
}

#[tauri::command]
pub async fn apply_view(state: State<'_, AppState>, filter: Option<String>, sort: Option<SortSpec>) -> CmdResult<ViewInfo> {
    blocking(&state, move |e| e.apply_view(filter.as_deref(), sort)).await
}

#[tauri::command]
pub async fn get_rows(state: State<'_, AppState>, view_id: u64, offset: u32, limit: u32) -> CmdResult<Vec<PacketRow>> {
    blocking(&state, move |e| e.rows(view_id, offset, limit)).await
}

#[tauri::command]
pub async fn find_row(state: State<'_, AppState>, view_id: u64, number: u32) -> CmdResult<Option<u32>> {
    blocking(&state, move |e| e.find_row(view_id, number)).await
}

#[tauri::command]
pub async fn packet_detail(state: State<'_, AppState>, number: u32) -> CmdResult<PacketDetail> {
    blocking(&state, move |e| e.packet_detail(number)).await
}

#[tauri::command]
pub async fn validate_filter(state: State<'_, AppState>, text: String) -> CmdResult<Option<FilterError>> {
    blocking(&state, move |e| Ok(e.validate_filter(&text).err())).await
}

#[tauri::command]
pub async fn list_fields(state: State<'_, AppState>) -> CmdResult<Vec<FieldInfo>> {
    blocking(&state, |e| Ok(e.fields())).await
}

#[tauri::command]
pub async fn set_coloring_rules(state: State<'_, AppState>, rules: Vec<String>) -> CmdResult<Vec<Option<FilterError>>> {
    blocking(&state, move |e| Ok(e.set_coloring_rules(&rules))).await
}

#[tauri::command]
pub async fn list_flows(state: State<'_, AppState>, query: FlowQuery) -> CmdResult<FlowPage> {
    blocking(&state, move |e| e.flows(&query)).await
}

#[tauri::command]
pub async fn get_flow(state: State<'_, AppState>, stream: StreamRef) -> CmdResult<FlowSummary> {
    blocking(&state, move |e| e.flow(stream)).await
}

#[tauri::command]
pub async fn get_sequence(state: State<'_, AppState>, stream: StreamRef, offset: u32, limit: u32) -> CmdResult<SequencePage> {
    blocking(&state, move |e| e.sequence(stream, offset, limit)).await
}

#[tauri::command]
pub async fn get_hosts(state: State<'_, AppState>) -> CmdResult<Vec<HostRow>> {
    blocking(&state, |e| e.hosts()).await
}

#[tauri::command]
pub async fn get_conversations(state: State<'_, AppState>, kind: ConversationKind) -> CmdResult<Vec<ConversationRow>> {
    blocking(&state, move |e| e.conversations(kind)).await
}

#[tauri::command]
pub async fn get_protocol_hierarchy(state: State<'_, AppState>) -> CmdResult<Vec<ProtocolNode>> {
    blocking(&state, |e| e.protocol_hierarchy()).await
}

#[tauri::command]
pub async fn get_io_graph(state: State<'_, AppState>, request: IoGraphRequest) -> CmdResult<IoGraph> {
    blocking(&state, move |e| e.io_graph(&request)).await
}

#[tauri::command]
pub async fn get_packet_lengths(state: State<'_, AppState>, filter: Option<String>) -> CmdResult<PacketLengths> {
    blocking(&state, move |e| e.packet_lengths(filter.as_deref())).await
}

#[tauri::command]
pub async fn get_timeline(state: State<'_, AppState>, request: TimelineRequest) -> CmdResult<Timeline> {
    blocking(&state, move |e| e.timeline(&request)).await
}

#[tauri::command]
pub async fn get_indicators(state: State<'_, AppState>) -> CmdResult<Vec<Indicator>> {
    blocking(&state, |e| e.indicators()).await
}

#[tauri::command]
pub async fn search(state: State<'_, AppState>, request: SearchRequest) -> CmdResult<Option<SearchHit>> {
    blocking(&state, move |e| e.search(&request)).await
}

/// Saves the packets of a view. The destination is chosen in a native dialog
/// opened by the backend, so the webview never supplies a file path to write.
#[tauri::command]
pub async fn export_view(
    app: AppHandle,
    state: State<'_, AppState>,
    view_id: u64,
    default_name: String,
    title: String,
) -> CmdResult<Option<u32>> {
    use tauri_plugin_dialog::DialogExt;
    blocking(&state, move |e| {
        let name: String = default_name.chars().filter(|c| !matches!(c, '/' | '\\' | ':')).take(120).collect();
        let picked = app
            .dialog()
            .file()
            .set_title(title)
            .set_file_name(name)
            .add_filter("PCAP", &["pcap"])
            .add_filter("PCAPNG", &["pcapng"])
            .blocking_save_file();
        let Some(picked) = picked else { return Ok(None) };
        let mut path = picked.into_path().map_err(|e| EngineError::new("io", e.to_string()))?;
        let ext = path.extension().map(|x| x.to_string_lossy().to_ascii_lowercase());
        if !matches!(ext.as_deref(), Some("pcap" | "pcapng")) {
            path.set_extension("pcap");
        }
        e.export(view_id, &path).map(Some)
    })
    .await
}
