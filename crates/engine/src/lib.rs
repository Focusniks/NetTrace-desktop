//! Analysis engine: the backend API used by the desktop shell.
//!
//! The engine owns at most one open capture ([`Session`]). Opening a file
//! returns immediately; indexing runs on a background thread and reports
//! [`IndexProgress`] through a callback. All query methods work on partial
//! data while indexing is still running.

mod error;
mod export;
mod fields;
mod frame;
mod indexer;
mod live;
mod rows;
mod search;
mod session;
mod streams;
mod view;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use nettrace_analysis::{IndicatorConfig, MAX_BUCKETS};
use nettrace_capture::{CaptureReader, PacketSource};
use nettrace_live::LiveSource;

use nettrace_model::{
    CaptureInfo, CaptureInterface, CaptureSummary, LiveOptions, ConversationKind, ConversationRow, FieldInfo, FilterError, FlowPage, FlowSummary,
    HostRow, IndexProgress, Indicator, IoGraph, PacketDetail, PacketLengths, PacketRow, ProtocolNode,
    SequencePage, StreamRef, Timeline, Transport, ViewInfo,
};
use nettrace_query::Filter;
use nettrace_storage::CaptureFile;
use parking_lot::RwLock;
use serde::Deserialize;

pub use error::{EngineError, Result};
pub use indexer::ProgressFn;
pub use search::{SearchHit, SearchQuery, SearchRequest};
pub use session::Session;
pub use streams::{FlowQuery, FlowSort};
pub use view::{SortKey, SortSpec};

use crate::error::filter_error;
use crate::view::{filter_indices, sort_rows, View};

const MAX_ROWS_PER_REQUEST: u32 = 2000;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IoGraphRequest {
    /// Bucket width in seconds.
    pub interval: f64,
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineRequest {
    /// Range in seconds relative to the first packet; defaults to the whole capture.
    pub start: Option<f64>,
    pub end: Option<f64>,
    pub buckets: u32,
    #[serde(default = "default_max_events")]
    pub max_events: u32,
}

fn default_max_events() -> u32 {
    2000
}

#[derive(Default)]
pub struct Engine {
    current: RwLock<Option<Arc<Session>>>,
    next_id: AtomicU64,
    coloring: RwLock<Arc<Vec<Option<Filter>>>>,
}

impl Engine {
    pub fn new() -> Self {
        live::clean_stale_files();
        Self::default()
    }

    /// Opens a capture and starts background indexing. Any open capture is closed.
    pub fn open(&self, path: &Path, on_progress: ProgressFn) -> Result<CaptureInfo> {
        // Validate the new file first: a failed open keeps the current capture.
        let reader = CaptureReader::open(path)?;
        let file = CaptureFile::open(path)?;
        self.close();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let info = CaptureInfo {
            capture_id: id,
            path: path.display().to_string(),
            file_name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            file_size: file.size(),
            format: reader.format().name().to_owned(),
            live: false,
        };
        let session = Arc::new(Session::new(id, info.clone(), file));
        self.spawn_indexer(session, reader, on_progress)?;
        Ok(info)
    }

    /// Makes `session` current and indexes `reader` in the background.
    fn spawn_indexer<S: PacketSource + Send + 'static>(&self, session: Arc<Session>, reader: S, on_progress: ProgressFn) -> Result<()> {
        *self.current.write() = Some(session.clone());
        std::thread::Builder::new().name("nettrace-indexer".into()).spawn(move || {
            let guard_session = session.clone();
            let guard_progress = on_progress.clone();
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| indexer::run(session, reader, on_progress)));
            if run.is_err() {
                // Never leave the UI waiting on an indexer that died.
                let mut p = guard_session.progress();
                p.state = nettrace_model::IndexState::Failed;
                p.error = Some("internal: indexer stopped unexpectedly".to_owned());
                guard_session.set_progress(p.clone());
                guard_progress(p);
            }
        })?;
        Ok(())
    }

    /// Version of the capture library (Npcap/libpcap), or why live capture is unavailable.
    pub fn capture_library(&self) -> Result<String> {
        nettrace_live::library_version().map_err(live_error)
    }

    pub fn capture_interfaces(&self) -> Result<Vec<CaptureInterface>> {
        nettrace_live::list_interfaces().map_err(live_error)
    }

    /// Starts a live capture on an interface. The previous capture is closed.
    pub fn start_capture(&self, opts: &LiveOptions, on_progress: ProgressFn) -> Result<CaptureInfo> {
        let source = nettrace_live::open(opts).map_err(live_error)?;
        // Show the driver's description ("Ethernet", "Wi-Fi") rather than \Device\NPF_{GUID}.
        let label = nettrace_live::list_interfaces()
            .ok()
            .and_then(|list| list.into_iter().find(|i| i.name == opts.interface))
            .and_then(|i| i.description)
            .unwrap_or_else(|| opts.interface.clone());
        self.start_capture_with(source, &label, on_progress)
    }

    /// Starts recording and indexing packets from any live source (also used by tests).
    pub fn start_capture_with(&self, source: Box<dyn LiveSource>, interface: &str, on_progress: ProgressFn) -> Result<CaptureInfo> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        std::fs::create_dir_all(live::temp_dir())?;
        let path = live::new_temp_path();
        let writer = live::create_file(&path, source.as_ref())?;
        let temp = live::TempFile(path.clone());
        let handle = live::LiveHandle::new(interface);
        let tail = live::TailReader::new(std::fs::File::open(&path)?, handle.done.clone());
        let reader = CaptureReader::from_reader(std::io::BufReader::with_capacity(64 * 1024, tail))?;
        let file = CaptureFile::open(&path)?;
        self.close();
        let info = CaptureInfo {
            capture_id: id,
            path: path.display().to_string(),
            file_name: interface.to_owned(),
            file_size: 0,
            format: "Live (PCAP)".to_owned(),
            live: true,
        };
        let recorder = live::LiveHandle {
            stop: handle.stop.clone(),
            done: handle.done.clone(),
            stats: handle.stats.clone(),
            error: handle.error.clone(),
        };
        let session = Arc::new(Session::with_live(id, info.clone(), file, Some(handle), Some(temp)));
        std::thread::Builder::new()
            .name("nettrace-capture".into())
            .spawn(move || live::record(source, writer, &recorder))?;
        self.spawn_indexer(session, reader, on_progress)?;
        Ok(info)
    }

    /// Stops the running live capture; indexing finishes with the packets recorded so far.
    pub fn stop_capture(&self) -> Result<()> {
        let s = self.session()?;
        match &s.live {
            Some(l) => {
                l.request_stop();
                Ok(())
            }
            None => Err(EngineError::new("not_live", "the open capture is not a live capture")),
        }
    }

    pub fn close(&self) {
        if let Some(old) = self.current.write().take() {
            old.cancel();
        }
    }

    pub fn session(&self) -> Result<Arc<Session>> {
        self.current.read().clone().ok_or_else(EngineError::no_capture)
    }

    pub fn progress(&self) -> Result<IndexProgress> {
        Ok(self.session()?.progress())
    }

    pub fn summary(&self) -> Result<CaptureSummary> {
        let s = self.session()?;
        let progress = s.progress();
        let sh = s.data.read();
        let first = sh.index.first_ts();
        let last = sh.index.all().iter().map(|m| m.ts_ns).max();
        Ok(CaptureSummary {
            info: s.info.clone(),
            packets: sh.index.len(),
            bytes: sh.acc.bytes,
            first_ts_sec: first.map(|t| t.div_euclid(1_000_000_000)),
            first_ts_nsec: first.map(|t| t.rem_euclid(1_000_000_000) as u32),
            duration: match (first, last) {
                (Some(a), Some(b)) => b.saturating_sub(a) as f64 / 1e9,
                _ => 0.0,
            },
            tcp_streams: sh.flows.tcp_count(),
            udp_streams: sh.flows.udp_count(),
            hosts: sh.acc.hosts.len() as u32,
            malformed: sh.acc.malformed,
            interfaces: sh.interfaces.clone(),
            state: progress.state,
        })
    }

    pub fn fields(&self) -> Vec<FieldInfo> {
        fields::registry().field_infos()
    }

    pub fn compile(&self, text: &str) -> Result<Filter> {
        Ok(fields::registry().compile(text)?)
    }

    pub fn validate_filter(&self, text: &str) -> std::result::Result<(), FilterError> {
        fields::registry().compile(text).map(|_| ()).map_err(|e| filter_error(&e))
    }

    /// Compiles coloring rules (in priority order). Invalid rules are disabled
    /// and their errors returned at the same positions.
    pub fn set_coloring_rules(&self, rules: &[String]) -> Vec<Option<FilterError>> {
        let mut compiled = Vec::with_capacity(rules.len());
        let mut errors = Vec::with_capacity(rules.len());
        for r in rules {
            match fields::registry().compile(r) {
                Ok(f) => {
                    compiled.push(Some(f));
                    errors.push(None);
                }
                Err(e) => {
                    compiled.push(None);
                    errors.push(Some(filter_error(&e)));
                }
            }
        }
        *self.coloring.write() = Arc::new(compiled);
        errors
    }

    /// Applies a display filter and/or sort. `None`/empty filter = all packets.
    pub fn apply_view(&self, filter: Option<&str>, sort: Option<SortSpec>) -> Result<ViewInfo> {
        let s = self.session()?;
        let started = Instant::now();
        let job = s.next_job();
        let filter = filter.map(str::trim).filter(|f| !f.is_empty());
        let compiled = filter.map(|f| self.compile(f)).transpose()?;
        let sort = sort.filter(|s| !(s.key == SortKey::Number && !s.desc));
        let scanned = s.data.read().index.len();
        if compiled.is_none() && sort.is_none() {
            return Ok(ViewInfo { view_id: 0, total: scanned, scanned, elapsed_ms: 0 });
        }
        let mut rows = match &compiled {
            Some(f) => filter_indices(&s.data, &s.file, f, 0..scanned, &|| s.job_current(job))?,
            None => (0..scanned).collect(),
        };
        if let Some(spec) = sort {
            // Index-only comparison: fast, so one read lock for the whole sort is fine.
            sort_rows(&s.data.read(), &mut rows, spec);
        }
        let total = rows.len() as u32;
        let view = s.add_view(View { id: 0, rows: Some(rows), ordered: sort.is_none() });
        Ok(ViewInfo { view_id: view.id, total, scanned, elapsed_ms: started.elapsed().as_millis() as u64 })
    }

    fn view(&self, s: &Session, view_id: u64) -> Result<Arc<View>> {
        s.view(view_id).ok_or_else(|| EngineError::not_found("view"))
    }

    pub fn view_len(&self, view_id: u64) -> Result<u32> {
        let s = self.session()?;
        let v = self.view(&s, view_id)?;
        let sh = s.data.read();
        Ok(v.len(&sh))
    }

    pub fn rows(&self, view_id: u64, offset: u32, limit: u32) -> Result<Vec<PacketRow>> {
        let s = self.session()?;
        let v = self.view(&s, view_id)?;
        let colors = self.coloring.read().clone();
        let sh = s.data.read();
        let len = v.len(&sh);
        let end = offset.saturating_add(limit.min(MAX_ROWS_PER_REQUEST)).min(len);
        let mut buf = Vec::with_capacity(2048);
        let mut out = Vec::with_capacity(end.saturating_sub(offset) as usize);
        let mut prev = offset
            .checked_sub(1)
            .and_then(|r| v.packet_at(&sh, r))
            .and_then(|i| sh.index.get(i))
            .map(|m| m.ts_ns);
        for row in offset..end {
            let Some(index) = v.packet_at(&sh, row) else { break };
            if let Some(r) = rows::build_row(&sh, &s.file, index, prev, &colors, &mut buf) {
                prev = sh.index.get(index).map(|m| m.ts_ns);
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Row of frame `number` (1-based) in the view, if the packet is visible.
    pub fn find_row(&self, view_id: u64, number: u32) -> Result<Option<u32>> {
        let s = self.session()?;
        let v = self.view(&s, view_id)?;
        let sh = s.data.read();
        Ok(number.checked_sub(1).and_then(|i| v.row_of(&sh, i)))
    }

    pub fn packet_detail(&self, number: u32) -> Result<PacketDetail> {
        let s = self.session()?;
        let sh = s.data.read();
        let index = number.checked_sub(1).ok_or_else(|| EngineError::not_found("packet"))?;
        rows::packet_detail(&sh, &s.file, index).ok_or_else(|| EngineError::not_found("packet"))?.map_err(Into::into)
    }

    pub fn flows(&self, q: &FlowQuery) -> Result<FlowPage> {
        let s = self.session()?;
        let sh = s.data.read();
        Ok(streams::list_flows(&sh, q))
    }

    pub fn flow(&self, stream: StreamRef) -> Result<FlowSummary> {
        let s = self.session()?;
        let sh = s.data.read();
        let (_, f) = sh.flows.stream(stream.kind, stream.id).ok_or_else(|| EngineError::not_found("stream"))?;
        Ok(f.summary(sh.index.first_ts().unwrap_or(0)))
    }

    pub fn sequence(&self, stream: StreamRef, offset: u32, limit: u32) -> Result<SequencePage> {
        let s = self.session()?;
        let sh = s.data.read();
        let (_, f) = sh.flows.stream(stream.kind, stream.id).ok_or_else(|| EngineError::not_found("stream"))?;
        streams::sequence(&sh, &s.file, f, offset, limit)
    }

    pub fn hosts(&self) -> Result<Vec<HostRow>> {
        let s = self.session()?;
        let sh = s.data.read();
        Ok(sh.acc.host_rows(sh.index.first_ts().unwrap_or(0)))
    }

    pub fn conversations(&self, kind: ConversationKind) -> Result<Vec<ConversationRow>> {
        let s = self.session()?;
        let sh = s.data.read();
        let base = sh.index.first_ts().unwrap_or(0);
        let transport = match kind {
            ConversationKind::Tcp => Transport::Tcp,
            ConversationKind::Udp => Transport::Udp,
            other => return Ok(sh.acc.conversation_rows(other, base)),
        };
        let mut rows: Vec<ConversationRow> = sh
            .flows
            .flows()
            .iter()
            .filter(|f| f.transport == transport)
            .map(|f| ConversationRow {
                kind,
                a: f.client.0.to_string(),
                a_port: Some(f.client.1),
                b: f.server.0.to_string(),
                b_port: Some(f.server.1),
                packets: f.packets.len() as u64,
                bytes: f.total_bytes(),
                a_to_b_packets: f.c2s.packets,
                a_to_b_bytes: f.c2s.bytes,
                b_to_a_packets: f.s2c.packets,
                b_to_a_bytes: f.s2c.bytes,
                start: f.first_ts_ns.saturating_sub(base) as f64 / 1e9,
                duration: f.duration_ns() as f64 / 1e9,
                state: f.tcp.as_deref().map(|t| tcp_state_code(t.state()).to_owned()),
                stream: Some(StreamRef { kind: f.transport, id: f.stream_id }),
                filter: f.filter(),
            })
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.bytes));
        Ok(rows)
    }

    pub fn protocol_hierarchy(&self) -> Result<Vec<ProtocolNode>> {
        let s = self.session()?;
        let sh = s.data.read();
        Ok(sh.acc.protocol_hierarchy())
    }

    fn selection(&self, s: &Session, filter: Option<&str>) -> Result<Option<Vec<u32>>> {
        let Some(text) = filter.map(str::trim).filter(|t| !t.is_empty()) else { return Ok(None) };
        let f = self.compile(text)?;
        let n = s.data.read().index.len();
        // Statistics selections must not cancel the packet-list view job.
        Ok(Some(filter_indices(&s.data, &s.file, &f, 0..n, &|| s.alive())?))
    }

    pub fn io_graph(&self, req: &IoGraphRequest) -> Result<IoGraph> {
        let s = self.session()?;
        let selected = self.selection(&s, req.filter.as_deref())?;
        let sh = s.data.read();
        let metas = sh.index.all();
        let base = sh.index.first_ts().unwrap_or(0);
        let end = metas.iter().map(|m| m.ts_ns).max().unwrap_or(base);
        let interval_ns = (req.interval.max(0.000_001) * 1e9) as i64;
        Ok(match selected {
            Some(sel) => nettrace_analysis::io_graph(metas, sel.into_iter(), base, end, interval_ns),
            None => nettrace_analysis::io_graph(metas, 0..sh.index.len(), base, end, interval_ns),
        })
    }

    pub fn packet_lengths(&self, filter: Option<&str>) -> Result<PacketLengths> {
        let s = self.session()?;
        let selected = self.selection(&s, filter)?;
        let sh = s.data.read();
        let metas = sh.index.all();
        Ok(match selected {
            Some(sel) => nettrace_analysis::packet_lengths(metas, sel.into_iter()),
            None => nettrace_analysis::packet_lengths(metas, 0..sh.index.len()),
        })
    }

    pub fn timeline(&self, req: &TimelineRequest) -> Result<Timeline> {
        let s = self.session()?;
        let sh = s.data.read();
        let metas = sh.index.all();
        let base = sh.index.first_ts().unwrap_or(0);
        let last = metas.iter().map(|m| m.ts_ns).max().unwrap_or(base);
        let start = req.start.map_or(base, |t| base.saturating_add((t.clamp(0.0, 1e9) * 1e9) as i64));
        let end = req.end.map_or(last, |t| base.saturating_add((t.clamp(0.0, 1e9) * 1e9) as i64)).max(start);
        let buckets = (req.buckets as usize).clamp(1, MAX_BUCKETS);
        Ok(nettrace_analysis::timeline(
            metas,
            &sh.flows,
            &sh.acc.events,
            base,
            start,
            end,
            buckets,
            req.max_events.min(20_000) as usize,
        ))
    }

    pub fn indicators(&self) -> Result<Vec<Indicator>> {
        let s = self.session()?;
        let sh = s.data.read();
        Ok(nettrace_analysis::indicators(&sh.flows, &sh.acc, &IndicatorConfig::default()))
    }

    pub fn search(&self, req: &SearchRequest) -> Result<Option<SearchHit>> {
        let s = self.session()?;
        let v = self.view(&s, req.view_id)?;
        let job = s.next_search();
        search::search(&s.data, &s.file, &v, req, |t| self.compile(t), &|| s.search_current(job))
    }

    /// Writes the packets of a view to a new capture file. Returns the packet count.
    pub fn export(&self, view_id: u64, path: &Path) -> Result<u32> {
        let s = self.session()?;
        let v = self.view(&s, view_id)?;
        if s.capturing() {
            return Err(EngineError::new("export_capturing", "stop the capture before saving"));
        }
        if s.is_indexing() {
            return Err(EngineError::new("export_indexing", "indexing is still in progress"));
        }
        if same_file(Path::new(&s.info.path), path) {
            return Err(EngineError::new("export_same_file", "cannot overwrite the open capture"));
        }
        let sh = s.data.read();
        export::write(&sh, &s.file, &v, path)
    }
}

/// `TcpState` as its serde string (snake_case).
fn tcp_state_code(state: nettrace_model::TcpState) -> &'static str {
    use nettrace_model::TcpState::*;
    match state {
        SynSent => "syn_sent",
        SynReceived => "syn_received",
        Established => "established",
        Midstream => "midstream",
        Closing => "closing",
        Closed => "closed",
        Reset => "reset",
        Refused => "refused",
    }
}

fn live_error(e: nettrace_live::LiveError) -> EngineError {
    EngineError::new(e.code(), e.to_string())
}

/// True if both paths name the same existing file (resolves relative paths,
/// symlinks and, on Windows, case differences).
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => {
            if cfg!(windows) {
                x.to_string_lossy().to_lowercase() == y.to_string_lossy().to_lowercase()
            } else {
                x == y
            }
        }
        _ => false,
    }
}

// The engine is shared across Tauri command threads.
const _: fn() = || {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Engine>();
    send_sync::<Session>();
};
