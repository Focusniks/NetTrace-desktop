use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nettrace_analysis::Accumulators;
use nettrace_flow::FlowTable;
use nettrace_model::{CaptureInfo, IndexProgress, IndexState};
use nettrace_storage::{CaptureFile, PacketIndex};
use parking_lot::{Condvar, Mutex, RwLock};

use crate::live::{LiveHandle, TempFile};
use crate::view::View;

/// Everything derived from the capture. Written by the indexer in batches,
/// read concurrently by UI requests.
#[derive(Debug, Default)]
pub struct Shared {
    pub index: PacketIndex,
    pub flows: FlowTable,
    pub acc: Accumulators,
    /// Capture interfaces as read from the file (name, snaplen, link type).
    pub interfaces: Vec<nettrace_model::InterfaceInfo>,
}

const MAX_VIEWS: usize = 16;

/// One open capture file.
pub struct Session {
    pub id: u64,
    pub info: CaptureInfo,
    pub(crate) file: CaptureFile,
    pub(crate) data: RwLock<Shared>,
    progress: Mutex<IndexProgress>,
    progress_changed: Condvar,
    pub(crate) cancel: AtomicBool,
    views: Mutex<HashMap<u64, Arc<View>>>,
    next_view: AtomicU64,
    /// Incremented by every view (filter/sort) job; older view jobs abort.
    pub(crate) job_gen: AtomicU64,
    /// Same for searches, so a search never cancels a view and vice versa.
    pub(crate) search_gen: AtomicU64,
    pub(crate) started: Instant,
    /// Present for live captures.
    pub(crate) live: Option<LiveHandle>,
    /// Temporary live-capture file; must stay the last field (dropped after `file`).
    _temp: Option<TempFile>,
}

impl Session {
    pub(crate) fn new(id: u64, info: CaptureInfo, file: CaptureFile) -> Self {
        Self::with_live(id, info, file, None, None)
    }

    pub(crate) fn with_live(id: u64, info: CaptureInfo, file: CaptureFile, live: Option<LiveHandle>, temp: Option<TempFile>) -> Self {
        let total = file.size();
        Session {
            id,
            info,
            file,
            data: RwLock::new(Shared::default()),
            progress: Mutex::new(IndexProgress {
                capture_id: id,
                state: IndexState::Indexing,
                packets: 0,
                tcp_streams: 0,
                udp_streams: 0,
                bytes_read: 0,
                total_bytes: total,
                elapsed_ms: 0,
                warning: None,
                error: None,
                capture: live.as_ref().map(|l| l.stats.lock().clone()),
            }),
            progress_changed: Condvar::new(),
            cancel: AtomicBool::new(false),
            views: Mutex::new(HashMap::new()),
            next_view: AtomicU64::new(1),
            job_gen: AtomicU64::new(0),
            search_gen: AtomicU64::new(0),
            started: Instant::now(),
            live,
            _temp: temp,
        }
    }

    pub fn progress(&self) -> IndexProgress {
        self.progress.lock().clone()
    }

    pub(crate) fn set_progress(&self, p: IndexProgress) {
        *self.progress.lock() = p;
        self.progress_changed.notify_all();
    }

    pub fn is_indexing(&self) -> bool {
        self.progress.lock().state == IndexState::Indexing
    }

    /// Blocks until indexing finishes or `timeout` elapses. Returns the final progress.
    pub fn wait_indexed(&self, timeout: Duration) -> IndexProgress {
        let deadline = Instant::now() + timeout;
        let mut p = self.progress.lock();
        while p.state == IndexState::Indexing {
            if self.progress_changed.wait_until(&mut p, deadline).timed_out() {
                break;
            }
        }
        p.clone()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(live) = &self.live {
            live.request_stop();
        }
    }

    /// True while a live capture of this session is still recording.
    pub fn capturing(&self) -> bool {
        self.live.as_ref().is_some_and(LiveHandle::running)
    }

    pub(crate) fn add_view(&self, mut view: View) -> Arc<View> {
        let id = self.next_view.fetch_add(1, Ordering::SeqCst);
        view.id = id;
        let view = Arc::new(view);
        let mut views = self.views.lock();
        if views.len() >= MAX_VIEWS {
            if let Some(oldest) = views.keys().min().copied() {
                views.remove(&oldest);
            }
        }
        views.insert(id, view.clone());
        view
    }

    /// View 0 is the implicit "all packets" view.
    pub(crate) fn view(&self, id: u64) -> Option<Arc<View>> {
        if id == 0 {
            return Some(Arc::new(View::all()));
        }
        self.views.lock().get(&id).cloned()
    }

    pub(crate) fn next_job(&self) -> u64 {
        self.job_gen.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub(crate) fn job_current(&self, job: u64) -> bool {
        self.job_gen.load(Ordering::SeqCst) == job && self.alive()
    }

    pub(crate) fn next_search(&self) -> u64 {
        self.search_gen.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub(crate) fn search_current(&self, job: u64) -> bool {
        self.search_gen.load(Ordering::SeqCst) == job && self.alive()
    }

    /// False once the capture was closed or replaced.
    pub(crate) fn alive(&self) -> bool {
        !self.cancel.load(Ordering::Relaxed)
    }
}
