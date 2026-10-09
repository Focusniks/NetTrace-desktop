//! Live capture plumbing.
//!
//! A recorder thread pulls packets from a [`LiveSource`] and appends them to a
//! temporary PCAP file; the regular indexer reads the same file through a
//! [`TailReader`] that waits for new data instead of reporting EOF. All
//! analysis features therefore work on live traffic unchanged, and the
//! capture can be saved like any opened file.

use std::fs::File;
use std::io::{self, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nettrace_capture::PcapWriter;
use nettrace_live::LiveSource;
use nettrace_model::LiveStats;
use parking_lot::Mutex;

const POLL: Duration = Duration::from_millis(100);
const FLUSH_EVERY: Duration = Duration::from_millis(20);
const STATS_EVERY: Duration = Duration::from_millis(500);
const TAIL_WAIT: Duration = Duration::from_millis(15);

/// Shared state between the recorder thread, the tail reader and the session.
pub struct LiveHandle {
    /// Set to ask the recorder to stop.
    pub stop: Arc<AtomicBool>,
    /// Set by the recorder after the last byte is flushed to the file.
    pub done: Arc<AtomicBool>,
    pub stats: Arc<Mutex<LiveStats>>,
    pub error: Arc<Mutex<Option<String>>>,
}

impl LiveHandle {
    pub fn new(interface: &str) -> Self {
        LiveHandle {
            stop: Arc::new(AtomicBool::new(false)),
            done: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(LiveStats { interface: interface.to_owned(), running: true, ..LiveStats::default() })),
            error: Arc::new(Mutex::new(None)),
        }
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn running(&self) -> bool {
        !self.done.load(Ordering::SeqCst)
    }
}

/// `Read` over a file that is still being written: waits for more bytes and
/// returns EOF only after the writer has finished.
pub struct TailReader {
    file: File,
    done: Arc<AtomicBool>,
}

impl TailReader {
    pub fn new(file: File, done: Arc<AtomicBool>) -> Self {
        TailReader { file, done }
    }
}

impl Read for TailReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.file.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            if self.done.load(Ordering::SeqCst) {
                // The writer flushed before setting `done`: one last read sees everything.
                return self.file.read(buf);
            }
            std::thread::sleep(TAIL_WAIT);
        }
    }
}

/// Creates the capture file with its header written, ready for the recorder.
pub fn create_file(path: &Path, source: &dyn LiveSource) -> io::Result<PcapWriter<BufWriter<File>>> {
    let file = File::create(path)?;
    let mut w = PcapWriter::new(BufWriter::with_capacity(256 * 1024, file), source.link_type(), false)?;
    w.flush()?;
    Ok(w)
}

/// Recorder thread body: copies packets until stopped or the source fails.
pub fn record(mut source: Box<dyn LiveSource>, mut out: PcapWriter<BufWriter<File>>, handle: &LiveHandle) {
    let mut buf = Vec::with_capacity(2048);
    let mut last_flush = Instant::now();
    let mut last_stats = Instant::now();
    let mut dirty = false;
    let result: Result<(), String> = (|| {
        while !handle.stop.load(Ordering::SeqCst) {
            match source.next_packet(&mut buf, POLL).map_err(|e| e.to_string())? {
                Some(p) => {
                    out.write(p.ts, &buf, p.origlen).map_err(|e| format!("write: {e}"))?;
                    handle.stats.lock().captured += 1;
                    dirty = true;
                }
                None => {
                    // Idle: make everything captured so far visible to the indexer.
                    if dirty {
                        out.flush().map_err(|e| format!("write: {e}"))?;
                        dirty = false;
                        last_flush = Instant::now();
                    }
                }
            }
            if dirty && last_flush.elapsed() >= FLUSH_EVERY {
                out.flush().map_err(|e| format!("write: {e}"))?;
                dirty = false;
                last_flush = Instant::now();
            }
            if last_stats.elapsed() >= STATS_EVERY {
                update_driver_stats(source.as_mut(), handle);
                last_stats = Instant::now();
            }
        }
        Ok(())
    })();
    update_driver_stats(source.as_mut(), handle);
    if let Err(e) = out.flush() {
        handle.error.lock().get_or_insert(format!("write: {e}"));
    }
    if let Err(e) = result {
        *handle.error.lock() = Some(e);
    }
    handle.stats.lock().running = false;
    // Close the driver handle before announcing completion.
    drop(source);
    drop(out);
    handle.done.store(true, Ordering::SeqCst);
}

fn update_driver_stats(source: &mut dyn LiveSource, handle: &LiveHandle) {
    if let Some(s) = source.stats() {
        let mut st = handle.stats.lock();
        st.dropped = s.dropped;
        st.if_dropped = s.if_dropped;
    }
}

/// Directory for temporary live-capture files.
pub fn temp_dir() -> PathBuf {
    std::env::temp_dir().join("NetTrace")
}

/// Unique path for a new live capture (unique across engines of this process).
pub fn new_temp_path() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    temp_dir().join(format!("live-{}-{n}.pcap", std::process::id()))
}

/// Removes leftovers of crashed earlier runs: live files untouched for a day.
/// (Recent files may belong to another running instance.)
pub fn clean_stale_files() {
    let Ok(entries) = std::fs::read_dir(temp_dir()) else { return };
    let day = Duration::from_secs(24 * 3600);
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > day);
        if name.starts_with("live-") && name.ends_with(".pcap") && old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Deletes the temporary capture file when the session is dropped.
/// Declared as the last field of `Session`, so the file handle is closed first.
pub struct TempFile(pub PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
