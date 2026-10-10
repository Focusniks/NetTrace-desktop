//! Live capture plumbing.
//!
//! A recorder thread pulls packets from a [`LiveSource`] and appends them to a
//! temporary PCAP file; the regular indexer reads the same file through a
//! [`TailReader`] that waits for new data instead of reporting EOF. All
//! analysis features therefore work on live traffic unchanged, and the
//! capture can be saved like any opened file.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read};
use std::path::PathBuf;
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

/// Creates a new, empty temporary capture file with an unpredictable name.
/// Never opens an existing file, so a file (or link) planted in the temp
/// directory cannot be written through.
pub fn create_temp_file() -> io::Result<(File, PathBuf)> {
    std::fs::create_dir_all(temp_dir())?;
    for _ in 0..8 {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let path = temp_dir().join(format!("live-{name}.pcap"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary file name"))
}

/// Writes the capture header to the new file, ready for the recorder.
pub fn create_file(file: File, source: &dyn LiveSource) -> io::Result<PcapWriter<BufWriter<File>>> {
    let mut w = PcapWriter::new(BufWriter::with_capacity(256 * 1024, file), source.link_type(), false)?;
    w.flush()?;
    Ok(w)
}

/// Sets `done` when the recorder ends in any way, panics included: the
/// indexer's `TailReader` waits for it.
struct DoneOnDrop<'a>(&'a LiveHandle);

impl Drop for DoneOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stats.lock().running = false;
        self.0.done.store(true, Ordering::SeqCst);
    }
}

/// Error text of a background thread that panicked (keeps the panic message for reports).
pub(crate) fn panic_text(thread: &str, payload: &(dyn std::any::Any + Send)) -> String {
    let what = payload.downcast_ref::<&str>().copied().or_else(|| payload.downcast_ref::<String>().map(String::as_str));
    format!("internal: the {thread} thread stopped unexpectedly ({})", what.unwrap_or("panic"))
}

/// Recorder thread body: copies packets until stopped or the source fails.
pub fn record(mut source: Box<dyn LiveSource>, mut out: PcapWriter<BufWriter<File>>, handle: &LiveHandle) {
    // Declared first, so it is dropped last (after the driver handle is closed).
    let _done = DoneOnDrop(handle);
    let mut buf = Vec::with_capacity(2048);
    let mut last_flush = Instant::now();
    let mut last_stats = Instant::now();
    let mut dirty = false;
    // A panic (e.g. inside the capture driver) must still end the session:
    // the indexer waits for `done`.
    let result: Result<(), String> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
    }))
    .unwrap_or_else(|p| Err(panic_text("capture", p.as_ref())));
    update_driver_stats(source.as_mut(), handle);
    if let Err(e) = out.flush() {
        handle.error.lock().get_or_insert(format!("write: {e}"));
    }
    if let Err(e) = result {
        *handle.error.lock() = Some(e);
    }
    // Close the driver handle before announcing completion (`_done`).
    drop(source);
    drop(out);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_files_are_new_and_unpredictable() {
        let (_a, pa) = create_temp_file().unwrap();
        let (_b, pb) = create_temp_file().unwrap();
        let _cleanup = (TempFile(pa.clone()), TempFile(pb.clone()));
        assert_ne!(pa, pb);
        let name = pa.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("live-") && name.ends_with(".pcap") && name.len() == "live-.pcap".len() + 32, "{name}");
        // The name is never reused for an existing file.
        assert!(OpenOptions::new().write(true).create_new(true).open(&pa).is_err());
    }
}
