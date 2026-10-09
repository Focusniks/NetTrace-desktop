//! Runtime binding to Npcap's `wpcap.dll` / libpcap.
//!
//! This is the only module of the project that uses `unsafe`: calling a C
//! library through function pointers is inherently unsafe. Every block below
//! upholds the libpcap API contract (valid handles, NUL-terminated strings,
//! buffers of `PCAP_ERRBUF_SIZE`, data pointers valid until the next call).
#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::sync::OnceLock;
use std::time::Duration;

use libloading::Library;
use nettrace_model::{CaptureInterface, LiveOptions};
use nettrace_packet::{LinkType, Timestamp};

use crate::sockaddr;
use crate::{DriverStats, LiveError, LivePacket, LiveSource};

const ERRBUF: usize = 256;
const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
const READ_TIMEOUT_MS: c_int = 100;
const BUFFER_SIZE: c_int = 16 * 1024 * 1024;
const MAX_SNAPLEN: u32 = 262_144;

const IF_LOOPBACK: u32 = 0x1;
const IF_UP: u32 = 0x2;
const IF_RUNNING: u32 = 0x4;
const IF_WIRELESS: u32 = 0x8;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *const c_char,
    description: *const c_char,
    addresses: *mut PcapAddr,
    flags: u32,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *const u8,
    netmask: *const u8,
    broadaddr: *const u8,
    dstaddr: *const u8,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

/// `struct pcap_stat` (+ the Win32-only `ps_capt`; unused trailing space elsewhere).
#[repr(C)]
#[derive(Default)]
struct PcapStat {
    recv: c_uint,
    drop: c_uint,
    ifdrop: c_uint,
    capt: c_uint,
}

#[cfg(windows)]
#[repr(C)]
struct Timeval {
    sec: i32,
    usec: i32,
}

#[cfg(all(unix, any(target_os = "macos", target_os = "ios")))]
#[repr(C)]
struct Timeval {
    sec: i64,
    usec: i32,
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
#[repr(C)]
struct Timeval {
    sec: std::ffi::c_long,
    usec: std::ffi::c_long,
}

#[repr(C)]
struct PktHdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

type Handle = *mut c_void;
type FnFindAll = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FnFreeAll = unsafe extern "C" fn(*mut PcapIf);
type FnCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> Handle;
type FnSetInt = unsafe extern "C" fn(Handle, c_int) -> c_int;
type FnHandleInt = unsafe extern "C" fn(Handle) -> c_int;
type FnNextEx = unsafe extern "C" fn(Handle, *mut *mut PktHdr, *mut *const u8) -> c_int;
type FnCompile = unsafe extern "C" fn(Handle, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type FnSetFilter = unsafe extern "C" fn(Handle, *mut BpfProgram) -> c_int;
type FnFreeCode = unsafe extern "C" fn(*mut BpfProgram);
type FnGetErr = unsafe extern "C" fn(Handle) -> *const c_char;
type FnClose = unsafe extern "C" fn(Handle);
type FnStats = unsafe extern "C" fn(Handle, *mut PcapStat) -> c_int;
type FnVersion = unsafe extern "C" fn() -> *const c_char;

pub struct Api {
    // Keeps the library mapped for the lifetime of the process (the Api is a static).
    _lib: Library,
    findalldevs: FnFindAll,
    freealldevs: FnFreeAll,
    create: FnCreate,
    set_snaplen: FnSetInt,
    set_promisc: FnSetInt,
    set_timeout: FnSetInt,
    set_buffer_size: FnSetInt,
    set_immediate_mode: Option<FnSetInt>,
    activate: FnHandleInt,
    datalink: FnHandleInt,
    next_ex: FnNextEx,
    compile: FnCompile,
    setfilter: FnSetFilter,
    freecode: FnFreeCode,
    geterr: FnGetErr,
    close: FnClose,
    stats: FnStats,
    lib_version: FnVersion,
}

fn candidates() -> Vec<std::path::PathBuf> {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let sys = std::path::Path::new(&root).join("System32");
        vec![sys.join("Npcap").join("wpcap.dll"), sys.join("wpcap.dll")]
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        vec!["libpcap.A.dylib".into(), "libpcap.dylib".into()]
    } else {
        vec!["libpcap.so.1".into(), "libpcap.so".into(), "libpcap.so.0.8".into()]
    }
}

#[cfg(windows)]
fn load(path: &std::path::Path) -> Result<Library, libloading::Error> {
    // Npcap's wpcap.dll depends on Packet.dll in the same directory.
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    // SAFETY: loading the vendor capture library runs its initialisation code;
    // the path comes from the system directory, not from capture data.
    unsafe { libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH).map(Into::into) }
}

#[cfg(not(windows))]
fn load(path: &std::path::Path) -> Result<Library, libloading::Error> {
    // SAFETY: see the Windows variant.
    unsafe { Library::new(path) }
}

fn sym<T: Copy>(lib: &Library, name: &[u8]) -> Result<T, String> {
    // SAFETY: each `T` matches the documented C signature of the symbol.
    unsafe { lib.get::<T>(name).map(|s| *s).map_err(|e| e.to_string()) }
}

impl Api {
    fn load() -> Result<Api, String> {
        let mut last = String::from("library not found");
        for path in candidates() {
            match load(&path) {
                Ok(lib) => return Api::bind(lib).map_err(|e| format!("{}: {e}", path.display())),
                Err(e) => last = format!("{}: {e}", path.display()),
            }
        }
        Err(last)
    }

    fn bind(lib: Library) -> Result<Api, String> {
        Ok(Api {
            findalldevs: sym(&lib, b"pcap_findalldevs\0")?,
            freealldevs: sym(&lib, b"pcap_freealldevs\0")?,
            create: sym(&lib, b"pcap_create\0")?,
            set_snaplen: sym(&lib, b"pcap_set_snaplen\0")?,
            set_promisc: sym(&lib, b"pcap_set_promisc\0")?,
            set_timeout: sym(&lib, b"pcap_set_timeout\0")?,
            set_buffer_size: sym(&lib, b"pcap_set_buffer_size\0")?,
            set_immediate_mode: sym(&lib, b"pcap_set_immediate_mode\0").ok(),
            activate: sym(&lib, b"pcap_activate\0")?,
            datalink: sym(&lib, b"pcap_datalink\0")?,
            next_ex: sym(&lib, b"pcap_next_ex\0")?,
            compile: sym(&lib, b"pcap_compile\0")?,
            setfilter: sym(&lib, b"pcap_setfilter\0")?,
            freecode: sym(&lib, b"pcap_freecode\0")?,
            geterr: sym(&lib, b"pcap_geterr\0")?,
            close: sym(&lib, b"pcap_close\0")?,
            stats: sym(&lib, b"pcap_stats\0")?,
            lib_version: sym(&lib, b"pcap_lib_version\0")?,
            _lib: lib,
        })
    }

    pub fn version(&self) -> String {
        // SAFETY: returns a static NUL-terminated string.
        unsafe { cstr((self.lib_version)()) }.unwrap_or_default()
    }

    pub fn interfaces(&self) -> Result<Vec<CaptureInterface>, LiveError> {
        let mut head: *mut PcapIf = std::ptr::null_mut();
        let mut err = [0 as c_char; ERRBUF];
        // SAFETY: out-pointer and errbuf of the required size.
        let rc = unsafe { (self.findalldevs)(&mut head, err.as_mut_ptr()) };
        if rc != 0 {
            return Err(LiveError::Open(errbuf(&err)));
        }
        let fam = sockaddr::platform();
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is a node of the list returned above, alive until freealldevs.
            let dev = unsafe { &*cur };
            let mut addresses = Vec::new();
            let mut a = dev.addresses;
            while !a.is_null() {
                // SAFETY: node of the same list.
                let addr = unsafe { &*a };
                if !addr.addr.is_null() {
                    if let Some(s) = read_sockaddr(addr.addr, fam) {
                        addresses.push(s);
                    }
                }
                a = addr.next;
            }
            out.push(CaptureInterface {
                // SAFETY: NUL-terminated strings owned by the list.
                name: unsafe { cstr(dev.name) }.unwrap_or_default(),
                description: unsafe { cstr(dev.description) }.filter(|d| !d.is_empty()),
                addresses,
                loopback: dev.flags & IF_LOOPBACK != 0,
                up: dev.flags & IF_UP != 0,
                running: dev.flags & IF_RUNNING != 0,
                wireless: dev.flags & IF_WIRELESS != 0,
            });
            cur = dev.next;
        }
        if !head.is_null() {
            // SAFETY: frees the list we received; no references outlive this point.
            unsafe { (self.freealldevs)(head) };
        }
        Ok(out)
    }

    pub fn open(&'static self, opts: &LiveOptions) -> Result<PcapSource, LiveError> {
        let name = CString::new(opts.interface.as_bytes()).map_err(|_| LiveError::Open("invalid interface name".into()))?;
        let mut err = [0 as c_char; ERRBUF];
        // SAFETY: valid C string and errbuf.
        let handle = unsafe { (self.create)(name.as_ptr(), err.as_mut_ptr()) };
        if handle.is_null() {
            return Err(LiveError::Open(errbuf(&err)));
        }
        // From here on `source` owns the handle and closes it on every error path.
        let mut source = PcapSource { api: self, handle, link: LinkType::Ethernet };
        let snaplen = opts.snaplen.clamp(64, MAX_SNAPLEN) as c_int;
        // SAFETY: handle is a freshly created, not yet activated pcap_t.
        unsafe {
            (self.set_snaplen)(handle, snaplen);
            (self.set_promisc)(handle, c_int::from(opts.promiscuous));
            (self.set_timeout)(handle, READ_TIMEOUT_MS);
            (self.set_buffer_size)(handle, BUFFER_SIZE);
            if let Some(f) = self.set_immediate_mode {
                f(handle, 1);
            }
        }
        // SAFETY: activating the handle configured above.
        let rc = unsafe { (self.activate)(handle) };
        if rc < 0 {
            return Err(LiveError::Open(activate_error(rc, &source.last_error())));
        }
        // SAFETY: activated handle.
        source.link = LinkType::from_raw(unsafe { (self.datalink)(handle) } as u32);
        if let Some(filter) = opts.capture_filter.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
            source.set_filter(filter)?;
        }
        Ok(source)
    }
}

/// # Safety
/// `p` must be null or point to a NUL-terminated string.
unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller.
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

fn errbuf(buf: &[c_char; ERRBUF]) -> String {
    let bytes: Vec<u8> = buf.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn read_sockaddr(p: *const u8, fam: sockaddr::Families) -> Option<String> {
    // Read the family first, then exactly the size of that sockaddr variant,
    // so we never read past a shorter structure.
    // SAFETY: a non-null sockaddr has at least the 2 bytes of its header.
    let head = unsafe { std::slice::from_raw_parts(p, 2) };
    let family = if fam.has_len_byte { u16::from(head[1]) } else { u16::from_ne_bytes([head[0], head[1]]) };
    let size = if family == fam.inet {
        16
    } else if family == fam.inet6 {
        28
    } else {
        return None;
    };
    // SAFETY: sockaddr_in is 16 bytes and sockaddr_in6 28 bytes long.
    let raw = unsafe { std::slice::from_raw_parts(p, size) };
    sockaddr::format(raw, fam)
}

fn activate_error(rc: c_int, detail: &str) -> String {
    let what = match rc {
        -8 => "permission denied (run with sufficient privileges or allow non-admin capture in Npcap)",
        -9 => "promiscuous mode not permitted",
        -5 => "no such device",
        -7 => "interface is not up",
        -4 => "interface does not support monitor mode",
        _ => "activation failed",
    };
    if detail.is_empty() { what.to_owned() } else { format!("{what}: {detail}") }
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

pub fn api() -> Result<&'static Api, LiveError> {
    API.get_or_init(Api::load).as_ref().map_err(|e| LiveError::NotAvailable(e.clone()))
}

/// An activated pcap handle.
pub struct PcapSource {
    api: &'static Api,
    handle: Handle,
    link: LinkType,
}

// SAFETY: a pcap_t may be used from any thread as long as it is not used from
// two threads at once; `PcapSource` is owned by exactly one capture thread.
unsafe impl Send for PcapSource {}

impl PcapSource {
    fn last_error(&self) -> String {
        // SAFETY: valid handle; geterr returns a NUL-terminated string owned by it.
        unsafe { cstr((self.api.geterr)(self.handle)) }.unwrap_or_default()
    }

    fn set_filter(&mut self, filter: &str) -> Result<(), LiveError> {
        let text = CString::new(filter).map_err(|_| LiveError::Filter("filter contains NUL".into()))?;
        let mut prog = BpfProgram { bf_len: 0, bf_insns: std::ptr::null_mut() };
        // SAFETY: valid handle, program out-struct and C string.
        let rc = unsafe { (self.api.compile)(self.handle, &mut prog, text.as_ptr(), 1, PCAP_NETMASK_UNKNOWN) };
        if rc != 0 {
            return Err(LiveError::Filter(self.last_error()));
        }
        // SAFETY: program compiled above; freed right after installing it.
        let rc = unsafe { (self.api.setfilter)(self.handle, &mut prog) };
        unsafe { (self.api.freecode)(&mut prog) };
        if rc != 0 {
            return Err(LiveError::Filter(self.last_error()));
        }
        Ok(())
    }
}

impl LiveSource for PcapSource {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn next_packet(&mut self, buf: &mut Vec<u8>, _timeout: Duration) -> Result<Option<LivePacket>, LiveError> {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: valid handle and out-pointers; the driver waits at most READ_TIMEOUT_MS.
        let rc = unsafe { (self.api.next_ex)(self.handle, &mut hdr, &mut data) };
        match rc {
            1 if !hdr.is_null() && !data.is_null() => {
                // SAFETY: on success both pointers stay valid until the next call.
                let h = unsafe { &*hdr };
                let caplen = h.caplen.min(MAX_SNAPLEN) as usize;
                let bytes = unsafe { std::slice::from_raw_parts(data, caplen) };
                buf.clear();
                buf.extend_from_slice(bytes);
                let usec = (h.ts.usec as i64).clamp(0, 999_999) as u32;
                Ok(Some(LivePacket { ts: Timestamp::from_parts(h.ts.sec as i64, usec * 1000), origlen: h.len.max(h.caplen) }))
            }
            0 | -2 => Ok(None),
            _ => Err(LiveError::Read(self.last_error())),
        }
    }

    fn stats(&mut self) -> Option<DriverStats> {
        let mut st = PcapStat::default();
        // SAFETY: valid handle and stats struct (with spare room for Win32's extra field).
        let rc = unsafe { (self.api.stats)(self.handle, &mut st) };
        (rc == 0).then(|| DriverStats {
            received: u64::from(st.recv),
            dropped: u64::from(st.drop),
            if_dropped: u64::from(st.ifdrop),
        })
    }
}

impl Drop for PcapSource {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed exactly once.
        unsafe { (self.api.close)(self.handle) };
    }
}
