//! Development bridge: serves `POST /invoke/<command>` with JSON arguments on
//! 127.0.0.1 so the UI can be exercised in a regular browser against the real
//! engine (Vite proxies `/__bridge` here). Not part of the shipped app.
//!
//! Usage: `cargo run -p nettrace-devbridge [-- --port 1421]`
//!
//! Requests must come from the Vite dev origin with a JSON body and a local
//! Host header; file export is not exposed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nettrace_engine::{Engine, EngineError, FlowQuery, IoGraphRequest, SearchRequest, SortSpec, TimelineRequest};
use nettrace_model::{ConversationKind, LiveOptions, StreamRef};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADERS: usize = 16 * 1024;

fn arg<T: DeserializeOwned>(args: &Value, name: &str) -> Result<T, EngineError> {
    serde_json::from_value(args.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|e| EngineError::new("bad_request", format!("argument {name}: {e}")))
}

fn ok<T: serde::Serialize>(v: T) -> Result<Value, EngineError> {
    serde_json::to_value(v).map_err(|e| EngineError::new("internal", e.to_string()))
}

fn dispatch(engine: &Engine, cmd: &str, a: &Value) -> Result<Value, EngineError> {
    match cmd {
        "open_capture" => {
            let path: String = arg(a, "path")?;
            ok(engine.open(&PathBuf::from(path), Arc::new(|_| {}))?)
        }
        "close_capture" => {
            engine.close();
            ok(())
        }
        "capture_library" => ok(engine.capture_library()?),
        "capture_interfaces" => ok(engine.capture_interfaces()?),
        "start_capture" => {
            let opts: LiveOptions = arg(a, "options")?;
            match opts.interface.strip_prefix("replay:") {
                // Dev only: replay a capture file as if it were live traffic (no driver needed).
                Some(path) => ok(engine.start_capture_with(replay(path)?, "replay", Arc::new(|_| {}))?),
                None => ok(engine.start_capture(&opts, Arc::new(|_| {}))?),
            }
        }
        "stop_capture" => ok(engine.stop_capture()?),
        "initial_file" => ok(Option::<String>::None),
        "capture_summary" => ok(engine.summary()?),
        "index_progress" => ok(engine.progress()?),
        "apply_view" => {
            let filter: Option<String> = arg(a, "filter")?;
            let sort: Option<SortSpec> = arg(a, "sort")?;
            ok(engine.apply_view(filter.as_deref(), sort)?)
        }
        "get_rows" => ok(engine.rows(arg(a, "viewId")?, arg(a, "offset")?, arg(a, "limit")?)?),
        "find_row" => ok(engine.find_row(arg(a, "viewId")?, arg(a, "number")?)?),
        "packet_detail" => ok(engine.packet_detail(arg(a, "number")?)?),
        "validate_filter" => {
            let text: String = arg(a, "text")?;
            ok(engine.validate_filter(&text).err())
        }
        "list_fields" => ok(engine.fields()),
        "set_coloring_rules" => {
            let rules: Vec<String> = arg(a, "rules")?;
            ok(engine.set_coloring_rules(&rules))
        }
        "list_flows" => ok(engine.flows(&arg::<FlowQuery>(a, "query")?)?),
        "get_flow" => ok(engine.flow(arg::<StreamRef>(a, "stream")?)?),
        "get_sequence" => ok(engine.sequence(arg(a, "stream")?, arg(a, "offset")?, arg(a, "limit")?)?),
        "get_hosts" => ok(engine.hosts()?),
        "get_conversations" => ok(engine.conversations(arg::<ConversationKind>(a, "kind")?)?),
        "get_protocol_hierarchy" => ok(engine.protocol_hierarchy()?),
        "get_io_graph" => ok(engine.io_graph(&arg::<IoGraphRequest>(a, "request")?)?),
        "get_packet_lengths" => {
            let filter: Option<String> = arg(a, "filter")?;
            ok(engine.packet_lengths(filter.as_deref())?)
        }
        "get_timeline" => ok(engine.timeline(&arg::<TimelineRequest>(a, "request")?)?),
        "get_indicators" => ok(engine.indicators()?),
        "search" => ok(engine.search(&arg::<SearchRequest>(a, "request")?)?),
        other => Err(EngineError::new("unknown_command", other.to_owned())),
    }
}

fn replay(path: &str) -> Result<Box<dyn nettrace_live::LiveSource>, EngineError> {
    use nettrace_capture::{CaptureReader, PacketSource};
    let mut reader = CaptureReader::open(std::path::Path::new(path)).map_err(|e| EngineError::new(e.code(), e.to_string()))?;
    let mut frames = Vec::new();
    let mut buf = Vec::new();
    while let Ok(Some(rec)) = reader.next_record(&mut buf) {
        frames.push((rec.ts, buf.clone()));
    }
    let link = reader.interfaces().first().map_or(nettrace_packet::LinkType::Ethernet, |i| i.link_type);
    Ok(Box::new(nettrace_live::ReplaySource::new(link, frames, std::time::Duration::from_millis(40))))
}

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// Origins of the Vite dev server; requests from any other web page are rejected.
fn allowed_origin(origin: &str) -> bool {
    matches!(origin, "http://127.0.0.1:1420" | "http://localhost:1420")
}

/// The Host header must name this machine (defeats DNS rebinding).
fn allowed_host(host: &str) -> bool {
    let name = host.rsplit_once(':').map_or(host, |(h, _)| h);
    matches!(name, "127.0.0.1" | "localhost")
}

fn handle(engine: &Engine, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(clone) = stream.try_clone() else { return };
    let mut reader = BufReader::new(clone.take((MAX_HEADERS + MAX_BODY) as u64));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut content_length = 0usize;
    let mut host_ok = false;
    let mut origin_ok = true;
    let mut json = false;
    for _ in 0..64 {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            } else if k.eq_ignore_ascii_case("host") {
                host_ok = allowed_host(v);
            } else if k.eq_ignore_ascii_case("origin") {
                origin_ok = allowed_origin(v);
            } else if k.eq_ignore_ascii_case("content-type") {
                // JSON forces a CORS preflight for cross-site requests, which the bridge never answers.
                json = v.starts_with("application/json");
            }
        }
    }
    if !host_ok || !origin_ok || !json {
        respond(&mut stream, "403 Forbidden", b"{}");
        return;
    }
    let mut parts = request_line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let Some(cmd) = path.strip_prefix("/invoke/").or_else(|| path.strip_prefix("/__bridge/invoke/")) else {
        respond(&mut stream, "404 Not Found", b"{}");
        return;
    };
    if method != "POST" || content_length > MAX_BODY {
        respond(&mut stream, "400 Bad Request", b"{}");
        return;
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let args: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let out = match dispatch(engine, cmd, &args) {
        Ok(v) => json!({ "ok": v }),
        Err(e) => json!({ "err": e }),
    };
    respond(&mut stream, "200 OK", out.to_string().as_bytes());
}

fn main() -> std::io::Result<()> {
    let port = std::env::args()
        .skip_while(|a| a != "--port")
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(1421);
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("nettrace devbridge listening on http://127.0.0.1:{port}");
    let engine = Arc::new(Engine::new());
    for stream in listener.incoming().flatten() {
        let engine = engine.clone();
        std::thread::spawn(move || handle(&engine, stream));
    }
    Ok(())
}
