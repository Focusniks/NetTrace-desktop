//! Golden snapshots of every query result, so refactors of the in-memory
//! structures can prove they change nothing visible. Regenerate with
//! `NETTRACE_BLESS=1 cargo test -p nettrace-engine --test golden`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nettrace_engine::{ConversationQuery, ConversationSort, Engine, FlowQuery, FlowSort, HostQuery, HostSort, TimelineRequest};
use nettrace_model::{ConversationKind, IndexState, StreamRef, Transport};
use nettrace_testkit::{scenarios, Capture};
use serde_json::{json, Value};

fn open(path: &Path) -> Engine {
    let engine = Engine::new();
    engine.open(path, Arc::new(|_| {})).unwrap();
    let p = engine.session().unwrap().wait_indexed(Duration::from_secs(60));
    assert_eq!(p.state, IndexState::Done, "{p:?}");
    engine
}

/// Rows whose order among equal sort keys is not part of the contract.
fn unordered(v: Value) -> Value {
    let mut rows = v.as_array().cloned().unwrap_or_default();
    rows.sort_by_key(|r| r.to_string());
    Value::Array(rows)
}

fn hosts(e: &Engine) -> Value {
    let mut rows = Vec::new();
    loop {
        let q = HostQuery { sort: HostSort::Bytes, desc: true, offset: rows.len() as u32, limit: 1000, search: None };
        let page = e.hosts_page(&q).unwrap();
        rows.extend(page.rows);
        if rows.len() as u32 >= page.total {
            return json!(rows);
        }
    }
}

fn conversations(e: &Engine, kind: ConversationKind) -> Value {
    let mut rows = Vec::new();
    loop {
        let q = ConversationQuery { kind, sort: ConversationSort::Bytes, desc: true, offset: rows.len() as u32, limit: 1000, search: None };
        let page = e.conversations_page(&q).unwrap();
        rows.extend(page.rows);
        if rows.len() as u32 >= page.total {
            return json!(rows);
        }
    }
}

fn snapshot(e: &Engine) -> Value {
    let all = |kind| FlowQuery { kind: Some(kind), sort: FlowSort::Id, desc: false, offset: 0, limit: 5000, search: None };
    let tcp = e.flows(&all(Transport::Tcp)).unwrap();
    let udp = e.flows(&all(Transport::Udp)).unwrap();
    let sequences: Vec<Value> = (0..tcp.total.min(20))
        .map(|id| json!(e.sequence(StreamRef { kind: Transport::Tcp, id }, 0, 5000).unwrap()))
        .collect();
    let total = e.session().unwrap().progress().packets;
    let details: Vec<Value> = (1..=total.min(25)).map(|n| json!(e.packet_detail(n).unwrap())).collect();
    json!({
        "summary": e.summary().unwrap(),
        "rows": e.rows(0, 0, total).unwrap(),
        "details": details,
        "hosts": unordered(hosts(e)),
        "conversations": {
            "eth": unordered(conversations(e, ConversationKind::Eth)),
            "ip": unordered(conversations(e, ConversationKind::Ip)),
            "tcp": unordered(conversations(e, ConversationKind::Tcp)),
            "udp": unordered(conversations(e, ConversationKind::Udp)),
        },
        "flows": { "tcp": tcp, "udp": udp },
        "sequences": sequences,
        "timeline": e.timeline(&TimelineRequest { start: None, end: None, buckets: 100, max_events: 20_000 }).unwrap(),
        "indicators": unordered(json!(e.indicators().unwrap())),
        "hierarchy": e.protocol_hierarchy().unwrap(),
    })
}

fn check(name: &str, cap: Capture) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{name}.pcapng"));
    std::fs::write(&path, cap.to_pcapng()).unwrap();
    let mut got = snapshot(&open(&path));
    // The capture path is a temp dir that differs per run.
    got["summary"]["info"]["path"] = Value::Null;
    let golden: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "golden", &format!("{name}.json")].iter().collect();
    if std::env::var_os("NETTRACE_BLESS").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        // Compact JSON, one key per line: small files, diffs that name the query.
        let lines: Vec<String> = got.as_object().unwrap().iter().map(|(k, v)| format!("{}: {v}", json!(k))).collect();
        std::fs::write(&golden, format!("{{\n{}\n}}\n", lines.join(",\n"))).unwrap();
        return;
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&golden).expect("golden missing: run with NETTRACE_BLESS=1")).unwrap();
    for (key, value) in want.as_object().unwrap() {
        assert!(got[key] == *value, "{name}: `{key}` differs from the golden snapshot");
    }
}

#[test]
fn demo_matches_golden() {
    check("demo", scenarios::demo());
}

#[test]
fn large_matches_golden() {
    check("large", scenarios::large(40));
}
