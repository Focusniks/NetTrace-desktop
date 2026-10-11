//! Golden snapshots of every query result, so refactors of the in-memory
//! structures can prove they change nothing visible. Regenerate with
//! `NETTRACE_BLESS=1 cargo test -p nettrace-engine --test golden`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nettrace_engine::{ConversationQuery, ConversationSort, Engine, FlowQuery, FlowSort, FollowRequest, HostQuery, HostSort, TimelineRequest};
use nettrace_model::{ConversationKind, FollowDirection, IndexState, StreamRef, Transport};
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
    let follow = |kind, total: u32| -> Vec<Value> {
        (0..total.min(5))
            .map(|id| {
                let req = FollowRequest { stream: StreamRef { kind, id }, direction: FollowDirection::Both, offset: 0, limit: 4096 };
                json!(e.follow_stream(&req).unwrap())
            })
            .collect()
    };
    let follow = json!({ "tcp": follow(Transport::Tcp, tcp.total), "udp": follow(Transport::Udp, udp.total) });
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
        "follow": follow,
    })
}

/// JSON pointers where `a` and `b` differ (added, removed or changed values).
fn diff(a: &Value, b: &Value, path: &mut String, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: std::collections::BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                let len = path.len();
                path.push('/');
                path.push_str(k);
                diff(x.get(k).unwrap_or(&Value::Null), y.get(k).unwrap_or(&Value::Null), path, out);
                path.truncate(len);
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            for i in 0..x.len().max(y.len()) {
                let len = path.len();
                path.push_str(&format!("/{i}"));
                diff(x.get(i).unwrap_or(&Value::Null), y.get(i).unwrap_or(&Value::Null), path, out);
                path.truncate(len);
            }
        }
        _ if a != b => out.push(path.clone()),
        _ => {}
    }
}

/// Differences grouped by pattern (array indices as `*`), so a re-bless can
/// be checked to change only what was intended.
fn diff_report(old: &Value, new: &Value) -> String {
    let mut paths = Vec::new();
    diff(old, new, &mut String::new(), &mut paths);
    let mut patterns: std::collections::BTreeMap<String, usize> = Default::default();
    for p in &paths {
        let pattern: Vec<&str> = p.split('/').map(|s| if s.parse::<usize>().is_ok() { "*" } else { s }).collect();
        *patterns.entry(pattern.join("/")).or_default() += 1;
    }
    let mut out: Vec<String> = patterns.iter().map(|(p, n)| format!("  {n:>6} × {p}")).collect();
    out.push(format!("  first differences: {:?}", &paths[..paths.len().min(10)]));
    out.join("\n")
}

#[test]
fn diff_report_names_the_changed_paths() {
    let old = json!({"a": [{"x": 1}, {"x": 2}], "b": 1});
    let new = json!({"a": [{"x": 1}, {"x": 3, "y": 0}], "b": 1});
    let report = diff_report(&old, &new);
    assert!(report.contains("1 × /a/*/x") && report.contains("1 × /a/*/y"), "{report}");
    assert!(!report.contains("/b"));
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
        if let Ok(old) = std::fs::read_to_string(&golden) {
            let old: Value = serde_json::from_str(&old).unwrap();
            println!("{name}: changes against the previous golden:\n{}", diff_report(&old, &got));
        }
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        // Compact JSON, one key per line: small files, diffs that name the query.
        let lines: Vec<String> = got.as_object().unwrap().iter().map(|(k, v)| format!("{}: {v}", json!(k))).collect();
        std::fs::write(&golden, format!("{{\n{}\n}}\n", lines.join(",\n"))).unwrap();
        return;
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&golden).expect("golden missing: run with NETTRACE_BLESS=1")).unwrap();
    // Keys the golden does not have yet (new queries) appear only after a bless.
    let got_known: serde_json::Map<String, Value> = want.as_object().unwrap().keys().map(|k| (k.clone(), got[k].clone())).collect();
    let got_known = Value::Object(got_known);
    assert!(got_known == want, "{name} differs from the golden snapshot:\n{}", diff_report(&want, &got_known));
}

#[test]
fn demo_matches_golden() {
    check("demo", scenarios::demo());
}

#[test]
fn large_matches_golden() {
    check("large", scenarios::large(40));
}
