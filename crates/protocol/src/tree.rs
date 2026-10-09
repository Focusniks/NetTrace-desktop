//! Protocol tree builder.
//!
//! One code path serves three consumers:
//! * `Off`    – indexing: only the packet summary is needed, nothing is recorded;
//! * `Values` – deep display filter: a flat list of typed values, no strings;
//! * `Full`   – packet details: the complete tree with labels and byte ranges.

use std::net::{Ipv4Addr, Ipv6Addr};

use nettrace_model::{FieldKind, FieldValue, PacketField, Severity};
use nettrace_packet::MacAddr;

use crate::fields::Field;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeMode {
    Off,
    Values,
    Full,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub field: Option<&'static Field>,
    /// Overrides the field name (protocol headings carry a summary here).
    pub label: Option<String>,
    pub display: String,
    pub value: FieldValue,
    pub start: usize,
    pub len: usize,
    pub generated: bool,
    pub severity: Option<Severity>,
    pub children: Vec<Node>,
}

impl Node {
    fn new(field: Option<&'static Field>, start: usize, len: usize) -> Self {
        Node {
            field,
            label: None,
            display: String::new(),
            value: FieldValue::None,
            start,
            len,
            generated: false,
            severity: None,
            children: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        self.label.as_deref().or(self.field.map(|f| f.name)).unwrap_or("")
    }
}

#[derive(Debug)]
pub struct Tree {
    mode: TreeMode,
    roots: Vec<Node>,
    stack: Vec<Node>,
    values: Vec<(&'static Field, FieldValue)>,
}

impl Tree {
    pub fn new(mode: TreeMode) -> Self {
        Tree { mode, roots: Vec::new(), stack: Vec::new(), values: Vec::new() }
    }

    pub fn mode(&self) -> TreeMode {
        self.mode
    }

    /// True if labels and display strings should be produced.
    pub fn full(&self) -> bool {
        self.mode == TreeMode::Full
    }

    pub fn enabled(&self) -> bool {
        self.mode != TreeMode::Off
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    fn attach(&mut self, node: Node) {
        match self.stack.last_mut() {
            Some(parent) => parent.children.push(node),
            None => self.roots.push(node),
        }
    }

    /// Opens a subtree for `field`; must be balanced with [`Tree::close`]
    /// (the dissector driver closes dangling subtrees after errors).
    pub fn open(&mut self, field: &'static Field, start: usize, len: usize) {
        match self.mode {
            TreeMode::Off => {}
            TreeMode::Values => self.values.push((field, FieldValue::None)),
            TreeMode::Full => self.stack.push(Node::new(Some(field), start, len)),
        }
    }

    /// Opens a subtree whose value can be filtered on (e.g. `tcp.flags`).
    pub fn open_value(
        &mut self,
        field: &'static Field,
        start: usize,
        len: usize,
        value: FieldValue,
        display: impl FnOnce() -> String,
    ) {
        match self.mode {
            TreeMode::Off => {}
            TreeMode::Values => self.values.push((field, value)),
            TreeMode::Full => {
                let mut node = Node::new(Some(field), start, len);
                node.display = display();
                node.value = value;
                self.stack.push(node);
            }
        }
    }

    pub fn open_text(&mut self, label: impl FnOnce() -> String, start: usize, len: usize) {
        if self.mode == TreeMode::Full {
            let mut node = Node::new(None, start, len);
            node.label = Some(label());
            self.stack.push(node);
        }
    }

    /// Sets the label of the innermost open node.
    pub fn heading(&mut self, label: impl FnOnce() -> String) {
        if self.mode == TreeMode::Full {
            if let Some(top) = self.stack.last_mut() {
                top.label = Some(label());
            }
        }
    }

    pub fn set_len(&mut self, len: usize) {
        if let Some(top) = self.stack.last_mut() {
            top.len = len;
        }
    }

    pub fn mark_generated(&mut self) {
        if let Some(top) = self.stack.last_mut() {
            top.generated = true;
        }
    }

    pub fn close(&mut self) {
        if let Some(node) = self.stack.pop() {
            self.attach(node);
        }
    }

    /// Closes open subtrees until `depth` remain.
    pub fn close_to(&mut self, depth: usize) {
        while self.stack.len() > depth {
            self.close();
        }
    }

    pub fn add(
        &mut self,
        field: &'static Field,
        start: usize,
        len: usize,
        value: FieldValue,
        display: impl FnOnce() -> String,
    ) {
        self.add_node(field, start, len, value, display, false, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn add_node(
        &mut self,
        field: &'static Field,
        start: usize,
        len: usize,
        value: FieldValue,
        display: impl FnOnce() -> String,
        generated: bool,
        severity: Option<Severity>,
    ) {
        match self.mode {
            TreeMode::Off => {}
            TreeMode::Values => self.values.push((field, value)),
            TreeMode::Full => {
                let mut node = Node::new(Some(field), start, len);
                node.display = display();
                node.value = value;
                node.generated = generated;
                node.severity = severity;
                self.attach(node);
            }
        }
    }

    /// Adds a value computed by the analyzer (shown in brackets, no byte range).
    pub fn generated(&mut self, field: &'static Field, value: FieldValue, display: impl FnOnce() -> String) {
        self.add_node(field, 0, 0, value, display, true, None);
    }

    /// Adds an expert-info item (analysis flags, malformed markers).
    pub fn expert(&mut self, field: &'static Field, severity: Severity, label: impl FnOnce() -> String) {
        match self.mode {
            TreeMode::Off => {}
            TreeMode::Values => self.values.push((field, FieldValue::None)),
            TreeMode::Full => {
                let mut node = Node::new(Some(field), 0, 0);
                node.label = Some(label());
                node.generated = true;
                node.severity = Some(severity);
                self.attach(node);
            }
        }
    }

    pub fn text(&mut self, label: impl FnOnce() -> String, start: usize, len: usize) {
        if self.mode == TreeMode::Full {
            let mut node = Node::new(None, start, len);
            node.label = Some(label());
            self.attach(node);
        }
    }

    pub fn uint(&mut self, field: &'static Field, start: usize, len: usize, v: u64) {
        self.add(field, start, len, FieldValue::U64(v), || v.to_string());
    }

    /// Unsigned value shown as `0x…` with `digits` hex digits.
    pub fn hex(&mut self, field: &'static Field, start: usize, len: usize, v: u64, digits: usize) {
        self.add(field, start, len, FieldValue::U64(v), || format!("0x{v:0digits$x}"));
    }

    /// Unsigned value with a symbolic name: `Name (value)`.
    pub fn named(&mut self, field: &'static Field, start: usize, len: usize, v: u64, name: &str) {
        self.add(field, start, len, FieldValue::U64(v), || format!("{name} ({v})"));
    }

    pub fn flag(&mut self, field: &'static Field, start: usize, len: usize, set: bool, bits: impl FnOnce() -> String) {
        self.add(field, start, len, FieldValue::Bool(set), || {
            format!("{} = {}", bits(), if set { "Set" } else { "Not set" })
        });
    }

    pub fn ipv4(&mut self, field: &'static Field, start: usize, b: [u8; 4]) {
        self.add(field, start, 4, FieldValue::Ipv4(b), || Ipv4Addr::from(b).to_string());
    }

    pub fn ipv6(&mut self, field: &'static Field, start: usize, b: [u8; 16]) {
        self.add(field, start, 16, FieldValue::Ipv6(b), || Ipv6Addr::from(b).to_string());
    }

    pub fn mac(&mut self, field: &'static Field, start: usize, b: [u8; 6]) {
        self.add(field, start, 6, FieldValue::Mac(b), || MacAddr(b).to_string());
    }

    pub fn string(&mut self, field: &'static Field, start: usize, len: usize, s: &str) {
        match self.mode {
            TreeMode::Off => {}
            _ => self.add(field, start, len, FieldValue::Str(s.to_owned()), || s.to_owned()),
        }
    }

    pub fn bytes(&mut self, field: &'static Field, start: usize, data: &[u8]) {
        match self.mode {
            TreeMode::Off => {}
            _ => self.add(field, start, data.len(), FieldValue::Bytes(data.to_vec()), || {
                crate::format::hex_preview(data, 24)
            }),
        }
    }

    /// Finishes the tree, closing any dangling subtrees.
    pub fn finish(mut self) -> (Vec<Node>, Vec<(&'static Field, FieldValue)>) {
        self.close_to(0);
        (self.roots, self.values)
    }
}

/// Converts the internal tree to the UI model.
pub fn to_model(nodes: &[Node]) -> Vec<PacketField> {
    nodes.iter().map(node_to_model).collect()
}

fn node_to_model(n: &Node) -> PacketField {
    PacketField {
        field: n.field.map(|f| f.abbrev.to_owned()).unwrap_or_default(),
        name: n.name().to_owned(),
        display: n.display.clone(),
        start: u32::try_from(n.start).unwrap_or(u32::MAX),
        len: u32::try_from(n.len).unwrap_or(0),
        generated: n.generated,
        severity: n.severity,
        filter: n.field.and_then(|f| filter_for(f, &n.value)),
        children: to_model(&n.children),
    }
}

/// Builds a display filter expression selecting this field value.
pub fn filter_for(field: &Field, value: &FieldValue) -> Option<String> {
    let a = field.abbrev;
    let lit = match value {
        FieldValue::None => return Some(a.to_owned()),
        FieldValue::Bool(b) => (if *b { "1" } else { "0" }).to_owned(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::I64(v) => v.to_string(),
        FieldValue::F64(v) => v.to_string(),
        FieldValue::Str(s) => quote(s),
        FieldValue::Bytes(b) if b.len() <= 64 && field.kind == FieldKind::Bytes && !b.is_empty() => b
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        FieldValue::Bytes(_) => return Some(a.to_owned()),
        FieldValue::Ipv4(b) => Ipv4Addr::from(*b).to_string(),
        FieldValue::Ipv6(b) => Ipv6Addr::from(*b).to_string(),
        FieldValue::Mac(b) => MacAddr(*b).to_string(),
    };
    Some(format!("{a} == {lit}"))
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32 & 0xff)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields;

    #[test]
    fn off_mode_records_nothing() {
        let mut t = Tree::new(TreeMode::Off);
        t.open(&fields::IP, 0, 20);
        t.uint(&fields::IP_TTL, 8, 1, 64);
        t.close();
        let (nodes, values) = t.finish();
        assert!(nodes.is_empty() && values.is_empty());
    }

    #[test]
    fn values_mode_is_flat() {
        let mut t = Tree::new(TreeMode::Values);
        t.open(&fields::IP, 0, 20);
        t.uint(&fields::IP_TTL, 8, 1, 64);
        t.text(|| "ignored".into(), 0, 0);
        t.close();
        let (nodes, values) = t.finish();
        assert!(nodes.is_empty());
        assert_eq!(values.len(), 2);
        assert_eq!(values[1], (&fields::IP_TTL, FieldValue::U64(64)));
    }

    #[test]
    fn full_mode_nests_and_closes_dangling() {
        let mut t = Tree::new(TreeMode::Full);
        t.open(&fields::IP, 14, 20);
        t.heading(|| "Internet Protocol Version 4, Src: 1.2.3.4".into());
        t.uint(&fields::IP_TTL, 22, 1, 64);
        t.open(&fields::IP_FLAGS, 20, 2);
        let (nodes, _) = t.finish();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name(), "Internet Protocol Version 4, Src: 1.2.3.4");
        assert_eq!(nodes[0].children.len(), 2);
        let model = to_model(&nodes);
        assert_eq!(model[0].children[0].field, "ip.ttl");
        assert_eq!(model[0].children[0].display, "64");
        assert_eq!(model[0].children[0].filter.as_deref(), Some("ip.ttl == 64"));
        assert_eq!(model[0].filter.as_deref(), Some("ip"));
    }

    #[test]
    fn string_filters_are_quoted() {
        let f = filter_for(&fields::HTTP_HOST, &FieldValue::Str("a\"b\\c".into())).unwrap();
        assert_eq!(f, r#"http.host == "a\"b\\c""#);
        let f = filter_for(&fields::IP_SRC, &FieldValue::Ipv4([10, 0, 0, 1])).unwrap();
        assert_eq!(f, "ip.src == 10.0.0.1");
    }
}
