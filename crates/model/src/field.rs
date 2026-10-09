use serde::Serialize;

/// Typed value of a dissected field. Used by the protocol tree and the
/// display filter evaluator.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// Structural node without a comparable value (protocol headers, labels).
    None,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Mac([u8; 6]),
}

/// Declared type of a field in the filter registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    /// Protocol presence (`tcp`, `dns`, …).
    Protocol,
    Bool,
    Uint,
    Int,
    Float,
    String,
    Bytes,
    Ipv4,
    Ipv6,
    Mac,
    /// Text-only node, cannot be compared.
    None,
}

/// Field description sent to the UI for autocompletion and the filter builder.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldInfo {
    pub abbrev: String,
    pub name: String,
    pub kind: FieldKind,
    /// True if the field is resolved from the packet index without reading the file.
    pub indexed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Note,
    Warning,
    Error,
}

/// One node of the protocol details tree.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketField {
    /// Filter field abbreviation (`ip.src`), empty for text-only nodes.
    pub field: String,
    /// Default (English) label; the UI may localize by `field`.
    pub name: String,
    /// Formatted value; empty for protocol headings that carry a summary in `name`.
    pub display: String,
    /// Absolute byte offset inside the frame.
    pub start: u32,
    pub len: u32,
    /// Value computed by the analyzer rather than read from the packet.
    pub generated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Filter expression that selects packets with this field value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    pub children: Vec<PacketField>,
}
