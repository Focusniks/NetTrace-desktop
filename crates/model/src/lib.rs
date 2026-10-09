//! UI-facing domain model.
//!
//! These types are the only contract between the backend and the React UI:
//! the frontend never sees dissector internals, only `Packet*`, `Flow*`,
//! `Host*`, `Conversation*`, `Protocol*`, `Timeline*` and `PacketField`.
//! All structs serialize to camelCase JSON.

mod capture;
mod field;
mod flow;
mod packet;
mod protocol;
mod stats;

pub use capture::*;
pub use field::*;
pub use flow::*;
pub use packet::*;
pub use protocol::*;
pub use stats::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_serializes_with_code_tag() {
        let ind = Indicator {
            severity: Severity::Warning,
            kind: IndicatorKind::TcpResets { streams: 3, packets: 4 },
            filter: "tcp.flags.reset == 1".into(),
            first_packet: Some(7),
        };
        let json = serde_json::to_value(&ind).unwrap();
        assert_eq!(json["code"], "tcp_resets");
        assert_eq!(json["streams"], 3);
        assert_eq!(json["severity"], "warning");
        assert_eq!(json["firstPacket"], 7);
    }

    #[test]
    fn stream_ref_is_camel_case() {
        let s = StreamRef { kind: Transport::Tcp, id: 42 };
        assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"kind":"tcp","id":42}"#);
    }
}
