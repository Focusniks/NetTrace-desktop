//! Display filter language.
//!
//! ```text
//! expr    := or
//! or      := and (("||" | "or") and)*
//! and     := unary (("&&" | "and") unary)*
//! unary   := ("!" | "not") unary | primary
//! primary := "(" expr ")" | field [op value] | field "in" "{" value* "}"
//! op      := == != < <= > >= eq ne lt le gt ge contains
//! ```
//!
//! The crate knows nothing about protocols or storage: field names are
//! resolved through [`FieldRegistry`] and values come from [`FieldSource`].

mod error;
mod filter;
mod lexer;
mod parser;

pub use error::{ErrorCode, QueryError};
pub use filter::{FieldRegistry, FieldSource, FieldSpec, Filter};
pub use parser::{parse, Ast, CmpOp, Lit, Span};

#[cfg(test)]
mod tests {
    use super::*;
    use nettrace_model::{FieldKind, FieldValue};
    use std::collections::HashMap;

    struct Reg;
    impl FieldRegistry for Reg {
        fn resolve(&self, name: &str) -> Option<FieldSpec> {
            let (kind, ids) = match name {
                "tcp" => (FieldKind::Protocol, vec![1]),
                "udp" => (FieldKind::Protocol, vec![2]),
                "ip.src" => (FieldKind::Ipv4, vec![3]),
                "ip.dst" => (FieldKind::Ipv4, vec![4]),
                "ip.addr" => (FieldKind::Ipv4, vec![3, 4]),
                "tcp.port" => (FieldKind::Uint, vec![5, 6]),
                "tcp.srcport" => (FieldKind::Uint, vec![5]),
                "http.host" => (FieldKind::String, vec![7]),
                "tcp.flags.syn" => (FieldKind::Bool, vec![8]),
                "frame.time_relative" => (FieldKind::Float, vec![9]),
                "eth.src" => (FieldKind::Mac, vec![10]),
                "tcp.payload" => (FieldKind::Bytes, vec![11]),
                "ipv6.addr" => (FieldKind::Ipv6, vec![12]),
                _ => return None,
            };
            Some(FieldSpec { kind, ids })
        }
    }

    #[derive(Default)]
    struct Pkt(HashMap<u32, Vec<FieldValue>>);
    impl Pkt {
        fn with(mut self, id: u32, v: FieldValue) -> Self {
            self.0.entry(id).or_default().push(v);
            self
        }
    }
    impl FieldSource for Pkt {
        fn values(&mut self, id: u32, out: &mut Vec<FieldValue>) {
            if let Some(v) = self.0.get(&id) {
                out.extend(v.iter().cloned());
            }
        }
    }

    fn pkt() -> Pkt {
        Pkt::default()
            .with(1, FieldValue::None)
            .with(3, FieldValue::Ipv4([10, 10, 1, 15]))
            .with(4, FieldValue::Ipv4([10, 10, 4, 21]))
            .with(5, FieldValue::U64(52144))
            .with(6, FieldValue::U64(443))
            .with(7, FieldValue::Str("api.example.com".into()))
            .with(8, FieldValue::Bool(false))
            .with(9, FieldValue::F64(12.5))
            .with(10, FieldValue::Mac([0, 0x1f, 0x1a, 0x2b, 0x3c, 1]))
            .with(11, FieldValue::Bytes(b"GET /x".to_vec()))
            .with(12, FieldValue::Ipv6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
    }

    fn m(f: &str) -> bool {
        Filter::compile(f, &Reg).unwrap_or_else(|e| panic!("{f}: {e}")).matches(&mut pkt())
    }

    #[test]
    fn mvp_filters() {
        assert!(m("ip.addr == 10.10.1.15"));
        assert!(m("ip.src == 10.10.1.15"));
        assert!(!m("ip.dst == 10.10.1.15"));
        assert!(m("tcp.port == 443"));
        assert!(!m("tcp.srcport == 443"));
        assert!(m("tcp"));
        assert!(!m("udp"));
        assert!(m("ip.addr == 10.10.1.15 && tcp.port == 443"));
        assert!(m("udp || tcp"));
        assert!(m("!udp"));
        assert!(m("not udp and tcp"));
    }

    #[test]
    fn ne_means_no_value_equal() {
        // ip.addr != X means "neither src nor dst is X".
        assert!(!m("ip.addr != 10.10.1.15"));
        assert!(m("ip.addr != 1.2.3.4"));
    }

    #[test]
    fn typed_comparisons() {
        assert!(m("ip.addr == 10.10.0.0/16"));
        assert!(!m("ip.addr == 192.168.0.0/16"));
        assert!(m("tcp.port > 1000 && tcp.port <= 0x1bb"));
        assert!(m("tcp.port in {80 443 8443}"));
        assert!(!m("tcp.port in {80, 8080}"));
        assert!(m(r#"http.host contains "example""#));
        assert!(m("http.host == api.example.com"));
        assert!(m("tcp.flags.syn == 0"));
        assert!(m("frame.time_relative >= 10"));
        assert!(m("frame.time_relative < 12.75"));
        assert!(m("eth.src == 00:1f:1a:2b:3c:01"));
        assert!(m(r#"tcp.payload contains "GET""#));
        assert!(m("tcp.payload contains 47:45:54"));
        assert!(m("ipv6.addr == fe80::/64"));
        assert!(!m("ipv6.addr == 2001:db8::/32"));
        assert!(m("ip.addr == 0.0.0.0/0"));
    }

    #[test]
    fn compile_errors() {
        let code = |f: &str| Filter::compile(f, &Reg).unwrap_err().code;
        assert_eq!(code("foo.bar"), ErrorCode::UnknownField);
        assert_eq!(code("tcp == 1"), ErrorCode::OperatorNotSupported);
        assert_eq!(code("ip.src > 1.2.3.4"), ErrorCode::OperatorNotSupported);
        assert_eq!(code("tcp.port contains 4"), ErrorCode::OperatorNotSupported);
        assert_eq!(code("ip.src == 300.1.1.1"), ErrorCode::InvalidValue);
        assert_eq!(code("ip.src == 10.0.0.0/33"), ErrorCode::InvalidValue);
        assert_eq!(code("tcp.port == abc"), ErrorCode::InvalidValue);
        assert_eq!(code(r#"tcp.port == "80""#), ErrorCode::InvalidValue);
        assert_eq!(code("tcp.flags.syn == 2"), ErrorCode::InvalidValue);
        assert_eq!(code("eth.src == 00:11"), ErrorCode::InvalidValue);
        assert_eq!(code("frame.time_relative > inf"), ErrorCode::InvalidValue);
        let e = Filter::compile("tcp && foo", &Reg).unwrap_err();
        assert_eq!((e.start, e.end, e.detail.as_str()), (7, 10, "foo"));
    }

    #[test]
    fn referenced_fields() {
        let f = Filter::compile("ip.addr == 1.2.3.4 || ip.src == 1.1.1.1 || tcp", &Reg).unwrap();
        assert_eq!(f.fields(), &[1, 3, 4]);
    }
}
