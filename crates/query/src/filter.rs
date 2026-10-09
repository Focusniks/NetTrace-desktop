//! Typed compilation of the AST and evaluation against a packet.

use std::net::{Ipv4Addr, Ipv6Addr};

use nettrace_model::{FieldKind, FieldValue};
use nettrace_packet::MacAddr;

use crate::error::{ErrorCode, QueryError};
use crate::parser::{parse, Ast, CmpOp, Lit, Span};

/// Field resolution provided by the host (the engine maps protocol fields to ids).
pub trait FieldRegistry {
    fn resolve(&self, name: &str) -> Option<FieldSpec>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpec {
    pub kind: FieldKind,
    /// One id for a plain field; several for aliases such as `ip.addr`.
    pub ids: Vec<u32>,
}

/// Values of the packet currently being evaluated.
pub trait FieldSource {
    /// Appends every occurrence of field `id` to `out`.
    fn values(&mut self, id: u32, out: &mut Vec<FieldValue>);
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    U64(u64),
    I64(i64),
    F64(f64),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    V4Net { addr: u32, mask: u32 },
    V6Net { addr: [u8; 16], prefix: u8 },
    Mac([u8; 6]),
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Exists(Vec<u32>),
    Cmp { ids: Vec<u32>, op: CmpOp, value: Value },
    In { ids: Vec<u32>, values: Vec<Value> },
}

/// A compiled display filter.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    expr: Expr,
    fields: Vec<u32>,
}

impl Filter {
    pub fn compile(text: &str, registry: &dyn FieldRegistry) -> Result<Filter, QueryError> {
        let ast = parse(text)?;
        let mut fields = Vec::new();
        let expr = compile(&ast, registry, &mut fields)?;
        fields.sort_unstable();
        fields.dedup();
        Ok(Filter { expr, fields })
    }

    /// Ids of all fields referenced by the filter.
    pub fn fields(&self) -> &[u32] {
        &self.fields
    }

    pub fn matches(&self, src: &mut dyn FieldSource) -> bool {
        let mut buf = Vec::with_capacity(4);
        eval(&self.expr, src, &mut buf)
    }
}

fn err(code: ErrorCode, span: Span, detail: &str) -> QueryError {
    QueryError::new(code, span.start, span.end, detail)
}

fn resolve(name: &str, span: Span, registry: &dyn FieldRegistry, fields: &mut Vec<u32>) -> Result<FieldSpec, QueryError> {
    let spec = registry.resolve(name).ok_or_else(|| err(ErrorCode::UnknownField, span, name))?;
    fields.extend_from_slice(&spec.ids);
    Ok(spec)
}

fn compile(ast: &Ast, registry: &dyn FieldRegistry, fields: &mut Vec<u32>) -> Result<Expr, QueryError> {
    Ok(match ast {
        Ast::Or(a, b) => Expr::Or(Box::new(compile(a, registry, fields)?), Box::new(compile(b, registry, fields)?)),
        Ast::And(a, b) => Expr::And(Box::new(compile(a, registry, fields)?), Box::new(compile(b, registry, fields)?)),
        Ast::Not(a) => Expr::Not(Box::new(compile(a, registry, fields)?)),
        Ast::Field { name, span } => Expr::Exists(resolve(name, *span, registry, fields)?.ids),
        Ast::Cmp { field, field_span, op, value, value_span } => {
            let spec = resolve(field, *field_span, registry, fields)?;
            check_op(spec.kind, *op, *field_span)?;
            let value = literal(spec.kind, *op, value, *value_span)?;
            Expr::Cmp { ids: spec.ids, op: *op, value }
        }
        Ast::In { field, field_span, values } => {
            let spec = resolve(field, *field_span, registry, fields)?;
            check_op(spec.kind, CmpOp::Eq, *field_span)?;
            let values = values
                .iter()
                .map(|(lit, span)| literal(spec.kind, CmpOp::Eq, lit, *span))
                .collect::<Result<Vec<_>, _>>()?;
            Expr::In { ids: spec.ids, values }
        }
    })
}

fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Protocol => "protocol",
        FieldKind::Bool => "bool",
        FieldKind::Uint => "uint",
        FieldKind::Int => "int",
        FieldKind::Float => "float",
        FieldKind::String => "string",
        FieldKind::Bytes => "bytes",
        FieldKind::Ipv4 => "ipv4",
        FieldKind::Ipv6 => "ipv6",
        FieldKind::Mac => "mac",
        FieldKind::None => "none",
    }
}

fn check_op(kind: FieldKind, op: CmpOp, span: Span) -> Result<(), QueryError> {
    let ok = match kind {
        FieldKind::Protocol | FieldKind::None => false,
        FieldKind::Bool | FieldKind::Ipv4 | FieldKind::Ipv6 | FieldKind::Mac => matches!(op, CmpOp::Eq | CmpOp::Ne),
        FieldKind::Uint | FieldKind::Int | FieldKind::Float => op != CmpOp::Contains,
        FieldKind::String | FieldKind::Bytes => true,
    };
    if ok { Ok(()) } else { Err(err(ErrorCode::OperatorNotSupported, span, kind_name(kind))) }
}

fn parse_u64(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_bytes(s: &str) -> Option<Vec<u8>> {
    let digits: String = s.chars().filter(|c| !matches!(c, ':' | '-' | '.')).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(digits.get(i..i + 2)?, 16).ok()).collect()
}

fn literal(kind: FieldKind, op: CmpOp, lit: &Lit, span: Span) -> Result<Value, QueryError> {
    let bad = || err(ErrorCode::InvalidValue, span, kind_name(kind));
    let word = match lit {
        Lit::Word(w) => Some(w.as_str()),
        Lit::Str(_) => None,
    };
    Ok(match kind {
        FieldKind::Uint => Value::U64(word.and_then(parse_u64).ok_or_else(bad)?),
        FieldKind::Int => Value::I64(word.and_then(|w| w.parse().ok()).ok_or_else(bad)?),
        FieldKind::Float => Value::F64(word.and_then(|w| w.parse::<f64>().ok()).filter(|f| f.is_finite()).ok_or_else(bad)?),
        FieldKind::Bool => match word.map(str::to_ascii_lowercase).as_deref() {
            Some("1" | "true") => Value::Bool(true),
            Some("0" | "false") => Value::Bool(false),
            _ => return Err(bad()),
        },
        FieldKind::String => match lit {
            Lit::Str(s) | Lit::Word(s) => Value::Str(s.clone()),
        },
        FieldKind::Bytes => match lit {
            Lit::Str(s) => Value::Bytes(s.as_bytes().to_vec()),
            Lit::Word(w) => Value::Bytes(parse_bytes(w).ok_or_else(bad)?),
        },
        FieldKind::Ipv4 => {
            let w = word.ok_or_else(bad)?;
            let (addr, prefix) = match w.split_once('/') {
                Some((a, p)) => (a, p.parse::<u8>().ok().filter(|p| *p <= 32).ok_or_else(bad)?),
                None => (w, 32),
            };
            let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
            Value::V4Net { addr: u32::from(addr) & mask, mask }
        }
        FieldKind::Ipv6 => {
            let w = word.ok_or_else(bad)?;
            let (addr, prefix) = match w.split_once('/') {
                Some((a, p)) => (a, p.parse::<u8>().ok().filter(|p| *p <= 128).ok_or_else(bad)?),
                None => (w, 128),
            };
            let addr: Ipv6Addr = addr.parse().map_err(|_| bad())?;
            Value::V6Net { addr: addr.octets(), prefix }
        }
        FieldKind::Mac => Value::Mac(word.and_then(MacAddr::parse).ok_or_else(bad)?.0),
        FieldKind::Protocol | FieldKind::None => {
            let _ = op;
            return Err(bad());
        }
    })
}

fn eval(e: &Expr, src: &mut dyn FieldSource, buf: &mut Vec<FieldValue>) -> bool {
    match e {
        Expr::Or(a, b) => eval(a, src, buf) || eval(b, src, buf),
        Expr::And(a, b) => eval(a, src, buf) && eval(b, src, buf),
        Expr::Not(a) => !eval(a, src, buf),
        Expr::Exists(ids) => {
            buf.clear();
            for id in ids {
                src.values(*id, buf);
                if !buf.is_empty() {
                    return true;
                }
            }
            false
        }
        Expr::Cmp { ids, op, value } => {
            gather(ids, src, buf);
            match op {
                // `a != b` ⇔ `!(a == b)`: true only if no occurrence equals the value.
                CmpOp::Ne => !buf.iter().any(|v| compare(v, CmpOp::Eq, value)),
                _ => buf.iter().any(|v| compare(v, *op, value)),
            }
        }
        Expr::In { ids, values } => {
            gather(ids, src, buf);
            buf.iter().any(|v| values.iter().any(|x| compare(v, CmpOp::Eq, x)))
        }
    }
}

fn gather(ids: &[u32], src: &mut dyn FieldSource, buf: &mut Vec<FieldValue>) {
    buf.clear();
    for id in ids {
        src.values(*id, buf);
    }
}

fn ord<T: PartialOrd>(a: T, op: CmpOp, b: T) -> bool {
    match op {
        CmpOp::Eq => a == b,
        CmpOp::Ne => a != b,
        CmpOp::Lt => a < b,
        CmpOp::Le => a <= b,
        CmpOp::Gt => a > b,
        CmpOp::Ge => a >= b,
        CmpOp::Contains => false,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

fn compare(v: &FieldValue, op: CmpOp, x: &Value) -> bool {
    match (v, x) {
        (FieldValue::U64(a), Value::U64(b)) => ord(*a, op, *b),
        (FieldValue::U64(a), Value::F64(b)) => ord(*a as f64, op, *b),
        (FieldValue::U64(a), Value::I64(b)) => ord(i128::from(*a), op, i128::from(*b)),
        (FieldValue::I64(a), Value::I64(b)) => ord(*a, op, *b),
        (FieldValue::I64(a), Value::U64(b)) => ord(i128::from(*a), op, i128::from(*b)),
        (FieldValue::I64(a), Value::F64(b)) => ord(*a as f64, op, *b),
        (FieldValue::F64(a), Value::F64(b)) => ord(*a, op, *b),
        (FieldValue::F64(a), Value::U64(b)) => ord(*a, op, *b as f64),
        (FieldValue::Bool(a), Value::Bool(b)) => ord(*a, op, *b),
        (FieldValue::U64(a), Value::Bool(b)) => ord(*a != 0, op, *b),
        (FieldValue::Str(a), Value::Str(b)) => match op {
            CmpOp::Contains => a.contains(b.as_str()),
            _ => ord(a.as_str(), op, b.as_str()),
        },
        (FieldValue::Str(a), Value::Bytes(b)) => match op {
            CmpOp::Contains => contains(a.as_bytes(), b),
            _ => ord(a.as_bytes(), op, b.as_slice()),
        },
        (FieldValue::Bytes(a), Value::Bytes(b)) => match op {
            CmpOp::Contains => contains(a, b),
            _ => ord(a.as_slice(), op, b.as_slice()),
        },
        (FieldValue::Bytes(a), Value::Str(b)) => match op {
            CmpOp::Contains => contains(a, b.as_bytes()),
            _ => ord(a.as_slice(), op, b.as_bytes()),
        },
        (FieldValue::Ipv4(a), Value::V4Net { addr, mask }) => {
            let hit = u32::from_be_bytes(*a) & mask == *addr;
            if op == CmpOp::Ne { !hit } else { hit }
        }
        (FieldValue::Ipv6(a), Value::V6Net { addr, prefix }) => {
            let full = usize::from(*prefix / 8);
            let rem = prefix % 8;
            let mut hit = a[..full] == addr[..full];
            if hit && rem != 0 {
                let mask = 0xffu8 << (8 - rem);
                hit = a[full] & mask == addr[full] & mask;
            }
            if op == CmpOp::Ne { !hit } else { hit }
        }
        (FieldValue::Mac(a), Value::Mac(b)) => ord(a, op, b),
        _ => false,
    }
}
