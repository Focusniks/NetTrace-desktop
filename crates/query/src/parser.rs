//! Recursive-descent parser: `or` < `and` < `not` < comparison.

use crate::error::{ErrorCode, QueryError};
use crate::lexer::{lex, Tok, Token};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    /// Unquoted literal.
    Word(String),
    /// Quoted string.
    Str(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Ast {
    /// `a || b || …` (at least two operands, kept flat).
    Or(Vec<Ast>),
    /// `a && b && …` (at least two operands, kept flat).
    And(Vec<Ast>),
    Not(Box<Ast>),
    Field { name: String, span: Span },
    Cmp { field: String, field_span: Span, op: CmpOp, value: Lit, value_span: Span },
    In { field: String, field_span: Span, values: Vec<(Lit, Span)> },
}

const MAX_DEPTH: usize = 64;
/// Comparisons per filter (a sanity bound; chains are flat, nesting is
/// bounded by `MAX_DEPTH`).
const MAX_TERMS: usize = 4096;

struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
    len: usize,
    depth: usize,
    terms: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Token> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let t = self.toks.get(self.pos);
        self.pos += 1;
        t
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if self.peek().is_some_and(|t| &t.tok == tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn end_err(&self, code: ErrorCode) -> QueryError {
        QueryError::new(code, self.len, self.len, "")
    }

    fn enter(&mut self) -> Result<(), QueryError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            let at = self.peek().map(|t| t.start).unwrap_or(self.len);
            return Err(QueryError::new(ErrorCode::TooComplex, at, at, ""));
        }
        Ok(())
    }

    fn or(&mut self) -> Result<Ast, QueryError> {
        self.enter()?;
        let mut terms = vec![self.and()?];
        while self.eat(&Tok::Or) {
            terms.push(self.and()?);
        }
        self.depth -= 1;
        Ok(if terms.len() == 1 { terms.remove(0) } else { Ast::Or(terms) })
    }

    fn and(&mut self) -> Result<Ast, QueryError> {
        let mut terms = vec![self.unary()?];
        while self.eat(&Tok::And) {
            terms.push(self.unary()?);
        }
        Ok(if terms.len() == 1 { terms.remove(0) } else { Ast::And(terms) })
    }

    fn unary(&mut self) -> Result<Ast, QueryError> {
        if self.eat(&Tok::Not) {
            self.enter()?;
            let inner = self.unary()?;
            self.depth -= 1;
            return Ok(Ast::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn literal(&mut self) -> Result<(Lit, Span), QueryError> {
        match self.next() {
            Some(Token { tok: Tok::Word(w), start, end }) => Ok((Lit::Word(w.clone()), Span { start: *start, end: *end })),
            Some(Token { tok: Tok::Str(s), start, end }) => Ok((Lit::Str(s.clone()), Span { start: *start, end: *end })),
            Some(t) => Err(QueryError::new(ErrorCode::ExpectedValue, t.start, t.end, "")),
            None => Err(self.end_err(ErrorCode::ExpectedValue)),
        }
    }

    fn primary(&mut self) -> Result<Ast, QueryError> {
        let Some(tok) = self.next() else { return Err(self.end_err(ErrorCode::UnexpectedEnd)) };
        match &tok.tok {
            Tok::LParen => {
                let inner = self.or()?;
                if !self.eat(&Tok::RParen) {
                    return Err(match self.peek() {
                        Some(t) => QueryError::new(ErrorCode::UnexpectedToken, t.start, t.end, ""),
                        None => QueryError::new(ErrorCode::UnclosedParen, tok.start, tok.end, ""),
                    });
                }
                Ok(inner)
            }
            Tok::Word(name) => {
                self.terms += 1;
                if self.terms > MAX_TERMS {
                    return Err(QueryError::new(ErrorCode::TooComplex, tok.start, tok.end, ""));
                }
                let field_span = Span { start: tok.start, end: tok.end };
                let op = match self.peek().map(|t| &t.tok) {
                    Some(Tok::Eq) => CmpOp::Eq,
                    Some(Tok::Ne) => CmpOp::Ne,
                    Some(Tok::Lt) => CmpOp::Lt,
                    Some(Tok::Le) => CmpOp::Le,
                    Some(Tok::Gt) => CmpOp::Gt,
                    Some(Tok::Ge) => CmpOp::Ge,
                    Some(Tok::Contains) => CmpOp::Contains,
                    Some(Tok::In) => {
                        self.pos += 1;
                        let open = self.next();
                        if !open.is_some_and(|t| t.tok == Tok::LBrace) {
                            let (s, e) = open.map(|t| (t.start, t.end)).unwrap_or((self.len, self.len));
                            return Err(QueryError::new(ErrorCode::UnexpectedToken, s, e, "{"));
                        }
                        let mut values = Vec::new();
                        loop {
                            if self.eat(&Tok::RBrace) {
                                break;
                            }
                            self.eat(&Tok::Comma);
                            if self.eat(&Tok::RBrace) {
                                break;
                            }
                            if self.peek().is_none() {
                                return Err(self.end_err(ErrorCode::UnexpectedEnd));
                            }
                            values.push(self.literal()?);
                        }
                        if values.is_empty() {
                            return Err(QueryError::new(ErrorCode::ExpectedValue, tok.end, tok.end, ""));
                        }
                        return Ok(Ast::In { field: name.clone(), field_span, values });
                    }
                    _ => return Ok(Ast::Field { name: name.clone(), span: field_span }),
                };
                self.pos += 1;
                let (value, value_span) = self.literal()?;
                Ok(Ast::Cmp { field: name.clone(), field_span, op, value, value_span })
            }
            _ => Err(QueryError::new(ErrorCode::UnexpectedToken, tok.start, tok.end, "")),
        }
    }
}

pub fn parse(input: &str) -> Result<Ast, QueryError> {
    let toks = lex(input)?;
    if toks.is_empty() {
        return Err(QueryError::new(ErrorCode::Empty, 0, 0, ""));
    }
    let mut p = Parser { toks: &toks, pos: 0, len: input.len(), depth: 0, terms: 0 };
    let ast = p.or()?;
    if let Some(t) = p.peek() {
        return Err(QueryError::new(ErrorCode::UnexpectedToken, t.start, t.end, ""));
    }
    Ok(ast)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_and_over_or() {
        let ast = parse("a || b && !c").unwrap();
        let Ast::Or(or) = ast else { panic!("{ast:?}") };
        assert!(matches!(&or[0], Ast::Field { name, .. } if name == "a"));
        let Ast::And(and) = &or[1] else { panic!("{:?}", or[1]) };
        assert!(matches!(and[1], Ast::Not(_)));
        assert!(matches!(parse("a || b || c"), Ok(Ast::Or(v)) if v.len() == 3));
    }

    #[test]
    fn comparisons_and_sets() {
        let ast = parse("ip.addr == 10.10.1.15 && tcp.port in {80 443}").unwrap();
        let Ast::And(and) = ast else { panic!() };
        let (l, r) = (&and[0], &and[1]);
        assert!(matches!(*l, Ast::Cmp { op: CmpOp::Eq, value: Lit::Word(ref v), .. } if v == "10.10.1.15"));
        assert!(matches!(*r, Ast::In { ref values, .. } if values.len() == 2));
        assert!(parse(r#"http.host contains "example""#).is_ok());
        assert!(parse("(tcp)").is_ok());
    }

    #[test]
    fn errors() {
        assert_eq!(parse("").unwrap_err().code, ErrorCode::Empty);
        assert_eq!(parse("   ").unwrap_err().code, ErrorCode::Empty);
        assert_eq!(parse("tcp &&").unwrap_err().code, ErrorCode::UnexpectedEnd);
        assert_eq!(parse("(tcp").unwrap_err().code, ErrorCode::UnclosedParen);
        assert_eq!(parse("tcp udp").unwrap_err().code, ErrorCode::UnexpectedToken);
        assert_eq!(parse("ip.src ==").unwrap_err().code, ErrorCode::ExpectedValue);
        assert_eq!(parse("tcp.port in {").unwrap_err().code, ErrorCode::UnexpectedEnd);
        assert_eq!(parse("tcp.port in {}").unwrap_err().code, ErrorCode::ExpectedValue);
        let e = parse("tcp )").unwrap_err();
        assert_eq!((e.code, e.start), (ErrorCode::UnexpectedToken, 4));
    }

    #[test]
    fn deep_nesting_is_rejected_not_overflowing() {
        let deep = "(".repeat(10_000) + "tcp" + &")".repeat(10_000);
        assert_eq!(parse(&deep).unwrap_err().code, ErrorCode::TooComplex);
        let nots = "!".repeat(10_000) + "tcp";
        assert_eq!(parse(&nots).unwrap_err().code, ErrorCode::TooComplex);
        assert!(parse(&("(".repeat(20) + "tcp" + &")".repeat(20))).is_ok());
    }
}
