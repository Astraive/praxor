use super::lexer::{Token, TokenKind, lex};
use super::{ByteSpan, ParseError};

const MAX_NESTING: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Identifier {
    pub name: String,
    pub span: ByteSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Projection {
    All,
    Fields(Vec<Identifier>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompareOp {
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ValueSyntax {
    Integer(String),
    Bool(bool),
    Null,
    Text(String),
    Positional(u16),
    Named(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ValueExpr {
    pub syntax: ValueSyntax,
    pub span: ByteSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PredicateExpr {
    Compare {
        field: Identifier,
        operator: CompareOp,
        value: ValueExpr,
    },
    IsNull {
        field: Identifier,
        negated: bool,
    },
    Not(Box<PredicateExpr>),
    And(Box<PredicateExpr>, Box<PredicateExpr>),
    Or(Box<PredicateExpr>, Box<PredicateExpr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SyntaxSelect {
    pub explain: bool,
    pub projection: Projection,
    pub collection: Identifier,
    pub predicate: Option<PredicateExpr>,
}

fn keyword(token: &Token, expected: &str) -> bool {
    matches!(&token.kind, TokenKind::Word(word) if word.eq_ignore_ascii_case(expected))
}

fn unsupported_word(word: &str) -> Option<&'static str> {
    let feature = if word.eq_ignore_ascii_case("DISTINCT") {
        "distinct"
    } else if word.eq_ignore_ascii_case("ORDER") {
        "order_by"
    } else if word.eq_ignore_ascii_case("OFFSET") {
        "offset"
    } else if word.eq_ignore_ascii_case("LIMIT") {
        "limit"
    } else if word.eq_ignore_ascii_case("GROUP") {
        "group_by"
    } else if word.eq_ignore_ascii_case("HAVING") {
        "having"
    } else if word.eq_ignore_ascii_case("BETWEEN") {
        "between"
    } else if word.eq_ignore_ascii_case("IN") {
        "in"
    } else if word.eq_ignore_ascii_case("LIKE") {
        "like"
    } else if word.eq_ignore_ascii_case("JOIN") {
        "join"
    } else if word.eq_ignore_ascii_case("UNION")
        || word.eq_ignore_ascii_case("INTERSECT")
        || word.eq_ignore_ascii_case("EXCEPT")
    {
        "set_operation"
    } else if word.eq_ignore_ascii_case("WITH") {
        "cte"
    } else if word.eq_ignore_ascii_case("AS") {
        "as_of"
    } else if word.eq_ignore_ascii_case("WATCH") {
        "watch"
    } else if word.eq_ignore_ascii_case("INSERT")
        || word.eq_ignore_ascii_case("UPDATE")
        || word.eq_ignore_ascii_case("DELETE")
    {
        "mutation"
    } else if word.eq_ignore_ascii_case("CREATE")
        || word.eq_ignore_ascii_case("ALTER")
        || word.eq_ignore_ascii_case("DROP")
    {
        "ddl"
    } else if word.eq_ignore_ascii_case("SIMILAR") {
        "vector"
    } else if word.eq_ignore_ascii_case("TRAVERSE") {
        "traversal"
    } else if word.eq_ignore_ascii_case("RANK") {
        "rank"
    } else if word.eq_ignore_ascii_case("OVER") || word.eq_ignore_ascii_case("WINDOW") {
        "window"
    } else if word.eq_ignore_ascii_case("FIND") {
        "pql_find"
    } else {
        return None;
    };
    Some(feature)
}

fn reserved_word(word: &str) -> bool {
    [
        "SELECT", "FROM", "WHERE", "EXPLAIN", "ANALYZE", "TRUE", "FALSE", "NULL", "NOT", "AND",
        "OR", "IS", "BY", "OF", "ASC", "DESC", "ON",
    ]
    .iter()
    .any(|reserved| word.eq_ignore_ascii_case(reserved))
        || unsupported_word(word).is_some()
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    input_len: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn current_span(&self) -> ByteSpan {
        self.peek().map_or(
            ByteSpan {
                start: self.input_len,
                end: self.input_len,
            },
            |token| token.span,
        )
    }

    fn syntax(&self, code: &'static str) -> ParseError {
        ParseError::Syntax {
            code,
            span: self.current_span(),
        }
    }

    fn word(&self, expected: &str) -> bool {
        self.peek().is_some_and(|token| keyword(token, expected))
    }

    fn take_word(&mut self, expected: &str) -> bool {
        if !self.word(expected) {
            return false;
        }
        self.at += 1;
        true
    }

    fn expect_word(&mut self, expected: &str, code: &'static str) -> Result<(), ParseError> {
        if self.take_word(expected) {
            Ok(())
        } else {
            Err(self.syntax(code))
        }
    }

    fn take_kind(&mut self, expected: TokenKind) -> bool {
        if !self.peek().is_some_and(|token| token.kind == expected) {
            return false;
        }
        self.at += 1;
        true
    }

    fn refuse_function_call_at(&self, at: usize) -> Result<(), ParseError> {
        if let Some(token) = self.tokens.get(at)
            && token.kind == TokenKind::LParen
        {
            return Err(ParseError::UnsupportedFeature {
                feature: "function",
                span: token.span,
            });
        }
        Ok(())
    }

    fn identifier(&mut self) -> Result<Identifier, ParseError> {
        let token = self
            .peek()
            .ok_or_else(|| self.syntax("expected_identifier"))?;
        let name = match &token.kind {
            TokenKind::QuotedIdentifier(name) => name.clone(),
            TokenKind::Word(word) if !reserved_word(word) => word.clone(),
            TokenKind::Word(word) if unsupported_word(word).is_some() => {
                return Err(ParseError::UnsupportedFeature {
                    feature: unsupported_word(word).unwrap(),
                    span: token.span,
                });
            }
            _ => return Err(self.syntax("expected_identifier")),
        };
        let span = token.span;
        self.at += 1;
        Ok(Identifier { name, span })
    }

    fn projection(&mut self) -> Result<Projection, ParseError> {
        if self.take_kind(TokenKind::Star) {
            if self.take_kind(TokenKind::Comma) {
                return Err(self.syntax("mixed_wildcard_projection"));
            }
            return Ok(Projection::All);
        }
        let mut fields = vec![self.identifier()?];
        if self.word("AS") {
            return Err(ParseError::UnsupportedFeature {
                feature: "alias",
                span: self.current_span(),
            });
        }
        self.refuse_function_call_at(self.at)?;
        while self.take_kind(TokenKind::Comma) {
            fields.push(self.identifier()?);
            if self.word("AS") {
                return Err(ParseError::UnsupportedFeature {
                    feature: "alias",
                    span: self.current_span(),
                });
            }
            self.refuse_function_call_at(self.at)?;
        }
        Ok(Projection::Fields(fields))
    }

    fn value(&mut self) -> Result<ValueExpr, ParseError> {
        let token = self.peek().ok_or_else(|| self.syntax("expected_value"))?;
        if matches!(&token.kind, TokenKind::QuotedIdentifier(_))
            || matches!(&token.kind, TokenKind::Word(word) if !reserved_word(word))
        {
            self.refuse_function_call_at(self.at + 1)?;
        }
        let syntax = match &token.kind {
            TokenKind::Integer(digits) => ValueSyntax::Integer(digits.clone()),
            TokenKind::Text(text) => ValueSyntax::Text(text.clone()),
            TokenKind::Positional(index) => ValueSyntax::Positional(*index),
            TokenKind::Named(name) => ValueSyntax::Named(name.clone()),
            TokenKind::Word(word) if word.eq_ignore_ascii_case("TRUE") => ValueSyntax::Bool(true),
            TokenKind::Word(word) if word.eq_ignore_ascii_case("FALSE") => ValueSyntax::Bool(false),
            TokenKind::Word(word) if word.eq_ignore_ascii_case("NULL") => ValueSyntax::Null,
            _ => return Err(self.syntax("expected_value")),
        };
        let span = token.span;
        self.at += 1;
        Ok(ValueExpr { syntax, span })
    }

    fn comparison(&mut self) -> Result<PredicateExpr, ParseError> {
        let field = self.identifier()?;
        self.refuse_function_call_at(self.at)?;
        if self.take_word("IS") {
            let negated = self.take_word("NOT");
            self.expect_word("NULL", "expected_null")?;
            return Ok(PredicateExpr::IsNull { field, negated });
        }
        let token = self
            .peek()
            .ok_or_else(|| self.syntax("expected_comparison"))?;
        let operator = match token.kind {
            TokenKind::Eq => CompareOp::Eq,
            TokenKind::NotEq => CompareOp::NotEq,
            TokenKind::Lt => CompareOp::Lt,
            TokenKind::Lte => CompareOp::Lte,
            TokenKind::Gt => CompareOp::Gt,
            TokenKind::Gte => CompareOp::Gte,
            TokenKind::Word(ref word) if unsupported_word(word).is_some() => {
                return Err(ParseError::UnsupportedFeature {
                    feature: unsupported_word(word).unwrap(),
                    span: token.span,
                });
            }
            _ => return Err(self.syntax("expected_comparison")),
        };
        self.at += 1;
        let value = self.value()?;
        Ok(PredicateExpr::Compare {
            field,
            operator,
            value,
        })
    }

    fn not_expr(&mut self, depth: usize) -> Result<PredicateExpr, ParseError> {
        if depth > MAX_NESTING {
            return Err(ParseError::LimitExceeded {
                code: "nesting",
                span: self.current_span(),
            });
        }
        if self.take_word("NOT") {
            return Ok(PredicateExpr::Not(Box::new(self.not_expr(depth + 1)?)));
        }
        if self.take_kind(TokenKind::LParen) {
            let expression = self.or_expr(depth + 1)?;
            if !self.take_kind(TokenKind::RParen) {
                return Err(self.syntax("expected_right_parenthesis"));
            }
            return Ok(expression);
        }
        self.comparison()
    }

    fn and_expr(&mut self, depth: usize) -> Result<PredicateExpr, ParseError> {
        let mut expression = self.not_expr(depth)?;
        while self.take_word("AND") {
            expression = PredicateExpr::And(Box::new(expression), Box::new(self.not_expr(depth)?));
        }
        Ok(expression)
    }

    fn or_expr(&mut self, depth: usize) -> Result<PredicateExpr, ParseError> {
        let mut expression = self.and_expr(depth)?;
        while self.take_word("OR") {
            expression = PredicateExpr::Or(Box::new(expression), Box::new(self.and_expr(depth)?));
        }
        Ok(expression)
    }

    fn trailing_feature(&self) -> Option<ParseError> {
        let token = self.peek()?;
        let TokenKind::Word(word) = &token.kind else {
            return None;
        };
        let feature = if word.eq_ignore_ascii_case("AS")
            && !self
                .tokens
                .get(self.at + 1)
                .is_some_and(|next| keyword(next, "OF"))
        {
            Some("alias")
        } else {
            unsupported_word(word)
        };
        feature.map(|feature| ParseError::UnsupportedFeature {
            feature,
            span: token.span,
        })
    }

    fn statement(mut self) -> Result<SyntaxSelect, ParseError> {
        let explain = self.take_word("EXPLAIN");
        if explain && self.word("ANALYZE") {
            return Err(ParseError::UnsupportedFeature {
                feature: "explain_analyze",
                span: self.current_span(),
            });
        }
        if !self.word("SELECT") {
            return Err(self
                .trailing_feature()
                .unwrap_or_else(|| self.syntax("expected_select")));
        }
        self.at += 1;
        let projection = self.projection()?;
        self.expect_word("FROM", "expected_from")?;
        let collection = self.identifier()?;
        self.refuse_function_call_at(self.at)?;
        let predicate = if self.take_word("WHERE") {
            Some(self.or_expr(0)?)
        } else {
            None
        };
        if self.take_kind(TokenKind::Semicolon) {
            if self.peek().is_some() {
                return Err(self.syntax("multiple_statements"));
            }
        } else if self.peek().is_some() {
            return Err(self
                .trailing_feature()
                .unwrap_or_else(|| self.syntax("trailing_input")));
        }
        Ok(SyntaxSelect {
            explain,
            projection,
            collection,
            predicate,
        })
    }
}

/// Parses the exact one-collection SELECT subset; every token is consumed.
pub(super) fn parse_sql(input: &str) -> Result<SyntaxSelect, ParseError> {
    Parser {
        tokens: lex(input)?,
        at: 0,
        input_len: input.len(),
    }
    .statement()
}
