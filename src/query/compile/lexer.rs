use super::{ByteSpan, ParseError};

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TOKENS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Token {
    pub kind: TokenKind,
    pub span: ByteSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TokenKind {
    Word(String),
    QuotedIdentifier(String),
    Text(String),
    Integer(String),
    Positional(u16),
    Named(String),
    Star,
    Comma,
    LParen,
    RParen,
    Semicolon,
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
}

fn syntax(code: &'static str, start: usize, end: usize) -> ParseError {
    ParseError::Syntax {
        code,
        span: ByteSpan { start, end },
    }
}

fn parameter(code: &'static str, start: usize, end: usize) -> ParseError {
    ParseError::Parameter {
        code,
        span: ByteSpan { start, end },
    }
}

fn ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn next(input: &str, at: usize) -> Option<(char, usize)> {
    input
        .get(at..)?
        .chars()
        .next()
        .map(|ch| (ch, at + ch.len_utf8()))
}

fn quoted(input: &str, start: usize, quote: char) -> Result<(String, usize), ParseError> {
    let mut at = start + 1;
    let mut value = String::new();
    while let Some((ch, after)) = next(input, at) {
        if ch == quote {
            if let Some((again, after_again)) = next(input, after)
                && again == quote
            {
                value.push(quote);
                at = after_again;
                continue;
            }
            if quote == '"' && value.is_empty() {
                return Err(syntax("empty_identifier", start, after));
            }
            return Ok((value, after));
        }
        if ch.is_control() {
            return Err(syntax("control_character", at, after));
        }
        value.push(ch);
        at = after;
    }
    Err(syntax("unterminated_quote", start, input.len()))
}

fn number(input: &str, start: usize) -> Result<(TokenKind, usize), ParseError> {
    let mut at = start;
    if input[at..].starts_with('-') {
        at += 1;
    }
    let first_digit = at;
    while let Some((ch, after)) = next(input, at) {
        if !ch.is_ascii_digit() {
            break;
        }
        at = after;
    }
    if at == first_digit {
        return Err(syntax("invalid_number", start, at));
    }
    let digits = &input[first_digit..at];
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(syntax("invalid_number", start, at));
    }
    if let Some((ch, after)) = next(input, at)
        && (ident_continue(ch) || ch == '.')
    {
        return Err(syntax("invalid_number", start, after));
    }
    Ok((TokenKind::Integer(input[start..at].into()), at))
}

/// Lexes one UTF-8 input into bounded, half-open byte-span tokens.
pub(super) fn lex(input: &str) -> Result<Vec<Token>, ParseError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ParseError::LimitExceeded {
            code: "input_bytes",
            span: ByteSpan {
                start: 0,
                end: input.len(),
            },
        });
    }
    let mut tokens = Vec::new();
    let mut at = 0;
    while let Some((ch, after)) = next(input, at) {
        if ch.is_whitespace() {
            at = after;
            continue;
        }
        if ch.is_control() {
            return Err(syntax("control_character", at, after));
        }
        let start = at;
        let (kind, end) = if ident_start(ch) {
            let mut end = after;
            while let Some((part, next_end)) = next(input, end) {
                if !ident_continue(part) {
                    break;
                }
                end = next_end;
            }
            (TokenKind::Word(input[start..end].into()), end)
        } else if ch == '"' || ch == '\'' {
            let (value, end) = quoted(input, start, ch)?;
            (
                if ch == '"' {
                    TokenKind::QuotedIdentifier(value)
                } else {
                    TokenKind::Text(value)
                },
                end,
            )
        } else if ch.is_ascii_digit() {
            number(input, start)?
        } else if ch == '-' {
            if input[after..].starts_with('-') {
                return Err(ParseError::UnsupportedFeature {
                    feature: "comments",
                    span: ByteSpan {
                        start,
                        end: after + 1,
                    },
                });
            }
            if next(input, after).is_some_and(|(digit, _)| digit.is_ascii_digit()) {
                number(input, start)?
            } else {
                return Err(syntax("unexpected_character", start, after));
            }
        } else if ch == '/' && input[after..].starts_with('*') {
            return Err(ParseError::UnsupportedFeature {
                feature: "comments",
                span: ByteSpan {
                    start,
                    end: after + 1,
                },
            });
        } else if ch == '$' {
            let Some((first, first_end)) = next(input, after) else {
                return Err(parameter("malformed_reference", start, after));
            };
            if first == '$' || ident_start(first) {
                let mut tag_end = first_end;
                if first != '$' {
                    while let Some((part, next_end)) = next(input, tag_end) {
                        if !ident_continue(part) {
                            break;
                        }
                        tag_end = next_end;
                    }
                }
                let delimiter_end = if first == '$' {
                    Some(first_end)
                } else if input[tag_end..].starts_with('$') {
                    Some(tag_end + 1)
                } else {
                    None
                };
                if let Some(delimiter_end) = delimiter_end {
                    let delimiter = &input[start..delimiter_end];
                    if input[delimiter_end..].contains(delimiter) {
                        return Err(ParseError::UnsupportedFeature {
                            feature: "dollar_quoted_strings",
                            span: ByteSpan {
                                start,
                                end: delimiter_end,
                            },
                        });
                    }
                    return Err(parameter("malformed_reference", start, delimiter_end));
                }
                return Err(parameter("malformed_reference", start, tag_end));
            }
            if !first.is_ascii_digit() {
                return Err(parameter("malformed_reference", start, first_end));
            }
            let mut end = after;
            while let Some((part, next_end)) = next(input, end) {
                if !part.is_ascii_digit() {
                    break;
                }
                end = next_end;
            }
            if input[after..end].starts_with('0')
                || next(input, end).is_some_and(|(part, _)| ident_continue(part))
            {
                return Err(parameter("malformed_reference", start, end));
            }
            let index = input[after..end]
                .parse::<u16>()
                .map_err(|_| parameter("malformed_reference", start, end))?;
            if !(1..=256).contains(&index) {
                return Err(parameter("malformed_reference", start, end));
            }
            (TokenKind::Positional(index), end)
        } else if ch == ':' || ch == '@' {
            let Some((first, mut end)) = next(input, after) else {
                return Err(parameter("malformed_reference", start, after));
            };
            if !ident_start(first) {
                return Err(parameter("malformed_reference", start, end));
            }
            while let Some((part, next_end)) = next(input, end) {
                if !ident_continue(part) {
                    break;
                }
                end = next_end;
            }
            (TokenKind::Named(input[after..end].into()), end)
        } else {
            match ch {
                '*' => (TokenKind::Star, after),
                ',' => (TokenKind::Comma, after),
                '(' => (TokenKind::LParen, after),
                ')' => (TokenKind::RParen, after),
                ';' => (TokenKind::Semicolon, after),
                '=' if input[after..].starts_with('=') => {
                    return Err(syntax("invalid_operator", start, after + 1));
                }
                '=' => (TokenKind::Eq, after),
                '!' if input[after..].starts_with('=') => (TokenKind::NotEq, after + 1),
                '<' if input[after..].starts_with('=') => (TokenKind::Lte, after + 1),
                '<' if input[after..].starts_with('>') => (TokenKind::NotEq, after + 1),
                '<' => (TokenKind::Lt, after),
                '>' if input[after..].starts_with('=') => (TokenKind::Gte, after + 1),
                '>' => (TokenKind::Gt, after),
                '`' => {
                    return Err(ParseError::UnsupportedFeature {
                        feature: "backtick_identifiers",
                        span: ByteSpan { start, end: after },
                    });
                }
                _ => return Err(syntax("unexpected_character", start, after)),
            }
        };
        if tokens.len() == MAX_TOKENS {
            return Err(ParseError::LimitExceeded {
                code: "tokens",
                span: ByteSpan { start, end },
            });
        }
        tokens.push(Token {
            kind,
            span: ByteSpan { start, end },
        });
        at = end;
    }
    Ok(tokens)
}
