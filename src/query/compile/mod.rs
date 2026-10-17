//! Strict syntax stage for the bounded, engine-owned SELECT compiler.
//! Binding, execution, and the public entrypoint follow in later checkpoints.
mod lexer;
mod syntax;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ParseError {
    Syntax {
        code: &'static str,
        span: ByteSpan,
    },
    UnsupportedFeature {
        feature: &'static str,
        span: ByteSpan,
    },
    Parameter {
        code: &'static str,
        span: ByteSpan,
    },
    LimitExceeded {
        code: &'static str,
        span: ByteSpan,
    },
}

#[cfg(test)]
mod tests {
    use super::lexer::{TokenKind, lex};
    use super::syntax::{PredicateExpr, Projection, ValueSyntax, parse_sql};
    use super::{ByteSpan, ParseError};

    #[test]
    fn lexer_retains_utf8_byte_spans_and_distinguishes_quotes_from_bindings() {
        let tokens = lex("\"é\" 'é' '$1' \"@name\" :name @name $10").unwrap();
        assert_eq!(tokens[0].span, ByteSpan { start: 0, end: 4 });
        assert_eq!(tokens[0].kind, TokenKind::QuotedIdentifier("é".into()));
        assert_eq!(tokens[1].span, ByteSpan { start: 5, end: 9 });
        assert_eq!(tokens[1].kind, TokenKind::Text("é".into()));
        assert_eq!(tokens[2].kind, TokenKind::Text("$1".into()));
        assert_eq!(tokens[3].kind, TokenKind::QuotedIdentifier("@name".into()));
        assert_eq!(tokens[4].kind, TokenKind::Named("name".into()));
        assert_eq!(tokens[5].kind, TokenKind::Named("name".into()));
        assert_eq!(tokens[6].kind, TokenKind::Positional(10));
        for token in tokens {
            assert!("\"é\" 'é' '$1' \"@name\" :name @name $10".is_char_boundary(token.span.start));
            assert!("\"é\" 'é' '$1' \"@name\" :name @name $10".is_char_boundary(token.span.end));
        }
    }

    #[test]
    fn lexer_handles_sql_quote_doubling_and_literal_backslashes() {
        let tokens = lex("\"Bé\"\"la\" 'x'' OR TRUE --' '\\' -9223372036854775808").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::QuotedIdentifier("Bé\"la".into()));
        assert_eq!(tokens[1].kind, TokenKind::Text("x' OR TRUE --".into()));
        assert_eq!(tokens[2].kind, TokenKind::Text("\\".into()));
        assert_eq!(
            tokens[3].kind,
            TokenKind::Integer("-9223372036854775808".into())
        );
    }

    #[test]
    fn syntax_preserves_projection_order_and_boolean_precedence() {
        let ast = parse_sql("EXPLAIN SELECT name, age FROM \"usérs\" WHERE NOT age = $1 OR name = :n AND age IS NOT NULL;").unwrap();
        assert!(ast.explain);
        assert_eq!(ast.collection.name, "usérs");
        match ast.projection {
            Projection::Fields(fields) => assert_eq!(
                fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                ["name", "age"]
            ),
            other => panic!("expected named projection, got {other:?}"),
        }
        let Some(PredicateExpr::Or(left, right)) = ast.predicate else {
            panic!("expected OR root")
        };
        assert!(matches!(*left, PredicateExpr::Not(_)));
        let PredicateExpr::And(first, second) = *right else {
            panic!("AND must bind within OR")
        };
        assert!(matches!(
            *second,
            PredicateExpr::IsNull { negated: true, .. }
        ));
        let PredicateExpr::Compare { value, .. } = *first else {
            panic!("expected comparison")
        };
        assert_eq!(value.syntax, ValueSyntax::Named("n".into()));
    }

    #[test]
    fn syntax_consumes_one_complete_statement_and_preserves_literal_values() {
        let ast =
            parse_sql("SELECT * FROM users WHERE age >= -18 AND name = 'x'' OR TRUE --'").unwrap();
        assert!(matches!(ast.projection, Projection::All));
        assert_eq!(ast.collection.name, "users");
        let Some(PredicateExpr::And(_, second)) = ast.predicate else {
            panic!("expected AND")
        };
        let PredicateExpr::Compare { value, .. } = *second else {
            panic!("expected comparison")
        };
        assert_eq!(value.syntax, ValueSyntax::Text("x' OR TRUE --".into()));
        assert!(parse_sql("SELECT * FROM users;").is_ok());
    }

    #[test]
    fn syntax_rejects_tail_and_multiple_statements_without_dropping_tokens() {
        for sql in [
            "SELECT * FROM users WHERE age >= 18 GARBAGE",
            "SELECT * FROM users; SELECT * FROM users",
            "SELECTED * FROM users",
            "SELECT * FROM users WHERE (age = 1))",
            "SELECT * FROM users WHERE age == 1",
            "SELECT *, age FROM users",
        ] {
            assert!(
                matches!(parse_sql(sql), Err(ParseError::Syntax { .. })),
                "{sql}"
            );
        }
    }

    #[test]
    fn unsupported_clauses_are_named_and_refused() {
        for (sql, feature) in [
            ("SELECT * FROM users ORDER BY age", "order_by"),
            ("SELECT * FROM users LIMIT 1", "limit"),
            ("SELECT * FROM users GROUP BY age", "group_by"),
            ("SELECT DISTINCT age FROM users", "distinct"),
            ("EXPLAIN ANALYZE SELECT * FROM users", "explain_analyze"),
            ("SELECT * FROM users AS OF COMMIT c1", "as_of"),
            ("WATCH users", "watch"),
        ] {
            assert!(
                matches!(parse_sql(sql), Err(ParseError::UnsupportedFeature { feature: got, .. }) if got == feature),
                "{sql}"
            );
        }
    }

    #[test]
    fn lexical_errors_carry_valid_byte_offsets_and_distinct_limits() {
        for sql in [
            "'unterminated",
            "\"unterminated",
            "SELECT * FROM users --comment",
            "SELECT * FROM users /*comment*/",
            "SELECT * FROM users WHERE age = 01",
            "SELECT * FROM users WHERE age = 1.0",
            "SELECT * FROM users WHERE name = 'a\0b'",
        ] {
            let err = parse_sql(sql).unwrap_err();
            let span = match err {
                ParseError::Syntax { span, .. }
                | ParseError::UnsupportedFeature { span, .. }
                | ParseError::Parameter { span, .. }
                | ParseError::LimitExceeded { span, .. } => span,
            };
            assert!(
                sql.is_char_boundary(span.start)
                    && sql.is_char_boundary(span.end)
                    && span.start <= span.end
                    && span.end <= sql.len(),
                "{sql:?}: {span:?}"
            );
        }
        assert!(matches!(
            parse_sql(&" ".repeat(65_537)),
            Err(ParseError::LimitExceeded {
                code: "input_bytes",
                ..
            })
        ));
        let too_many = format!(
            "SELECT * FROM users WHERE {}",
            (0..2_050).map(|_| "a = 1").collect::<Vec<_>>().join(" OR ")
        );
        assert!(matches!(
            parse_sql(&too_many),
            Err(ParseError::LimitExceeded { code: "tokens", .. })
        ));
        let deep = format!(
            "SELECT * FROM users WHERE {}a = 1{}",
            "(".repeat(65),
            ")".repeat(65)
        );
        assert!(matches!(
            parse_sql(&deep),
            Err(ParseError::LimitExceeded {
                code: "nesting",
                ..
            })
        ));
    }

    #[test]
    fn malformed_positional_parameters_are_rejected_at_lexing() {
        for sql in ["$0", "$01", "$257", "$1x", ":", "@9", "$name$"] {
            assert!(
                matches!(
                    lex(sql),
                    Err(ParseError::Parameter { .. }) | Err(ParseError::UnsupportedFeature { .. })
                ),
                "{sql}"
            );
        }
    }

    #[test]
    fn unsupported_comparison_operators_and_aliases_are_named() {
        for (sql, feature) in [
            ("SELECT * FROM users WHERE age BETWEEN 1 AND 2", "between"),
            ("SELECT * FROM users WHERE age IN (1)", "in"),
            ("SELECT * FROM users WHERE name LIKE 'A%'", "like"),
            ("SELECT * FROM users AS u", "alias"),
            ("SELECT age AS years FROM users", "alias"),
        ] {
            assert!(
                matches!(parse_sql(sql), Err(ParseError::UnsupportedFeature { feature: got, .. }) if got == feature),
                "{sql}"
            );
        }
    }

    #[test]
    fn quoted_keywords_are_identifiers_but_bare_keywords_and_double_quoted_values_refuse() {
        let ast = parse_sql("sElEcT \"SELECT\", \"na\"\"me\" fRoM \"usérs\" wHeRe \"Bé\" IS NULL")
            .unwrap();
        let Projection::Fields(fields) = ast.projection else {
            panic!("expected named projection")
        };
        assert_eq!(
            fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["SELECT", "na\"me"]
        );
        assert_eq!(ast.collection.name, "usérs");
        assert!(matches!(
            ast.predicate,
            Some(PredicateExpr::IsNull { negated: false, .. })
        ));
        assert!(matches!(
            parse_sql("SELECT select FROM users"),
            Err(ParseError::Syntax {
                code: "expected_identifier",
                ..
            })
        ));
        assert!(matches!(
            parse_sql("SELECT * FROM users WHERE name = \"Ada\""),
            Err(ParseError::Syntax {
                code: "expected_value",
                ..
            })
        ));
    }

    #[test]
    fn review_boundary_nesting_accepts_64_and_refuses_65_levels() {
        for (open, close) in [
            ("(".repeat(64), ")".repeat(64)),
            ("NOT ".repeat(64), String::new()),
        ] {
            let sql = format!("SELECT * FROM users WHERE {open}age = 1{close}");
            assert!(parse_sql(&sql).is_ok(), "64 levels must remain valid");
        }
        for (open, close) in [
            ("(".repeat(65), ")".repeat(65)),
            ("NOT ".repeat(65), String::new()),
        ] {
            let sql = format!("SELECT * FROM users WHERE {open}age = 1{close}");
            assert!(
                matches!(
                    parse_sql(&sql),
                    Err(ParseError::LimitExceeded {
                        code: "nesting",
                        ..
                    })
                ),
                "65 levels must refuse"
            );
        }
    }

    #[test]
    fn review_boundary_dollar_word_needs_a_complete_dollar_quote() {
        assert!(matches!(
            lex("$name"),
            Err(ParseError::Parameter {
                code: "malformed_reference",
                span: ByteSpan { start: 0, end: 5 }
            })
        ));
        assert!(matches!(
            lex("$name$payload"),
            Err(ParseError::Parameter {
                code: "malformed_reference",
                ..
            })
        ));
        assert!(matches!(
            lex("$name$payload$name$"),
            Err(ParseError::UnsupportedFeature {
                feature: "dollar_quoted_strings",
                ..
            })
        ));
        assert!(matches!(
            lex("$$payload$$"),
            Err(ParseError::UnsupportedFeature {
                feature: "dollar_quoted_strings",
                ..
            })
        ));
    }
}
