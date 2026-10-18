//! Strict, process-local Q1 SELECT compiler and pure in-memory row semantics.
//! This does not authorize product storage, routing, or persisted catalog reads.
mod binder;
mod catalog;
mod evaluator;
mod explain;
mod lexer;
mod syntax;

#[cfg(test)]
mod stage4_tests;

pub use binder::{BoundSelect, ParameterValue, TypedParameters};
pub use catalog::{QueryCatalogAuthority, QueryCatalogView};
pub use evaluator::{ProjectedRow, execute_in_memory};
pub use explain::{ExplainV1, PredicateShapeOp};

use super::parser::{LogicalPlan, QueryOperation};
use std::fmt;

/// Accepted source forms for the Q1 compiler. Legacy plans are inspected only
/// for deterministic refusal because they lack projection and literal provenance.
#[derive(Clone, Copy)]
pub enum CompileInput<'a> {
    Sql(&'a str),
    LegacyPlan(&'a LogicalPlan),
}

impl fmt::Debug for CompileInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sql(_) => "CompileInput::Sql(<redacted>)",
            Self::LegacyPlan(_) => "CompileInput::LegacyPlan(<redacted>)",
        })
    }
}

/// Only `Select` carries an executable capability; `Explain` carries no rows or
/// bound values and cannot be passed to `execute_in_memory`.
#[derive(Debug)]
pub enum CompiledStatement {
    Select(BoundSelect),
    Explain(ExplainV1),
}

fn unsupported_legacy_feature(plan: &LogicalPlan) -> Option<&'static str> {
    if plan.operation != QueryOperation::Select {
        Some("operation")
    } else if !plan.joins.is_empty() {
        Some("join")
    } else if plan.full_text.is_some() {
        Some("full_text")
    } else if plan.vector.is_some() {
        Some("vector")
    } else if plan.traversal.is_some() {
        Some("traversal")
    } else if plan.rank_by.is_some() {
        Some("rank")
    } else if plan.order_by.is_some() {
        Some("order_by")
    } else if plan.limit.is_some() {
        Some("limit")
    } else if plan.offset.is_some() {
        Some("offset")
    } else if plan.distinct {
        Some("distinct")
    } else if plan.group_by.is_some() {
        Some("group_by")
    } else if plan.having.is_some() {
        Some("having")
    } else if plan.as_of.is_some() {
        Some("as_of")
    } else if plan.mutation.is_some() {
        Some("mutation")
    } else if plan.ddl.is_some() {
        Some("ddl")
    } else if !plan.ctes.is_empty() {
        Some("cte")
    } else if !plan.window_functions.is_empty() {
        Some("window")
    } else if plan.explain_analyze {
        Some("explain_analyze")
    } else if !plan.params.positional.is_empty() || !plan.params.named.is_empty() {
        Some("legacy_parameters")
    } else {
        None
    }
}

/// Compile one SQL SELECT or EXPLAIN SELECT against a detached catalog view.
///
/// The source is capped at 64 KiB UTF-8, 4096 tokens, and 64 nested boolean
/// groups/NOTs. Positional placeholders are `$1..$256`; every supplied value
/// must be referenced. Join, grouping, history, ordering, limit, mutation,
/// specialized search/vector/graph clauses, and multiple statements are refused.
/// Legacy `LogicalPlan` values can never be promoted to a bound select.
pub fn compile(
    input: CompileInput<'_>,
    values: &TypedParameters,
    catalog: &QueryCatalogView,
) -> Result<CompiledStatement, QueryCompileError> {
    match input {
        CompileInput::Sql(sql) => {
            let syntax = syntax::parse_sql(sql)?;
            let explain = syntax.explain;
            let bound = binder::bind_syntax(syntax, values, catalog)?;
            if explain {
                Ok(CompiledStatement::Explain(ExplainV1::from_bound(&bound)))
            } else {
                Ok(CompiledStatement::Select(bound))
            }
        }
        CompileInput::LegacyPlan(plan) => {
            if let Some(feature) = unsupported_legacy_feature(plan) {
                return Err(QueryCompileError::UnsupportedFeature {
                    feature,
                    span: None,
                });
            }
            Err(QueryCompileError::LegacyPlanUnbound)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

#[cfg(test)]
mod stage3_tests {
    use super::QueryCompileError;
    use super::binder::{BoundPredicateOp, ParameterValue, TypedParameters, bind_sql};
    use super::catalog::QueryCatalogAuthority;
    use crate::catalog::schema::{
        AttributeSchema, AttributeType, Catalog, CollectionSchema, IntegerType, ScalarType,
    };
    use std::collections::BTreeMap;

    fn schema(name: &str, fields: &[(&str, AttributeType)]) -> CollectionSchema {
        fields
            .iter()
            .fold(CollectionSchema::new(name), |schema, (field, kind)| {
                schema.with_attribute(AttributeSchema::new(*field, kind.clone()))
            })
    }

    fn authority(collection: CollectionSchema) -> QueryCatalogAuthority {
        let mut catalog = Catalog::new();
        catalog.create_collection(collection).unwrap();
        QueryCatalogAuthority::new(catalog)
    }

    fn bind(
        sql: &str,
        catalog: &QueryCatalogAuthority,
    ) -> Result<super::binder::BoundSelect, QueryCompileError> {
        bind_sql(sql, &TypedParameters::default(), &catalog.view())
    }

    #[test]
    fn catalog_view_is_detached_versioned_and_owner_bound() {
        let mut old = Catalog::new();
        old.create_collection(schema("users", &[("name", AttributeType::Text)]))
            .unwrap();
        let mut retained_copy = old.clone();
        let owner = QueryCatalogAuthority::new(old);
        let view = owner.view();
        assert_eq!(view.revision(), 1);
        retained_copy.drop_collection("users").unwrap();
        let selected =
            bind_sql("SELECT name FROM users", &TypedParameters::default(), &view).unwrap();
        assert_eq!(selected.collection(), "users");
        assert_eq!(selected.projection_names(), ["name"]);
        assert!(owner.validate_bound(&selected).is_ok());

        let foreign = authority(schema("users", &[("name", AttributeType::Text)]));
        assert!(matches!(
            foreign.validate_bound(&selected),
            Err(QueryCompileError::ForeignCatalog)
        ));
        assert!(matches!(
            foreign.validate_view(&view),
            Err(QueryCompileError::ForeignCatalog)
        ));

        owner
            .replace_collection(schema(
                "users",
                &[("age", AttributeType::Integer(IntegerType::Int4))],
            ))
            .unwrap();
        assert_eq!(owner.view().revision(), 2);
        assert!(view.schemas["users"].attributes.contains_key("name"));
        assert!(!view.schemas["users"].attributes.contains_key("age"));
        assert!(owner.view().schemas["users"].attributes.contains_key("age"));
        assert!(
            !owner.view().schemas["users"]
                .attributes
                .contains_key("name")
        );
        assert!(matches!(
            owner.validate_bound(&selected),
            Err(QueryCompileError::StaleCatalog)
        ));
        assert!(matches!(
            bind_sql("SELECT name FROM users", &TypedParameters::default(), &view),
            Err(QueryCompileError::StaleCatalog)
        ));

        owner.drop_collection("users").unwrap();
        assert_eq!(owner.view().revision(), 3);
        owner
            .replace_collection(schema("users", &[("name", AttributeType::Text)]))
            .unwrap();
        assert_eq!(owner.view().revision(), 4);
        assert!(matches!(
            owner.validate_bound(&selected),
            Err(QueryCompileError::StaleCatalog)
        ));
    }

    #[test]
    fn named_projection_resolves_only_referenced_fields_and_star_uses_catalog_order() {
        let owner = authority(schema(
            "docs",
            &[
                ("title", AttributeType::Text),
                ("payload", AttributeType::Json),
            ],
        ));
        let selected = bind("SELECT title FROM docs", &owner).unwrap();
        assert_eq!(selected.projection_names(), ["title"]);
        assert!(
            matches!(bind("SELECT * FROM docs", &owner), Err(QueryCompileError::UnsupportedFieldType { field, .. }) if field == "payload")
        );
        assert!(
            matches!(bind("SELECT payload FROM docs", &owner), Err(QueryCompileError::UnsupportedFieldType { field, .. }) if field == "payload")
        );
        assert!(
            matches!(bind("SELECT unknown FROM docs", &owner), Err(QueryCompileError::UnknownField { field, .. }) if field == "unknown")
        );
        assert!(matches!(
            bind("SELECT title, title FROM docs", &owner),
            Err(QueryCompileError::Syntax {
                code: "duplicate_projection",
                ..
            })
        ));

        let ordered = authority(schema(
            "users",
            &[
                ("name", AttributeType::Text),
                ("age", AttributeType::Integer(IntegerType::Int4)),
                ("active", AttributeType::Boolean),
            ],
        ));
        assert_eq!(
            bind("SELECT * FROM users", &ordered)
                .unwrap()
                .projection_names(),
            ["active", "age", "name"]
        );
        assert_eq!(
            bind("SELECT name, age FROM users", &ordered)
                .unwrap()
                .projection_names(),
            ["name", "age"]
        );
        assert!(matches!(
            bind("SELECT name FROM missing", &ordered),
            Err(QueryCompileError::UnknownCollection { .. })
        ));
    }

    #[test]
    fn integer_literals_obey_exact_declared_signed_and_unsigned_ranges() {
        let owner = authority(schema(
            "ints",
            &[
                ("s2", AttributeType::Integer(IntegerType::Int2)),
                ("s4", AttributeType::Integer(IntegerType::Int4)),
                ("s8", AttributeType::Integer(IntegerType::Int8)),
                ("scalar", AttributeType::Scalar(ScalarType::Integer)),
                ("u8", AttributeType::Integer(IntegerType::Uint8)),
            ],
        ));
        for sql in [
            "SELECT s2 FROM ints WHERE s2 = -32768",
            "SELECT s2 FROM ints WHERE s2 = 32767",
            "SELECT s4 FROM ints WHERE s4 = -2147483648",
            "SELECT s4 FROM ints WHERE s4 = 2147483647",
            "SELECT s8 FROM ints WHERE s8 = -9223372036854775808",
            "SELECT s8 FROM ints WHERE s8 = 9223372036854775807",
            "SELECT scalar FROM ints WHERE scalar = -9223372036854775808",
            "SELECT scalar FROM ints WHERE scalar = 9223372036854775807",
            "SELECT u8 FROM ints WHERE u8 = 0",
            "SELECT u8 FROM ints WHERE u8 = 18446744073709551615",
        ] {
            assert!(bind(sql, &owner).is_ok(), "{sql}");
        }
        for sql in [
            "SELECT s2 FROM ints WHERE s2 = -32769",
            "SELECT s2 FROM ints WHERE s2 = 32768",
            "SELECT s4 FROM ints WHERE s4 = -2147483649",
            "SELECT s4 FROM ints WHERE s4 = 2147483648",
            "SELECT s8 FROM ints WHERE s8 = -9223372036854775809",
            "SELECT s8 FROM ints WHERE s8 = 9223372036854775808",
            "SELECT scalar FROM ints WHERE scalar = -9223372036854775809",
            "SELECT scalar FROM ints WHERE scalar = 9223372036854775808",
            "SELECT u8 FROM ints WHERE u8 = -1",
            "SELECT u8 FROM ints WHERE u8 = 18446744073709551616",
        ] {
            assert!(
                matches!(
                    bind(sql, &owner),
                    Err(QueryCompileError::TypeMismatch { .. })
                ),
                "{sql}"
            );
        }
    }

    #[test]
    fn typed_parameters_do_not_cross_domains_or_reuse_different_field_types() {
        let owner = authority(schema(
            "ints",
            &[
                ("s2", AttributeType::Integer(IntegerType::Int2)),
                ("s4", AttributeType::Integer(IntegerType::Int4)),
                ("s8", AttributeType::Integer(IntegerType::Int8)),
                ("u8", AttributeType::Integer(IntegerType::Uint8)),
            ],
        ));
        let signed = TypedParameters {
            positional: vec![ParameterValue::I64(1)],
            named: BTreeMap::new(),
        };
        let unsigned = TypedParameters {
            positional: vec![ParameterValue::U64(1)],
            named: BTreeMap::new(),
        };
        let null = TypedParameters {
            positional: vec![ParameterValue::Null],
            named: BTreeMap::new(),
        };
        assert!(bind_sql("SELECT s2 FROM ints WHERE s2 = $1", &signed, &owner.view()).is_ok());
        assert!(
            bind_sql(
                "SELECT u8 FROM ints WHERE u8 = $1",
                &unsigned,
                &owner.view()
            )
            .is_ok()
        );
        assert!(matches!(
            bind_sql("SELECT u8 FROM ints WHERE u8 = $1", &signed, &owner.view()),
            Err(QueryCompileError::Parameter {
                code: "incompatible_type",
                ..
            })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT s8 FROM ints WHERE s8 = $1",
                &unsigned,
                &owner.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "incompatible_type",
                ..
            })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT s2 FROM ints WHERE s2 = $1 AND s4 = $1",
                &null,
                &owner.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "incompatible_reuse",
                ..
            })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT s2 FROM ints WHERE s2 = $1",
                &TypedParameters::default(),
                &owner.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "missing",
                ..
            })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT s2 FROM ints WHERE s2 = $1",
                &TypedParameters {
                    positional: vec![ParameterValue::I64(1), ParameterValue::I64(2)],
                    named: BTreeMap::new()
                },
                &owner.view()
            ),
            Err(QueryCompileError::Parameter { code: "extra", .. })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT s2 FROM ints WHERE s2 = $2",
                &TypedParameters {
                    positional: vec![ParameterValue::I64(1), ParameterValue::I64(2)],
                    named: BTreeMap::new()
                },
                &owner.view()
            ),
            Err(QueryCompileError::Parameter { code: "gap", .. })
        ));
    }

    #[test]
    fn supplied_positional_parameters_are_bounded_before_index_conversion() {
        let owner = authority(schema(
            "ints",
            &[("s2", AttributeType::Integer(IntegerType::Int2))],
        ));
        for supplied_count in [257, 65_537] {
            let parameters = TypedParameters {
                positional: vec![ParameterValue::I64(1); supplied_count],
                named: BTreeMap::new(),
            };
            assert!(matches!(
                bind_sql(
                    "SELECT s2 FROM ints WHERE s2 = $1",
                    &parameters,
                    &owner.view()
                ),
                Err(QueryCompileError::LimitExceeded {
                    code: "positional_parameters",
                    span: None
                })
            ));
        }
    }

    #[test]
    fn named_parameter_namespace_is_exact_and_reused_without_text_rewriting() {
        let owner = authority(schema("tokens", &[("name", AttributeType::Text)]));
        let hostile = ParameterValue::Text("x' OR TRUE --".into());
        let values = TypedParameters {
            positional: vec![],
            named: BTreeMap::from([("needle".into(), hostile)]),
        };
        let plan = bind_sql(
            "SELECT name FROM tokens WHERE name = :needle OR name = @needle",
            &values,
            &owner.view(),
        )
        .unwrap();
        assert_eq!(plan.projection_names(), ["name"]);
        assert_eq!(plan.predicate.as_ref().unwrap().len(), 3);
        for operator in plan.predicate.as_ref().unwrap().iter().take(2) {
            let BoundPredicateOp::Compare { value, .. } = operator else {
                panic!("expected bound comparison")
            };
            assert_eq!(value, &ParameterValue::Text("x' OR TRUE --".into()));
        }
        assert!(matches!(
            bind_sql(
                "SELECT name FROM tokens WHERE name = :Needle",
                &values,
                &owner.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "missing",
                ..
            })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT name FROM tokens WHERE name = :needle",
                &TypedParameters {
                    positional: vec![],
                    named: BTreeMap::from([
                        ("needle".into(), ParameterValue::Text("Ada".into())),
                        ("extra".into(), ParameterValue::Text("x".into()))
                    ])
                },
                &owner.view()
            ),
            Err(QueryCompileError::Parameter { code: "extra", .. })
        ));
        assert!(matches!(
            bind_sql(
                "SELECT name FROM tokens WHERE name = :needle",
                &TypedParameters::default(),
                &owner.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "missing",
                ..
            })
        ));
    }

    #[test]
    fn flat_boolean_predicate_binds_iteratively_without_recursive_left_spine() {
        let owner = authority(schema(
            "ints",
            &[("s2", AttributeType::Integer(IntegerType::Int2))],
        ));
        let sql = format!(
            "SELECT s2 FROM ints WHERE {}",
            (0..1_000)
                .map(|_| "s2 = 1")
                .collect::<Vec<_>>()
                .join(" OR ")
        );
        let plan = bind(&sql, &owner).unwrap();
        assert_eq!(plan.predicate.as_ref().unwrap().len(), 1_999);
    }

    #[test]
    fn scalar_bool_and_text_bind_exact_types_and_ten_positional_slots() {
        let scalars = authority(schema(
            "scalars",
            &[
                ("flag", AttributeType::Scalar(ScalarType::Boolean)),
                ("label", AttributeType::Scalar(ScalarType::Text)),
            ],
        ));
        let boolean = TypedParameters {
            positional: vec![ParameterValue::Bool(true)],
            named: BTreeMap::new(),
        };
        assert!(
            bind_sql(
                "SELECT label FROM scalars WHERE flag = $1",
                &boolean,
                &scalars.view()
            )
            .is_ok()
        );
        assert!(matches!(
            bind_sql(
                "SELECT label FROM scalars WHERE flag = $1",
                &TypedParameters {
                    positional: vec![ParameterValue::Text("true".into())],
                    named: BTreeMap::new()
                },
                &scalars.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "incompatible_type",
                ..
            })
        ));
        assert!(bind("SELECT label FROM scalars WHERE label < 'Ž'", &scalars).is_ok());
        assert!(matches!(
            bind("SELECT label FROM scalars WHERE flag < TRUE", &scalars),
            Err(QueryCompileError::UnsupportedFeature {
                feature: "boolean_order",
                ..
            })
        ));

        let ints = authority(schema(
            "ints",
            &[("s2", AttributeType::Integer(IntegerType::Int2))],
        ));
        let params = TypedParameters {
            positional: vec![ParameterValue::I64(1); 10],
            named: BTreeMap::new(),
        };
        let sql = format!(
            "SELECT s2 FROM ints WHERE {}",
            (1..=10)
                .map(|index| format!("s2 = ${index}"))
                .collect::<Vec<_>>()
                .join(" OR ")
        );
        assert_eq!(
            bind_sql(&sql, &params, &ints.view())
                .unwrap()
                .predicate
                .as_ref()
                .unwrap()
                .len(),
            19
        );
        assert!(matches!(
            bind_sql(
                "SELECT s2 FROM ints WHERE s2 = $1",
                &TypedParameters {
                    positional: vec![ParameterValue::I64(32_768)],
                    named: BTreeMap::new()
                },
                &ints.view()
            ),
            Err(QueryCompileError::Parameter {
                code: "incompatible_type",
                ..
            })
        ));
    }
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

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum QueryCompileError {
    #[error("query syntax error: {code}")]
    Syntax { code: &'static str, span: ByteSpan },
    #[error("unsupported query feature: {feature}")]
    UnsupportedFeature {
        feature: &'static str,
        span: Option<ByteSpan>,
    },
    #[error("unknown collection")]
    UnknownCollection {
        name: String,
        span: Option<ByteSpan>,
    },
    #[error("unknown field")]
    UnknownField { field: String, span: ByteSpan },
    #[error("unsupported field type")]
    UnsupportedFieldType { field: String, span: ByteSpan },
    #[error("parameter error: {code}")]
    Parameter {
        code: &'static str,
        reference: String,
        span: Option<ByteSpan>,
    },
    #[error("query type mismatch")]
    TypeMismatch { field: String, span: ByteSpan },
    #[error("stale catalog view")]
    StaleCatalog,
    #[error("foreign catalog view")]
    ForeignCatalog,
    #[error("legacy logical plans lack bound projection and literal provenance")]
    LegacyPlanUnbound,
    #[error("row data contract violation: {code}")]
    DataContract { code: &'static str },
    #[error("invalid bound predicate: {code}")]
    InvalidBoundPlan { code: &'static str },
    #[error("query limit exceeded: {code}")]
    LimitExceeded {
        code: &'static str,
        span: Option<ByteSpan>,
    },
}

impl From<ParseError> for QueryCompileError {
    fn from(error: ParseError) -> Self {
        match error {
            ParseError::Syntax { code, span } => Self::Syntax { code, span },
            ParseError::UnsupportedFeature { feature, span } => Self::UnsupportedFeature {
                feature,
                span: Some(span),
            },
            ParseError::Parameter { code, span } => Self::Parameter {
                code,
                reference: "<lexical>".into(),
                span: Some(span),
            },
            ParseError::LimitExceeded { code, span } => Self::LimitExceeded {
                code,
                span: Some(span),
            },
        }
    }
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
