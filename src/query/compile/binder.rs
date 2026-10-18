//! Typed binding over the detached catalog view. No storage provider is involved.
use super::catalog::{CatalogOwner, QueryCatalogAuthority, QueryCatalogView};
#[cfg(test)]
use super::syntax::parse_sql;
use super::syntax::{CompareOp, PredicateExpr, Projection, SyntaxSelect, ValueExpr, ValueSyntax};
use super::{ByteSpan, QueryCompileError};
use crate::catalog::schema::{AttributeType, CollectionSchema, IntegerType, ScalarType};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// Exact typed bindings for `$1..$256`, `:name`, and `@name`; values are never
/// rewritten into SQL source. Named placeholders share one case-sensitive map.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct TypedParameters {
    pub positional: Vec<ParameterValue>,
    pub named: BTreeMap<String, ParameterValue>,
}

/// A Q1 scalar parameter; signed and unsigned integer domains do not coerce.
impl fmt::Debug for TypedParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedParameters")
            .field("positional_count", &self.positional.len())
            .field("named_count", &self.named.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ParameterValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    Text(String),
}

impl fmt::Debug for ParameterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Null => "Null",
            Self::Bool(_) => "Bool(<redacted>)",
            Self::I64(_) => "I64(<redacted>)",
            Self::U64(_) => "U64(<redacted>)",
            Self::Text(_) => "Text(<redacted>)",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QueryFieldType {
    Int2,
    Int4,
    Int8,
    Uint8,
    Bool,
    Text,
}

impl QueryFieldType {
    fn from_declared(declared: &AttributeType) -> Option<Self> {
        Some(match declared {
            AttributeType::Integer(IntegerType::Int2) => Self::Int2,
            AttributeType::Integer(IntegerType::Int4) => Self::Int4,
            AttributeType::Integer(IntegerType::Int8)
            | AttributeType::Scalar(ScalarType::Integer) => Self::Int8,
            AttributeType::Integer(IntegerType::Uint8) => Self::Uint8,
            AttributeType::Boolean | AttributeType::Scalar(ScalarType::Boolean) => Self::Bool,
            AttributeType::Text | AttributeType::Scalar(ScalarType::Text) => Self::Text,
            _ => return None,
        })
    }

    fn accepts_signed(self, value: i64) -> bool {
        match self {
            Self::Int2 => i16::try_from(value).is_ok(),
            Self::Int4 => i32::try_from(value).is_ok(),
            Self::Int8 => true,
            Self::Uint8 | Self::Bool | Self::Text => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BoundField {
    pub name: String,
    pub kind: QueryFieldType,
    pub nullable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum BoundPredicateOp {
    Compare {
        field: BoundField,
        operator: CompareOp,
        value: ParameterValue,
    },
    IsNull {
        field: BoundField,
        negated: bool,
    },
    Not,
    And,
    Or,
}

/// Opaque executable SELECT produced only by `compile`. Fields are private and
/// there is no `Deserialize` implementation to forge one from a legacy plan.
pub struct BoundSelect {
    pub(super) collection: String,
    pub(super) projection: Vec<BoundField>,
    pub(super) predicate: Option<Vec<BoundPredicateOp>>,
    pub(super) owner: Arc<CatalogOwner>,
    pub(super) revision: u64,
}

impl fmt::Debug for BoundSelect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundSelect")
            .field("collection", &self.collection)
            .field("projection", &self.projection_names())
            .field("predicate_ops", &self.predicate.as_ref().map(Vec::len))
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl BoundSelect {
    pub fn collection(&self) -> &str {
        &self.collection
    }

    pub fn projection_names(&self) -> Vec<&str> {
        self.projection
            .iter()
            .map(|field| field.name.as_str())
            .collect()
    }
}

impl QueryCatalogAuthority {
    pub(crate) fn validate_bound(&self, select: &BoundSelect) -> Result<(), QueryCompileError> {
        self.validate_handle(&select.owner, select.revision)
    }
}

fn field(
    schema: &CollectionSchema,
    name: &str,
    span: ByteSpan,
) -> Result<BoundField, QueryCompileError> {
    let declared = schema
        .attributes
        .get(name)
        .ok_or_else(|| QueryCompileError::UnknownField {
            field: name.into(),
            span,
        })?;
    let kind = QueryFieldType::from_declared(&declared.attribute_type).ok_or_else(|| {
        QueryCompileError::UnsupportedFieldType {
            field: name.into(),
            span,
        }
    })?;
    Ok(BoundField {
        name: name.into(),
        kind,
        nullable: declared.nullable,
    })
}

fn projection(
    projection: Projection,
    schema: &CollectionSchema,
    collection_span: ByteSpan,
) -> Result<Vec<BoundField>, QueryCompileError> {
    match projection {
        Projection::All => schema
            .attributes
            .keys()
            .map(|name| field(schema, name, collection_span))
            .collect(),
        Projection::Fields(identifiers) => {
            let mut seen = BTreeSet::new();
            let mut fields = Vec::with_capacity(identifiers.len());
            for identifier in identifiers {
                if !seen.insert(identifier.name.clone()) {
                    return Err(QueryCompileError::Syntax {
                        code: "duplicate_projection",
                        span: identifier.span,
                    });
                }
                fields.push(field(schema, &identifier.name, identifier.span)?);
            }
            Ok(fields)
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ParameterKey {
    Positional(u16),
    Named(String),
}

#[derive(Default)]
struct ParameterUse {
    field_types: BTreeMap<ParameterKey, QueryFieldType>,
    used_positional: BTreeSet<u16>,
    used_named: BTreeSet<String>,
}

impl ParameterUse {
    fn take(
        &mut self,
        key: ParameterKey,
        kind: QueryFieldType,
        params: &TypedParameters,
        span: ByteSpan,
    ) -> Result<ParameterValue, QueryCompileError> {
        let reference = match &key {
            ParameterKey::Positional(index) => format!("${index}"),
            ParameterKey::Named(name) => format!(":{name}"),
        };
        if let Some(previous) = self.field_types.get(&key)
            && *previous != kind
        {
            return Err(QueryCompileError::Parameter {
                code: "incompatible_reuse",
                reference,
                span: Some(span),
            });
        }
        let supplied = match &key {
            ParameterKey::Positional(index) => params.positional.get(usize::from(*index - 1)),
            ParameterKey::Named(name) => params.named.get(name),
        }
        .ok_or_else(|| QueryCompileError::Parameter {
            code: "missing",
            reference: reference.clone(),
            span: Some(span),
        })?;
        let compatible = match supplied {
            ParameterValue::Null => true,
            ParameterValue::Bool(_) => kind == QueryFieldType::Bool,
            ParameterValue::Text(_) => kind == QueryFieldType::Text,
            ParameterValue::I64(value) => kind.accepts_signed(*value),
            ParameterValue::U64(_) => kind == QueryFieldType::Uint8,
        };
        if !compatible {
            return Err(QueryCompileError::Parameter {
                code: "incompatible_type",
                reference,
                span: Some(span),
            });
        }
        self.field_types.entry(key.clone()).or_insert(kind);
        match key {
            ParameterKey::Positional(index) => {
                self.used_positional.insert(index);
            }
            ParameterKey::Named(name) => {
                self.used_named.insert(name);
            }
        }
        Ok(supplied.clone())
    }

    fn finish(&self, params: &TypedParameters) -> Result<(), QueryCompileError> {
        // The lexer only admits $1..$256. Bound caller input before converting an
        // index to u16 so a very large Vec cannot wrap into a valid slot.
        if params.positional.len() > 256 {
            return Err(QueryCompileError::LimitExceeded {
                code: "positional_parameters",
                span: None,
            });
        }
        if let Some(highest) = self.used_positional.last() {
            for index in 1..=*highest {
                if !self.used_positional.contains(&index) {
                    return Err(QueryCompileError::Parameter {
                        code: "gap",
                        reference: format!("${index}"),
                        span: None,
                    });
                }
            }
        }
        for index in 1..=params.positional.len() {
            if !self.used_positional.contains(&(index as u16)) {
                return Err(QueryCompileError::Parameter {
                    code: "extra",
                    reference: format!("${index}"),
                    span: None,
                });
            }
        }
        for name in params.named.keys() {
            if !self.used_named.contains(name) {
                return Err(QueryCompileError::Parameter {
                    code: "extra",
                    reference: format!(":{name}"),
                    span: None,
                });
            }
        }
        Ok(())
    }
}

fn bind_literal(
    syntax: &ValueExpr,
    field: &BoundField,
    params: &TypedParameters,
    usage: &mut ParameterUse,
) -> Result<ParameterValue, QueryCompileError> {
    let mismatch = || QueryCompileError::TypeMismatch {
        field: field.name.clone(),
        span: syntax.span,
    };
    match &syntax.syntax {
        ValueSyntax::Null => Ok(ParameterValue::Null),
        ValueSyntax::Bool(value) if field.kind == QueryFieldType::Bool => {
            Ok(ParameterValue::Bool(*value))
        }
        ValueSyntax::Text(value) if field.kind == QueryFieldType::Text => {
            Ok(ParameterValue::Text(value.clone()))
        }
        ValueSyntax::Integer(value) => match field.kind {
            QueryFieldType::Int2 => value
                .parse::<i16>()
                .map(|n| ParameterValue::I64(i64::from(n)))
                .map_err(|_| mismatch()),
            QueryFieldType::Int4 => value
                .parse::<i32>()
                .map(|n| ParameterValue::I64(i64::from(n)))
                .map_err(|_| mismatch()),
            QueryFieldType::Int8 => value
                .parse::<i64>()
                .map(ParameterValue::I64)
                .map_err(|_| mismatch()),
            QueryFieldType::Uint8 => value
                .parse::<u64>()
                .map(ParameterValue::U64)
                .map_err(|_| mismatch()),
            QueryFieldType::Bool | QueryFieldType::Text => Err(mismatch()),
        },
        ValueSyntax::Positional(index) => usage.take(
            ParameterKey::Positional(*index),
            field.kind,
            params,
            syntax.span,
        ),
        ValueSyntax::Named(name) => usage.take(
            ParameterKey::Named(name.clone()),
            field.kind,
            params,
            syntax.span,
        ),
        ValueSyntax::Bool(_) | ValueSyntax::Text(_) => Err(mismatch()),
    }
}

enum Work<'a> {
    Enter(&'a PredicateExpr),
    Not,
    And,
    Or,
}

/// Emits postorder operations with an explicit stack. Flat boolean chains do not
/// create a recursive bound tree for the later evaluator to traverse.
fn bind_predicate(
    root: &PredicateExpr,
    schema: &CollectionSchema,
    params: &TypedParameters,
    usage: &mut ParameterUse,
) -> Result<Vec<BoundPredicateOp>, QueryCompileError> {
    let mut pending = vec![Work::Enter(root)];
    let mut output = Vec::new();
    while let Some(work) = pending.pop() {
        match work {
            Work::Enter(PredicateExpr::Compare {
                field: identifier,
                operator,
                value,
            }) => {
                let bound_field = field(schema, &identifier.name, identifier.span)?;
                if bound_field.kind == QueryFieldType::Bool
                    && !matches!(operator, CompareOp::Eq | CompareOp::NotEq)
                {
                    return Err(QueryCompileError::UnsupportedFeature {
                        feature: "boolean_order",
                        span: Some(identifier.span),
                    });
                }
                let bound_value = bind_literal(value, &bound_field, params, usage)?;
                output.push(BoundPredicateOp::Compare {
                    field: bound_field,
                    operator: *operator,
                    value: bound_value,
                });
            }
            Work::Enter(PredicateExpr::IsNull {
                field: identifier,
                negated,
            }) => {
                output.push(BoundPredicateOp::IsNull {
                    field: field(schema, &identifier.name, identifier.span)?,
                    negated: *negated,
                });
            }
            Work::Enter(PredicateExpr::Not(child)) => {
                pending.push(Work::Not);
                pending.push(Work::Enter(child));
            }
            Work::Enter(PredicateExpr::And(left, right)) => {
                pending.push(Work::And);
                pending.push(Work::Enter(right));
                pending.push(Work::Enter(left));
            }
            Work::Enter(PredicateExpr::Or(left, right)) => {
                pending.push(Work::Or);
                pending.push(Work::Enter(right));
                pending.push(Work::Enter(left));
            }
            Work::Not => output.push(BoundPredicateOp::Not),
            Work::And => output.push(BoundPredicateOp::And),
            Work::Or => output.push(BoundPredicateOp::Or),
        }
    }
    Ok(output)
}

#[cfg(test)]
pub(super) fn bind_sql(
    sql: &str,
    params: &TypedParameters,
    view: &QueryCatalogView,
) -> Result<BoundSelect, QueryCompileError> {
    let syntax = parse_sql(sql)?;
    if syntax.explain {
        return Err(QueryCompileError::UnsupportedFeature {
            feature: "explain_requires_compile",
            span: None,
        });
    }
    bind_syntax(syntax, params, view)
}

pub(super) fn bind_syntax(
    syntax: SyntaxSelect,
    params: &TypedParameters,
    view: &QueryCatalogView,
) -> Result<BoundSelect, QueryCompileError> {
    view.validate_current()?;
    let schema = view.schemas.get(&syntax.collection.name).ok_or_else(|| {
        QueryCompileError::UnknownCollection {
            name: syntax.collection.name.clone(),
            span: Some(syntax.collection.span),
        }
    })?;
    let projection = projection(syntax.projection, schema, syntax.collection.span)?;
    let mut usage = ParameterUse::default();
    let predicate = syntax
        .predicate
        .as_ref()
        .map(|expression| bind_predicate(expression, schema, params, &mut usage))
        .transpose()?;
    usage.finish(params)?;
    view.validate_current()?;
    Ok(BoundSelect {
        collection: schema.name.clone(),
        projection,
        predicate,
        owner: Arc::clone(&view.owner),
        revision: view.revision,
    })
}
