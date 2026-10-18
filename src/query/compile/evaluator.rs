//! Pure in-memory row semantics for bound Q1 SELECTs. This module does not
//! access a provider, page store, catalog store, or product query route.
use super::QueryCompileError;
use super::binder::{BoundField, BoundPredicateOp, BoundSelect, ParameterValue, QueryFieldType};
use super::catalog::QueryCatalogAuthority;
use super::syntax::CompareOp;
use crate::document::{Record, RecordId};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeMap;

/// A document logical ID and ordered projection pairs from an in-memory scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectedRow {
    pub id: RecordId,
    pub fields: Vec<(String, Value)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Unknown,
}

impl Truth {
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

fn referenced_fields(select: &BoundSelect) -> BTreeMap<&str, &BoundField> {
    let mut fields = BTreeMap::new();
    for field in &select.projection {
        fields.entry(field.name.as_str()).or_insert(field);
    }
    if let Some(predicate) = &select.predicate {
        for operation in predicate {
            let field = match operation {
                BoundPredicateOp::Compare { field, .. }
                | BoundPredicateOp::IsNull { field, .. } => field,
                BoundPredicateOp::Not | BoundPredicateOp::And | BoundPredicateOp::Or => continue,
            };
            fields.entry(field.name.as_str()).or_insert(field);
        }
    }
    fields
}

fn validate_field(row: &Record, field: &BoundField) -> Result<(), QueryCompileError> {
    let Some(value) = row.attributes.get(&field.name) else {
        return if field.nullable {
            Ok(())
        } else {
            Err(QueryCompileError::DataContract {
                code: "missing_required",
            })
        };
    };
    if value.is_null() {
        return if field.nullable {
            Ok(())
        } else {
            Err(QueryCompileError::DataContract {
                code: "null_required",
            })
        };
    }
    let valid = match field.kind {
        QueryFieldType::Int2 => value
            .as_i64()
            .is_some_and(|number| i16::try_from(number).is_ok()),
        QueryFieldType::Int4 => value
            .as_i64()
            .is_some_and(|number| i32::try_from(number).is_ok()),
        QueryFieldType::Int8 => value.as_i64().is_some(),
        QueryFieldType::Uint8 => value.as_u64().is_some(),
        QueryFieldType::Bool => value.is_boolean(),
        QueryFieldType::Text => value.is_string(),
    };
    if valid {
        Ok(())
    } else {
        Err(QueryCompileError::DataContract { code: "wrong_type" })
    }
}

fn validate_row(
    row: &Record,
    select: &BoundSelect,
    fields: &BTreeMap<&str, &BoundField>,
) -> Result<(), QueryCompileError> {
    if row.id.collection != select.collection {
        return Err(QueryCompileError::DataContract {
            code: "wrong_collection",
        });
    }
    for field in fields.values() {
        validate_field(row, field)?;
    }
    Ok(())
}

fn compare(
    row: &Record,
    field: &BoundField,
    operator: CompareOp,
    rhs: &ParameterValue,
) -> Result<Truth, QueryCompileError> {
    let lhs = row.attributes.get(&field.name);
    if lhs.is_none_or(Value::is_null) || matches!(rhs, ParameterValue::Null) {
        return Ok(Truth::Unknown);
    }
    let lhs = lhs.ok_or(QueryCompileError::InvalidBoundPlan {
        code: "missing_operand",
    })?;
    let ordering = match (field.kind, lhs, rhs) {
        (
            QueryFieldType::Int2 | QueryFieldType::Int4 | QueryFieldType::Int8,
            Value::Number(lhs),
            ParameterValue::I64(rhs),
        ) => lhs.as_i64().map(|value| value.cmp(rhs)),
        (QueryFieldType::Uint8, Value::Number(lhs), ParameterValue::U64(rhs)) => {
            lhs.as_u64().map(|value| value.cmp(rhs))
        }
        (QueryFieldType::Bool, Value::Bool(lhs), ParameterValue::Bool(rhs)) => {
            if !matches!(operator, CompareOp::Eq | CompareOp::NotEq) {
                return Err(QueryCompileError::InvalidBoundPlan {
                    code: "boolean_order",
                });
            }
            Some(lhs.cmp(rhs))
        }
        (QueryFieldType::Text, Value::String(lhs), ParameterValue::Text(rhs)) => {
            Some(lhs.as_str().cmp(rhs.as_str()))
        }
        _ => None,
    }
    .ok_or(QueryCompileError::InvalidBoundPlan {
        code: "operand_type",
    })?;
    let passes = match operator {
        CompareOp::Eq => ordering == Ordering::Equal,
        CompareOp::NotEq => ordering != Ordering::Equal,
        CompareOp::Lt => ordering == Ordering::Less,
        CompareOp::Lte => ordering != Ordering::Greater,
        CompareOp::Gt => ordering == Ordering::Greater,
        CompareOp::Gte => ordering != Ordering::Less,
    };
    Ok(if passes { Truth::True } else { Truth::False })
}

fn predicate_result(
    row: &Record,
    operations: &[BoundPredicateOp],
) -> Result<Truth, QueryCompileError> {
    let mut stack = Vec::with_capacity(operations.len().min(64));
    for operation in operations {
        match operation {
            BoundPredicateOp::Compare {
                field,
                operator,
                value,
            } => {
                stack.push(compare(row, field, *operator, value)?);
            }
            BoundPredicateOp::IsNull { field, negated } => {
                let is_null = row.attributes.get(&field.name).is_none_or(Value::is_null);
                stack.push(if is_null == *negated {
                    Truth::False
                } else {
                    Truth::True
                });
            }
            BoundPredicateOp::Not => {
                let top = stack
                    .last_mut()
                    .ok_or(QueryCompileError::InvalidBoundPlan {
                        code: "predicate_stack",
                    })?;
                *top = top.not();
            }
            BoundPredicateOp::And | BoundPredicateOp::Or => {
                let right = stack.pop().ok_or(QueryCompileError::InvalidBoundPlan {
                    code: "predicate_stack",
                })?;
                let left = stack.pop().ok_or(QueryCompileError::InvalidBoundPlan {
                    code: "predicate_stack",
                })?;
                stack.push(if matches!(operation, BoundPredicateOp::And) {
                    left.and(right)
                } else {
                    left.or(right)
                });
            }
        }
    }
    match stack.as_slice() {
        [result] => Ok(*result),
        _ => Err(QueryCompileError::InvalidBoundPlan {
            code: "predicate_stack",
        }),
    }
}

/// Scan the supplied immutable records in slice order with three-valued WHERE
/// semantics. Validates owner/revision before any row and again before return;
/// every referenced field is type-checked on every row, including filtered rows.
/// This helper does not access a provider or promise storage result ordering.
pub fn execute_in_memory(
    authority: &QueryCatalogAuthority,
    select: &BoundSelect,
    rows: &[Record],
) -> Result<Vec<ProjectedRow>, QueryCompileError> {
    authority.validate_bound(select)?;
    let fields = referenced_fields(select);
    let mut results = Vec::new();
    for row in rows {
        validate_row(row, select, &fields)?;
        let passes = match &select.predicate {
            Some(operations) => predicate_result(row, operations)? == Truth::True,
            None => true,
        };
        if passes {
            results.push(ProjectedRow {
                id: row.id.clone(),
                fields: select
                    .projection
                    .iter()
                    .map(|field| {
                        (
                            field.name.clone(),
                            row.attributes
                                .get(&field.name)
                                .cloned()
                                .unwrap_or(Value::Null),
                        )
                    })
                    .collect(),
            });
        }
    }
    authority.validate_bound(select)?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::Truth::{False, True, Unknown};

    #[test]
    fn three_valued_not_and_or_follow_literal_truth_tables() {
        let values = [True, False, Unknown];
        let not = [False, True, Unknown];
        let and = [
            [True, False, Unknown],
            [False, False, False],
            [Unknown, False, Unknown],
        ];
        let or = [
            [True, True, True],
            [True, False, Unknown],
            [True, Unknown, Unknown],
        ];
        for (left_index, left) in values.into_iter().enumerate() {
            assert_eq!(left.not(), not[left_index]);
            for (right_index, right) in values.into_iter().enumerate() {
                assert_eq!(left.and(right), and[left_index][right_index]);
                assert_eq!(left.or(right), or[left_index][right_index]);
            }
        }
    }
}
