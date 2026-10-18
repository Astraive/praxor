use crate::document::{Record, RecordId};
use crate::errors::{PraxisError, Result};
use crate::planner::{AggregateExpr, PhysicalOperator, PhysicalPlan};
use crate::query::{BooleanExpression, JoinClause, LogicalPlan, MutationPlan, Predicate};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Trait for providing records to the executor.
/// Implementors wrap any storage engine (praxis's KV store, Poiesis's engine, etc.)
pub trait RecordProvider {
    /// Get all records in a collection.
    fn collection(&self, name: &str) -> Vec<Record>;
    /// Get a single record by ID.
    fn get(&self, id: &RecordId) -> Option<Record>;
    /// Filter records using a scalar index if available.
    fn scalar_filter(&self, collection: &str, predicate: &Predicate) -> Option<Vec<Record>>;
    /// Full-text search using an inverted index if available.
    fn full_text_search(
        &self,
        collection: &str,
        attribute: &str,
        query: &str,
        top: Option<usize>,
    ) -> Option<Vec<Record>>;
    /// Vector similarity search using HNSW/flat index if available.
    fn vector_similarity(
        &self,
        collection: &str,
        target_key: &str,
        top: usize,
    ) -> Option<Vec<Record>>;
    /// Graph traversal using adjacency index if available.
    fn graph_connected_to(
        &self,
        collection: &str,
        target_key: &str,
        hops: usize,
        edge_label: Option<&str>,
    ) -> Vec<Record>;
}

/// Trait for mutating records in storage.
pub trait RecordStore: RecordProvider {
    fn insert(&mut self, record: Record) -> Result<()>;
    fn update(&mut self, id: &RecordId, attributes: BTreeMap<String, Value>) -> Result<Record>;
    fn delete(&mut self, id: &RecordId) -> Result<Option<Record>>;
}

#[derive(Debug, Clone, Default)]
pub struct Executor;

impl Executor {
    pub fn execute<P: RecordProvider>(
        &self,
        provider: &P,
        plan: &PhysicalPlan,
    ) -> Result<Vec<Record>> {
        for operator in &plan.operators {
            match operator {
                PhysicalOperator::AsOf => {
                    return Err(PraxisError::Query(
                        "unsupported query feature: as_of".into(),
                    ));
                }
                PhysicalOperator::GroupBy(_) => {
                    return Err(PraxisError::Query(
                        "unsupported query feature: group_by".into(),
                    ));
                }
                _ => {}
            }
        }
        let mut records = plan
            .operators
            .iter()
            .find_map(|operator| match operator {
                PhysicalOperator::Filter(predicate) => {
                    provider.scalar_filter(&plan.collection, predicate)
                }
                PhysicalOperator::FilterExpression(BooleanExpression::Predicate(predicate)) => {
                    provider.scalar_filter(&plan.collection, predicate)
                }
                _ => None,
            })
            .unwrap_or_else(|| provider.collection(&plan.collection));

        for operator in &plan.operators {
            match operator {
                PhysicalOperator::Filter(predicate) => {
                    records.retain(|record| matches_predicate(record, predicate));
                }
                PhysicalOperator::FilterExpression(expression) => {
                    records.retain(|record| matches_boolean_expression(record, expression));
                }
                PhysicalOperator::Join(join) => {
                    records = execute_join(provider, records, join);
                }
                PhysicalOperator::FullText(full_text) => {
                    if let Some(hits) = provider.full_text_search(
                        &plan.collection,
                        &full_text.attribute,
                        &full_text.query,
                        full_text.top,
                    ) {
                        records = hits;
                    } else {
                        records.retain(|record| {
                            record
                                .attributes
                                .get(&full_text.attribute)
                                .and_then(Value::as_str)
                                .map(|text| {
                                    text.to_ascii_lowercase()
                                        .contains(&full_text.query.to_ascii_lowercase())
                                })
                                .unwrap_or(false)
                        });
                        if let Some(top) = full_text.top {
                            records.truncate(top);
                        }
                    }
                }
                PhysicalOperator::Order(order) => {
                    records.sort_by(|left, right| {
                        let ordering = compare_values(
                            left.attributes.get(&order.attribute),
                            right.attributes.get(&order.attribute),
                        );
                        if order.descending {
                            ordering.reverse()
                        } else {
                            ordering
                        }
                    });
                }
                PhysicalOperator::Limit(limit) => records.truncate(*limit),
                PhysicalOperator::Offset(offset) => {
                    if *offset < records.len() {
                        records = records.split_off(*offset);
                    } else {
                        records.clear();
                    }
                }
                PhysicalOperator::Distinct => {
                    let mut seen = BTreeSet::new();
                    records.retain(|r| seen.insert(r.id.storage_key()));
                }
                PhysicalOperator::GroupBy(_) => unreachable!("preflight rejects GroupBy"),
                PhysicalOperator::Aggregate(expr) => {
                    records = execute_aggregate(records, expr);
                }
                PhysicalOperator::Similarity(vector) => {
                    if let Some(hits) =
                        provider.vector_similarity(&plan.collection, &vector.target, vector.top)
                    {
                        records = intersect_by_id(records, hits);
                    }
                }
                PhysicalOperator::Traverse(traversal) => {
                    let hits = provider.graph_connected_to(
                        &plan.collection,
                        &traversal.target,
                        traversal.hops,
                        traversal.edge_label.as_deref(),
                    );
                    records = intersect_by_id(records, hits);
                }
                PhysicalOperator::Rank(rank_expr) => {
                    records = rank_records(records, rank_expr);
                }
                PhysicalOperator::AsOf => unreachable!("preflight rejects AsOf"),
            }
        }
        Ok(records)
    }

    pub fn execute_mutation<S: RecordStore>(
        &self,
        store: &mut S,
        plan: &LogicalPlan,
    ) -> Result<Option<Record>> {
        let Some(mutation) = &plan.mutation else {
            return Ok(None);
        };
        match mutation {
            MutationPlan::Insert { key, attributes } => {
                let mut record = Record::new(&plan.collection, key);
                for (attribute, value) in attributes {
                    record = record.with_attribute(attribute, value.clone());
                }
                store.insert(record.clone())?;
                Ok(Some(record))
            }
            MutationPlan::Update { key, attributes } => {
                let id = RecordId::new(&plan.collection, key);
                Ok(Some(store.update(&id, attributes.clone())?))
            }
            MutationPlan::Delete { key } => {
                let id = RecordId::new(&plan.collection, key);
                store.delete(&id)
            }
        }
    }
}

fn intersect_by_id(left: Vec<Record>, right: Vec<Record>) -> Vec<Record> {
    let right_ids: BTreeSet<_> = right.into_iter().map(|record| record.id).collect();
    left.into_iter()
        .filter(|record| right_ids.contains(&record.id))
        .collect()
}

pub fn matches_predicate(record: &Record, predicate: &Predicate) -> bool {
    let Some(value) = record.attributes.get(&predicate.attribute) else {
        return false;
    };
    match predicate.operator.as_str() {
        "=" | "==" => value_equals(value, &predicate.value),
        ">" => compare_literal(value, &predicate.value).is_gt(),
        ">=" => {
            let ordering = compare_literal(value, &predicate.value);
            ordering.is_gt() || ordering.is_eq()
        }
        "<" => compare_literal(value, &predicate.value).is_lt(),
        "<=" => {
            let ordering = compare_literal(value, &predicate.value);
            ordering.is_lt() || ordering.is_eq()
        }
        "!=" | "<>" => !value_equals(value, &predicate.value),
        _ => false,
    }
}

pub fn matches_boolean_expression(record: &Record, expression: &BooleanExpression) -> bool {
    match expression {
        BooleanExpression::Predicate(predicate) => matches_predicate(record, predicate),
        BooleanExpression::And(left, right) => {
            matches_boolean_expression(record, left) && matches_boolean_expression(record, right)
        }
        BooleanExpression::Or(left, right) => {
            matches_boolean_expression(record, left) || matches_boolean_expression(record, right)
        }
    }
}

fn execute_join<P: RecordProvider>(
    provider: &P,
    records: Vec<Record>,
    join: &JoinClause,
) -> Vec<Record> {
    let right_records = provider.collection(&join.collection);
    let right_attr = join
        .right_attribute
        .rsplit('.')
        .next()
        .unwrap_or(&join.right_attribute);
    let left_attr = join
        .left_attribute
        .rsplit('.')
        .next()
        .unwrap_or(&join.left_attribute);
    records
        .into_iter()
        .filter_map(|mut left| {
            let left_value = left.attributes.get(left_attr)?;
            let joined: Vec<_> = right_records
                .iter()
                .filter(|right| right.attributes.get(right_attr) == Some(left_value))
                .cloned()
                .collect();
            if joined.is_empty() {
                None
            } else {
                left.attributes.insert(
                    format!("join.{}", join.collection),
                    serde_json::json!(joined),
                );
                Some(left)
            }
        })
        .collect()
}

fn value_equals(value: &Value, literal: &str) -> bool {
    if let Some(text) = value.as_str() {
        text == literal
    } else if let Some(number) = value.as_f64() {
        literal
            .parse::<f64>()
            .map(|right| number == right)
            .unwrap_or(false)
    } else {
        serde_json::from_str::<Value>(literal)
            .map(|parsed| value == &parsed)
            .unwrap_or(false)
    }
}

fn compare_literal(value: &Value, literal: &str) -> Ordering {
    if let Some(number) = value.as_f64() {
        return literal
            .parse::<f64>()
            .ok()
            .and_then(|right| number.partial_cmp(&right))
            .unwrap_or(Ordering::Equal);
    }
    value.as_str().unwrap_or_default().cmp(literal)
}

fn compare_values(left: Option<&Value>, right: Option<&Value>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
                return left.partial_cmp(&right).unwrap_or(Ordering::Equal);
            }
            left.as_str()
                .unwrap_or_default()
                .cmp(right.as_str().unwrap_or_default())
        }
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

fn rank_records(mut records: Vec<Record>, rank_expr: &str) -> Vec<Record> {
    let lower = rank_expr.to_ascii_lowercase();

    if lower.contains("text") || lower.contains("relevance") || lower.contains("bm25") {
        records.sort_by(|a, b| {
            let score_a = text_relevance_score(a);
            let score_b = text_relevance_score(b);
            score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
        });
        return records;
    }

    if (lower.contains("vector") || lower.contains("similarity"))
        && let Some(first) = records.first()
        && let Some((attr, query_vec)) = first.vectors.iter().next()
    {
        let query = query_vec.clone();
        let attr_name = attr.clone();
        records.sort_by(|a, b| {
            let score_a = a
                .vectors
                .get(&attr_name)
                .map(|v| cosine_similarity(&query, v))
                .unwrap_or(0.0);
            let score_b = b
                .vectors
                .get(&attr_name)
                .map(|v| cosine_similarity(&query, v))
                .unwrap_or(0.0);
            score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
        });
        return records;
    }

    if lower.contains("graph") || lower.contains("connectivity") {
        records.sort_by_key(|b| std::cmp::Reverse(b.edges.len()));
        return records;
    }

    records.sort_by_key(|b| std::cmp::Reverse(b.updated_at_ms));
    records
}

fn text_relevance_score(record: &Record) -> f64 {
    let mut score = 0.0;
    for value in record.attributes.values() {
        if let Some(text) = value.as_str() {
            let words: std::collections::HashSet<&str> = text.split_whitespace().collect();
            score += words.len() as f64;
            score += (text.len() as f64).sqrt();
        }
    }
    score
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        0.0
    } else {
        dot / (mag_a * mag_b)
    }
}

fn execute_aggregate(records: Vec<Record>, expr: &AggregateExpr) -> Vec<Record> {
    let func = expr.function.to_ascii_uppercase();
    let attr = &expr.attribute;

    let values: Vec<&Value> = records
        .iter()
        .filter_map(|r| r.attributes.get(attr))
        .collect();

    let result_value = match func.as_str() {
        "COUNT" => serde_json::json!(values.len()),
        "SUM" => {
            let sum: f64 = values.iter().filter_map(|v| v.as_f64()).sum();
            serde_json::json!(sum)
        }
        "AVG" => {
            let nums: Vec<f64> = values.iter().filter_map(|v| v.as_f64()).collect();
            if nums.is_empty() {
                serde_json::json!(null)
            } else {
                serde_json::json!(nums.iter().sum::<f64>() / nums.len() as f64)
            }
        }
        "MIN" => {
            let min = values
                .iter()
                .filter_map(|v| v.as_f64())
                .fold(f64::INFINITY, f64::min);
            if min == f64::INFINITY {
                serde_json::json!(null)
            } else {
                serde_json::json!(min)
            }
        }
        "MAX" => {
            let max = values
                .iter()
                .filter_map(|v| v.as_f64())
                .fold(f64::NEG_INFINITY, f64::max);
            if max == f64::NEG_INFINITY {
                serde_json::json!(null)
            } else {
                serde_json::json!(max)
            }
        }
        _ => serde_json::json!(values.len()),
    };

    let mut record = Record::new("_aggregate", &expr.alias);
    record.attributes.insert(expr.alias.clone(), result_value);
    vec![record]
}
