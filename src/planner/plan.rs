use crate::errors::Result;
use crate::query::{
    BooleanExpression, FullTextClause, JoinClause, LogicalPlan, OrderClause, Predicate,
    TraversalClause, VectorClause,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhysicalPlan {
    pub collection: String,
    pub operators: Vec<PhysicalOperator>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostedPlan {
    pub physical: PhysicalPlan,
    pub operators: Vec<CostedOperator>,
    pub total_cost: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostedOperator {
    pub operator: PhysicalOperator,
    pub estimated_rows: u64,
    pub estimated_cost: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PhysicalOperator {
    Filter(Predicate),
    FilterExpression(BooleanExpression),
    Join(JoinClause),
    FullText(FullTextClause),
    Similarity(VectorClause),
    Traverse(TraversalClause),
    Rank(String),
    Order(OrderClause),
    Limit(usize),
    Offset(usize),
    Distinct,
    GroupBy(Vec<String>),
    Aggregate(AggregateExpr),
    AsOf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateExpr {
    pub function: String,
    pub attribute: String,
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlannerStats {
    pub collection_cardinality: u64,
    pub filter_selectivity: f64,
    pub vector_fanout: u64,
    pub graph_average_degree: f64,
    pub graph_depth: u64,
    pub full_text_posting_hits: u64,
    pub scalar_index_density: f64,
}

impl Default for PlannerStats {
    fn default() -> Self {
        Self {
            collection_cardinality: 1_000,
            filter_selectivity: 0.1,
            vector_fanout: 100,
            graph_average_degree: 8.0,
            graph_depth: 2,
            full_text_posting_hits: 100,
            scalar_index_density: 0.1,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Planner;

impl Planner {
    pub fn plan(&self, logical: &LogicalPlan) -> Result<PhysicalPlan> {
        let mut operators = Vec::new();

        // 1. AsOf first (snapshot isolation)
        if logical.as_of.is_some() {
            operators.push(PhysicalOperator::AsOf);
        }

        // 2. Predicate pushdown: filters before expensive operators
        if let Some(expression) = &logical.filter_expression {
            operators.push(PhysicalOperator::FilterExpression(expression.clone()));
        } else if let Some(filter) = &logical.filter {
            operators.push(PhysicalOperator::Filter(filter.clone()));
        }

        // 3. Full-text search (uses inverted index, moderate cost)
        if let Some(full_text) = &logical.full_text {
            operators.push(PhysicalOperator::FullText(full_text.clone()));
        }

        // 4. Vector similarity (ANN search, higher cost)
        if let Some(vector) = &logical.vector {
            operators.push(PhysicalOperator::Similarity(vector.clone()));
        }

        // 5. Graph traversal (BFS, can be expensive)
        if let Some(traversal) = &logical.traversal {
            operators.push(PhysicalOperator::Traverse(traversal.clone()));
        }

        // 6. Joins (nested loop, expensive - should be after filters)
        for join in &logical.joins {
            operators.push(PhysicalOperator::Join(join.clone()));
        }

        // 7. Ranking (re-scores candidate set)
        if let Some(rank_by) = &logical.rank_by {
            operators.push(PhysicalOperator::Rank(rank_by.clone()));
        }

        // 8. Order (sort)
        if let Some(order_by) = &logical.order_by {
            operators.push(PhysicalOperator::Order(order_by.clone()));
        }

        // 9. Group By
        if let Some(group_by) = &logical.group_by {
            operators.push(PhysicalOperator::GroupBy(group_by.clone()));
        }

        // 10. Distinct
        if logical.distinct {
            operators.push(PhysicalOperator::Distinct);
        }

        // 11. Offset
        if let Some(offset) = logical.offset {
            operators.push(PhysicalOperator::Offset(offset));
        }

        // 12. Limit last (caps output)
        if let Some(limit) = logical.limit {
            operators.push(PhysicalOperator::Limit(limit));
        }

        Ok(PhysicalPlan {
            collection: logical.collection.clone(),
            operators,
        })
    }

    pub fn explain(&self, logical: &LogicalPlan) -> Result<String> {
        let costed = self.plan_with_stats(logical, &PlannerStats::default())?;
        let target = if logical.collection == "_scalar" {
            "scalar expression".to_string()
        } else if logical.collection == "_meta" {
            format!("{:?}", logical.operation).to_lowercase()
        } else {
            logical.collection.clone()
        };
        let total_cost = if costed.total_cost == 0.0
            && costed.operators.is_empty()
            && logical.collection != "_scalar"
            && logical.collection != "_meta"
        {
            // Default full table scan cost
            100.0
        } else {
            costed.total_cost
        };
        let mut lines = vec![
            format!("EXPLAIN PLAN FOR {target}"),
            format!("  Total Cost: {total_cost:.2}"),
            "  Operators:".to_string(),
        ];
        if costed.operators.is_empty()
            && logical.collection != "_scalar"
            && logical.collection != "_meta"
        {
            lines.push("    1. FullScan (rows=*, cost=100.00) -- full collection scan".to_string());
        }
        for (i, op) in costed.operators.iter().enumerate() {
            lines.push(format!(
                "    {}. {} (rows={}, cost={:.2}) -- {}",
                i + 1,
                operator_name(&op.operator),
                op.estimated_rows,
                op.estimated_cost,
                op.reason
            ));
        }
        Ok(lines.join("\n"))
    }

    pub fn plan_with_stats(
        &self,
        logical: &LogicalPlan,
        stats: &PlannerStats,
    ) -> Result<CostedPlan> {
        let physical = self.plan(logical)?;
        let mut input_rows = stats.collection_cardinality.max(1);
        let mut costed = Vec::with_capacity(physical.operators.len());
        let mut total_cost = 0.0;
        for operator in &physical.operators {
            let estimate = estimate_operator(operator, input_rows, stats);
            input_rows = estimate.estimated_rows.max(1);
            total_cost += estimate.estimated_cost;
            costed.push(estimate);
        }
        Ok(CostedPlan {
            physical,
            operators: costed,
            total_cost,
        })
    }
}

fn estimate_operator(
    operator: &PhysicalOperator,
    input_rows: u64,
    stats: &PlannerStats,
) -> CostedOperator {
    match operator {
        PhysicalOperator::Filter(_) | PhysicalOperator::FilterExpression(_) => {
            let rows = ((input_rows as f64) * stats.filter_selectivity.clamp(0.0, 1.0)) as u64;
            CostedOperator {
                operator: operator.clone(),
                estimated_rows: rows.max(1),
                estimated_cost: (input_rows as f64) * stats.scalar_index_density.max(0.01),
                reason: "scalar selectivity and index density".into(),
            }
        }
        PhysicalOperator::Similarity(vector) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: vector.top.min(stats.vector_fanout as usize) as u64,
            estimated_cost: (stats.vector_fanout.max(vector.top as u64) as f64).log2() * 10.0,
            reason: "vector fanout estimate".into(),
        },
        PhysicalOperator::Traverse(traversal) => {
            let depth = traversal.hops as f64;
            let fanout = stats.graph_average_degree.max(1.0).powf(depth);
            CostedOperator {
                operator: operator.clone(),
                estimated_rows: fanout.min(input_rows as f64) as u64,
                estimated_cost: fanout,
                reason: "graph degree by traversal depth".into(),
            }
        }
        PhysicalOperator::FullText(full_text) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: full_text
                .top
                .unwrap_or(stats.full_text_posting_hits as usize)
                as u64,
            estimated_cost: (stats.full_text_posting_hits.max(1) as f64).log2() * 4.0,
            reason: "full-text posting hits".into(),
        },
        PhysicalOperator::Join(_) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows,
            estimated_cost: (input_rows as f64) * 1.5,
            reason: "indexed inner join estimate".into(),
        },
        PhysicalOperator::Order(_) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows,
            estimated_cost: (input_rows as f64) * (input_rows as f64).log2(),
            reason: "sort n log n".into(),
        },
        PhysicalOperator::Limit(limit) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows.min(*limit as u64),
            estimated_cost: 1.0,
            reason: "limit caps rows".into(),
        },
        PhysicalOperator::Rank(_) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows,
            estimated_cost: input_rows as f64,
            reason: "rank scores current candidate set".into(),
        },
        PhysicalOperator::AsOf => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows,
            estimated_cost: (input_rows as f64).log2(),
            reason: "snapshot plus bounded delta visibility".into(),
        },
        PhysicalOperator::Offset(offset) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows.saturating_sub(*offset as u64),
            estimated_cost: 1.0,
            reason: "offset skips rows".into(),
        },
        PhysicalOperator::Distinct => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows / 2,
            estimated_cost: (input_rows as f64) * (input_rows as f64).log2(),
            reason: "dedup via hash set".into(),
        },
        PhysicalOperator::GroupBy(_) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: (input_rows as f64).sqrt() as u64,
            estimated_cost: (input_rows as f64) * (input_rows as f64).log2(),
            reason: "group by hash partition".into(),
        },
        PhysicalOperator::Aggregate(_) => CostedOperator {
            operator: operator.clone(),
            estimated_rows: input_rows,
            estimated_cost: input_rows as f64,
            reason: "aggregate over grouped rows".into(),
        },
    }
}

fn operator_name(op: &PhysicalOperator) -> &'static str {
    match op {
        PhysicalOperator::Filter(_) => "Filter",
        PhysicalOperator::FilterExpression(_) => "FilterExpression",
        PhysicalOperator::Join(_) => "Join",
        PhysicalOperator::FullText(_) => "FullText",
        PhysicalOperator::Similarity(_) => "Similarity",
        PhysicalOperator::Traverse(_) => "Traverse",
        PhysicalOperator::Rank(_) => "Rank",
        PhysicalOperator::Order(_) => "Order",
        PhysicalOperator::Limit(_) => "Limit",
        PhysicalOperator::Offset(_) => "Offset",
        PhysicalOperator::Distinct => "Distinct",
        PhysicalOperator::GroupBy(_) => "GroupBy",
        PhysicalOperator::Aggregate(_) => "Aggregate",
        PhysicalOperator::AsOf => "AsOf",
    }
}
