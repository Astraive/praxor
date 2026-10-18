use super::*;
use crate::catalog::schema::{AttributeSchema, AttributeType, CollectionSchema, IntegerType};
use crate::core_records::codec::{Key, Role, Row};
use crate::query::fixture_v1::{decode_document, encode_document};
use crate::types::ColumnFamily;
use bytes::Bytes;
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog
        .create_collection(
            CollectionSchema::new("docs").with_attribute(AttributeSchema::new(
                "n",
                AttributeType::Integer(IntegerType::Uint8),
            )),
        )
        .unwrap();
    catalog
}

fn fixture() -> (tempfile::TempDir, CoreDatabase, QueryGateway) {
    let dir = tempfile::tempdir().unwrap();
    let db = CoreDatabase::create_fresh(
        crate::PraxisConfig::new(dir.path()),
        crate::RecordAuthorityOptions::default(),
    )
    .unwrap();
    let gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    (dir, db, gateway)
}

fn put(db: &CoreDatabase, collection: &str, key: &str, n: Value) -> (CoreRecordId, Record) {
    let frame = encode_document(collection, key, &BTreeMap::from([("n".into(), n)])).unwrap();
    let rid = db.records().put(&frame, &[]).unwrap();
    (rid, decode_document(&frame).unwrap())
}

struct CandidateBackend {
    candidate: Vec<(CoreRecordId, Record)>,
}

impl QueryAccelerationBackend for CandidateBackend {
    fn complete_collection_at(
        &self,
        gateway: &QueryGateway,
        view: &QueryReadView,
        bound: &BoundSelect,
        request_identity: &Arc<()>,
    ) -> Result<Acceleration, QueryReadError> {
        gateway.certify_ready_candidate(view, bound, request_identity, self.candidate.clone())
    }
}

enum Tamper {
    ReadIdentity(Arc<()>),
    RequestIdentity,
    Collection,
}

struct TamperBackend {
    candidate: Vec<(CoreRecordId, Record)>,
    tamper: Tamper,
}

impl QueryAccelerationBackend for TamperBackend {
    fn complete_collection_at(
        &self,
        gateway: &QueryGateway,
        view: &QueryReadView,
        bound: &BoundSelect,
        request_identity: &Arc<()>,
    ) -> Result<Acceleration, QueryReadError> {
        let Acceleration::Ready(mut certificate) = gateway.certify_ready_candidate(
            view,
            bound,
            request_identity,
            self.candidate.clone(),
        )?
        else {
            panic!("test certifier did not return Ready")
        };
        match &self.tamper {
            Tamper::ReadIdentity(other) => certificate.read_identity = Arc::clone(other),
            Tamper::RequestIdentity => certificate.request_identity = Arc::new(()),
            Tamper::Collection => certificate.collection = "foreign".into(),
        }
        // If the caller were to evaluate rows first, this wrong referenced
        // type would leak a DataContract error before the identity refusal.
        certificate.ordered[0]
            .1
            .attributes
            .insert("n".into(), Value::String("tampered".into()));
        Ok(Acceleration::Ready(certificate))
    }
}

struct ReplayBackend {
    candidate: Vec<(CoreRecordId, Record)>,
    prior: parking_lot::Mutex<Option<ReadyCertificate>>,
}

impl QueryAccelerationBackend for ReplayBackend {
    fn complete_collection_at(
        &self,
        gateway: &QueryGateway,
        view: &QueryReadView,
        bound: &BoundSelect,
        request_identity: &Arc<()>,
    ) -> Result<Acceleration, QueryReadError> {
        if let Some(prior) = self.prior.lock().clone() {
            return Ok(Acceleration::Ready(prior));
        }
        let Acceleration::Ready(certificate) = gateway.certify_ready_candidate(
            view,
            bound,
            request_identity,
            self.candidate.clone(),
        )?
        else {
            panic!("test certifier did not return Ready")
        };
        *self.prior.lock() = Some(certificate.clone());
        Ok(Acceleration::Ready(certificate))
    }
}

#[test]
fn synthetic_ready_must_select_a_complete_branch_without_fallback() {
    let (_dir, db, mut gateway) = fixture();
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row],
    });
    let view = gateway.begin_read().unwrap();

    let QueryResult::Rows(rows) = gateway
        .query(&view, "SELECT n FROM docs", &TypedParameters::default())
        .unwrap()
    else {
        panic!("expected rows")
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id.key, "one");
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 1);
    assert_eq!(gateway.test_hooks.ready_selected.load(Ordering::Relaxed), 1);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn canonical_output_cap_precedes_a_mismatched_candidate() {
    let (_dir, db, mut gateway) = fixture();
    put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    gateway.limits.logical_output_bytes = 0;
    gateway.acceleration = Arc::new(CandidateBackend { candidate: vec![] });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::ResourceLimit {
            code: "logical_output_bytes"
        })
    ));
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn canonical_referenced_type_failure_precedes_a_mismatched_candidate() {
    let (_dir, db, mut gateway) = fixture();
    put(&db, "docs", "wrong", Value::String("text".into()));
    gateway.acceleration = Arc::new(CandidateBackend { candidate: vec![] });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(
            &view,
            "SELECT n FROM docs WHERE n = 7",
            &TypedParameters::default()
        ),
        Err(QueryReadError::Compile(QueryCompileError::DataContract {
            code: "wrong_type"
        }))
    ));
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn mismatched_candidate_is_an_acceleration_invariant_not_partial_rows() {
    let (_dir, db, mut gateway) = fixture();
    put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    gateway.acceleration = Arc::new(CandidateBackend { candidate: vec![] });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::AccelerationInvariant {
            code: "candidate_mismatch"
        })
    ));
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn production_unavailable_and_direct_backend_error_have_distinct_counts() {
    let (_dir, db, mut gateway) = fixture();
    put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Ok(QueryResult::Rows(_))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 1);
    assert_eq!(gateway.test_hooks.ready_selected.load(Ordering::Relaxed), 0);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        0
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 1);

    struct DirectErrorBackend;
    impl QueryAccelerationBackend for DirectErrorBackend {
        fn complete_collection_at(
            &self,
            _gateway: &QueryGateway,
            _view: &QueryReadView,
            _bound: &BoundSelect,
            _request_identity: &Arc<()>,
        ) -> Result<Acceleration, QueryReadError> {
            Err(QueryReadError::Storage(PraxisError::RecoveryRequired))
        }
    }
    gateway.acceleration = Arc::new(DirectErrorBackend);
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Storage(PraxisError::RecoveryRequired))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        0
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 1);
}

#[test]
fn ready_matches_unavailable_with_typed_predicates_and_physical_order() {
    let (_dir, db, mut ready) = fixture();
    let first = put(&db, "docs", "first", Value::Number(Number::from(7_u64)));
    let second = put(&db, "docs", "second", Value::Number(Number::from(8_u64)));
    let fallback = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    ready.acceleration = Arc::new(CandidateBackend {
        candidate: vec![first, second],
    });
    let ready_view = ready.begin_read().unwrap();
    let fallback_view = fallback.begin_read().unwrap();
    let params = TypedParameters {
        positional: vec![super::super::ParameterValue::U64(7)],
        ..TypedParameters::default()
    };
    for (sql, params) in [
        ("SELECT n FROM docs", TypedParameters::default()),
        ("SELECT * FROM docs", TypedParameters::default()),
        ("SELECT n FROM docs WHERE n = $1", params),
    ] {
        let QueryResult::Rows(expected) = fallback.query(&fallback_view, sql, &params).unwrap()
        else {
            panic!("fallback did not return rows")
        };
        let QueryResult::Rows(actual) = ready.query(&ready_view, sql, &params).unwrap() else {
            panic!("Ready did not return rows")
        };
        assert_eq!(actual, expected);
    }
    assert_eq!(ready.test_hooks.backend_calls.load(Ordering::Relaxed), 3);
    assert_eq!(ready.test_hooks.ready_selected.load(Ordering::Relaxed), 3);
    assert_eq!(
        ready.test_hooks.certificate_scans.load(Ordering::Relaxed),
        3
    );
    assert_eq!(ready.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn certificate_compares_complete_ordered_rid_and_record_not_projected_columns() {
    let (_dir, db, mut gateway) = fixture();
    let first = put(&db, "docs", "first", Value::Number(Number::from(7_u64)));
    let second = put(&db, "docs", "second", Value::Number(Number::from(8_u64)));
    let exact = vec![first.clone(), second.clone()];
    let mut mutants = vec![
        Vec::new(),
        vec![first.clone(), second.clone(), second.clone()],
        vec![second.clone(), first.clone()],
        vec![first.clone(), first],
    ];
    let mut wrong_rid = exact.clone();
    wrong_rid[0].0 = CoreRecordId(999);
    mutants.push(wrong_rid);
    let mut projected = exact.clone();
    projected[0]
        .1
        .attributes
        .insert("n".into(), Value::Number(Number::from(9_u64)));
    mutants.push(projected);
    let mut unused = exact.clone();
    unused[0].1.created_at_ms = 1;
    mutants.push(unused);
    let view = gateway.begin_read().unwrap();
    for candidate in mutants {
        gateway.acceleration = Arc::new(CandidateBackend { candidate });
        assert!(matches!(
            gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
            Err(QueryReadError::AccelerationInvariant {
                code: "candidate_mismatch"
            })
        ));
    }
    let mut changed_where = exact;
    changed_where[0]
        .1
        .attributes
        .insert("n".into(), Value::Number(Number::from(9_u64)));
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: changed_where,
    });
    assert!(matches!(
        gateway.query(
            &view,
            "SELECT n FROM docs WHERE n = 7",
            &TypedParameters::default()
        ),
        Err(QueryReadError::AccelerationInvariant {
            code: "candidate_mismatch"
        })
    ));
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        8
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn ready_identity_is_the_exact_read_and_fresh_request_not_equal_sequence() {
    let (_dir, db, mut gateway) = fixture();
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    let first = gateway.begin_read().unwrap();
    let clone = first.clone();
    let second = gateway.begin_read().unwrap();
    assert_eq!(first.core.core_sequence(), second.core.core_sequence());
    assert!(Arc::ptr_eq(&first.read_identity, &clone.read_identity));
    assert!(!Arc::ptr_eq(&first.read_identity, &second.read_identity));

    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row.clone()],
    });
    for view in [&clone, &second] {
        assert!(matches!(
            gateway.query(view, "SELECT n FROM docs", &TypedParameters::default()),
            Ok(QueryResult::Rows(_))
        ));
    }
    for (tamper, expected) in [
        (
            Tamper::ReadIdentity(Arc::clone(&first.read_identity)),
            "read_identity",
        ),
        (Tamper::RequestIdentity, "request_identity"),
        (Tamper::Collection, "collection"),
    ] {
        gateway.acceleration = Arc::new(TamperBackend {
            candidate: vec![row.clone()],
            tamper,
        });
        assert!(matches!(
            gateway.query(&second, "SELECT n FROM docs", &TypedParameters::default()),
            Err(QueryReadError::AccelerationInvariant { code }) if code == expected
        ));
    }
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn a_prior_certificate_cannot_be_replayed_on_the_same_held_read() {
    let (_dir, db, mut gateway) = fixture();
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    gateway.acceleration = Arc::new(ReplayBackend {
        candidate: vec![row],
        prior: parking_lot::Mutex::new(None),
    });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Ok(QueryResult::Rows(_))
    ));
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::AccelerationInvariant {
            code: "request_identity"
        })
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 2);
    assert_eq!(gateway.test_hooks.ready_selected.load(Ordering::Relaxed), 2);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn malformed_foreign_envelopes_precede_filtered_out_wrong_type_in_both_paths() {
    for bad_at in 0..3 {
        let (_dir, db, mut ready) = fixture();
        let mut bad_rid = CoreRecordId::NULL;
        for index in 0..3 {
            if index == bad_at {
                let mut invalid = encode_document("foreign", "bad", &BTreeMap::new()).unwrap();
                invalid[0] ^= 1;
                bad_rid = db.records().put(&invalid, &[]).unwrap();
            } else if index == (bad_at + 1) % 3 {
                put(&db, "docs", "wrong", Value::String("text".into()));
            } else {
                put(&db, "docs", "good", Value::Number(Number::from(7_u64)));
            }
        }
        let fallback = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
        ready.acceleration = Arc::new(CandidateBackend { candidate: vec![] });
        let ready_view = ready.begin_read().unwrap();
        let fallback_view = fallback.begin_read().unwrap();
        let sql = "SELECT n FROM docs WHERE n = 7";
        for (gateway, view) in [(&ready, &ready_view), (&fallback, &fallback_view)] {
            assert!(matches!(
                gateway.query(view, sql, &TypedParameters::default()),
                Err(QueryReadError::Document {
                    core_rid,
                    reason: FixtureDecodeReason::InvalidMagic
                }) if core_rid == bad_rid
            ));
        }
        assert_eq!(
            ready.test_hooks.certificate_scans.load(Ordering::Relaxed),
            1
        );
        assert_eq!(ready.test_hooks.ready_selected.load(Ordering::Relaxed), 0);
        assert_eq!(ready.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn duplicate_requested_logical_ids_are_terminal_before_ready_selection() {
    let (_dir, db, mut ready) = fixture();
    let first = put(&db, "docs", "same", Value::Number(Number::from(7_u64)));
    let later = put(&db, "docs", "same", Value::Number(Number::from(8_u64)));
    let fallback = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    ready.acceleration = Arc::new(CandidateBackend {
        candidate: vec![first],
    });
    let ready_view = ready.begin_read().unwrap();
    let fallback_view = fallback.begin_read().unwrap();
    for (gateway, view) in [(&ready, &ready_view), (&fallback, &fallback_view)] {
        assert!(matches!(
            gateway.query(view, "SELECT n FROM docs", &TypedParameters::default()),
            Err(QueryReadError::DuplicateLogicalId { core_rid }) if core_rid == later.0
        ));
    }
    assert_eq!(
        ready.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(ready.test_hooks.ready_selected.load(Ordering::Relaxed), 0);
    assert_eq!(ready.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn certificate_uses_scanner_derived_payload_bytes_including_foreign_rows() {
    let (_dir, db, mut gateway) = fixture();
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    put(&db, "foreign", "one", Value::Number(Number::from(1_u64)));
    let view = gateway.begin_read().unwrap();
    let CompiledStatement::Select(bound) = compile(
        CompileInput::Sql("SELECT n FROM docs"),
        &TypedParameters::default(),
        &view.catalog,
    )
    .unwrap() else {
        panic!("expected bound SELECT")
    };
    let expected_payload_bytes = db
        .records()
        .scan_live_at_snapshot(&view.core, RecordScanLimits::fixture_v1())
        .unwrap()
        .iter()
        .map(|(_, bytes)| bytes.len() as u64)
        .sum::<u64>();
    let Acceleration::Ready(certificate) = gateway
        .certify_ready_candidate(&view, &bound, &Arc::new(()), vec![row.clone()])
        .unwrap()
    else {
        panic!("expected Ready")
    };
    assert_eq!(certificate.pinned_payload_bytes, expected_payload_bytes);
    assert_eq!(certificate.ordered, vec![row.clone()]);
    let exact = expected_payload_bytes + 7 + 129;
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row],
    });
    for sql in ["SELECT n FROM docs", "SELECT * FROM docs"] {
        gateway.limits.logical_output_bytes = exact - 1;
        assert!(matches!(
            gateway.query(&view, sql, &TypedParameters::default()),
            Err(QueryReadError::ResourceLimit {
                code: "logical_output_bytes"
            })
        ));
        gateway.limits.logical_output_bytes = exact;
        assert!(matches!(
            gateway.query(&view, sql, &TypedParameters::default()),
            Ok(QueryResult::Rows(_))
        ));
    }
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn ready_and_unavailable_agree_on_exact_and_over_cumulative_attribute_caps() {
    let (_dir, db, mut ready) = fixture();
    put(&db, "foreign", "one", Value::Number(Number::from(1_u64)));
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    let mut fallback = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    ready.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row],
    });
    let ready_view = ready.begin_read().unwrap();
    let fallback_view = fallback.begin_read().unwrap();
    for cap in [1, 2] {
        ready.limits.decoded_attribute_entries = cap;
        fallback.limits.decoded_attribute_entries = cap;
        for sql in ["SELECT n FROM docs", "SELECT * FROM docs"] {
            let actual = ready.query(&ready_view, sql, &TypedParameters::default());
            let expected = fallback.query(&fallback_view, sql, &TypedParameters::default());
            if cap == 1 {
                assert!(matches!(
                    actual,
                    Err(QueryReadError::ResourceLimit {
                        code: "attribute_entries"
                    })
                ));
                assert!(matches!(
                    expected,
                    Err(QueryReadError::ResourceLimit {
                        code: "attribute_entries"
                    })
                ));
            } else {
                let (Ok(QueryResult::Rows(actual)), Ok(QueryResult::Rows(expected))) =
                    (actual, expected)
                else {
                    panic!("both paths must return rows at exact cap")
                };
                assert_eq!(actual, expected);
            }
        }
    }
    assert_eq!(
        ready.test_hooks.certificate_scans.load(Ordering::Relaxed),
        4
    );
    assert_eq!(ready.test_hooks.ready_selected.load(Ordering::Relaxed), 2);
    assert_eq!(ready.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn foreign_stale_and_poisoned_preflight_never_invokes_the_backend() {
    let (_dir, db, mut gateway) = fixture();
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row],
    });
    let view = gateway.begin_read().unwrap();
    let foreign = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    let foreign_view = foreign.begin_read().unwrap();
    assert!(matches!(
        gateway.query(
            &foreign_view,
            "SELECT n FROM docs",
            &TypedParameters::default()
        ),
        Err(QueryReadError::ForeignGateway)
    ));

    let mut wrong_core = view.clone();
    let (_other_dir, other_db, _) = fixture();
    wrong_core.core = other_db.records().pin_snapshot().unwrap();
    assert!(matches!(
        gateway.query(
            &wrong_core,
            "SELECT n FROM docs",
            &TypedParameters::default()
        ),
        Err(QueryReadError::Storage(
            PraxisError::ForeignRecordSnapshot { .. }
        ))
    ));

    let CompiledStatement::Select(foreign_bound) = compile(
        CompileInput::Sql("SELECT n FROM docs"),
        &TypedParameters::default(),
        &foreign_view.catalog,
    )
    .unwrap() else {
        panic!("expected bound SELECT")
    };
    assert!(matches!(
        gateway.execute_bound(&view, &foreign_bound),
        Err(QueryReadError::Compile(QueryCompileError::ForeignCatalog))
    ));

    let CompiledStatement::Select(stale_bound) = compile(
        CompileInput::Sql("SELECT n FROM docs"),
        &TypedParameters::default(),
        &view.catalog,
    )
    .unwrap() else {
        panic!("expected bound SELECT")
    };
    gateway
        .catalog
        .replace_collection(catalog().collection("docs").unwrap().clone())
        .unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
    ));
    let fresh_view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.execute_bound(&fresh_view, &stale_bound),
        Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 0);
    assert_eq!(gateway.test_hooks.scan_calls.load(Ordering::Relaxed), 0);

    db.kv().inner.group_commit.poison("test preflight".into());
    assert!(matches!(
        gateway.query(
            &fresh_view,
            "SELECT n FROM docs",
            &TypedParameters::default()
        ),
        Err(QueryReadError::Storage(PraxisError::RecoveryRequired))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 0);
    assert_eq!(gateway.test_hooks.scan_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn ready_and_explain_final_barriers_suppress_success() {
    for explain in [false, true] {
        let (_dir, db, mut gateway) = fixture();
        let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
        gateway.acceleration = Arc::new(CandidateBackend {
            candidate: vec![row],
        });
        let gateway = Arc::new(gateway);
        let view = gateway.begin_read().unwrap();
        let weak = Arc::downgrade(&gateway);
        *gateway.test_hooks.before_final.lock() = Some(Arc::new(move || {
            if let Some(gateway) = weak.upgrade() {
                gateway.catalog.drop_collection("docs").unwrap();
            }
        }));
        let sql = if explain {
            "EXPLAIN SELECT n FROM docs"
        } else {
            "SELECT n FROM docs"
        };
        assert!(matches!(
            gateway.query(&view, sql, &TypedParameters::default()),
            Err(QueryReadError::Compile(QueryCompileError::StaleCatalog))
        ));
        assert_eq!(
            gateway.test_hooks.backend_calls.load(Ordering::Relaxed),
            usize::from(!explain)
        );
        assert_eq!(
            gateway.test_hooks.ready_selected.load(Ordering::Relaxed),
            usize::from(!explain)
        );
        assert_eq!(
            gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
            usize::from(!explain)
        );
        assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn ready_final_owner_poison_suppresses_rows_without_partial_success() {
    let (_dir, db, mut gateway) = fixture();
    let row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row],
    });
    let view = gateway.begin_read().unwrap();
    let engine = db.kv();
    *gateway.test_hooks.before_final.lock() = Some(Arc::new(move || {
        engine.inner.group_commit.poison("test final owner".into());
    }));
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Storage(PraxisError::RecoveryRequired))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn fresh_ready_and_fallback_agree_on_held_old_view_after_each_compaction_strategy() {
    for strategy in [
        crate::CompactionStrategy::Leveled,
        crate::CompactionStrategy::Tiered,
        crate::CompactionStrategy::Universal,
    ] {
        let (_dir, db, mut gateway) = fixture();
        let old = put(&db, "docs", "old", Value::Number(Number::from(7_u64)));
        db.records().flush().unwrap();
        let old_view = gateway.begin_read().unwrap();
        db.records().delete_record(old.0).unwrap();
        put(&db, "docs", "old", Value::Number(Number::from(8_u64)));
        db.records().flush().unwrap();
        assert!(db.kv().compact_with_strategy(strategy).unwrap() > 0);
        db.records().reclaim_snapshot_history().unwrap();
        db.kv().garbage_collect().unwrap();

        gateway.acceleration = Arc::new(CandidateBackend {
            candidate: vec![old],
        });
        let QueryResult::Rows(ready_rows) = gateway
            .query(&old_view, "SELECT n FROM docs", &TypedParameters::default())
            .unwrap()
        else {
            panic!("Ready did not return rows")
        };
        gateway.acceleration = Arc::new(UnavailableBackend);
        let QueryResult::Rows(fallback_rows) = gateway
            .query(&old_view, "SELECT n FROM docs", &TypedParameters::default())
            .unwrap()
        else {
            panic!("fallback did not return rows")
        };
        assert_eq!(ready_rows, fallback_rows);
        assert_eq!(ready_rows.len(), 1);
        assert_eq!(ready_rows[0].id.key, "old");
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 1);
        drop(old_view);
        assert_eq!(db.kv().inner.snapshots.pinned_count(), 0);
    }
}

#[test]
fn a_later_corrupt_payload_defeats_fresh_ready_on_the_same_view() {
    let (_dir, db, mut gateway) = fixture();
    let first = put(&db, "docs", "first", Value::Number(Number::from(7_u64)));
    let second = put(&db, "docs", "second", Value::Number(Number::from(8_u64)));
    let rid = second.0;
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![first, second],
    });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Ok(QueryResult::Rows(_))
    ));
    let mut batch = crate::WriteBatch::new();
    batch.put(
        Role::Payload.cf(),
        Key::Payload(rid.0).encode().unwrap(),
        Row::Payload(b"short").encode().unwrap(),
    );
    for op in batch.ops() {
        db.kv()
            .inner
            .memtable
            .write()
            .apply(view.core.core_sequence(), op);
    }
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Storage(PraxisError::Corrupt { .. }))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        2
    );
    assert_eq!(gateway.test_hooks.ready_selected.load(Ordering::Relaxed), 1);
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn a_later_external_payload_io_fault_defeats_fresh_ready_on_the_same_view() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crate::PraxisConfig::new(dir.path());
    config.large_value_threshold = 1;
    let db = CoreDatabase::create_fresh(config.clone(), crate::RecordAuthorityOptions::default())
        .unwrap();
    let first = put(&db, "docs", "first", Value::Number(Number::from(7_u64)));
    let second = put(&db, "docs", "second", Value::Number(Number::from(8_u64)));
    db.records().flush().unwrap();
    drop(db);
    let db = CoreDatabase::open(config).unwrap();
    let mut gateway = QueryGateway::attach_fixture_v1(&db, catalog()).unwrap();
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![first, second.clone()],
    });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Ok(QueryResult::Rows(_))
    ));
    let path = {
        let engine = db.kv();
        let index = engine.inner.segment_index.read();
        let versions = &index[&(
            ColumnFamily(Role::Payload.cf().into()),
            Bytes::from(Key::Payload(second.0.0).encode().unwrap()),
        )];
        let crate::types::StoredValue::BlobPointer(pointer) = &versions.last().unwrap().value
        else {
            panic!("persisted external payload pointer required")
        };
        std::path::PathBuf::from(&pointer.path)
    };
    let unavailable = path.with_extension("held");
    std::fs::rename(&path, &unavailable).unwrap();
    let result = gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default());
    std::fs::rename(&unavailable, &path).unwrap();
    assert!(matches!(
        result,
        Err(QueryReadError::Storage(PraxisError::Io(_)))
    ));
    assert_eq!(gateway.test_hooks.backend_calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        2
    );
    assert_eq!(gateway.test_hooks.ready_selected.load(Ordering::Relaxed), 1);
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Ok(QueryResult::Rows(_))
    ));
}

#[test]
fn ready_preserves_literal_colon_pairs_utf8_empty_keys_and_null_projection() {
    const A: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x03a:b\x00\x01c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
    const B: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x2a\x00\x01a\x00\x03b:c\x00\x02\x00\x01n\x00\x00\x01v\x04\x00\x00\x00\x00\x00\x00\x00\x07";
    const C: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x19\x00\x01u\x00\x02\xc3\xa9\x00\x00";
    const D: &[u8] = b"\x50\x52\x58\x51\x44\x4f\x43\x00\x00\x01\x00\x00\x00\x00\x00\x17\x00\x01u\x00\x00\x00\x00";
    let dir = tempfile::tempdir().unwrap();
    let db = CoreDatabase::create_fresh(
        crate::PraxisConfig::new(dir.path()),
        crate::RecordAuthorityOptions::default(),
    )
    .unwrap();
    let mut candidates = BTreeMap::<String, Vec<(CoreRecordId, Record)>>::new();
    for wire in [A, B, C, D] {
        let rid = db.records().put(wire, &[]).unwrap();
        let record = decode_document(wire).unwrap();
        candidates
            .entry(record.id.collection.clone())
            .or_default()
            .push((rid, record));
    }
    let mut schema = Catalog::new();
    for name in ["a:b", "a", "u"] {
        schema
            .create_collection(
                CollectionSchema::new(name).with_attribute(AttributeSchema::new(
                    "v",
                    AttributeType::Integer(IntegerType::Uint8),
                )),
            )
            .unwrap();
    }
    let mut ready = QueryGateway::attach_fixture_v1(&db, schema.clone()).unwrap();
    let fallback = QueryGateway::attach_fixture_v1(&db, schema).unwrap();
    let ready_view = ready.begin_read().unwrap();
    let fallback_view = fallback.begin_read().unwrap();
    for (sql, collection) in [
        ("SELECT v FROM \"a:b\"", "a:b"),
        ("SELECT v FROM a", "a"),
        ("SELECT v FROM u", "u"),
    ] {
        ready.acceleration = Arc::new(CandidateBackend {
            candidate: candidates[collection].clone(),
        });
        let QueryResult::Rows(actual) = ready
            .query(&ready_view, sql, &TypedParameters::default())
            .unwrap()
        else {
            panic!("Ready did not return rows")
        };
        let QueryResult::Rows(expected) = fallback
            .query(&fallback_view, sql, &TypedParameters::default())
            .unwrap()
        else {
            panic!("fallback did not return rows")
        };
        assert_eq!(actual, expected);
    }
    assert_eq!(ready.test_hooks.ready_selected.load(Ordering::Relaxed), 3);
    assert_eq!(ready.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn ready_keeps_frame_count_and_remaining_attribute_budget_precedence() {
    let (_dir, db, mut gateway) = fixture();
    put(&db, "foreign", "one", Value::Number(Number::from(1_u64)));
    let mut bad_count = encode_document(
        "docs",
        "bad-count",
        &BTreeMap::from([("n".into(), Value::Number(Number::from(7_u64)))]),
    )
    .unwrap();
    let count_at = 16 + 2 + "docs".len() + 2 + "bad-count".len();
    bad_count[count_at..count_at + 2].copy_from_slice(&257_u16.to_be_bytes());
    let bad_rid = db.records().put(&bad_count, &[]).unwrap();
    gateway.limits.decoded_attribute_entries = 1;
    gateway.acceleration = Arc::new(CandidateBackend { candidate: vec![] });
    let view = gateway.begin_read().unwrap();
    assert!(matches!(
        gateway.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Document {
            core_rid,
            reason: FixtureDecodeReason::InvalidAttributeCount
        }) if core_rid == bad_rid
    ));
    assert_eq!(
        gateway.test_hooks.certificate_scans.load(Ordering::Relaxed),
        1
    );
    assert_eq!(gateway.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);

    let (_dir2, db2, mut second) = fixture();
    put(&db2, "foreign", "one", Value::Number(Number::from(1_u64)));
    let mut bad_entry = encode_document(
        "docs",
        "bad-entry",
        &BTreeMap::from([("n".into(), Value::Number(Number::from(7_u64)))]),
    )
    .unwrap();
    let tag_at = bad_entry.len() - 9;
    bad_entry[tag_at] = 255;
    let bad_rid = db2.records().put(&bad_entry, &[]).unwrap();
    second.acceleration = Arc::new(CandidateBackend { candidate: vec![] });
    let view = second.begin_read().unwrap();
    second.limits.decoded_attribute_entries = 1;
    assert!(matches!(
        second.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::ResourceLimit {
            code: "attribute_entries"
        })
    ));
    second.limits.decoded_attribute_entries = 2;
    assert!(matches!(
        second.query(&view, "SELECT n FROM docs", &TypedParameters::default()),
        Err(QueryReadError::Document {
            core_rid,
            reason: FixtureDecodeReason::UnknownValueTag
        }) if core_rid == bad_rid
    ));
    assert_eq!(
        second.test_hooks.certificate_scans.load(Ordering::Relaxed),
        2
    );
    assert_eq!(second.test_hooks.fallback_scans.load(Ordering::Relaxed), 0);
}

#[test]
fn acceleration_invariant_debug_is_finite_and_does_not_echo_candidate_data() {
    let (_dir, db, mut gateway) = fixture();
    let mut row = put(&db, "docs", "one", Value::Number(Number::from(7_u64)));
    row.1.id.collection = "secret_collection".into();
    row.1.id.key = "secret_key".into();
    row.1
        .attributes
        .insert("n".into(), Value::String("secret_value".into()));
    gateway.acceleration = Arc::new(CandidateBackend {
        candidate: vec![row],
    });
    let view = gateway.begin_read().unwrap();
    let error = gateway
        .query(&view, "SELECT n FROM docs", &TypedParameters::default())
        .unwrap_err();
    assert!(matches!(
        error,
        QueryReadError::AccelerationInvariant {
            code: "candidate_mismatch"
        }
    ));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("secret_collection"));
    assert!(!rendered.contains("secret_key"));
    assert!(!rendered.contains("secret_value"));
    assert!(rendered.contains("candidate_mismatch"));
}
