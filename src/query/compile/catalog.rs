//! Detached, process-local binding authority. It owns no persisted catalog writer.
use super::QueryCompileError;
use crate::catalog::schema::{Catalog, CollectionSchema};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug)]
struct CatalogState {
    revision: u64,
    schemas: Arc<BTreeMap<String, CollectionSchema>>,
}

#[derive(Debug)]
pub(super) struct CatalogOwner {
    state: RwLock<CatalogState>,
}

#[derive(Debug)]
pub(super) struct QueryCatalogAuthority {
    pub(super) owner: Arc<CatalogOwner>,
}

#[derive(Clone, Debug)]
pub(super) struct QueryCatalogView {
    pub(super) owner: Arc<CatalogOwner>,
    pub(super) schemas: Arc<BTreeMap<String, CollectionSchema>>,
    pub(super) revision: u64,
}

impl QueryCatalogAuthority {
    pub(super) fn new(catalog: Catalog) -> Self {
        let schemas = catalog
            .collections()
            .map(|schema| (schema.name.clone(), schema.clone()))
            .collect();
        Self {
            owner: Arc::new(CatalogOwner {
                state: RwLock::new(CatalogState {
                    revision: 1,
                    schemas: Arc::new(schemas),
                }),
            }),
        }
    }

    pub(super) fn view(&self) -> QueryCatalogView {
        let state = self.owner.state.read();
        QueryCatalogView {
            owner: Arc::clone(&self.owner),
            schemas: Arc::clone(&state.schemas),
            revision: state.revision,
        }
    }

    pub(super) fn replace_collection(
        &self,
        schema: CollectionSchema,
    ) -> Result<(), QueryCompileError> {
        let mut state = self.owner.state.write();
        let next_revision =
            state
                .revision
                .checked_add(1)
                .ok_or(QueryCompileError::LimitExceeded {
                    code: "catalog_revision",
                    span: None,
                })?;
        Arc::make_mut(&mut state.schemas).insert(schema.name.clone(), schema);
        state.revision = next_revision;
        Ok(())
    }

    pub(super) fn drop_collection(&self, name: &str) -> Result<(), QueryCompileError> {
        let mut state = self.owner.state.write();
        if !state.schemas.contains_key(name) {
            return Err(QueryCompileError::UnknownCollection {
                name: name.into(),
                span: None,
            });
        }
        let next_revision =
            state
                .revision
                .checked_add(1)
                .ok_or(QueryCompileError::LimitExceeded {
                    code: "catalog_revision",
                    span: None,
                })?;
        Arc::make_mut(&mut state.schemas).remove(name);
        state.revision = next_revision;
        Ok(())
    }

    pub(super) fn validate_view(&self, view: &QueryCatalogView) -> Result<(), QueryCompileError> {
        self.validate_handle(&view.owner, view.revision)
    }

    pub(super) fn validate_handle(
        &self,
        owner: &Arc<CatalogOwner>,
        revision: u64,
    ) -> Result<(), QueryCompileError> {
        if !Arc::ptr_eq(&self.owner, owner) {
            return Err(QueryCompileError::ForeignCatalog);
        }
        if self.owner.state.read().revision != revision {
            return Err(QueryCompileError::StaleCatalog);
        }
        Ok(())
    }
}

impl QueryCatalogView {
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn validate_current(&self) -> Result<(), QueryCompileError> {
        if self.owner.state.read().revision != self.revision {
            return Err(QueryCompileError::StaleCatalog);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::schema::{AttributeSchema, AttributeType};

    #[test]
    fn revision_overflow_does_not_mutate_a_collection_or_snapshot() {
        let authority = QueryCatalogAuthority::new(Catalog::new());
        authority
            .replace_collection(
                CollectionSchema::new("users")
                    .with_attribute(AttributeSchema::new("name", AttributeType::Text)),
            )
            .unwrap();
        {
            authority.owner.state.write().revision = u64::MAX;
        }
        let before = authority.view();
        assert_eq!(before.revision, u64::MAX);
        assert!(matches!(
            authority.replace_collection(CollectionSchema::new("users")),
            Err(QueryCompileError::LimitExceeded {
                code: "catalog_revision",
                span: None
            })
        ));
        assert!(matches!(
            authority.drop_collection("users"),
            Err(QueryCompileError::LimitExceeded {
                code: "catalog_revision",
                span: None
            })
        ));
        let after = authority.view();
        assert_eq!(after.revision, u64::MAX);
        assert!(Arc::ptr_eq(&before.schemas, &after.schemas));
        assert_eq!(after.schemas["users"].attributes.len(), 1);
    }
}
