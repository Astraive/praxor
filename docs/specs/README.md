# Specifications for praxor

This repository owns storage, transactions, query compilation, catalog, retrieval and replication. Start with a detailed existing issue and the [current roadmap](../status-roadmap.md). An old report or a feature-list slogan is input to discovery, not approved semantics or implementation evidence.

1. Create a bounded specification using [TEMPLATE.md](TEMPLATE.md), with an actual owning issue URL and relevant cross-repository contracts.
2. Define positive, negative and boundary/fault fixtures with expected outcomes, explicit limits, supported/refused platforms and compatibility behavior.
3. Review alternatives and decisions independently; record unresolved choices. Keep Project Spec status Draft/In review until required decisions are approved.
4. Decompose approved scope into bounded implementation and verification sub-issues. Link native parents and real blockers; do not make a child wait for completion of its own parent.
5. Link the approved spec in every implementing PR. Record deviations as reviewed amendments before changing the contract.
6. Close only with current-head evidence for the complete acceptance, or a clear verified-existing/superseded disposition with replacement hyperlinks.

Use YYYY-MM-DD-topic.md for specifications. Keep [GIT.md](../../GIT.md), native relationships and [Project #2](https://github.com/orgs/Astraive/projects/2) consistent. The [contribution foundation spec](2026-11-06-contribution-foundation.md) records this rollout's checks and limits.
