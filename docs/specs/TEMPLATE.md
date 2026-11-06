# Specification title

Status: Draft
Owner: Astraive/praxor
Issue: replace with an actual GitHub issue URL
Evidence revision: full owning commit

## Summary and motivation

Describe the concrete trigger, required result and why it matters to this repository.

## Current behavior and source evidence

Link current files, reports and verified existing work. Distinguish committed behavior, unpublished local work and proposed paths.

## Scope and exclusions

List supported operations, owners and platforms. Explicitly exclude unrelated behavior and unsupported guarantees.

## Requirements

Number falsifiable inputs, outputs, errors, state transitions, authority boundaries and resource limits. Identify decisions still requiring approval.

## Design and alternatives

Describe public interfaces, dependency direction, storage/lifetime/concurrency behavior where relevant and the considered alternatives with reasons.

## Compatibility, security and failure behavior

Name version negotiation/migrations, authorization/capability assumptions, cancellation, partial effects, recovery and unsupported combinations.

## Fixtures and acceptance

| Case | Input/schedule | Expected result/state | Owning verification |
| --- | --- | --- | --- |
| Positive | Concrete valid input | Exact public result | Actual test/task link |
| Negative | Concrete malformed/denied input | Typed error and no unintended effect | Actual test/task link |
| Boundary/fault | Relevant concurrency/restart/platform cut | Exact preserved/refused behavior | Actual test/task link |

## Implementation and verification decomposition

Link bounded native sub-issues, real prerequisite URLs and the artifact each edge requires. Include independent integration/release evidence.

## Decisions, risks and review

Record approved choices, open questions, reviewer, revision/date and amendments. Do not substitute a feature title or issue count for delivery evidence.
